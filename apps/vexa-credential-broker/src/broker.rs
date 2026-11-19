//! The broker's core: the state every route shares, and the checks every
//! route runs. It owns the metadata database and the credential store port,
//! verifies the caller, writes the audit trail before the action it records,
//! and logs faults as typed lines.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rusqlite::types::{ToSql, ValueRef};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::config::Settings;
use crate::fail::{Fail, R};
use crate::lock::ReentrantLock;
use crate::store::{Record, Store, StoreUnavailable};
use crate::{assertion, google, identity, metadata, obs, sensor_grants, util};

/// The verified caller of one request.
#[derive(Debug, Clone, Default)]
pub struct Who {
    pub actor: String,
    pub session: String,
    pub role: String,
    /// The shared workspaces the gateway signed for this person.
    pub memberships: Vec<String>,
    /// A worker's identity with nobody in the loop.
    pub unwatched: bool,
    /// Any worker's identity.
    pub delegated: bool,
    /// Other people read this turn's answer.
    pub shared: bool,
}

/// A path with connection ids folded to {cid}: low-cardinality, safe to log.
pub fn route_of(path: &str) -> String {
    let path = path.split('?').next().unwrap_or("");
    path.split('/')
        .map(|seg| if seg.len() == 32 && seg.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) { "{cid}" } else { seg })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn host_of(url: &str) -> String {
    util::urlsplit(url).ok().and_then(|s| s.hostname()).unwrap_or_default()
}

/// The host a human's secret is sent to for a prepared setup.
pub fn destination_host(spec: &Value) -> String {
    if util::truthy(spec.get("oauth")) {
        host_of(spec["oauth"].get("token_url").and_then(Value::as_str).unwrap_or(""))
    } else {
        host_of(util::text(spec, "endpoint"))
    }
}

/// Every host a prepared setup sends a credential to, in order, without repeats.
pub fn credential_hosts(spec: &Value) -> Vec<String> {
    let mut hosts = vec![destination_host(spec)];
    if util::truthy(spec.get("oauth")) {
        hosts.push(host_of(util::text(spec, "endpoint")));
    }
    let mut out: Vec<String> = Vec::new();
    for h in hosts {
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

pub type Row = Map<String, Value>;

pub fn row_text<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).and_then(Value::as_str).unwrap_or("")
}

pub fn row_int(row: &Row, key: &str) -> i64 {
    row.get(key).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0)
}

pub fn row_f64(row: &Row, key: &str) -> f64 {
    row.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

pub struct Broker {
    pub settings: Settings,
    pub store: Box<dyn Store>,
    pub db_path: PathBuf,
    pub lock: ReentrantLock,
    pub hmac_key: Vec<u8>,
    owners_sealed: AtomicBool,
}

impl Broker {
    pub fn new(settings: Settings, store: Box<dyn Store>) -> Result<Self, String> {
        let root = settings.state_dir.clone();
        std::fs::create_dir_all(&root).map_err(|e| format!("state directory: {e}"))?;
        let db_path = root.join("metadata.sqlite");
        let hmac_key = metadata::state_key(&root.join("state-hmac.key")).map_err(|e| format!("state key: {e}"))?;
        let b = Self { settings, store, db_path, lock: ReentrantLock::default(), hmac_key, owners_sealed: AtomicBool::new(false) };
        let mut c = b.db().map_err(|e| format!("metadata database: {e}"))?;
        metadata::open_schema(&mut c).map_err(|e| format!("metadata schema: {e}"))?;
        if let Err(e) = b.seal_owners() {
            // The store is down at boot: the first credential read retries.
            obs::fault("store", &format!("seal_{}", e.0), None);
        }
        sensor_grants::adopt(&b, util::now()).map_err(|_| "sensor grant upgrade failed".to_owned())?;
        Ok(b)
    }

    // ── storage ────────────────────────────────────────────────────────────

    pub fn db(&self) -> rusqlite::Result<Connection> {
        let c = Connection::open(&self.db_path)?;
        c.busy_timeout(Duration::from_secs(10))?;
        Ok(c)
    }

    pub fn exec(&self, statement: &str, args: &[&dyn ToSql]) -> R<usize> {
        Ok(self.db()?.execute(statement, args)?)
    }

    pub fn rows(&self, statement: &str, args: &[&dyn ToSql]) -> R<Vec<Row>> {
        let c = self.db()?;
        let mut s = c.prepare(statement)?;
        let names: Vec<String> = s.column_names().iter().map(|n| n.to_string()).collect();
        let mut q = s.query(args)?;
        let mut out = Vec::new();
        while let Some(r) = q.next()? {
            let mut row = Map::new();
            for (i, name) in names.iter().enumerate() {
                let v = match r.get_ref(i)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(n) => json!(n),
                    ValueRef::Real(f) => json!(f),
                    ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
                    ValueRef::Blob(b) => Value::String(String::from_utf8_lossy(b).into_owned()),
                };
                row.insert(name.clone(), v);
            }
            out.push(row);
        }
        Ok(out)
    }

    pub fn one(&self, statement: &str, args: &[&dyn ToSql]) -> R<Option<Row>> {
        Ok(self.rows(statement, args)?.into_iter().next())
    }

    /// A store write; a record of a connection carries its owner sealed inside.
    pub fn put(&self, path: &str, data: Value, cas: Option<i64>, owner: Option<&str>) -> R<Record> {
        let mut data = data;
        if let (Some(owner), Some(obj)) = (owner, data.as_object_mut()) {
            obj.insert("owner".into(), owner.into());
        }
        self.store.put(path, &data, cas).map_err(|e| {
            obs::fault("store", e.0, None);
            Fail::store_unavailable()
        })
    }

    pub fn get(&self, path: &str, version: Option<i64>, owner: Option<&str>) -> R<Option<Record>> {
        let result = (|| {
            if owner.is_some() {
                self.seal_owners()?;
            }
            self.store.get(path, version)
        })();
        let record = result.map_err(|e| {
            obs::fault("store", e.0, None);
            Fail::store_unavailable()
        })?;
        if let (Some(owner), Some(r)) = (owner, &record) {
            if r.data.get("owner").and_then(Value::as_str) != Some(owner) {
                obs::fault("store", "owner_mismatch", None);
                return Err(Fail::store_unavailable());
            }
        }
        Ok(record)
    }

    pub fn must_get(&self, path: &str, version: i64, owner: &str) -> R<Value> {
        match self.get(path, Some(version), Some(owner))? {
            Some(r) => Ok(r.data),
            None => {
                obs::fault("store", "missing", None);
                Err(Fail::store_unavailable())
            }
        }
    }

    pub fn remove(&self, path: &str) -> R<()> {
        self.store.delete(path).map_err(|e| {
            obs::fault("store", e.0, None);
            Fail::store_unavailable()
        })
    }

    /// Once per state directory: records written before owners were sealed
    /// are rewritten with the owner the metadata names.
    pub fn seal_owners(&self) -> Result<(), StoreUnavailable> {
        if self.owners_sealed.load(Ordering::SeqCst) {
            return Ok(());
        }
        let _g = self.lock.lock();
        if self.owners_sealed.load(Ordering::SeqCst) {
            return Ok(());
        }
        let internal = |_| StoreUnavailable("transport");
        if self.one("SELECT 1 FROM broker_meta WHERE key='owners_sealed'", &[]).map_err(internal)?.is_none() {
            let rows = self.rows("SELECT id, actor, status, version, oauth_app_version FROM connections", &[]).map_err(internal)?;
            for row in rows {
                let cid = row_text(&row, "id").to_owned();
                let status = row_text(&row, "status");
                let app = format!("oauth-app-{cid}");
                if status == "deleted" {
                    self.store.delete(&cid)?;
                    self.store.delete(&app)?;
                    continue;
                }
                if status == "disconnected" {
                    self.store.delete(&cid)?;
                }
                for (path, column) in [(cid.as_str(), "version"), (app.as_str(), "oauth_app_version")] {
                    let version = row_int(&row, column);
                    if version == 0 || (column == "version" && status == "disconnected") {
                        continue;
                    }
                    let record = match self.store.get(path, Some(version)) {
                        Ok(r) => r,
                        Err(StoreUnavailable("integrity")) => continue,
                        Err(e) => return Err(e),
                    };
                    let Some(record) = record else { continue };
                    if record.data.get("owner").is_some() {
                        continue;
                    }
                    let mut data = record.data.clone();
                    if let Some(o) = data.as_object_mut() {
                        o.insert("owner".into(), util::py_str(row.get("actor").unwrap_or(&Value::Null)).into());
                    }
                    let saved = self.store.put(path, &data, None)?;
                    self.exec(&format!("UPDATE connections SET {column}=? WHERE id=?"), &[&saved.version, &cid]).map_err(internal)?;
                }
            }
            self.exec("INSERT OR REPLACE INTO broker_meta(key, value) VALUES ('owners_sealed', ?)", &[&util::py_float(util::now())]).map_err(internal)?;
        }
        self.owners_sealed.store(true, Ordering::SeqCst);
        Ok(())
    }

    // ── identity ───────────────────────────────────────────────────────────

    pub fn key_for(&self, role: &str) -> Option<Vec<u8>> {
        assertion::load_key(self.settings.key_files.get(role).map(String::as_str).unwrap_or("")).ok()
    }

    /// gateway-identity.v1 for an agent- or git-role call: the gateway's
    /// signature over actor. Err is the typed refusal kind.
    pub fn person_signed(&self, header: &str, actor: &str) -> Result<Map<String, Value>, &'static str> {
        if header.is_empty() {
            return Err("identity_missing");
        }
        let key = identity::read_verify_key(&self.settings.identity_public_key_file).map_err(|_| "identity_key")?;
        let claims = identity::verify(&key, header, util::now() as i64).map_err(|_| "identity_invalid")?;
        let sub = claims.get("sub").and_then(Value::as_str).unwrap_or("");
        if !util::ct_eq(sub.as_bytes(), actor.as_bytes()) {
            return Err("identity_mismatch");
        }
        Ok(claims)
    }

    pub fn remember(&self, nonce: &str, expires: f64) -> bool {
        let now = util::now();
        let Ok(mut c) = self.db() else { return false };
        let Ok(tx) = c.transaction() else { return false };
        if tx.execute("DELETE FROM assertion_nonces WHERE expires < ?", [now]).is_err() {
            return false;
        }
        if tx.execute("INSERT INTO assertion_nonces VALUES (?, ?)", rusqlite::params![nonce, expires]).is_err() {
            return false;
        }
        tx.commit().is_ok()
    }

    /// The verified caller, refused unless its role is in roles.
    pub fn identity(&self, who: &Who, route: &str, roles: &[&str], unwatched_ok: bool) -> R<Who> {
        if !roles.contains(&who.role.as_str()) {
            obs::event("role_refused", "warning", Some(&who.actor), Some(json!({"role": who.role, "route": route})));
            return Err(Fail::http(403, "Human setup required"));
        }
        if who.role == "agent" && who.shared {
            obs::event("shared_refused", "warning", Some(&who.actor), Some(json!({"route": route})));
            return Err(Fail::Object(403, identity::shared_refusal()));
        }
        if who.role == "agent" && who.unwatched && !unwatched_ok {
            obs::event("regime_refused", "warning", Some(&who.actor), Some(json!({"route": route})));
            return Err(Fail::http(403, "This session runs without a person in the loop"));
        }
        Ok(who.clone())
    }

    /// The caller's live connection cid: 410 for one they deleted, 404 for
    /// another person's.
    pub fn connection(&self, who: &Who, cid: &str) -> R<Row> {
        let row = self.one("SELECT * FROM connections WHERE id=? AND actor=?", &[&cid, &who.actor])?.ok_or_else(|| Fail::http(404, "Connection not found"))?;
        if row_text(&row, "status") == "deleted" {
            let successor = self.successor(&row)?;
            if !successor.is_empty() {
                return Err(Fail::Http(
                    410,
                    format!("This connection was deleted and replaced by connection {successor}; use that connection_id"),
                ));
            }
            return Err(Fail::http(410, "This connection was deleted; call connections_status for the current ones"));
        }
        Ok(row)
    }

    /// The live connection the person created in place of deleted row, or "".
    pub fn successor(&self, row: &Row) -> R<String> {
        let host = |r: &Row| -> String {
            let spec: Value = serde_json::from_str(row_text(r, "setup_spec")).unwrap_or(json!({}));
            let from_spec = if util::truthy(Some(&spec)) { destination_host(&spec) } else { String::new() };
            if !from_spec.is_empty() {
                from_spec
            } else {
                row_text(r, "approved_host").split(' ').next().unwrap_or("").to_owned()
            }
        };
        let created = row.get("created").cloned().filter(|v| util::truthy(Some(v))).unwrap_or(json!(0));
        let created = created.as_f64().unwrap_or(0.0);
        let candidates = self.rows(
            "SELECT * FROM connections WHERE actor=? AND provider=? AND status!='deleted' AND created>=? AND id!=? ORDER BY (status='ready') DESC, created DESC",
            &[&row_text(row, "actor"), &row_text(row, "provider"), &created, &row_text(row, "id")],
        )?;
        let mine = if row_text(row, "provider") == "custom_secret" { host(row) } else { String::new() };
        for c in candidates {
            if util::label_key(row_text(&c, "label")) == util::label_key(row_text(row, "label")) || (!mine.is_empty() && host(&c) == mine) {
                return Ok(row_text(&c, "id").to_owned());
            }
        }
        Ok(String::new())
    }

    // ── audit ──────────────────────────────────────────────────────────────

    /// Committed BEFORE the action it precedes; a failed insert prevents the action.
    #[allow(clippy::too_many_arguments)]
    pub fn audit_full(&self, who: &Who, cid: &str, action: &str, outcome: &str, operation: &str, receipt_id: &str, version: i64, receipt: &str) -> R<()> {
        self.exec(
            "INSERT INTO audit(at,actor,session,operation_id,connection,action,outcome,vault_request_id,version,receipt) VALUES (?,?,?,?,?,?,?,?,?,?)",
            &[&util::now(), &who.actor, &who.session, &operation, &cid, &action, &outcome, &receipt_id, &version, &receipt],
        )?;
        obs::event(
            "connection_audit",
            "info",
            Some(&who.actor),
            Some(json!({"action": action, "outcome": outcome, "connection": cid, "role": who.role, "store": self.store.name(), "version": version, "operation": operation})),
        );
        Ok(())
    }

    pub fn audit(&self, who: &Who, cid: &str, action: &str, outcome: &str) -> R<()> {
        self.audit_full(who, cid, action, outcome, "", "", 0, "")
    }

    pub fn audit_op(&self, who: &Who, cid: &str, action: &str, outcome: &str, operation: &str, version: i64) -> R<()> {
        self.audit_full(who, cid, action, outcome, operation, "", version, "")
    }

    // ── OAuth helpers ──────────────────────────────────────────────────────

    pub fn pkce(&self, state: &str) -> (String, String) {
        let verifier = util::b64url_nopad(&vexa_native_kit::sha256::hmac(&self.hmac_key, state.as_bytes()));
        let challenge = util::b64url_nopad(&vexa_native_kit::sha256::digest(verifier.as_bytes()));
        (verifier, challenge)
    }

    /// The operator's Google OAuth application, from configuration only.
    pub fn google(&self) -> R<(String, String)> {
        if !self.settings.google_client_id.is_empty() && !self.settings.google_client_secret.is_empty() {
            Ok((self.settings.google_client_id.clone(), self.settings.google_client_secret.clone()))
        } else {
            Err(Fail::provider("Provider application is not configured on this deployment"))
        }
    }

    pub fn redirect(&self) -> R<String> {
        if self.settings.product_redirect.is_empty() {
            obs::fault("config", "oauth_redirect_unset", None);
            return Err(Fail::http(503, "Product OAuth callback is not configured"));
        }
        Ok(self.settings.product_redirect.clone())
    }

    pub fn oauth_application(&self, row: &Row) -> R<Value> {
        let version = row_int(row, "oauth_app_version");
        if version == 0 {
            return Err(Fail::http(409, "Save the OAuth application first"));
        }
        Ok(self.must_get(&format!("oauth-app-{}", row_text(row, "id")), version, row_text(row, "actor"))?.get("value").cloned().unwrap_or(Value::Null))
    }

    /// A fresh Google access token, rotated in the store, when the stored one is near expiry.
    pub fn refreshed(&self, who: &Who, cid: &str, row: &mut Row, value: Value, operation: &str) -> R<Value> {
        let expires = value.get("expires_at").and_then(Value::as_f64).ok_or(Fail::Internal)?;
        if expires > util::now() + 30.0 {
            return Ok(value);
        }
        if !util::truthy(value.get("refresh_token")) {
            return Err(Fail::provider("Authorization expired; reconnect this account"));
        }
        let value = google::refresh(row_text(row, "provider"), &self.google()?, &value)?;
        let saved = self.put(cid, json!({"value": value}), None, Some(&who.actor))?;
        row.insert("version".into(), json!(saved.version));
        self.exec("UPDATE connections SET version=? WHERE id=?", &[&saved.version, &cid])?;
        self.audit_full(who, cid, "credential.refresh", "stored", operation, &saved.receipt, saved.version, "")?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_connection_ids() {
        assert_eq!(route_of("/api/connections/0123456789abcdef0123456789abcdef/read?x=1"), "/api/connections/{cid}/read");
        assert_eq!(route_of("/api/connections"), "/api/connections");
    }

    #[test]
    fn credential_hosts_in_order() {
        let spec = json!({"oauth": {"token_url": "https://auth.example/token"}, "endpoint": "https://api.example/x"});
        assert_eq!(credential_hosts(&spec), vec!["auth.example", "api.example"]);
        assert_eq!(credential_hosts(&json!({"endpoint": "https://api.example/x"})), vec!["api.example"]);
    }
}
