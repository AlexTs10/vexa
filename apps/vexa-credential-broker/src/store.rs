//! The credential store port and its two adapters (ADR-0040).
//!
//! Every credential is written through Store: a versioned key-value store of
//! JSON objects. A write keeps the new version and the one before it; delete
//! destroys every version of a path. Nothing here logs or returns a value.
//!
//! * LocalEncryptedStore (the default): AES-256-GCM, a random 96-bit nonce per
//!   version, the path and version bound as associated data, in secrets.sqlite.
//! * OpenBaoStore: the OpenBao/Vault KV v2 HTTP API.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::{net, obs, util};

pub const KEEP_VERSIONS: i64 = 2;

/// The store could not complete an operation: config, transport, integrity or conflict.
#[derive(Debug, Clone, PartialEq)]
pub struct StoreUnavailable(pub &'static str);

#[derive(Debug, Clone)]
pub struct Record {
    pub data: Value,
    pub version: i64,
    pub receipt: String,
}

pub trait Store: Send + Sync {
    fn name(&self) -> &'static str;
    fn put(&self, path: &str, data: &Value, cas: Option<i64>) -> Result<Record, StoreUnavailable>;
    fn get(&self, path: &str, version: Option<i64>) -> Result<Option<Record>, StoreUnavailable>;
    fn delete(&self, path: &str) -> Result<(), StoreUnavailable>;
    /// True when the store answers this broker; Err names the kind.
    fn healthy(&self) -> Result<bool, StoreUnavailable>;
}

fn segment_ok(s: &str) -> bool {
    (1..=160).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

pub fn check_path(path: &str) -> Result<(), StoreUnavailable> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 4 || !parts.iter().all(|p| segment_ok(p)) || parts.contains(&"..") {
        return Err(StoreUnavailable("config"));
    }
    Ok(())
}

/// The local store key: 64 hex characters, whitespace stripped.
pub fn load_store_key(path: &str) -> Result<[u8; 32], StoreUnavailable> {
    let text = std::fs::read_to_string(path).map_err(|_| StoreUnavailable("config"))?;
    let text = text.trim();
    if text.len() != 64 || !text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(StoreUnavailable("config"));
    }
    let mut key = [0u8; 32];
    for (i, k) in key.iter_mut().enumerate() {
        *k = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| StoreUnavailable("config"))?;
    }
    Ok(key)
}

pub struct LocalEncryptedStore {
    aead: Aes256Gcm,
    key_id: String,
    db: PathBuf,
    lock: Mutex<()>,
}

impl LocalEncryptedStore {
    pub fn open(db: &Path, key: &[u8; 32]) -> Result<Self, StoreUnavailable> {
        let mut id_input = b"vexa-credential-store-key-id\0".to_vec();
        id_input.extend_from_slice(key);
        let store = Self {
            aead: Aes256Gcm::new_from_slice(key).map_err(|_| StoreUnavailable("config"))?,
            key_id: util::sha256_hex(&id_input)[..16].to_owned(),
            db: db.to_owned(),
            lock: Mutex::new(()),
        };
        let c = store.connect().map_err(|_| StoreUnavailable("config"))?;
        c.execute(
            "CREATE TABLE IF NOT EXISTS secret_versions (path TEXT NOT NULL, version INTEGER NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, key_id TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY (path, version))",
            [],
        )
        .map_err(|_| StoreUnavailable("config"))?;
        Ok(store)
    }

    fn connect(&self) -> rusqlite::Result<Connection> {
        let c = Connection::open(&self.db)?;
        c.busy_timeout(Duration::from_secs(10))?;
        c.execute_batch("PRAGMA secure_delete=ON")?;
        Ok(c)
    }

    fn aad(path: &str, version: i64) -> Vec<u8> {
        format!("credential-broker.v1\0{path}\0{version}").into_bytes()
    }
}

impl Store for LocalEncryptedStore {
    fn name(&self) -> &'static str {
        "local"
    }

    fn put(&self, path: &str, data: &Value, cas: Option<i64>) -> Result<Record, StoreUnavailable> {
        check_path(path)?;
        let plaintext = util::py_dumps_compact(data).into_bytes();
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let transport = |_| StoreUnavailable("transport");
        let mut c = self.connect().map_err(transport)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(transport)?;
        let current: i64 = tx
            .query_row("SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE path=?", [path], |r| r.get(0))
            .map_err(transport)?;
        if cas.is_some_and(|cas| cas != current) {
            return Err(StoreUnavailable("conflict"));
        }
        let version = current + 1;
        let nonce = util::random_bytes(12);
        let ciphertext = self
            .aead
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &Self::aad(path, version) })
            .map_err(|_| StoreUnavailable("config"))?;
        tx.execute(
            "INSERT INTO secret_versions VALUES (?,?,?,?,?,?)",
            params![path, version, nonce, ciphertext, self.key_id, util::now()],
        )
        .map_err(transport)?;
        tx.execute("DELETE FROM secret_versions WHERE path=? AND version<=?", params![path, version - KEEP_VERSIONS]).map_err(transport)?;
        tx.commit().map_err(transport)?;
        Ok(Record { data: data.clone(), version, receipt: util::uuid_hex() })
    }

    fn get(&self, path: &str, version: Option<i64>) -> Result<Option<Record>, StoreUnavailable> {
        check_path(path)?;
        let transport = |_| StoreUnavailable("transport");
        let c = self.connect().map_err(transport)?;
        let row: Option<(i64, Vec<u8>, Vec<u8>)> = match version {
            None => c
                .query_row(
                    "SELECT version, nonce, ciphertext FROM secret_versions WHERE path=? ORDER BY version DESC LIMIT 1",
                    [path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional(),
            Some(v) => c
                .query_row(
                    "SELECT version, nonce, ciphertext FROM secret_versions WHERE path=? AND version=?",
                    params![path, v],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional(),
        }
        .map_err(transport)?;
        let Some((stored, nonce, ciphertext)) = row else { return Ok(None) };
        if nonce.len() != 12 {
            return Err(StoreUnavailable("integrity"));
        }
        // A different key, or bytes changed on disk: never "absent".
        let plaintext = self
            .aead
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &Self::aad(path, stored) })
            .map_err(|_| StoreUnavailable("integrity"))?;
        let data: Value = serde_json::from_slice(&plaintext).map_err(|_| StoreUnavailable("integrity"))?;
        Ok(Some(Record { data, version: stored, receipt: util::uuid_hex() }))
    }

    fn delete(&self, path: &str) -> Result<(), StoreUnavailable> {
        check_path(path)?;
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let c = self.connect().map_err(|_| StoreUnavailable("transport"))?;
        c.execute("DELETE FROM secret_versions WHERE path=?", [path]).map_err(|_| StoreUnavailable("transport"))?;
        Ok(())
    }

    fn healthy(&self) -> Result<bool, StoreUnavailable> {
        Ok(self
            .connect()
            .and_then(|c| c.prepare("SELECT 1 FROM secret_versions LIMIT 1").and_then(|mut s| s.query([]).map(|_| ())))
            .is_ok())
    }
}

/// Whether the vault token may be sent to address: https, or plain http only
/// to this host's loopback; no credentials, query or fragment.
pub fn address_allowed(address: &str) -> bool {
    let Ok(parsed) = util::urlsplit(address) else { return false };
    if parsed.port().is_err() {
        return false;
    }
    let Some(host) = parsed.hostname() else { return false };
    if parsed.username().is_some() || parsed.password().is_some() || !parsed.query.is_empty() || !parsed.fragment.is_empty() {
        return false;
    }
    match parsed.scheme.as_str() {
        "https" => true,
        "http" => {
            if host == "localhost" {
                return true;
            }
            match host.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback(),
                Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
                Err(_) => false,
            }
        }
        _ => false,
    }
}

pub struct OpenBaoStore {
    address: String,
    token_file: PathBuf,
    mount: String,
}

/// A path nothing is ever written to; reading it proves the token is alive.
const PROBE_PATH: &str = "vexa-readiness-probe";

impl OpenBaoStore {
    pub fn new(address: &str, token_file: &Path, mount: &str) -> Result<Self, StoreUnavailable> {
        let mount_ok = (1..=64).contains(&mount.len()) && mount.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
        if !address_allowed(address) || !mount_ok {
            return Err(StoreUnavailable("config"));
        }
        Ok(Self { address: address.trim_end_matches('/').to_owned(), token_file: token_file.to_owned(), mount: mount.to_owned() })
    }

    fn request(&self, method: &str, path: &str, body: Option<&Value>, query: &str, allow_missing: bool, kind: &str) -> Result<Option<Value>, StoreUnavailable> {
        let token = std::fs::read_to_string(&self.token_file).map_err(|_| StoreUnavailable("config"))?;
        let mut url = format!("{}/v1/{}/{kind}/{path}", self.address, self.mount);
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        let mut req = net::Request::new(method, &url, Duration::from_secs(5)).header("X-Vault-Token", token.trim());
        if let Some(body) = body {
            req = req.json(body);
        }
        let answer = net::send(&req).map_err(|_| StoreUnavailable("transport"))?;
        if allow_missing && answer.status == 404 {
            return Ok(None);
        }
        if answer.status == 400 && body.is_some_and(|b| b.get("options").is_some()) {
            return Err(StoreUnavailable("conflict"));
        }
        if matches!(answer.status, 401 | 403) {
            return Err(StoreUnavailable("config"));
        }
        if answer.status >= 400 {
            return Err(StoreUnavailable("transport"));
        }
        if answer.body.is_empty() {
            return Ok(Some(json!({})));
        }
        serde_json::from_slice(&answer.body).map(Some).map_err(|_| StoreUnavailable("transport"))
    }
}

impl Store for OpenBaoStore {
    fn name(&self) -> &'static str {
        "openbao"
    }

    fn put(&self, path: &str, data: &Value, cas: Option<i64>) -> Result<Record, StoreUnavailable> {
        check_path(path)?;
        let mut body = json!({"data": data});
        if let Some(cas) = cas {
            body["options"] = json!({"cas": cas});
        }
        let result = self.request("POST", path, Some(&body), "", false, "data")?.unwrap_or_default();
        let version = result.get("data").and_then(|d| d.get("version")).and_then(Value::as_i64).ok_or(StoreUnavailable("transport"))?;
        let receipt = result.get("request_id").map(util::py_str).unwrap_or_default();
        // Retention, set after the write landed; a refusal is logged and the mount's own max_versions applies.
        if let Err(e) = self.request("POST", path, Some(&json!({"max_versions": KEEP_VERSIONS})), "", false, "metadata") {
            obs::warn("broker_fault", json!({"source": "store", "kind": format!("retention_{}", e.0)}));
        }
        Ok(Record { data: data.clone(), version, receipt })
    }

    fn get(&self, path: &str, version: Option<i64>) -> Result<Option<Record>, StoreUnavailable> {
        check_path(path)?;
        let query = version.map(|v| format!("version={v}")).unwrap_or_default();
        let Some(result) = self.request("GET", path, None, &query, true, "data")? else { return Ok(None) };
        let payload = result.get("data").ok_or(StoreUnavailable("transport"))?;
        match payload.get("data") {
            None | Some(Value::Null) => Ok(None),
            Some(data) => {
                let version = payload.get("metadata").and_then(|m| m.get("version")).and_then(Value::as_i64).ok_or(StoreUnavailable("transport"))?;
                let receipt = result.get("request_id").map(util::py_str).unwrap_or_default();
                Ok(Some(Record { data: data.clone(), version, receipt }))
            }
        }
    }

    fn delete(&self, path: &str) -> Result<(), StoreUnavailable> {
        check_path(path)?;
        self.request("DELETE", path, None, "", true, "metadata").map(|_| ())
    }

    fn healthy(&self) -> Result<bool, StoreUnavailable> {
        self.request("GET", PROBE_PATH, None, "", true, "data").map(|_| true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vcb-store-{}", util::uuid_hex()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn keeps_two_versions_binds_the_path_and_refuses_a_wrong_key() {
        let dir = temp();
        let db = dir.join("secrets.sqlite");
        let store = LocalEncryptedStore::open(&db, &[7u8; 32]).unwrap();
        assert_eq!(store.put("c1", &json!({"value": "a"}), None).unwrap().version, 1);
        assert_eq!(store.put("c1", &json!({"value": "b"}), Some(1)).unwrap().version, 2);
        assert_eq!(store.put("c1", &json!({"value": "c"}), Some(1)).unwrap_err(), StoreUnavailable("conflict"));
        assert_eq!(store.put("c1", &json!({"value": "c"}), None).unwrap().version, 3);
        assert!(store.get("c1", Some(1)).unwrap().is_none());
        assert_eq!(store.get("c1", Some(2)).unwrap().unwrap().data["value"], "b");
        assert_eq!(store.get("c1", None).unwrap().unwrap().data["value"], "c");
        let other = LocalEncryptedStore::open(&db, &[8u8; 32]).unwrap();
        assert_eq!(other.get("c1", None).unwrap_err(), StoreUnavailable("integrity"));
        // A row moved to another path does not decrypt there.
        let c = Connection::open(&db).unwrap();
        c.execute("UPDATE secret_versions SET path='c2' WHERE path='c1' AND version=3", []).unwrap();
        assert_eq!(store.get("c2", None).unwrap_err(), StoreUnavailable("integrity"));
        store.delete("c1").unwrap();
        assert!(store.get("c1", None).unwrap().is_none());
        assert_eq!(store.put("../x", &json!({}), None).unwrap_err(), StoreUnavailable("config"));
        assert_eq!(store.put("a/b/c/d/e", &json!({}), None).unwrap_err(), StoreUnavailable("config"));
        assert!(store.healthy().unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_vault_address_rule() {
        assert!(address_allowed("https://vault.example"));
        assert!(address_allowed("http://127.0.0.1:8200"));
        assert!(address_allowed("http://localhost:8200"));
        assert!(address_allowed("http://[::1]:8200"));
        assert!(!address_allowed("http://vault.example"));
        assert!(!address_allowed("https://u:p@vault.example"));
        assert!(!address_allowed("https://vault.example/?x"));
        assert!(!address_allowed("ftp://127.0.0.1"));
    }
}
