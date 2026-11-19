//! Every route of credential-broker.v1 (x-routes). Each takes the verified
//! caller and the request, and answers a JSON value or a Fail the server
//! renders. Bodies are validated before the route's identity checks, as the
//! request models are.

use serde_json::{json, Map, Value};

use crate::broker::{credential_hosts, host_of, row_int, row_text, Broker, Row, Who};
use crate::fail::{refusal_reason, Fail, R};
use crate::models::*;
use crate::{calendar, google, obs, policy, sensor_grants, service, setup, util};

/// An unfinished setup nobody asked for in this long is hidden and never reused.
const PENDING_SETUP_TTL: f64 = 24.0 * 3600.0;
const PENDING: &str = "status='awaiting_user' AND version=0 AND oauth_app_version=0";
const CALLBACK: &str = "/api/auth/callback/google";

pub struct Call<'a> {
    pub method: &'a str,
    pub query: &'a str,
    pub body: &'a [u8],
    pub who: &'a Who,
}

fn json_body(body: &[u8]) -> R<Value> {
    serde_json::from_slice(body).map_err(|_| Fail::Invalid)
}

/// An HTTPException (with or without a reason).
fn is_http(f: &Fail) -> bool {
    matches!(f, Fail::Http(..) | Fail::Object(..) | Fail::Reasoned(..))
}

fn spec_of(row: &Row) -> Value {
    let text = row_text(row, "setup_spec");
    if text.is_empty() {
        return json!({});
    }
    serde_json::from_str(text).unwrap_or(json!({}))
}

fn endpoint_host(endpoint: &str) -> String {
    host_of(&endpoint.replace("{secret}", "x"))
}

/// The routes this server answers: (method, pattern).
pub const ROUTES: [(&str, &str); 25] = [
    ("GET", "/api/connections"),
    ("GET", "/api/preferences"),
    ("POST", "/api/preferences"),
    ("POST", "/api/setup"),
    ("POST", "/api/connections/{}/request"),
    ("POST", "/api/connections/{}/prepare"),
    ("POST", "/api/connections/{}/custom-secret"),
    ("POST", "/api/connections/{}/oauth-application"),
    ("POST", "/api/connections/{}/authorize"),
    ("GET", "/api/auth/callback/google"),
    ("POST", "/api/connections/{}/disconnect"),
    ("POST", "/api/connections/{}/delete"),
    ("POST", "/api/connections/{}/read"),
    ("POST", "/api/connections/{}/draft"),
    ("POST", "/api/connections/{}/draft-update"),
    ("POST", "/api/connections/{}/calendar-event"),
    ("POST", "/api/connections/{}/call"),
    ("POST", "/api/internal/git-secret"),
    ("POST", "/api/internal/bot-account"),
    ("POST", "/api/internal/sensor/calendar-changes"),
    ("POST", "/api/sensor-grants"),
    ("GET", "/api/sensor-grants"),
    ("POST", "/api/sensor-grants/{}/revoke"),
    ("POST", "/api/internal/signals/model-key"),
    ("POST", "/api/internal/mail/smtp-credential"),
];

/// The path parameter when path matches pattern.
pub fn matches(pattern: &str, path: &str) -> Option<String> {
    let (p, s): (Vec<&str>, Vec<&str>) = (pattern.split('/').collect(), path.split('/').collect());
    if p.len() != s.len() {
        return None;
    }
    let mut param = String::new();
    for (a, b) in p.iter().zip(&s) {
        if *a == "{}" {
            if b.is_empty() {
                return None;
            }
            param = (*b).to_owned();
        } else if a != b {
            return None;
        }
    }
    Some(param)
}

/// Python's query parsing for one key: the last value, '+' a space.
fn query_value(query: &str, name: &str) -> String {
    let mut out = String::new();
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if vexa_native_kit::http::decode(k) == name {
            out = vexa_native_kit::http::decode(v);
        }
    }
    out
}

pub fn dispatch(b: &Broker, c: &Call, pattern: &str, param: &str) -> R<Value> {
    let body = || json_body(c.body);
    match (c.method, pattern) {
        ("GET", "/api/connections") => connection_list(b, c.who),
        ("GET", "/api/preferences") => preferences_read(b, c.who),
        ("POST", "/api/preferences") => preferences_write(b, c.who, action_preferences(&body()?)?),
        ("POST", "/api/setup") => setup_request(b, c.who, SetupBody::parse(&body()?)?),
        ("POST", "/api/connections/{}/request") => request_setup(b, c.who, param),
        ("POST", "/api/connections/{}/prepare") => prepare(b, c.who, param, prepared_setup(&body()?)?),
        ("POST", "/api/connections/{}/custom-secret") => save_custom(b, c.who, param, CustomSecretBody::parse(&body()?)?),
        ("POST", "/api/connections/{}/oauth-application") => save_oauth_application(b, c.who, param, OAuthApplicationBody::parse(&body()?)?),
        ("POST", "/api/connections/{}/authorize") => {
            let raw = if c.body.is_empty() { None } else { Some(body()?) };
            begin_authorize(b, c.who, param, authorize_grant(raw.as_ref())?)
        }
        ("GET", CALLBACK) => oauth_callback(b, c.who, &query_value(c.query, "state"), &query_value(c.query, "code"), &query_value(c.query, "error")),
        ("POST", "/api/connections/{}/disconnect") => disconnect(b, c.who, param),
        ("POST", "/api/connections/{}/delete") => delete_connection(b, c.who, param),
        ("POST", "/api/connections/{}/read") => account_read(b, c.who, param, AccountReadBody::parse(&body()?)?),
        ("POST", "/api/connections/{}/draft") => draft(b, c.who, param, GmailDraftBody::parse(&body()?, false)?, false),
        ("POST", "/api/connections/{}/draft-update") => draft(b, c.who, param, GmailDraftBody::parse(&body()?, true)?, true),
        ("POST", "/api/connections/{}/calendar-event") => calendar_event(b, c.who, param, CalendarEventBody::parse(&body()?)?),
        ("POST", "/api/connections/{}/call") => call_custom(b, c.who, param, CustomCallBody::parse(&body()?)?),
        ("POST", "/api/internal/git-secret") => git_secret(b, c.who, GitSecretBody::parse(&body()?)?),
        ("POST", "/api/internal/bot-account") => bot_account(b, c.who, BotAccountBody::parse(&body()?)?),
        ("POST", "/api/internal/sensor/calendar-changes") => sensor_calendar_changes(b, c.who, CalendarChangesBody::parse(&body()?)?),
        ("POST", "/api/sensor-grants") => grant_issue(b, c.who, SensorGrantBody::parse(&body()?)?),
        ("GET", "/api/sensor-grants") => grant_list(b, c.who),
        ("POST", "/api/sensor-grants/{}/revoke") => grant_revoke(b, c.who, param),
        ("POST", "/api/internal/signals/model-key") => service_value(b, c.who, service_name(&body()?)?, "signals"),
        ("POST", "/api/internal/mail/smtp-credential") => service_value(b, c.who, service_name(&body()?)?, "mail"),
        _ => Err(Fail::http(404, "Not Found")),
    }
}

// ── lifecycle ──────────────────────────────────────────────────────────────

fn stale_before() -> f64 {
    util::now() - PENDING_SETUP_TTL
}

fn live_pending(b: &Broker, actor: &str, provider: &str) -> R<Vec<Row>> {
    b.rows(
        &format!("SELECT id,label,session,setup_spec FROM connections WHERE actor=? AND provider=? AND {PENDING} AND MAX(created,touched)>=? ORDER BY created DESC"),
        &[&actor, &provider, &stale_before()],
    )
}

fn same_label(a: &str, b: &str) -> bool {
    util::label_key(a) == util::label_key(b)
}

fn connection_list(b: &Broker, who: &Who) -> R<Value> {
    let who = b.identity(who, "/api/connections", &["agent", "human"], true)?;
    let rows = b.rows(
        &format!("SELECT id,provider,label,status,created,setup_request,account,setup_spec,oauth_app_version,approved_host,grants FROM connections WHERE actor=? AND status!='deleted' AND NOT ({PENDING} AND MAX(created,touched)<?) ORDER BY created DESC"),
        &[&who.actor, &stale_before()],
    )?;
    let mut out = Vec::new();
    for mut row in rows {
        let spec = row.shift_remove("setup_spec").and_then(|v| v.as_str().filter(|s| !s.is_empty()).map(str::to_owned));
        row.insert("setup".into(), spec.map_or(json!({}), |s| serde_json::from_str(&s).unwrap_or(json!({}))));
        let app = row.shift_remove("oauth_app_version");
        row.insert("application_configured".into(), json!(util::truthy(app.as_ref())));
        let grants = row.shift_remove("grants").and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
        row.insert("permissions".into(), json!(grants.split_whitespace().collect::<Vec<_>>()));
        out.push(Value::Object(row));
    }
    Ok(json!({"connections": out}))
}

fn preferences_read(b: &Broker, who: &Who) -> R<Value> {
    let who = b.identity(who, "/api/preferences", &["agent", "human"], true)?;
    let row = b.one("SELECT value FROM preferences WHERE actor=?", &[&who.actor])?;
    let stored = match row {
        Some(r) => serde_json::from_str(row_text(&r, "value")).map_err(|_| Fail::Internal)?,
        None => json!({}),
    };
    action_preferences(&stored).map_err(|_| Fail::Internal)
}

fn preferences_write(b: &Broker, who: &Who, value: Value) -> R<Value> {
    let who = b.identity(who, "/api/preferences", &["agent", "human"], false)?;
    if who.delegated {
        b.audit(&who, "", "preferences.write", "refused")?;
        return Err(Fail::http(403, "Only the person can change their own setting"));
    }
    b.audit(&who, "", "preferences.write", "requested")?;
    b.exec(
        "INSERT INTO preferences(actor,value,updated) VALUES (?,?,?) ON CONFLICT(actor) DO UPDATE SET value=excluded.value, updated=excluded.updated",
        &[&who.actor, &util::py_dumps(&value), &util::now()],
    )?;
    b.audit(&who, "", "preferences.write", "stored")?;
    Ok(value)
}

fn setup_request(b: &Broker, who: &Who, body: SetupBody) -> R<Value> {
    let who = b.identity(who, "/api/setup", &["agent", "human"], false)?;
    let _g = b.lock.lock();
    let pending = live_pending(b, &who.actor, &body.provider)?;
    if let Some(again) = pending.iter().find(|r| same_label(row_text(r, "label"), &body.label)) {
        let id = row_text(again, "id").to_owned();
        b.audit(&who, &id, "setup.request", "requested")?;
        b.exec("UPDATE connections SET setup_request=?,touched=? WHERE id=?", &[&util::uuid_hex(), &util::now(), &id])?;
        return Ok(json!({"connection_id": id, "status": "awaiting_user"}));
    }
    let cid = util::uuid_hex();
    b.audit(&who, &cid, "setup.request", "requested")?;
    let now = util::now();
    b.exec(
        "INSERT INTO connections(id,actor,session,label,status,created,provider,setup_request,touched) VALUES (?,?,?,?,?,?,?,?,?)",
        &[&cid, &who.actor, &who.session, &body.label, &"awaiting_user", &now, &body.provider, &util::uuid_hex(), &now],
    )?;
    Ok(json!({"connection_id": cid, "status": "awaiting_user"}))
}

fn request_setup(b: &Broker, who: &Who, cid: &str) -> R<Value> {
    let who = b.identity(who, "/api/connections/{cid}/request", &["agent", "human"], false)?;
    let row = b.connection(&who, cid)?;
    let status = row_text(&row, "status");
    if status == "ready" || status == "awaiting_user" {
        b.audit(&who, cid, "setup.request", "requested")?;
        b.exec("UPDATE connections SET setup_request=?,touched=? WHERE id=? AND actor=? AND status!='deleted'", &[&util::uuid_hex(), &util::now(), &cid, &who.actor])?;
    }
    Ok(json!({"connection_id": cid, "status": row["status"]}))
}

/// A prepared setup replaces the person's other unfinished setups for the
/// same service: same destination host, same name, or, from this session, one
/// never proposed. Only unfinished rows match.
fn supersede(b: &Broker, who: &Who, keep: &str, spec: &Value, label: &str) -> R<()> {
    let host = endpoint_host(util::text(spec, "endpoint"));
    for row in live_pending(b, &who.actor, "custom_secret")? {
        let id = row_text(&row, "id").to_owned();
        if id == keep {
            continue;
        }
        let previous = spec_of(&row);
        let empty = previous.as_object().is_none_or(|o| o.is_empty());
        if (!host.is_empty() && endpoint_host(util::text(&previous, "endpoint")) == host) || same_label(row_text(&row, "label"), label) || (empty && row_text(&row, "session") == who.session) {
            b.exec(&format!("UPDATE connections SET status='deleted' WHERE id=? AND actor=? AND {PENDING}"), &[&id, &who.actor])?;
            b.exec("DELETE FROM oauth_states WHERE connection=?", &[&id])?;
            b.audit(who, &id, "setup.prepare", "superseded")?;
        }
    }
    Ok(())
}

fn prepare(b: &Broker, who: &Who, cid: &str, raw: Value) -> R<Value> {
    let who = b.identity(who, "/api/connections/{cid}/prepare", &["agent", "human"], false)?;
    let row = b.connection(&who, cid)?;
    if row_text(&row, "provider") != "custom_secret" {
        return Err(Fail::http(409, "Only custom service setup can be prepared"));
    }
    if util::truthy(spec_of(&row).get("oauth")) && !util::truthy(raw.get("oauth")) {
        return Err(Fail::http(409, "This connection uses OAuth. Preserve its OAuth definition; create a separate connection for an API token."));
    }
    let spec = setup::validate(&raw)?;
    let _g = b.lock.lock();
    let current = b.connection(&who, cid)?;
    let previous = spec_of(&current);
    if util::truthy(previous.get("oauth")) && !util::truthy(spec.get("oauth")) {
        return Err(Fail::http(409, "This connection uses OAuth. Preserve its OAuth definition."));
    }
    supersede(b, &who, cid, &spec, row_text(&current, "label"))?;
    if setup::normalised(&previous) == spec {
        b.exec("UPDATE connections SET touched=? WHERE id=?", &[&util::now(), &cid])?;
        return Ok(json!({"connection_id": cid, "status": current["status"], "setup": spec}));
    }
    b.audit(&who, cid, "setup.prepare", "proposed")?;
    b.exec("UPDATE connections SET setup_spec=?,setup_request=?,oauth_app_version=0,touched=? WHERE id=?", &[&util::py_dumps(&spec), &util::uuid_hex(), &util::now(), &cid])?;
    b.exec("DELETE FROM oauth_states WHERE connection=?", &[&cid])?;
    Ok(json!({"connection_id": cid, "status": row["status"], "setup": spec}))
}

/// The first human save that sends a credential to a host must name that host back.
fn require_confirmation(row: &Row, hosts: &[String], confirmed: &[&str]) -> R<()> {
    let approved: Vec<&str> = row_text(row, "approved_host").split_whitespace().collect();
    let typed: Vec<String> = confirmed.iter().filter(|c| !c.is_empty()).map(|c| c.trim().to_lowercase()).collect();
    if hosts.iter().any(|h| !approved.contains(&h.as_str()) && !typed.contains(h)) {
        return Err(Fail::http(409, "Confirm the destination host before saving"));
    }
    Ok(())
}

fn is_chat_id(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    (!digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()))
        || s.strip_prefix('@').is_some_and(|u| u.len() >= 5 && u.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'))
}

fn save_custom(b: &Broker, who: &Who, cid: &str, body: CustomSecretBody) -> R<Value> {
    let who = b.identity(who, "/api/connections/{cid}/custom-secret", &["human"], false)?;
    let row = b.connection(&who, cid)?;
    if row_text(&row, "provider") != "custom_secret" {
        return Err(Fail::http(409, "Wrong connection type"));
    }
    let spec = spec_of(&row);
    let has_spec = util::truthy(Some(&spec));
    if util::truthy(spec.get("oauth")) {
        return Err(Fail::http(409, "Use the secure OAuth application form"));
    }
    if has_spec {
        require_confirmation(&row, &credential_hosts(&spec), &[&body.confirmed_host])?;
    }
    let mut value = body.value.clone();
    if value.is_empty() && row_text(&row, "status") == "ready" {
        let saved = b.must_get(cid, row_int(&row, "version"), &who.actor)?;
        let saved_config = saved.get("value").cloned().unwrap_or(json!({}));
        b.audit_op(&who, cid, "credential.read", "retrieved", "", row_int(&row, "version"))?;
        let proposed = if has_spec { spec.clone() } else { json!({"endpoint": body.endpoint, "header": body.header, "scheme": body.scheme, "method": body.method}) };
        let or_empty = |v: &Value, k: &str| -> Value { v.get(k).filter(|x| util::truthy(Some(x))).cloned().unwrap_or(json!("")) };
        if ["endpoint", "header", "scheme", "method", "prefix"].iter().any(|k| or_empty(&saved_config, k) != or_empty(&proposed, k)) {
            return Err(Fail::http(409, "Saved credentials cannot be reused for a different service configuration. Create a separate connection."));
        }
        value = util::text(&saved_config, "value").to_owned();
    }
    let built = (|| -> R<(Value, String)> {
        if has_spec {
            let spec = setup::validate(&spec).map_err(|_| Fail::Internal)?;
            let fields = spec["fields"].as_array().cloned().unwrap_or_default();
            let mut required: Vec<&str> = fields.iter().map(|f| f["name"].as_str().unwrap_or("")).collect();
            required.sort();
            required.dedup();
            let mut given: Vec<&str> = body.fields.iter().map(|(k, _)| k.as_str()).collect();
            given.sort();
            given.dedup();
            if given != required || body.fields.iter().any(|(_, v)| v.trim().is_empty() || v.chars().count() > 2000) {
                return Err(Fail::service("Fill all requested connection fields"));
            }
            let text = |k: &str| spec[k].as_str().unwrap_or("").to_owned();
            let mut config = service::configure(&value, &text("endpoint"), &text("header"), &text("scheme"), &text("method"), &text("prefix"))?;
            let field = |name: &str| body.fields.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.clone()).unwrap_or_default();
            let (mut query, mut fixed) = (Map::new(), Map::new());
            for f in &fields {
                let name = f["name"].as_str().unwrap_or("");
                if f["location"] == "query" { query.insert(name.into(), json!(field(name))) } else { fixed.insert(name.into(), json!(field(name))) };
            }
            config["fixed_query"] = Value::Object(query);
            config["fixed_body"] = Value::Object(fixed);
            if text("scheme") == "telegram" && body.fields.iter().any(|(k, _)| k == "chat_id") && !is_chat_id(&field("chat_id")) {
                return Err(Fail::service("Enter the Telegram chat ID or channel username; do not use an email address"));
            }
            Ok((config, credential_hosts(&spec).join(" ")))
        } else {
            let config = service::configure(&value, &body.endpoint, &body.header, &body.scheme, &body.method, "")?;
            let host = if body.endpoint.is_empty() { String::new() } else { host_of(&body.endpoint) };
            Ok((config, host))
        }
    })();
    let (config, host) = built.map_err(|e| match e {
        Fail::Service(s) => Fail::Http(400, s),
        other => other,
    })?;
    let _g = b.lock.lock();
    let current = b.connection(&who, cid)?;
    if !row_text(&current, "setup_spec").is_empty() && (body.setup_request != row_text(&current, "setup_request") || row_text(&current, "setup_spec") != row_text(&row, "setup_spec")) {
        return Err(Fail::http(409, "Setup changed; review the updated form and save again"));
    }
    b.audit(&who, cid, "credential.store", "requested")?;
    let saved = b.put(cid, json!({"value": config}), None, Some(&who.actor))?;
    b.audit_full(&who, cid, "credential.store", "stored", "", &saved.receipt, saved.version, "")?;
    b.exec("UPDATE connections SET status=?,version=?,approved_host=? WHERE id=?", &[&"ready", &saved.version, &host, &cid])?;
    Ok(json!({"connection_id": cid, "status": "ready"}))
}

fn save_oauth_application(b: &Broker, who: &Who, cid: &str, body: OAuthApplicationBody) -> R<Value> {
    let who = b.identity(who, "/api/connections/{cid}/oauth-application", &["human"], false)?;
    let _g = b.lock.lock();
    let row = b.connection(&who, cid)?;
    let spec = spec_of(&row);
    if row_text(&row, "provider") != "custom_secret" || !util::truthy(spec.get("oauth")) {
        return Err(Fail::http(409, "Prepare an OAuth connection first"));
    }
    if row_text(&row, "setup_request") != body.setup_request {
        return Err(Fail::http(409, "Setup changed; review the updated form"));
    }
    let spec = setup::validate(&spec).map_err(|_| Fail::http(422, "Invalid OAuth definition"))?;
    let hosts = credential_hosts(&spec);
    let mut confirmed: Vec<&str> = vec![&body.confirmed_host];
    confirmed.extend(body.confirmed_hosts.iter().map(String::as_str));
    require_confirmation(&row, &hosts, &confirmed)?;
    b.audit(&who, cid, "oauth.application", "requested")?;
    let saved = b.put(
        &format!("oauth-app-{cid}"),
        json!({"value": {"client_id": body.client_id, "client_secret": body.client_secret, "spec": spec}}),
        None,
        Some(&who.actor),
    )?;
    b.audit_full(&who, cid, "oauth.application", "stored", "", &saved.receipt, saved.version, "")?;
    b.exec("UPDATE connections SET oauth_app_version=?,status='awaiting_user',approved_host=? WHERE id=?", &[&saved.version, &hosts.join(" "), &cid])?;
    b.exec("DELETE FROM oauth_states WHERE connection=?", &[&cid])?;
    Ok(json!({"connection_id": cid, "status": "awaiting_user"}))
}

fn begin_authorize(b: &Broker, who: &Who, cid: &str, grant: String) -> R<Value> {
    let who = b.identity(who, "/api/connections/{cid}/authorize", &["human"], false)?;
    let row = b.connection(&who, cid)?;
    let provider = row_text(&row, "provider");
    let custom_oauth = provider == "custom_secret" && util::truthy(spec_of(&row).get("oauth"));
    if !custom_oauth && google::method(provider) != "oauth" {
        return Err(Fail::http(409, "This connection uses the secure input panel"));
    }
    let state = format!("vxc_{}", util::token_urlsafe(32));
    let (_, challenge) = b.pkce(&state);
    let url = if custom_oauth {
        let cfg = b.oauth_application(&row)?;
        let redirect = b.redirect()?;
        service::authorize(&cfg["spec"], &cfg, &redirect, &state, &challenge).map_err(|e| match e {
            Fail::Service(s) => {
                let reason = refusal_reason(&s);
                Fail::Reasoned(409, s, reason)
            }
            other => other,
        })?
    } else {
        (|| -> R<String> {
            let app = b.google()?;
            let redirect = b.redirect()?;
            google::authorize(provider, &app, &redirect, &state, &challenge, &grant)
        })()
        .map_err(|e| match e {
            Fail::Provider(s) => Fail::Http(409, s),
            other => other,
        })?
    };
    if !grant.is_empty() && custom_oauth {
        return Err(Fail::http(409, "This permission does not apply to this connection"));
    }
    b.exec("DELETE FROM oauth_states WHERE connection=? OR expires<?", &[&cid, &util::now()])?;
    b.exec(
        "INSERT INTO oauth_states(state_hash,actor,session,connection,expires,grant_name) VALUES (?,?,?,?,?,?)",
        &[&util::sha256_hex(state.as_bytes()), &who.actor, &who.session, &cid, &(util::now() + 600.0), &grant],
    )?;
    b.audit(&who, cid, "oauth.authorize", "requested")?;
    Ok(json!({"authorize_url": url}))
}

fn oauth_callback(b: &Broker, who: &Who, state: &str, code: &str, error: &str) -> R<Value> {
    let who = b.identity(who, CALLBACK, &["human"], false)?;
    let state_hash = util::sha256_hex(state.as_bytes());
    let pending = {
        let _g = b.lock.lock();
        let pending = b.one("SELECT * FROM oauth_states WHERE state_hash=?", &[&state_hash])?;
        let ok = pending.as_ref().is_some_and(|p| {
            row_text(p, "actor") == who.actor && row_text(p, "session") == who.session && crate::broker::row_f64(p, "expires") >= util::now()
        });
        if !ok {
            obs::fault("oauth", "state_mismatch", None);
            return Err(Fail::http(403, "Authorization expired or does not belong to this session"));
        }
        b.exec("DELETE FROM oauth_states WHERE state_hash=?", &[&state_hash])?;
        pending.unwrap_or_default()
    };
    let cid = row_text(&pending, "connection").to_owned();
    let _g = b.lock.lock();
    let row = b.connection(&who, &cid)?;
    if !error.is_empty() || code.is_empty() {
        b.audit(&who, &cid, "oauth.authorize", "refused")?;
        return Ok(json!({"connection_id": cid, "status": "refused"}));
    }
    let exchanged = (|| -> R<()> {
        let (verifier, _) = b.pkce(state);
        let provider = row_text(&row, "provider");
        let value = if provider == "custom_secret" {
            let cfg = b.oauth_application(&row)?;
            let redirect = b.redirect()?;
            let mut value = service::exchange(&cfg["spec"], &cfg, code, &verifier, &redirect, None)?;
            value["oauth_application"] = cfg;
            value
        } else {
            let app = b.google()?;
            let redirect = b.redirect()?;
            google::tokens(provider, &app, code, &verifier, &redirect, None, row_text(&pending, "grant_name"))?
        };
        let saved = b.put(&cid, json!({"value": value}), None, Some(&who.actor))?;
        let account = google::account_email(provider, &value);
        b.audit_full(&who, &cid, "oauth.authorize", "stored", "", &saved.receipt, saved.version, "")?;
        let grants = google::permissions(provider, util::text(&value, "scope")).join(" ");
        b.exec("UPDATE connections SET status=?,version=?,account=?,grants=? WHERE id=?", &[&"ready", &saved.version, &account, &grants, &cid])?;
        Ok(())
    })();
    match exchanged {
        Ok(()) => Ok(json!({"connection_id": cid, "status": "connected"})),
        Err(e) if is_http(&e) || matches!(e, Fail::Provider(_) | Fail::Service(_)) => {
            obs::refused("oauth", "exchange_refused", CALLBACK);
            b.audit(&who, &cid, "oauth.authorize", "refused")?;
            Ok(json!({"connection_id": cid, "status": "refused"}))
        }
        Err(Fail::Upstream { source, kind, .. }) => {
            obs::fault(source, kind, Some(CALLBACK));
            b.audit(&who, &cid, "oauth.authorize", "failed")?;
            Ok(json!({"connection_id": cid, "status": "refused"}))
        }
        Err(e) => Err(e),
    }
}

fn disconnect(b: &Broker, who: &Who, cid: &str) -> R<Value> {
    let who = b.identity(who, "/api/connections/{cid}/disconnect", &["human"], false)?;
    let _g = b.lock.lock();
    b.connection(&who, cid)?;
    b.audit(&who, cid, "connection.disconnect", "requested")?;
    b.remove(cid)?;
    b.exec("UPDATE connections SET status=?,version=0 WHERE id=?", &[&"disconnected", &cid])?;
    b.exec("DELETE FROM oauth_states WHERE connection=?", &[&cid])?;
    b.audit(&who, cid, "connection.disconnect", "disabled_and_credential_removed")?;
    Ok(json!({"connection_id": cid, "status": "disconnected"}))
}

fn delete_connection(b: &Broker, who: &Who, cid: &str) -> R<Value> {
    let who = b.identity(who, "/api/connections/{cid}/delete", &["human"], false)?;
    let _g = b.lock.lock();
    b.connection(&who, cid)?;
    b.audit(&who, cid, "connection.delete", "requested")?;
    b.remove(cid)?;
    b.remove(&format!("oauth-app-{cid}"))?;
    b.exec("UPDATE connections SET status=?,version=0,oauth_app_version=0 WHERE id=?", &[&"deleted", &cid])?;
    b.exec("DELETE FROM oauth_states WHERE connection=?", &[&cid])?;
    b.audit(&who, cid, "connection.delete", "disabled_and_removed")?;
    Ok(json!({"connection_id": cid, "status": "deleted"}))
}

// ── use ────────────────────────────────────────────────────────────────────

fn account_read(b: &Broker, who: &Who, cid: &str, body: AccountReadBody) -> R<Value> {
    let route = "/api/connections/{cid}/read";
    let who = b.identity(who, route, &["agent", "human"], true)?;
    let policy = body.policy.clone().unwrap_or_default();
    policy::require_regime(&who, &policy, route)?;
    let operation = util::uuid_hex();
    let (row, value) = {
        let _g = b.lock.lock();
        let mut row = b.connection(&who, cid)?;
        let expected = if body.action == "calendar.events" { "google_calendar" } else { "google_email" };
        if row_text(&row, "provider") != expected || row_text(&row, "status") != "ready" {
            return Err(Fail::http(409, "Matching connection is not ready"));
        }
        b.audit_op(&who, cid, &body.action, "requested", &operation, row_int(&row, "version"))?;
        let got = (|| -> R<Value> {
            let value = b.must_get(cid, row_int(&row, "version"), &who.actor)?.get("value").cloned().unwrap_or(Value::Null);
            b.audit_op(&who, cid, "credential.read", "retrieved", &operation, row_int(&row, "version"))?;
            b.refreshed(&who, cid, &mut row, value, &operation)
        })();
        match got {
            Ok(v) => (row, v),
            Err(e) => {
                if is_http(&e) || matches!(e, Fail::Provider(_) | Fail::Upstream { .. }) {
                    b.audit_op(&who, cid, &body.action, "failed", &operation, row_int(&row, "version"))?;
                }
                return Err(e);
            }
        }
    };
    let read = google::Read {
        action: &body.action,
        query: &body.query,
        message_id: &body.message_id,
        time_min: &body.time_min,
        time_max: &body.time_max,
        limit: body.limit,
        page_token: &body.page_token,
    };
    let provider = row_text(&row, "provider");
    match google::read_account(provider, &value, row_text(&row, "account"), &read) {
        Ok(result) => {
            b.audit_op(&who, cid, &body.action, "success", &operation, row_int(&row, "version"))?;
            let mut out = Map::new();
            out.insert("operation_id".into(), json!(operation));
            out.insert("source".into(), json!(provider));
            out.insert("untrusted_content".into(), json!(true));
            out.extend(result);
            Ok(Value::Object(out))
        }
        Err(e) => {
            if is_http(&e) || matches!(e, Fail::Provider(_) | Fail::Upstream { .. }) {
                b.audit_op(&who, cid, &body.action, "failed", &operation, row_int(&row, "version"))?;
            }
            Err(e)
        }
    }
}

/// The keyed fingerprint binding a retry to exact input, and the first result
/// when this request id already ran.
#[allow(clippy::too_many_arguments)]
fn idempotent(b: &Broker, who: &Who, cid: &str, request_id: &str, kind: &str, content: &Value, plain: Option<&Value>, unknown: &str) -> R<(String, Option<Value>)> {
    let mut content = content.clone();
    if content.get("replace_person_draft") == Some(&json!(false)) {
        content.as_object_mut().map(|o| o.shift_remove("replace_person_draft"));
    }
    let fingerprint = util::hmac_hex(&b.hmac_key, format!("{kind}:{}", util::py_dumps_sorted(&content)).as_bytes());
    let legacy = match plain {
        Some(p) if kind == "gmail.draft" => util::hmac_hex(&b.hmac_key, util::py_dumps_sorted(p).as_bytes()),
        _ => fingerprint.clone(),
    };
    if let Some(prior) = b.one("SELECT * FROM draft_requests WHERE id=?", &[&request_id])? {
        let fp = row_text(&prior, "fingerprint");
        if row_text(&prior, "actor") != who.actor || row_text(&prior, "connection") != cid || (fp != fingerprint && fp != legacy) {
            return Err(Fail::http(409, "Request ID already used"));
        }
        let result = row_text(&prior, "result");
        if result.is_empty() {
            return Err(Fail::http(409, unknown));
        }
        return Ok((fingerprint, Some(serde_json::from_str(result).map_err(|_| Fail::Internal)?)));
    }
    Ok((fingerprint, None))
}

/// The stored grant, or the permission_required answer when it lacks scope.
#[allow(clippy::too_many_arguments)]
fn credential(b: &Broker, who: &Who, cid: &str, row: &mut Row, operation: &str, action: &str, scope: &str, permission: &str, instruction: &str) -> R<Result<Value, Value>> {
    let value = b.must_get(cid, row_int(row, "version"), &who.actor)?.get("value").cloned().unwrap_or(Value::Null);
    b.audit_op(who, cid, "credential.read", "retrieved", operation, row_int(row, "version"))?;
    let granted = util::text(&value, "scope").to_owned();
    b.exec("UPDATE connections SET grants=? WHERE id=?", &[&google::permissions(row_text(row, "provider"), &granted).join(" "), &cid])?;
    if !granted.split_whitespace().any(|s| s == scope) {
        b.exec("UPDATE connections SET setup_request=? WHERE id=?", &[&util::token_urlsafe(18), &cid])?;
        b.audit_op(who, cid, action, "permission_required", operation, 0)?;
        return Ok(Err(json!({"status": "permission_required", "ui_action": "open_connections", "permission": permission, "instruction": instruction})));
    }
    Ok(Ok(b.refreshed(who, cid, row, value, operation)?))
}

fn draft(b: &Broker, who: &Who, cid: &str, body: GmailDraftBody, update: bool) -> R<Value> {
    let kind = if update { "gmail.draft.update" } else { "gmail.draft" };
    let route = if update { "/api/connections/{cid}/draft-update" } else { "/api/connections/{cid}/draft" };
    let who = b.identity(who, route, &["agent", "human"], false)?;
    let policy = body.policy.clone().unwrap_or_default();
    let _g = b.lock.lock();
    let mut row = b.connection(&who, cid)?;
    if row_text(&row, "provider") != "google_email" || row_text(&row, "status") != "ready" {
        return Err(Fail::http(409, "Gmail connection is not ready"));
    }
    let plain = (!update && body.is_plain()).then(|| json!({"request_id": body.request_id, "recipient": body.recipient, "subject": body.subject, "body": body.body}));
    let (fingerprint, prior) = idempotent(b, &who, cid, &body.request_id, kind, &body.content(update), plain.as_ref(), "Draft outcome unknown; check Gmail before retrying")?;
    if let Some(prior) = prior {
        return Ok(prior);
    }
    let rid = body.request_id.as_str();
    if update && b.one("SELECT 1 FROM drafts WHERE draft_id=? AND actor=? AND connection=?", &[&body.draft_id, &who.actor, &cid])?.is_none() {
        if !body.replace_person_draft {
            b.audit_op(&who, cid, kind, "refused", rid, 0)?;
            return Err(Fail::http(409, "Only drafts Vexa created in this mailbox can be updated by default. If the person asked in this chat to replace their own draft, retry with replace_person_draft true; otherwise create a new draft"));
        }
        b.audit_op(&who, cid, kind, "person_draft_replace_requested", rid, 0)?;
    }
    let checked = (|| -> R<Vec<(String, String, Vec<u8>)>> {
        let mut addresses = vec![body.recipient.clone()];
        addresses.extend(body.cc.iter().cloned());
        addresses.extend(body.bcc.iter().cloned());
        policy::require_domains(addresses.iter(), &policy.recipient_domains, "draft_recipient_domains")?;
        policy::attachments(&body.attachments, &policy)
    })();
    let files = match checked {
        Ok(f) => f,
        Err(e) => {
            if is_http(&e) {
                b.audit_op(&who, cid, kind, "refused_by_policy", rid, 0)?;
            }
            return Err(e);
        }
    };
    b.audit_op(&who, cid, kind, "requested", rid, 0)?;
    let value = match credential(b, &who, cid, &mut row, rid, kind, google::DRAFT_SCOPE, "drafts", "Use Enable drafts in Connections and approve the additional Google permission. No draft has been saved. Do not construct a link.")? {
        Ok(v) => v,
        Err(answer) => return Ok(answer),
    };
    b.exec("INSERT INTO draft_requests VALUES (?,?,?,?,?)", &[&rid, &who.actor, &cid, &fingerprint, &""])?;
    let result = google::create_gmail_draft(&value, &body.recipient, &body.subject, &body.body, &body.cc, &body.bcc, &body.thread_id, &body.in_reply_to, &files, if update { &body.draft_id } else { "" });
    let result = match result {
        Ok(r) => r,
        Err(e @ Fail::Provider(_)) => {
            b.exec("DELETE FROM draft_requests WHERE id=? AND result=''", &[&rid])?;
            b.audit_op(&who, cid, kind, "refused", rid, 0)?;
            return Err(e);
        }
        Err(e @ Fail::Upstream { .. }) => {
            b.audit_op(&who, cid, kind, "unknown", rid, 0)?;
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    b.exec("UPDATE draft_requests SET result=? WHERE id=?", &[&util::py_dumps(&result), &rid])?;
    b.exec("INSERT OR IGNORE INTO drafts(draft_id,actor,connection,created) VALUES (?,?,?,?)", &[&util::text(&result, "draft_id"), &who.actor, &cid, &util::now()])?;
    b.audit_op(&who, cid, kind, "success", rid, row_int(&row, "version"))?;
    Ok(result)
}

fn calendar_event(b: &Broker, who: &Who, cid: &str, body: CalendarEventBody) -> R<Value> {
    let who = b.identity(who, "/api/connections/{cid}/calendar-event", &["agent", "human"], false)?;
    let policy = body.policy.clone().unwrap_or_default();
    let unknown = "Calendar change outcome unknown; check your calendar before retrying";
    let rid = body.request_id.as_str();
    let action = body.action.as_str();
    let _g = b.lock.lock();
    let mut row = b.connection(&who, cid)?;
    if row_text(&row, "provider") != "google_calendar" || row_text(&row, "status") != "ready" {
        return Err(Fail::http(409, "Google Calendar connection is not ready"));
    }
    let content = body.content();
    let (fingerprint, prior) = idempotent(b, &who, cid, rid, action, &content, None, unknown)?;
    if let Some(prior) = prior {
        return Ok(prior);
    }
    let create = action == "calendar.event.create";
    if create != body.event_id.is_empty() {
        return Err(Fail::http(422, "event_id is required to update or cancel, and not accepted to create"));
    }
    let checked = (|| -> R<()> {
        policy::require_calendar(&body.calendar_id, &policy)?;
        policy::require_notify(body.notify, &policy)?;
        policy::require_domains(body.attendees.iter().flatten(), &policy.attendee_domains, "calendar_attendee_domains")
    })();
    if let Err(e) = checked {
        if is_http(&e) {
            b.audit_op(&who, cid, action, "refused_by_policy", rid, 0)?;
        }
        return Err(e);
    }
    b.audit_op(&who, cid, action, "requested", rid, 0)?;
    let value = match credential(b, &who, cid, &mut row, rid, action, google::CALENDAR_WRITE_SCOPE, "calendar_write", "Use Enable calendar changes in Connections and approve the additional Google permission. Nothing was changed. Do not construct a link.")? {
        Ok(v) => v,
        Err(answer) => return Ok(answer),
    };
    b.exec("INSERT INTO draft_requests VALUES (?,?,?,?,?)", &[&rid, &who.actor, &cid, &fingerprint, &""])?;
    let fields = json!({"title": content["title"], "start": content["start"], "end": content["end"], "description": content["description"], "location": content["location"], "attendees": content["attendees"]});
    let result = match calendar::write_calendar_event(&value, action, &body.calendar_id, &body.event_id, &fields, body.notify, body.conference, &format!("{}:{rid}", who.actor)) {
        Ok(r) => r,
        Err(e @ Fail::Provider(_)) => {
            b.exec("DELETE FROM draft_requests WHERE id=? AND result=''", &[&rid])?;
            b.audit_op(&who, cid, action, "refused", rid, 0)?;
            return Err(e);
        }
        Err(e @ Fail::Upstream { .. }) => {
            b.audit_op(&who, cid, action, "unknown", rid, 0)?;
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    b.exec("UPDATE draft_requests SET result=? WHERE id=?", &[&util::py_dumps(&result), &rid])?;
    b.audit_op(&who, cid, action, "success", rid, row_int(&row, "version"))?;
    if body.notify {
        let sent = format!("sent:{}", body.attendees.as_ref().map_or(0, Vec::len));
        b.audit_op(&who, cid, "calendar.attendees_notified", &sent, rid, row_int(&row, "version"))?;
    }
    Ok(result)
}

fn call_custom(b: &Broker, who: &Who, cid: &str, body: CustomCallBody) -> R<Value> {
    let route = "/api/connections/{cid}/call";
    let who = b.identity(who, route, &["agent", "human"], false)?;
    let row = b.connection(&who, cid)?;
    if row_text(&row, "provider") != "custom_secret" || row_text(&row, "status") != "ready" {
        return Err(Fail::http(409, "Service connection is not ready"));
    }
    let operation = util::uuid_hex();
    b.audit_op(&who, cid, "service.call", "requested", &operation, row_int(&row, "version"))?;
    let value = b.must_get(cid, row_int(&row, "version"), &who.actor)?.get("value").cloned().unwrap_or(Value::Null);
    b.audit_op(&who, cid, "credential.read", "retrieved", &operation, row_int(&row, "version"))?;
    let run = (|| -> R<Value> {
        if util::truthy(value.get("oauth_application")) {
            let _g = b.lock.lock();
            let row = b.connection(&who, cid)?;
            if row_text(&row, "status") != "ready" {
                return Err(Fail::http(409, "Service connection is not ready"));
            }
            let mut value = b.must_get(cid, row_int(&row, "version"), &who.actor)?.get("value").cloned().unwrap_or(Value::Null);
            let cfg = value["oauth_application"].clone();
            let expires = value.get("expires_at").and_then(Value::as_f64);
            if expires.is_some_and(|e| e <= util::now() + 30.0) {
                if !util::truthy(value.get("refresh_token")) {
                    return Err(Fail::service("Authorization expired; reconnect"));
                }
                let refresh = util::text(&value, "refresh_token").to_owned();
                value = service::exchange(&cfg["spec"], &cfg, "", "", "", Some(&refresh))?;
                value["oauth_application"] = cfg.clone();
                let saved = b.put(cid, json!({"value": value}), None, Some(&who.actor))?;
                b.exec("UPDATE connections SET version=? WHERE id=?", &[&saved.version, &cid])?;
                b.audit_full(&who, cid, "credential.refresh", "stored", &operation, &saved.receipt, saved.version, "")?;
            }
            let spec = &cfg["spec"];
            let text = |k: &str| util::text(spec, k).to_owned();
            let config = service::configure(util::text(&value, "access_token"), &text("endpoint"), &text("header"), &text("scheme"), &text("method"), "")?;
            service::execute(&config, &body.parameters, body.body.as_ref())
        } else {
            service::execute(&value, &body.parameters, body.body.as_ref())
        }
    })();
    match run {
        Ok(result) => {
            b.audit_op(&who, cid, "service.call", "complete", &operation, 0)?;
            let mut out = Map::new();
            out.insert("operation_id".into(), json!(operation));
            if let Value::Object(r) = result {
                out.extend(r);
            }
            Ok(Value::Object(out))
        }
        Err(Fail::Service(s)) => {
            obs::refused("service", "refused", route);
            b.audit_op(&who, cid, "service.call", "failed", &operation, 0)?;
            let reason = refusal_reason(&s);
            Err(Fail::Reasoned(409, s, reason))
        }
        Err(e @ Fail::Upstream { .. }) => {
            b.audit_op(&who, cid, "service.call", "failed", &operation, 0)?;
            Err(e)
        }
        Err(e) => Err(e),
    }
}

// ── internal roles ─────────────────────────────────────────────────────────

/// Whether the Git credential name belongs to the signed person.
pub fn owned_by(name: &str, person: &str, memberships: &[String]) -> bool {
    if name.contains("..") {
        return false;
    }
    if let Some(rest) = name.strip_prefix("pat/") {
        return rest.split('/').next() == Some(person);
    }
    let Some(rest) = name.strip_prefix("deploy/") else { return false };
    let Some(stem) = rest.strip_suffix(".priv").or_else(|| rest.strip_suffix(".pub")) else { return false };
    if let Some(owner) = stem.strip_prefix("user-").filter(|o| !o.is_empty()) {
        return owner == person;
    }
    if let Some(owner) = stem.strip_prefix("ws-").filter(|o| !o.is_empty()) {
        return memberships.iter().any(|m| m == owner);
    }
    false
}

fn git_secret(b: &Broker, who: &Who, body: GitSecretBody) -> R<Value> {
    let who = b.identity(who, "/api/internal/git-secret", &["git"], false)?;
    if !owned_by(&body.name, &who.actor, &who.memberships) {
        return Err(Fail::http(403, "Git credential scope refused"));
    }
    let path = format!("git/{}", body.name);
    let operation = util::uuid_hex();
    let action = format!("git.credential.{}", body.action);
    let _g = b.lock.lock();
    b.audit_op(&who, &body.name, &action, "requested", &operation, 0)?;
    let mut stored = b.get(&path, None, None)?;
    if body.action == "put" || (body.action == "migrate" && stored.is_none()) {
        b.put(&path, json!({"value": body.value}), Some(stored.as_ref().map_or(0, |s| s.version)), None)?;
        stored = b.get(&path, None, None)?;
    }
    let (receipt, version) = stored.as_ref().map_or((String::new(), 0), |s| (s.receipt.clone(), s.version));
    b.audit_full(&who, &body.name, &action, "success", &operation, &receipt, version, "")?;
    Ok(json!({"found": stored.is_some(), "value": stored.map_or(Value::Null, |s| s.data.get("value").cloned().unwrap_or(Value::Null))}))
}

const INDEX: &str = "bot-index";

fn bot_now() -> String {
    let (y, mo, d, h, mi, s) = util::civil(util::now().floor() as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn bot_account(b: &Broker, who: &Who, body: BotAccountBody) -> R<Value> {
    let route = "/api/internal/bot-account";
    let who = b.identity(who, route, &["bots"], false)?;
    let action = format!("bot.account.{}", body.action);
    let subject = body.id.clone().unwrap_or_else(|| INDEX.to_owned());
    let operation = util::uuid_hex();
    let _g = b.lock.lock();
    b.audit_op(&who, &subject, &action, "requested", &operation, 0)?;
    let stored_index = b.get(INDEX, None, None)?;
    let mut accounts: Map<String, Value> = stored_index.as_ref().and_then(|s| s.data.get("accounts").and_then(Value::as_object).cloned()).unwrap_or_default();
    let cas = Some(stored_index.as_ref().map_or(0, |s| s.version));
    let id = body.id.clone().unwrap_or_default();
    let mut files = Value::Null;
    let mut version = 0;
    let result: Vec<Value> = match body.action.as_str() {
        "list" => {
            let owners = body.owners.clone().unwrap_or_default();
            let mut list: Vec<Value> = accounts.values().filter(|a| owners.iter().any(|o| a.get("owner").and_then(Value::as_str) == Some(o))).cloned().collect();
            list.sort_by(|a, c| (util::text(a, "created_at"), util::text(a, "id")).cmp(&(util::text(c, "created_at"), util::text(c, "id"))));
            list
        }
        "get" => {
            let account = accounts.get(&id).cloned().ok_or_else(|| Fail::http(404, "Bot account not found"))?;
            let record = b.get(&format!("bot/{id}"), None, Some(util::text(&account, "owner")))?;
            let Some(record) = record else {
                obs::fault("store", "missing", Some(route));
                return Err(Fail::store_unavailable());
            };
            files = json!(record.data.get("files").and_then(Value::as_array).cloned().unwrap_or_default());
            version = record.version;
            vec![account]
        }
        "put" => {
            let spec = body.account.as_ref().ok_or(Fail::Invalid)?;
            let existing = accounts.get(&id).cloned();
            if let Some(e) = &existing {
                if util::text(e, "owner") != spec.owner || util::text(e, "platform") != spec.platform {
                    return Err(Fail::http(409, "Bot account belongs to another owner or platform"));
                }
            }
            let now = bot_now();
            let account = json!({
                "id": id, "owner": spec.owner, "platform": spec.platform, "display_name": spec.display_name,
                "state": "ok", "verified_at": now,
                "created_at": existing.as_ref().map_or(json!(now), |e| e["created_at"].clone()),
                "created_by": existing.as_ref().map_or(json!(spec.created_by), |e| e["created_by"].clone()),
                "updated_at": now,
            });
            let saved = b.put(&format!("bot/{id}"), json!({"account": account, "files": body.files.clone().unwrap_or_default()}), None, Some(&spec.owner))?;
            version = saved.version;
            accounts.insert(id.clone(), account.clone());
            b.put(INDEX, json!({"accounts": accounts}), cas, None)?;
            vec![account]
        }
        "state" => {
            let mut account = accounts.get(&id).cloned().ok_or_else(|| Fail::http(404, "Bot account not found"))?;
            let now = bot_now();
            let state = body.state.clone().unwrap_or_default();
            account["state"] = json!(state);
            account["updated_at"] = json!(now);
            if state == "ok" {
                account["verified_at"] = json!(now);
            }
            accounts.insert(id.clone(), account.clone());
            b.put(INDEX, json!({"accounts": accounts}), cas, None)?;
            vec![account]
        }
        _ => {
            let account = accounts.shift_remove(&id);
            b.remove(&format!("bot/{id}"))?;
            if account.is_some() {
                b.put(INDEX, json!({"accounts": accounts}), cas, None)?;
            }
            account.into_iter().collect()
        }
    };
    b.audit_op(&who, &subject, &action, "success", &operation, version)?;
    Ok(json!({"accounts": result, "files": files}))
}

const NO_GRANT: [(&str, &str); 3] = [
    ("none", "This person has not let their sensors read this calendar"),
    ("revoked", "This person revoked their sensors' access to this calendar"),
    ("expired", "This person's grant for their sensors to read this calendar has expired"),
];

fn ready_calendar(b: &Broker, actor: &str, cid: Option<&str>) -> R<Option<Row>> {
    match cid.filter(|c| !c.is_empty()) {
        Some(c) => b.one("SELECT * FROM connections WHERE id=? AND actor=? AND status='ready' AND provider='google_calendar'", &[&c, &actor]),
        None => b.one("SELECT * FROM connections WHERE actor=? AND status='ready' AND provider='google_calendar' ORDER BY created DESC", &[&actor]),
    }
}

fn sensor_calendar_changes(b: &Broker, who: &Who, body: CalendarChangesBody) -> R<Value> {
    let who = b.identity(who, "/api/internal/sensor/calendar-changes", &["sensors"], false)?;
    if who.actor != body.owner {
        return Err(Fail::http(403, "A sensor reads only the person its request is signed for"));
    }
    let operation = util::uuid_hex();
    let (row, cid, value) = {
        let _g = b.lock.lock();
        let named = match body.connection_id.clone().filter(|c| !c.is_empty()) {
            Some(c) => Some(c),
            None => sensor_grants::granted_connection(b, &body.owner, util::now())?,
        };
        let mut row = ready_calendar(b, &body.owner, named.as_deref())?.ok_or_else(|| Fail::http(409, "No ready calendar connection for this person"))?;
        let cid = row_text(&row, "id").to_owned();
        let version = row_int(&row, "version");
        let grant = sensor_grants::latest(b, &body.owner, &cid)?;
        let state = grant.as_ref().map_or("none", |g| sensor_grants::status(g, util::now()));
        if state != "active" {
            b.audit_op(&who, &cid, "calendar.changes", "refused", &operation, version)?;
            let sentence = NO_GRANT.iter().find(|(k, _)| *k == state).map_or("", |(_, s)| s);
            return Err(Fail::Reasoned(409, sentence.to_owned(), "sensor_grant_required"));
        }
        b.audit_op(&who, &cid, "calendar.changes", "requested", &operation, version)?;
        let got = (|| -> R<Value> {
            let value = b.must_get(&cid, version, &body.owner)?.get("value").cloned().unwrap_or(Value::Null);
            b.refreshed(&who, &cid, &mut row, value, &operation)
        })();
        match got {
            Ok(v) => (row, cid, v),
            Err(e) => {
                if is_http(&e) || matches!(e, Fail::Provider(_) | Fail::Upstream { .. }) {
                    b.audit_op(&who, &cid, "calendar.changes", "failed", &operation, row_int(&row, "version"))?;
                }
                return Err(e);
            }
        }
    };
    let version = row_int(&row, "version");
    match calendar::calendar_changes(&value, body.cursor.as_deref(), util::now()) {
        Ok(result) => {
            b.audit_op(&who, &cid, "calendar.changes", "success", &operation, version)?;
            let mut out = Map::new();
            out.insert("connection_id".into(), json!(cid));
            if let Value::Object(r) = result {
                out.extend(r);
            }
            Ok(Value::Object(out))
        }
        Err(e) => {
            if matches!(e, Fail::Provider(_) | Fail::Upstream { .. }) {
                b.audit_op(&who, &cid, "calendar.changes", "failed", &operation, version)?;
            }
            Err(e)
        }
    }
}

fn grant_issue(b: &Broker, who: &Who, body: SensorGrantBody) -> R<Value> {
    let who = b.identity(who, "/api/sensor-grants", &["agent", "human"], false)?;
    let row = ready_calendar(b, &who.actor, body.connection_id.as_deref())?.ok_or_else(|| Fail::http(409, "No ready calendar connection for this person"))?;
    let cid = row_text(&row, "id").to_owned();
    b.audit(&who, &cid, "sensor_grant.issue", "requested")?;
    let grant = sensor_grants::issue(b, &who.actor, &cid, body.days, "person", util::now())?;
    b.audit_full(&who, &cid, "sensor_grant.issue", "stored", "", "", 0, row_text(&grant, "id"))?;
    Ok(sensor_grants::view(&grant, util::now()))
}

fn grant_list(b: &Broker, who: &Who) -> R<Value> {
    let who = b.identity(who, "/api/sensor-grants", &["agent", "human"], true)?;
    let rows = b.rows("SELECT * FROM sensor_grants WHERE actor=? ORDER BY created DESC LIMIT 100", &[&who.actor])?;
    let now = util::now();
    Ok(json!({"grants": rows.iter().map(|r| sensor_grants::view(r, now)).collect::<Vec<_>>()}))
}

fn grant_revoke(b: &Broker, who: &Who, grant_id: &str) -> R<Value> {
    let who = b.identity(who, "/api/sensor-grants/{grant_id}/revoke", &["agent", "human"], true)?;
    let row = b.one("SELECT * FROM sensor_grants WHERE id=? AND actor=?", &[&grant_id, &who.actor])?.ok_or_else(|| Fail::http(404, "Grant not found"))?;
    if !util::truthy(row.get("revoked")) {
        b.exec("UPDATE sensor_grants SET revoked=? WHERE id=?", &[&util::now(), &grant_id])?;
    }
    b.audit_full(&who, row_text(&row, "connection"), "sensor_grant.revoke", "stored", "", "", 0, grant_id)?;
    let row = b.one("SELECT * FROM sensor_grants WHERE id=?", &[&grant_id])?.ok_or(Fail::Internal)?;
    Ok(sensor_grants::view(&row, util::now()))
}

/// A company secret under service/<owner>/<name>: the signals model key
/// (role signals) or the outbound-mail credential (role sensors).
fn service_value(b: &Broker, who: &Who, name: String, owner: &str) -> R<Value> {
    let (route, role, action, missing) = if owner == "signals" {
        ("/api/internal/signals/model-key", "signals", "signals.model_key", "No signal-model key is stored under this name")
    } else {
        ("/api/internal/mail/smtp-credential", "sensors", "mail.smtp_credential", "No mail credential is stored under this name")
    };
    let who = b.identity(who, route, &[role], false)?;
    let operation = util::uuid_hex();
    let _g = b.lock.lock();
    b.audit_op(&who, &name, action, "requested", &operation, 0)?;
    let record = b.get(&format!("service/{owner}/{name}"), None, Some(owner))?;
    let value = record.as_ref().and_then(|r| r.data.get("value").cloned()).filter(|v| util::truthy(Some(v)));
    let Some(value) = value else {
        b.audit_op(&who, &name, action, "missing", &operation, 0)?;
        return Err(Fail::http(404, missing));
    };
    b.audit_op(&who, &name, action, "success", &operation, record.map_or(0, |r| r.version))?;
    Ok(json!({"name": name, "value": value}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_names_belong_to_the_signed_person() {
        let ws = vec!["7".to_owned()];
        assert!(owned_by("pat/42", "42", &ws) && owned_by("pat/42/gitlab.com", "42", &ws));
        assert!(owned_by("deploy/user-42.priv", "42", &ws) && owned_by("deploy/ws-7.pub", "42", &ws));
        assert!(!owned_by("pat/43", "42", &ws) && !owned_by("deploy/ws-8.pub", "42", &ws) && !owned_by("deploy/user-4..2.pub", "42", &ws));
    }

    #[test]
    fn routes_match_their_patterns() {
        assert_eq!(matches("/api/connections/{}/read", "/api/connections/abc/read").as_deref(), Some("abc"));
        assert!(matches("/api/connections/{}/read", "/api/connections//read").is_none());
        assert!(matches("/api/connections", "/api/connections/x").is_none());
        assert_eq!(query_value("state=a%2Bb&code=x+y&state=c", "state"), "c");
    }
}
