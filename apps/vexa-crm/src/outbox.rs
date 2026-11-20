//! Bounded, retryable delivery to Flows. No CRM field values leave the record service, except the
//! enumerated lifecycle coordination fields of a card fact (kind, state, next_actor, next_check_at,
//! handoff).
//!
//! A row whose event carries an `envelope` (event.v2) is SEALED here, at delivery, with the CRM's own
//! Ed25519 private key, bound to the fact it rides on and good for `fact_envelope::SEAL_TTL_S`; it is
//! posted as `{event_type, source_event_id, refs, envelope}`. flows refuses it 403 if the seal does
//! not verify under the CRM's public key. The key is the PEM file at `VEXA_FACT_SEAL_KEY_FILE`, which
//! only this process holds, and delivery refuses to start without it. A refused row stays pending
//! and is sealed afresh on the next pass. It posts with the CRM's publish key (`FLOWS_PUBLISH_KEY`,
//! `X-Flows-Publisher-Key`). A row without an `envelope` is posted unsealed and reaches its subject
//! only.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};
use vexa_native_kit::pg::{Int, Pool};

use crate::err::{CrmError, R};
use crate::fact_envelope::{self, SealError};
use crate::fact_keys::{self, Signer};
pub use crate::preflight::{process_env, Env};
use crate::preflight::env_value;

/// The CRM's own Ed25519 private key file (config.v1 `VEXA_FACT_SEAL_KEY_FILE`); only the outbox holds it.
pub const SEAL_KEY_FILE_ENV: &str = "VEXA_FACT_SEAL_KEY_FILE";
/// True only when the desktop deployment combines CRM delivery into the API process.
pub const OUTBOX_ENABLED_ENV: &str = "VEXA_CRM_OUTBOX_ENABLED";
pub const LIMIT: i64 = 100;

/// `VEXA_CRM_OUTBOX_ENABLED` is "true" (case-insensitive, stripped).
pub fn outbox_enabled(env: &Env) -> bool {
    crate::val::lower(env_value(env, OUTBOX_ENABLED_ENV)) == "true"
}

/// The CRM's signer from the file `VEXA_FACT_SEAL_KEY_FILE` names (this process's env when None), else None.
pub fn signer_from_env(env: Option<&Env>) -> Option<Signer> {
    let path = match env {
        Some(e) => e.get(SEAL_KEY_FILE_ENV).cloned(),
        None => std::env::var(SEAL_KEY_FILE_ENV).ok(),
    };
    fact_keys::signer_from_file(path.as_deref())
}

fn key<'a>(event: &'a Value, k: &str) -> R<&'a Value> {
    match event {
        Value::Object(o) => o.get(k).ok_or_else(|| CrmError::internal(format!("KeyError: '{k}'"))),
        _ => Err(CrmError::internal("TypeError: the outbox event is not a mapping")),
    }
}

/// The POST body for one outbox event. Ok(Err) when an envelope cannot be sealed (ValueError).
pub fn body(event: &Value, sign: Option<&Signer>) -> R<Result<Value, String>> {
    let mut body = Map::new();
    body.insert("event_type".into(), key(event, "event_type")?.clone());
    body.insert("source_event_id".into(), key(event, "source_event_id")?.clone());
    body.insert("refs".into(), key(event, "subject_refs")?.clone());
    if let Some(env) = event.get("envelope").filter(|e| !e.is_null()) {
        let the_fact = fact_envelope::fact(&body["event_type"], &body["source_event_id"], &body["refs"]);
        match fact_envelope::seal(env, sign, &the_fact, None) {
            Ok(sealed) => {
                body.insert("envelope".into(), sealed);
            }
            Err(SealError::Value(m)) => return Ok(Err(m)),
            Err(SealError::Other(m)) => return Err(CrmError::internal(m)),
        }
    }
    Ok(Ok(Value::Object(body)))
}

/// One delivery pass: the pending rows (`FOR UPDATE SKIP LOCKED`, by id, at most `limit`), each
/// sealed and posted to `endpoint/events`; a 202 marks the row delivered in the same transaction.
/// The first failure ends the pass and keeps what was delivered before it. A crash after Flows
/// accepts but before commit redelivers the SAME event id. `sign` None reads the key from this
/// process's env; `log_http` writes httpx's INFO line for each answer.
pub fn deliver(pool: &Arc<Pool>, endpoint: &str, token: &str, limit: i64, record_id: Option<&str>, sign: Option<&Signer>, log_http: bool) -> R<Value> {
    if endpoint.is_empty() || token.is_empty() {
        return Ok(json!({"delivered": 0, "pending": true, "reason": "Flows is not configured"}));
    }
    let own;
    let sign = match sign {
        Some(s) => Some(s),
        None => {
            own = signer_from_env(None);
            own.as_ref()
        }
    };
    let mut c = pool.begin()?;
    let rows = match record_id.filter(|r| !r.is_empty()) {
        Some(r) => c.maps(&format!("SELECT {} FROM crm_outbox WHERE crm_outbox.delivered = false AND crm_outbox.record_id = $2 \
                                    ORDER BY crm_outbox.id LIMIT $1 FOR UPDATE SKIP LOCKED", crate::schema::OUTBOX), &[&Int(limit), &r])?,
        None => c.maps(&format!("SELECT {} FROM crm_outbox WHERE crm_outbox.delivered = false \
                                 ORDER BY crm_outbox.id LIMIT $1 FOR UPDATE SKIP LOCKED", crate::schema::OUTBOX), &[&Int(limit)])?,
    };
    let url = format!("{}/events", endpoint.trim_end_matches('/'));
    let mut delivered: i64 = 0;
    let stop = |c: vexa_native_kit::pg::Tx, answer: Value| -> R<Value> {
        c.commit()?;
        Ok(answer)
    };
    for row in &rows {
        let event = row.get("event").unwrap_or(&Value::Null);
        let body = match body(event, sign)? {
            Ok(b) => b,
            // A row that cannot be sealed stays pending and says so — never posted unsealed.
            Err(_) => return stop(c, json!({"delivered": delivered, "pending": true, "reason": "Envelope could not be sealed"})),
        };
        let reply = match crate::net::post_json(&url, &[("X-Flows-Publisher-Key", token)], &body, 10.0) {
            Ok(r) => r,
            Err(_) => return stop(c, json!({"delivered": delivered, "pending": true, "reason": "Flows unavailable"})),
        };
        if log_http {
            eprintln!("INFO:httpx:HTTP Request: POST {url} \"HTTP/1.1 {} {}\"", reply.status, vexa_native_kit::reason::phrase(reply.status));
        }
        if reply.status != 202 {
            return stop(c, json!({"delivered": delivered, "pending": true, "status": reply.status}));
        }
        let org = row.get("org_id").and_then(Value::as_str).unwrap_or("");
        let id = row.get("id").and_then(Value::as_str).unwrap_or("");
        c.exec("UPDATE crm_outbox SET delivered=$1 WHERE crm_outbox.org_id = $2 AND crm_outbox.id = $3", &[&true, &org, &id])?;
        delivered += 1;
    }
    stop(c, json!({"delivered": delivered, "pending": rows.len() as i64 == limit}))
}

/// The in-process loop's one pass: `deliver` with this env's endpoint and key; any failure is
/// `{"delivered": 0, "pending": true}`, never its text (it can hold credentials or SQL values).
pub fn deliver_once(pool: &Arc<Pool>, endpoint: &str, token: &str) -> Value {
    deliver(pool, endpoint, token, LIMIT, None, None, true).unwrap_or_else(|_| json!({"delivered": 0, "pending": true}))
}

/// The outbox's own boot check: its login, the fact seal key and, where flows is named, the publish
/// key — each set and none a published placeholder, and the seal key a readable Ed25519 private
/// key. Err names every key, never a value (Python's SystemExit text).
pub fn preflight(env: Option<&Env>) -> Result<(), String> {
    let own;
    let env = match env {
        Some(e) => e,
        None => {
            own = process_env();
            &own
        }
    };
    let mut need = vec!["CRM_DATABASE_URL", SEAL_KEY_FILE_ENV];
    if !env_value(env, "FLOWS_API_URL").is_empty() {
        need.push("FLOWS_PUBLISH_KEY");
    }
    let missing: Vec<&str> = need.iter().copied().filter(|k| env_value(env, k).is_empty()).collect();
    if !missing.is_empty() {
        return Err(format!("crm outbox refuses to start — not set: {}. The outbox seals every card fact it delivers \
                            with the CRM's own key ({SEAL_KEY_FILE_ENV}, whose public half flows-api verifies under) \
                            and posts it with the CRM's publish key", missing.join(", ")));
    }
    let decl = crate::preflight::load_declaration()?;
    let forbidden = |k: &str| -> Vec<String> {
        decl.get("keys").and_then(Value::as_array).into_iter().flatten()
            .filter(|e| e.get("key").and_then(Value::as_str) == Some(k))
            .last()
            .and_then(|e| e.get("forbidden_values"))
            .map(crate::val::strings)
            .unwrap_or_default()
    };
    let held: Vec<&str> = need.iter().copied().filter(|k| forbidden(k).iter().any(|f| f == env_value(env, k))).collect();
    if !held.is_empty() {
        return Err(format!("crm outbox refuses to start — {} hold(s) a published placeholder; mint a real value \
                            (`openssl rand -hex 32`)", held.join(", ")));
    }
    if signer_from_env(Some(env)).is_none() {
        return Err(format!("crm outbox refuses to start — {SEAL_KEY_FILE_ENV} is not a readable Ed25519 private key \
                            in PKCS#8 PEM (`openssl genpkey -algorithm ed25519`)"));
    }
    Ok(())
}

/// The running in-process delivery loop.
pub struct Loop {
    stop: Arc<(Mutex<bool>, Condvar)>,
    done: Arc<(Mutex<bool>, Condvar)>,
}

impl Loop {
    /// Ask the loop to stop and wait up to 2 s for its pass to end.
    pub fn stop(&self) {
        let (flag, cv) = &*self.stop;
        *flag.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
        let (done, cv) = &*self.done;
        let guard = done.lock().unwrap_or_else(|e| e.into_inner());
        let _ = cv.wait_timeout_while(guard, Duration::from_secs(2), |d| !*d);
    }
}

/// Start the bounded delivery loop in this process (`VEXA_CRM_OUTBOX_ENABLED`): the outbox
/// preflight first (Err: its refusal), then a `crm-outbox` thread that delivers, waits 1 s after a
/// pass that delivered and 10 s otherwise, until stopped.
pub fn start(pool: Arc<Pool>, env: Option<&Env>) -> Result<Loop, String> {
    preflight(env)?;
    let read = |k: &str| match env {
        Some(e) => e.get(k).cloned().unwrap_or_default(),
        None => std::env::var(k).unwrap_or_default(),
    };
    let (endpoint, token) = (read("FLOWS_API_URL"), read("FLOWS_PUBLISH_KEY"));
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let done = Arc::new((Mutex::new(false), Condvar::new()));
    let (s, d) = (Arc::clone(&stop), Arc::clone(&done));
    std::thread::Builder::new()
        .name("crm-outbox".into())
        .spawn(move || {
            let (flag, cv) = &*s;
            loop {
                if *flag.lock().unwrap_or_else(|e| e.into_inner()) {
                    break;
                }
                let result = deliver_once(&pool, &endpoint, &token);
                let delay = if crate::val::truthy(&result["delivered"]) { 1 } else { 10 };
                let guard = flag.lock().unwrap_or_else(|e| e.into_inner());
                let _ = cv.wait_timeout_while(guard, Duration::from_secs(delay), |stopped| !*stopped);
            }
            let (done, cv) = &*d;
            *done.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cv.notify_all();
        })
        .map_err(|e| e.to_string())?;
    Ok(Loop { stop, done })
}

/// `outbox [--watch]`: the preflight, then one pass (or passes for ever with --watch), printing each
/// pass that delivered, failed or ran once as JSON on stdout. Returns the exit code.
pub fn main(args: &[String]) -> i32 {
    let mut watch = false;
    for a in args {
        match a.as_str() {
            "--watch" => watch = true,
            "-h" | "--help" => {
                println!("usage: outbox.py [-h] [--watch]\n\noptions:\n  -h, --help  show this help message and exit\n  --watch");
                return 0;
            }
            _ => {
                eprintln!("usage: outbox.py [-h] [--watch]\noutbox.py: error: unrecognized arguments: {}", args.iter().filter(|x| *x != "--watch").cloned().collect::<Vec<_>>().join(" "));
                return 2;
            }
        }
    }
    if let Err(m) = preflight(None) {
        eprintln!("{m}");
        return 1;
    }
    let pool = match Pool::new(&std::env::var("CRM_DATABASE_URL").unwrap_or_default(), 1) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Traceback (most recent call last):\nsqlalchemy.exc.ArgumentError: {e}");
            return 1;
        }
    };
    loop {
        let endpoint = std::env::var("FLOWS_API_URL").unwrap_or_default();
        let token = std::env::var("FLOWS_PUBLISH_KEY").unwrap_or_default();
        let result = deliver(&pool, &endpoint, &token, LIMIT, None, None, false)
            .unwrap_or_else(|_| json!({"delivered": 0, "pending": true, "reason": "Delivery failed; retry pending"}));
        let t = |k: &str| crate::val::truthy(result.get(k).unwrap_or(&Value::Null));
        if t("delivered") || t("reason") || t("status") || !watch {
            println!("{}", vexa_native_kit::pyjson::Dumps::DEFAULT.text(&result));
        }
        if !watch {
            return 0;
        }
        std::thread::sleep(Duration::from_secs(if t("delivered") { 1 } else { 10 }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n-----END PRIVATE KEY-----\n";

    fn key_file() -> String {
        let p = std::env::temp_dir().join(format!("crm-outbox-test-{}.pem", std::process::id()));
        std::fs::write(&p, PEM).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// `crm.outbox.preflight` in Python for the same envs (KEY: a readable Ed25519 key file).
    const PY: &str = r##"["crm outbox refuses to start \u2014 not set: CRM_DATABASE_URL, VEXA_FACT_SEAL_KEY_FILE. The outbox seals every card fact it delivers with the CRM's own key (VEXA_FACT_SEAL_KEY_FILE, whose public half flows-api verifies under) and posts it with the CRM's publish key", "crm outbox refuses to start \u2014 not set: CRM_DATABASE_URL, VEXA_FACT_SEAL_KEY_FILE, FLOWS_PUBLISH_KEY. The outbox seals every card fact it delivers with the CRM's own key (VEXA_FACT_SEAL_KEY_FILE, whose public half flows-api verifies under) and posts it with the CRM's publish key", "crm outbox refuses to start \u2014 VEXA_FACT_SEAL_KEY_FILE is not a readable Ed25519 private key in PKCS#8 PEM (`openssl genpkey -algorithm ed25519`)", "crm outbox refuses to start \u2014 FLOWS_PUBLISH_KEY hold(s) a published placeholder; mint a real value (`openssl rand -hex 32`)", "crm outbox refuses to start \u2014 VEXA_FACT_SEAL_KEY_FILE is not a readable Ed25519 private key in PKCS#8 PEM (`openssl genpkey -algorithm ed25519`)", null, null]"##;

    #[test]
    fn preflight_matches_python() {
        let expected: Vec<Value> = serde_json::from_str(PY).unwrap();
        let key = key_file();
        let envs = [env(&[]), env(&[("FLOWS_API_URL", "http://f")]),
                    env(&[("CRM_DATABASE_URL", "x"), (SEAL_KEY_FILE_ENV, " changeme ")]),
                    env(&[("CRM_DATABASE_URL", "x"), (SEAL_KEY_FILE_ENV, &key), ("FLOWS_API_URL", "http://f"), ("FLOWS_PUBLISH_KEY", "secret")]),
                    env(&[("CRM_DATABASE_URL", "x"), (SEAL_KEY_FILE_ENV, "/nonexistent")]),
                    env(&[("CRM_DATABASE_URL", "x"), (SEAL_KEY_FILE_ENV, &key), ("FLOWS_API_URL", "http://f"), ("FLOWS_PUBLISH_KEY", "real")]),
                    env(&[("CRM_DATABASE_URL", "x"), (SEAL_KEY_FILE_ENV, &key)])];
        for (e, want) in envs.iter().zip(expected) {
            let got = match preflight(Some(e)) { Ok(()) => Value::Null, Err(m) => Value::String(m) };
            assert_eq!(got, want);
        }
        assert!(outbox_enabled(&env(&[(OUTBOX_ENABLED_ENV, " TRUE ")])));
        assert!(!outbox_enabled(&env(&[(OUTBOX_ENABLED_ENV, "1")])));
    }

    #[test]
    fn body_keeps_event_order_and_refuses_unsealable() {
        let s = fact_keys::load_signer(PEM.as_bytes()).unwrap();
        let ev = json!({"event_type": "crm.record.changed", "source_event_id": "e1", "subject_refs": {"uid": "1"}, "envelope": null});
        assert_eq!(body(&ev, Some(&s)).unwrap().unwrap(), json!({"event_type": "crm.record.changed", "source_event_id": "e1", "refs": {"uid": "1"}}));
        let mut sealed = ev.clone();
        sealed["envelope"] = json!({"v": 2, "producer": "crm", "object": "card", "owner": "1", "visibility": "owner", "audience": ["1"]});
        let b = body(&sealed, Some(&s)).unwrap().unwrap();
        assert_eq!(crate::val::keys(&b), ["event_type", "source_event_id", "refs", "envelope"]);
        assert_eq!(crate::val::keys(&b["envelope"]), ["v", "producer", "object", "owner", "visibility", "audience", "exp", "sig"]);
        assert!(body(&sealed, None).unwrap().is_err());
        assert!(body(&json!({"event_type": "x"}), Some(&s)).is_err());
    }

    /// A Flows stand-in: answers each request with `status` and keeps what it was sent.
    fn flows(statuses: Vec<u16>) -> (String, std::thread::JoinHandle<Vec<(String, String)>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for status in statuses {
                let (mut sock, _) = l.accept().unwrap();
                let mut r = BufReader::new(sock.try_clone().unwrap());
                let mut head = String::new();
                let mut len = 0;
                loop {
                    let mut line = String::new();
                    r.read_line(&mut line).unwrap();
                    if line == "\r\n" { break; }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") { len = v.trim().parse().unwrap(); }
                    head.push_str(&line);
                }
                let mut b = vec![0; len];
                r.read_exact(&mut b).unwrap();
                seen.push((head, String::from_utf8(b).unwrap()));
                write!(sock, "HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").unwrap();
            }
            seen
        });
        (url, h)
    }

    fn db() -> Option<(Arc<Pool>, String)> {
        let url = std::env::var("VEXA_TEST_PG_URL").ok()?;
        Some((Pool::new(&url, 2).unwrap(), url))
    }

    /// Rows written with the referential triggers off (a superuser session), so a test needs no records.
    fn seed(url: &str, rid: &str, events: &[Value]) {
        let mut c = Pool::new(url, 1).unwrap().begin().unwrap();
        c.exec("SET LOCAL session_replication_role = replica", &[]).unwrap();
        for (i, e) in events.iter().enumerate() {
            c.exec("INSERT INTO crm_outbox (org_id, id, record_id, revision, event, delivered) VALUES ('t-outbox', $1, $2, $3, $4, false)",
                   &[&format!("{rid}-{i}"), &rid, &Int(i as i64 + 1), e]).unwrap();
        }
        c.commit().unwrap();
    }

    fn clean(url: &str, rid: &str) -> Vec<(String, bool)> {
        let mut c = Pool::new(url, 1).unwrap().begin().unwrap();
        c.exec("SET LOCAL session_replication_role = replica", &[]).unwrap();
        let rows = c.tuples("SELECT id, delivered FROM crm_outbox WHERE record_id = $1 ORDER BY id", &[&rid]).unwrap();
        c.exec("DELETE FROM crm_outbox WHERE record_id = $1", &[&rid]).unwrap();
        c.commit().unwrap();
        rows.iter().map(|r| (crate::val::s(&r[0]), r[1].as_bool().unwrap())).collect()
    }

    fn ev(n: usize, envelope: Value) -> Value {
        json!({"event_type": "crm.record.changed", "source_event_id": format!("ev-{n}"), "subject_refs": {"uid": "1", "revision": n}, "envelope": envelope})
    }

    #[test]
    fn deliver_marks_accepted_rows_and_stops_at_the_first_refusal() {
        let Some((pool, url)) = db() else { return };
        let s = fact_keys::load_signer(PEM.as_bytes()).unwrap();
        let rid = format!("outbox-test-{}-a", std::process::id());
        let env = json!({"v": 2, "producer": "crm", "object": "card", "owner": "1", "visibility": "owner", "audience": ["1"]});
        seed(&url, &rid, &[ev(0, Value::Null), ev(1, env.clone()), ev(2, Value::Null)]);
        let (flows_url, h) = flows(vec![202, 202, 503]);
        let got = deliver(&pool, &flows_url, "pk", LIMIT, Some(&rid), Some(&s), false).unwrap();
        let seen = h.join().unwrap();
        let rows = clean(&url, &rid);
        assert_eq!(got, json!({"delivered": 2, "pending": true, "status": 503}));
        assert_eq!(rows.iter().map(|r| r.1).collect::<Vec<_>>(), [true, true, false]);
        assert!(seen[0].0.starts_with("POST /events HTTP/1.1"));
        assert!(seen[0].0.to_ascii_lowercase().contains("x-flows-publisher-key: pk"));
        assert_eq!(seen[0].1, r#"{"event_type":"crm.record.changed","source_event_id":"ev-0","refs":{"uid":"1","revision":0}}"#);
        let posted: Value = serde_json::from_str(&seen[1].1).unwrap();
        assert_eq!(posted["envelope"]["sig"].as_str().unwrap().len(), 128);
    }

    #[test]
    fn deliver_reasons() {
        let Some((pool, url)) = db() else { return };
        assert_eq!(deliver(&pool, "", "pk", LIMIT, None, None, false).unwrap(), json!({"delivered": 0, "pending": true, "reason": "Flows is not configured"}));
        let rid = format!("outbox-test-{}-b", std::process::id());
        let env = json!({"v": 2, "producer": "crm", "object": "card", "owner": "1", "visibility": "owner", "audience": ["1"], "title": "x"});
        seed(&url, &rid, &[ev(0, env)]);
        let s = fact_keys::load_signer(PEM.as_bytes()).unwrap();
        let unsealable = deliver(&pool, "http://127.0.0.1:1", "pk", LIMIT, Some(&rid), Some(&s), false).unwrap();
        clean(&url, &rid);
        assert_eq!(unsealable, json!({"delivered": 0, "pending": true, "reason": "Envelope could not be sealed"}));
        seed(&url, &rid, &[ev(0, Value::Null)]);
        let down = deliver(&pool, "http://127.0.0.1:1", "pk", 1, Some(&rid), Some(&s), false).unwrap();
        clean(&url, &rid);
        assert_eq!(down, json!({"delivered": 0, "pending": true, "reason": "Flows unavailable"}));
        seed(&url, &rid, &[ev(0, Value::Null)]);
        let (flows_url, h) = flows(vec![202]);
        let full = deliver(&pool, &flows_url, "pk", 1, Some(&rid), Some(&s), false).unwrap();
        h.join().unwrap();
        clean(&url, &rid);
        assert_eq!(full, json!({"delivered": 1, "pending": true}));
    }

    #[test]
    fn migrate_check_and_personal_org() {
        assert_eq!(crate::migrate::check(&Pool::new("postgresql://u:p@127.0.0.1:1/vexa", 1).unwrap()).unwrap_err(),
                   "the CRM's schema is not there yet (InterfaceError)");
        let Some((pool, url)) = db() else { return };
        assert_eq!(crate::migrate::check(&pool).unwrap_err(),
                   "crm-api refuses a superuser login; give it its own role (CRM_DB_USER, created by `python -m crm.migrate init`)");
        if let Ok(crm) = std::env::var("VEXA_TEST_CRM_PG_URL") {
            assert_eq!(crate::migrate::check(&Pool::new(&crm, 1).unwrap()), Ok(()));
            let other = format!("{}/postgres", crm.rsplit_once('/').unwrap().0);
            assert_eq!(crate::migrate::check(&Pool::new(&other, 1).unwrap()).unwrap_err(), "the CRM's schema is not there yet (ProgrammingError)");
        }
        let store = crate::store::Store::new(Pool::new(&url, 1).unwrap());
        let e = crate::bootstrap::ensure_personal_org(&store, "one", "x").unwrap_err();
        assert_eq!((e.class, e.message()), ("ValueError", "only an individual's own CRM (p-<id>) is made at runtime".to_string()));
        let org = format!("p-9{}{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
        let made = crate::bootstrap::ensure_personal_org_created(&store, &format!(" {org} "), "").unwrap();
        assert_eq!(made.first().map(String::as_str), Some("org"));
        assert_eq!(crate::bootstrap::ensure_personal_org_created(&store, &org, "x").unwrap(), Vec::<String>::new());
        let mut c = pool.begin().unwrap();
        assert_eq!(c.first("SELECT name FROM crm_orgs WHERE org_id = $1", &[&org]).unwrap(), Some(json!(org)));
    }
}
