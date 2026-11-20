//! The websockets of the edge: the /ws multiplex (ws.v1: a Redis fan-in per subscription, the
//! signals stream, live re-authorization) and the two relays to meeting-api (a voice note's audio,
//! a sign-in session's live view).

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use vexa_native_kit::httpd::{decode_path, Exchange};
use vexa_native_kit::pyjson::{py_dumps, py_str, truthy, Dumps};

use crate::edge::{is_delegated, query_params, scopes_of, Edge};
use crate::obs::{self, ev, TRACE_HEADER};
use crate::redis::{self, Reply};
use crate::routes::{ws_match, WsRoute};
use crate::ws::{self, Msg, Writer};

const CHANGED_IN: &str = "0.13.4";
const DOCS: &str = "https://docs.vexa.ai/changes-0-13-4-auth";
const WS_KEY_HOW: &str = "send the key in the x-api-key header, or (a browser) in the subprotocol list: new WebSocket(url, ['vexa.v1', 'vexa.key.' + key])";
const SCOPE_HOW: &str = "use a key that holds the bot or tx scope (every key the quickstart mints holds one); GET /auth/me lists your key's scopes";
const REAUTH_INTERVAL: Duration = Duration::from_secs(15);
const REAUTH_MAX_FAILURES: u32 = 2;
const SIGNALS_BACKLOG: usize = 500;
const VOICE_MAX_FRAME: usize = 128 * 1024;
static QUERY_KEY_USES: Mutex<u64> = Mutex::new(0);

fn refusal(error: &str, do_instead: &str) -> serde_json::Map<String, Value> {
    let v = json!({"type": "error", "error": error, "changed_in": CHANGED_IN, "do_instead": do_instead, "docs": DOCS});
    v.as_object().cloned().unwrap_or_default()
}

fn frame(v: &Value) -> String {
    py_dumps(v)
}

struct Credential {
    key: Option<String>,
    subprotocol: Option<String>,
    source: &'static str,
}

fn credential(headers: &[(String, String)], query: &str) -> Credential {
    let protocols = ws::offered(headers);
    let answer = protocols.iter().any(|p| p == "vexa.v1").then(|| "vexa.v1".to_owned());
    if let Some(k) = headers.iter().find(|(k, _)| k == "x-api-key").map(|(_, v)| v.clone()).filter(|v| !v.is_empty()) {
        return Credential { key: Some(k), subprotocol: answer, source: "header" };
    }
    for p in &protocols {
        if let Some(k) = p.strip_prefix("vexa.key.").filter(|k| !k.is_empty()) {
            return Credential { key: Some(k.to_owned()), subprotocol: answer, source: "subprotocol" };
        }
    }
    let q = query_params(query);
    if let Some((_, v)) = q.iter().find(|(k, _)| k == "api_key").filter(|(_, v)| !v.is_empty()) {
        return Credential { key: Some(v.clone()), subprotocol: answer, source: "query" };
    }
    Credential { key: None, subprotocol: answer, source: "" }
}

/// An error frame, then the close.
fn send_close(w: &Writer, body: &Value, code: u16) {
    let _ = w.text(&frame(body));
    let _ = w.close(code);
}

/// A refusal on an accepted socket nothing else reads: the error frame, the close, the peer's answer.
fn refuse(r: &mut ws::Reader, body: &Value, code: u16) {
    let w = r.w.clone();
    send_close(&w, body, code);
    ws::linger(r);
}

pub fn serve_upgrade(edge: &Edge, ex: &mut Exchange) {
    let head = ex.head.clone();
    let path = decode_path(&head.raw_path);
    let key = head.header("sec-websocket-key").unwrap_or("").to_owned();
    let Ok((sock, leftover)) = ex.take() else { return };
    let Some(route) = ws_match(&path) else {
        ws::refuse(sock);
        return;
    };
    if key.is_empty() || head.header("sec-websocket-version") != Some("13") {
        let mut s = sock;
        let _ = std::io::Write::write_all(&mut s, b"HTTP/1.1 400 Bad Request\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        return;
    }
    let prev = obs::begin(None);
    let peer = ex.peer.ip().to_string();
    match route {
        WsRoute::Multiplex => multiplex(edge, sock, leftover, &key, &head.headers, &head.query, &peer),
        WsRoute::Voice(id) => voice(edge, sock, leftover, &key, &head.headers, &id),
        WsRoute::Vnc(id) => vnc(edge, sock, leftover, &key, &head.headers, &head.query, &id),
    }
    obs::restore(prev);
}

/// A thread that stops when its flag is set.
struct Task {
    stop: Arc<AtomicBool>,
}

impl Task {
    fn cancel(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn fan_in(target: &redis::Target, channels: Vec<String>, w: Arc<Writer>) -> Task {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let target = target.clone();
    std::thread::spawn(move || {
        let Ok(mut conn) = redis::Conn::open(&target, Some(Duration::from_millis(500))) else { return };
        let mut args: Vec<&[u8]> = vec![b"SUBSCRIBE"];
        args.extend(channels.iter().map(|c| c.as_bytes()));
        if conn.send(&args).is_err() {
            return;
        }
        while !flag.load(Ordering::SeqCst) {
            match conn.read() {
                Ok(Reply::Array(items)) => {
                    if items.first().and_then(Reply::text).as_deref() == Some("message") {
                        if let Some(data) = items.get(2).and_then(Reply::text) {
                            if flag.load(Ordering::SeqCst) || w.text(&data).is_err() {
                                break;
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
        let _ = conn.cmd(&[b"UNSUBSCRIBE"]);
    });
    Task { stop }
}

fn num(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok().filter(|f| !s.trim().is_empty() && f.is_finite() || s.trim().eq_ignore_ascii_case("inf")),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn int_of(v: Option<&Value>) -> Option<Value> {
    match v? {
        Value::Number(n) if n.is_i64() || n.is_u64() => Some(Value::Number(n.clone())),
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite()).map(|f| json!(f.trunc() as i64)),
        Value::Bool(b) => Some(json!(*b as i64)),
        Value::String(s) => {
            let t = s.trim().replace('_', "");
            t.parse::<i64>().ok().map(|i| json!(i))
        }
        _ => None,
    }
}

fn scores(v: Option<&Value>) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(Value::Object(m)) = v {
        for (k, x) in m {
            if let (false, Some(n)) = (k.is_empty(), num(Some(x))) {
                let key: String = k.chars().take(64).collect();
                out.insert(key, json!(n.clamp(0.0, 1.0)));
            }
        }
    }
    Value::Object(out)
}

/// One signals stream entry as the annotation a frame carries, or None.
pub fn signal_annotation(id: &str, fields: &[(String, String)]) -> Option<Value> {
    let mut raw: serde_json::Map<String, Value> = fields.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
    for name in ["payload", "data"] {
        if let Some(Value::String(s)) = raw.get(name).cloned() {
            let body: Value = serde_json::from_str(&s).ok()?;
            raw = body.as_object().cloned().unwrap_or_default();
            break;
        }
    }
    for name in ["scores", "words"] {
        if let Some(Value::String(s)) = raw.get(name).cloned() {
            raw.insert(name.into(), serde_json::from_str(&s).unwrap_or_else(|_| json!({})));
        }
    }
    let segment = match raw.get("segment_id") {
        Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.to_string(),
        Some(Value::Bool(b)) => (if *b { "True" } else { "False" }).to_owned(),
        _ => return None,
    };
    let mut out = serde_json::Map::new();
    out.insert("id".into(), id.into());
    out.insert("segment_id".into(), segment.into());
    out.insert("scores".into(), scores(raw.get("scores")));
    out.insert("words".into(), scores(raw.get("words")));
    if let Some(Value::String(m)) = raw.get("model") {
        out.insert("model".into(), m.chars().take(128).collect::<String>().into());
    }
    if let Some(v) = int_of(raw.get("brief_version")) {
        out.insert("brief_version".into(), v);
    }
    if let Some(at) = num(raw.get("at")) {
        out.insert("at".into(), json!(at));
    }
    Some(Value::Object(out))
}

fn signals_in(target: &redis::Target, row: String, platform: Value, native: Value, w: Arc<Writer>, user_id: Value) -> Task {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let target = target.clone();
    std::thread::spawn(move || {
        let key = format!("sig:meeting:{row}");
        let meeting = json!({"id": row, "platform": platform, "native_id": native});
        let send = |entries: &[redis::Entry]| -> bool {
            let batch: Vec<Value> = entries.iter().filter_map(|(i, f)| signal_annotation(i, f)).collect();
            if batch.is_empty() {
                return true;
            }
            w.text(&frame(&json!({"type": "meeting.signals", "meeting": meeting, "annotations": batch}))).is_ok()
        };
        let run = || -> std::io::Result<()> {
            let mut conn = redis::Conn::open(&target, Some(Duration::from_secs(10)))?;
            let mut last = "0-0".to_owned();
            let back = redis::ok(conn.cmd(&[b"XREVRANGE", key.as_bytes(), b"+", b"-", b"COUNT", SIGNALS_BACKLOG.to_string().as_bytes()])?)?;
            let mut backlog = redis::entries(&back);
            backlog.reverse();
            if let Some((id, _)) = backlog.last() {
                last = id.clone();
                if !send(&backlog) {
                    return Ok(());
                }
            }
            while !flag.load(Ordering::SeqCst) {
                let r = redis::ok(conn.cmd(&[b"XREAD", b"COUNT", b"200", b"BLOCK", b"5000", b"STREAMS", key.as_bytes(), last.as_bytes()])?)?;
                for stream in r.items() {
                    let entries = redis::entries(stream.items().get(1).unwrap_or(&Reply::Nil));
                    if let Some((id, _)) = entries.last() {
                        last = id.clone();
                        if flag.load(Ordering::SeqCst) || !send(&entries) {
                            return Ok(());
                        }
                    }
                }
            }
            Ok(())
        };
        if let Err(e) = run() {
            if !flag.load(Ordering::SeqCst) {
                ev("ws_signals_read_failed", "system", "warning", Some("ws")).user(user_id).fields(json!({"detail": e.to_string()})).emit();
            }
        }
    });
    Task { stop }
}

type SubKey = (Value, Value, Value);

struct Subs {
    fan: HashMap<String, Task>,
    sig: HashMap<String, Task>,
    keys: Vec<SubKey>,
    row: HashMap<String, String>,
}

fn kid(k: &SubKey) -> String {
    serde_json::to_string(&json!([k.0, k.1, k.2])).unwrap_or_default()
}

impl Subs {
    fn unsubscribe(&mut self, k: &SubKey) {
        let id = kid(k);
        for tasks in [&mut self.fan, &mut self.sig] {
            if let Some(t) = tasks.remove(&id) {
                t.cancel();
            }
        }
        self.keys.retain(|x| kid(x) != id);
        self.row.remove(&id);
    }
}

fn member_channels(user: &Value) -> Vec<String> {
    match user.get("workspaces") {
        Some(Value::Array(a)) => a.iter().map(|w| py_str(w).trim().to_owned()).filter(|w| !w.is_empty()).map(|w| format!("w:{w}:meetings")).collect(),
        _ => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn multiplex(edge: &Edge, sock: std::net::TcpStream, leftover: Vec<u8>, wskey: &str, headers: &[(String, String)], query: &str, peer: &str) {
    let ip = edge.guard.client_ip(peer, headers.iter().find(|(k, _)| k == "x-forwarded-for").map(|(_, v)| v.as_str()));
    if !edge.guard.ws_admits(&ip) {
        ws::refuse(sock);
        return;
    }
    let cred = credential(headers, query);
    let Ok((mut reader, w)) = ws::accept(sock, leftover, wskey, cred.subprotocol.as_deref()) else { return };
    if cred.source == "query" {
        let count = {
            let mut c = QUERY_KEY_USES.lock().unwrap_or_else(|p| p.into_inner());
            *c += 1;
            *c
        };
        ev("ws_query_key_deprecated", "system", "warning", Some("ws"))
            .fields(json!({"path": "/ws", "count": count, "removed_in": "0.13.6", "use": "x-api-key header or the vexa.key.<key> subprotocol"}))
            .emit();
    }
    let Some(api_key) = cred.key else {
        return refuse(&mut reader, &json!({"type": "error", "error": "missing_api_key"}), 4401);
    };
    let user = match edge.resolve(&api_key) {
        Err(e) => {
            ev("auth_infra_unavailable", "system", "error", Some("ws")).fields(json!({"reason": "AuthUnavailable", "detail": e})).emit();
            return refuse(&mut reader, &json!({"type": "error", "error": "auth_unavailable"}), 4503);
        }
        Ok(None) => return refuse(&mut reader, &json!({"type": "error", "error": "invalid_api_key"}), 4401),
        Ok(Some(u)) if is_delegated(&api_key, &u) => return refuse(&mut reader, &json!({"type": "error", "error": "invalid_api_key"}), 4401),
        Ok(Some(u)) => u,
    };
    let mut user_id = user.get("user_id").cloned().unwrap_or(Value::Null);
    obs::set_user(&user);
    let table = &edge.asm.scopes;
    let held = scopes_of(&user);
    let mut status_scopes = BTreeSet::new();
    for r in [("GET", "/meetings"), ("GET", "/bots/status")] {
        if let Some(s) = table.get(&(r.0.to_owned(), r.1.to_owned())) {
            status_scopes.extend(s.iter().cloned());
        }
    }
    let transcript_scopes = table.get(&("GET".to_owned(), "/transcripts/{platform}/{native_meeting_id}".to_owned())).cloned().unwrap_or_default();
    if held.is_disjoint(&status_scopes) {
        ev("request_denied_scope", "user", "warning", Some("ws")).user(user_id.clone())
            .fields(json!({"path": "/ws", "required": status_scopes.iter().collect::<Vec<_>>()})).emit();
        let mut body = refusal("insufficient_scope", SCOPE_HOW);
        body.insert("details".into(), "this key reads no meeting status".into());
        return refuse(&mut reader, &Value::Object(body), 4403);
    }
    let uid = py_str(&user_id);
    let base = vec![format!("u:{uid}:meetings"), format!("u:{uid}:notifications")];
    let members = member_channels(&user);
    let user_task = fan_in(&edge.redis, [base.clone(), members.clone()].concat(), w.clone());
    let subs = Arc::new(Mutex::new(Subs { fan: HashMap::new(), sig: HashMap::new(), keys: Vec::new(), row: HashMap::new() }));
    let state = Arc::new(Mutex::new((members, user_task)));
    let done = Arc::new(AtomicBool::new(false));
    let uid_cell = Arc::new(Mutex::new(user_id.clone()));

    // Live re-authorization, every REAUTH_INTERVAL.
    std::thread::scope(|scope| {
        let (subs2, state2, done2, w2, key2, uid2) = (subs.clone(), state.clone(), done.clone(), w.clone(), api_key.clone(), uid_cell.clone());
        let user0 = user.clone();
        scope.spawn(move || {
            let prev = obs::begin(None);
            let mut failures = 0u32;
            'outer: loop {
                let deadline = std::time::Instant::now() + REAUTH_INTERVAL;
                while std::time::Instant::now() < deadline {
                    if done2.load(Ordering::SeqCst) {
                        break 'outer;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                let uidv = uid2.lock().map(|u| u.clone()).unwrap_or(Value::Null);
                let fresh = edge.resolve(&key2).unwrap_or_else(|_| Some(user0.clone()));
                let fresh = match fresh {
                    Some(f) if !is_delegated(&key2, &f) => f,
                    _ => {
                        send_close(&w2, &json!({"type": "error", "error": "invalid_api_key"}), 4401);
                        break;
                    }
                };
                let channels = member_channels(&fresh);
                {
                    let mut st = state2.lock().unwrap_or_else(|p| p.into_inner());
                    if channels != st.0 {
                        st.1.cancel();
                        let uid = py_str(&user0["user_id"]);
                        st.1 = fan_in(&edge.redis, [vec![format!("u:{uid}:meetings"), format!("u:{uid}:notifications")], channels.clone()].concat(), w2.clone());
                        st.0 = channels;
                    }
                }
                let keys = subs2.lock().map(|s| s.keys.clone()).unwrap_or_default();
                if keys.is_empty() {
                    continue;
                }
                let refs: Vec<Value> = keys.iter().map(|k| json!({"platform": k.0, "native_meeting_id": k.1})).collect();
                let result = edge.authorize_subscribe(&key2, &Value::Array(refs));
                let errors: Vec<String> = result.get("errors").and_then(Value::as_array).map(|a| a.iter().map(py_str).collect()).unwrap_or_default();
                let hop_failed = errors.iter().any(|e| e.starts_with("authorization_call_failed") || e.starts_with("authorization_service_error") || e.starts_with("authorization_unavailable"));
                if hop_failed {
                    failures += 1;
                    ev("ws_reauthorize_failed", "system", "warning", Some("ws")).user(uidv.clone()).fields(json!({"failures": failures})).emit();
                    if failures < REAUTH_MAX_FAILURES {
                        continue;
                    }
                    let mut s = subs2.lock().unwrap_or_else(|p| p.into_inner());
                    for k in &keys {
                        s.unsubscribe(k);
                    }
                    drop(s);
                    let _ = w2.text(&frame(&json!({"type": "error", "error": "authorization_call_failed",
                        "details": "access to the subscribed meetings could not be re-confirmed; subscribe again"})));
                    failures = 0;
                    continue;
                }
                failures = 0;
                let still: BTreeSet<String> = result.get("authorized").and_then(Value::as_array).map(|a| {
                    a.iter().filter_map(|x| x.get("meeting_id").filter(|m| !m.is_null()).map(py_str)).collect()
                }).unwrap_or_default();
                for k in &keys {
                    let mut s = subs2.lock().unwrap_or_else(|p| p.into_inner());
                    if s.row.get(&kid(k)).is_some_and(|r| still.contains(r)) {
                        continue;
                    }
                    s.unsubscribe(k);
                    drop(s);
                    ev("ws_subscription_revoked", "user", "info", Some("ws")).user(uidv.clone())
                        .fields(json!({"platform": k.0, "native_id": k.1})).emit();
                    let _ = w2.text(&frame(&json!({"type": "error", "error": "subscription_revoked", "details": {"platform": k.0, "native_id": k.1}})));
                }
            }
            obs::restore(prev);
        });

        let send = |v: Value| {
            let _ = w.text(&frame(&v));
        };
        loop {
            let raw = match reader.next() {
                Ok(Msg::Text(t)) => t,
                Ok(Msg::Binary(_)) => {
                    let _ = w.close(1011);
                    break;
                }
                Ok(Msg::Close(_)) | Err(_) => break,
            };
            let msg: Value = match serde_json::from_str(&raw) {
                Ok(Value::Object(m)) => Value::Object(m),
                _ => {
                    send(json!({"type": "error", "error": "invalid_json"}));
                    continue;
                }
            };
            match msg.get("action").and_then(Value::as_str) {
                Some("subscribe") => {
                    let meetings = match msg.get("meetings") {
                        Some(Value::Array(a)) => a.clone(),
                        _ => {
                            send(json!({"type": "error", "error": "invalid_subscribe_payload", "details": "'meetings' must be a non-empty list"}));
                            continue;
                        }
                    };
                    if meetings.is_empty() {
                        send(json!({"type": "error", "error": "invalid_subscribe_payload", "details": "'meetings' list cannot be empty"}));
                        continue;
                    }
                    let payload: Vec<Value> = meetings.iter().filter_map(|m| {
                        let o = m.as_object()?;
                        let plat = py_str(o.get("platform").unwrap_or(&Value::String(String::new()))).trim().to_owned();
                        let nid = py_str(o.get("native_id").unwrap_or(&Value::String(String::new()))).trim().to_owned();
                        (!plat.is_empty() && !nid.is_empty()).then(|| json!({"platform": plat, "native_meeting_id": nid}))
                    }).collect();
                    if payload.is_empty() {
                        send(json!({"type": "error", "error": "invalid_subscribe_payload", "details": "no valid meeting objects"}));
                        continue;
                    }
                    let streams: Vec<String> = match msg.get("streams") {
                        None | Some(Value::Null) => vec!["transcript".into()],
                        Some(Value::Array(a)) if !a.is_empty() && a.iter().all(|s| matches!(s.as_str(), Some("transcript" | "signals"))) => {
                            a.iter().filter_map(|s| s.as_str().map(str::to_owned)).collect()
                        }
                        _ => {
                            send(json!({"type": "error", "error": "invalid_subscribe_payload", "details": "'streams' must be a non-empty list of ['transcript', 'signals']"}));
                            continue;
                        }
                    };
                    if held.is_disjoint(&transcript_scopes) {
                        ev("request_denied_scope", "user", "warning", Some("ws")).user(user_id.clone())
                            .fields(json!({"path": "/ws subscribe", "required": transcript_scopes.iter().collect::<Vec<_>>()})).emit();
                        let mut body = refusal("insufficient_scope", SCOPE_HOW);
                        body.insert("details".into(), "subscribing streams a meeting's transcript; this key may not read transcripts".into());
                        send(Value::Object(body));
                        continue;
                    }
                    let result = edge.authorize_subscribe(&api_key, &Value::Array(payload));
                    let authorized = result.get("authorized").filter(|a| truthy(Some(a))).and_then(Value::as_array).cloned().unwrap_or_default();
                    let errors = result.get("errors").filter(|a| truthy(Some(a))).and_then(Value::as_array).cloned().unwrap_or_default();
                    if authorized.is_empty() && !errors.is_empty() {
                        let first = py_str(&errors[0]);
                        let code = if first.starts_with("authorization_call_failed") { "authorization_call_failed" } else { "authorization_service_error" };
                        send(json!({"type": "error", "error": code, "details": first}));
                        continue;
                    }
                    let mut subscribed = Vec::new();
                    for item in &authorized {
                        let g = |k: &str| item.get(k).cloned().unwrap_or(Value::Null);
                        let (plat, nid, uidv, mid) = (g("platform"), g("native_id"), g("user_id"), g("meeting_id"));
                        if !(truthy(Some(&plat)) && truthy(Some(&nid)) && truthy(Some(&uidv)) && truthy(Some(&mid))) {
                            continue;
                        }
                        user_id = uidv.clone();
                        if let Ok(mut c) = uid_cell.lock() {
                            *c = uidv.clone();
                        }
                        let key: SubKey = (plat.clone(), nid.clone(), uidv);
                        let id = kid(&key);
                        let row = py_str(&mid);
                        let mut s = subs.lock().unwrap_or_else(|p| p.into_inner());
                        if !s.keys.iter().any(|k| kid(k) == id) {
                            s.keys.push(key.clone());
                        }
                        s.row.insert(id.clone(), row.clone());
                        if streams.iter().any(|x| x == "transcript") && !s.fan.contains_key(&id) {
                            let ch = vec![format!("tc:meeting:{row}:mutable"), format!("bm:meeting:{row}:status"), format!("va:meeting:{row}:chat")];
                            s.fan.insert(id.clone(), fan_in(&edge.redis, ch, w.clone()));
                        }
                        if streams.iter().any(|x| x == "signals") && !s.sig.contains_key(&id) {
                            s.sig.insert(id.clone(), signals_in(&edge.redis, row, plat.clone(), nid.clone(), w.clone(), user_id.clone()));
                        }
                        subscribed.push(json!({"platform": plat, "native_id": nid}));
                    }
                    send(json!({"type": "subscribed", "meetings": subscribed}));
                }
                Some("unsubscribe") => {
                    let meetings = match msg.get("meetings") {
                        Some(Value::Array(a)) => a.clone(),
                        _ => {
                            send(json!({"type": "error", "error": "invalid_unsubscribe_payload", "details": "'meetings' must be a list"}));
                            continue;
                        }
                    };
                    let mut done_list = Vec::new();
                    let mut errors = Vec::new();
                    for (idx, m) in meetings.iter().enumerate() {
                        let Some(o) = m.as_object() else {
                            errors.push(format!("meetings[{idx}] must be an object"));
                            continue;
                        };
                        let plat = py_str(o.get("platform").unwrap_or(&Value::String(String::new()))).trim().to_owned();
                        let nid = py_str(o.get("native_id").unwrap_or(&Value::String(String::new()))).trim().to_owned();
                        if plat.is_empty() || nid.is_empty() {
                            errors.push(format!("meetings[{idx}] missing 'platform' or 'native_id'"));
                            continue;
                        }
                        let mut s = subs.lock().unwrap_or_else(|p| p.into_inner());
                        let found = s.keys.iter().find(|k| k.0 == Value::String(plat.clone()) && k.1 == Value::String(nid.clone())).cloned();
                        match found {
                            Some(k) => {
                                s.unsubscribe(&k);
                                done_list.push(json!({"platform": plat, "native_id": nid}));
                            }
                            None => errors.push(format!("meetings[{idx}] not currently subscribed")),
                        }
                    }
                    if !errors.is_empty() && done_list.is_empty() {
                        send(json!({"type": "error", "error": "invalid_unsubscribe_payload", "details": errors}));
                        continue;
                    }
                    send(json!({"type": "unsubscribed", "meetings": done_list}));
                }
                Some("ping") => send(json!({"type": "pong"})),
                _ => send(json!({"type": "error", "error": "unknown_action"})),
            }
        }
        done.store(true, Ordering::SeqCst);
    });
    state.lock().unwrap_or_else(|p| p.into_inner()).1.cancel();
    let s = subs.lock().unwrap_or_else(|p| p.into_inner());
    for t in s.fan.values().chain(s.sig.values()) {
        t.cancel();
    }
    w.shutdown();
}

fn close_code(code: Option<u16>) -> u16 {
    match code {
        Some(c) if c == 1000 || (3000..=4999).contains(&c) => c,
        _ => 1000,
    }
}

#[derive(Clone, Copy)]
enum End {
    Client(Option<u16>),
    Upstream(Option<u16>),
    TooLarge,
}

/// Relay frames both ways until one side ends, closing the other: an upstream close is passed to
/// the client (an application code, else 1000); a client close reaches the upstream with its own
/// code when `pass_client_code`, else 1000. `max` bounds a client frame (characters of a text
/// frame, bytes of a binary one): a longer one ends the relay with `frame_too_large`, 4400.
fn pump(client: &mut ws::Reader, cw: &Arc<Writer>, upstream: &mut ws::Reader, uw: &Arc<Writer>, max: Option<usize>, pass_client_code: bool) -> End {
    let first: Mutex<Option<End>> = Mutex::new(None);
    let settle = |e: End| *first.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert(e);
    std::thread::scope(|s| {
        s.spawn(|| {
            let r = loop {
                let sent = match upstream.next() {
                    Ok(Msg::Text(t)) => cw.text(&t),
                    Ok(Msg::Binary(b)) => cw.binary(&b),
                    Ok(Msg::Close(c)) => break End::Upstream(c),
                    Err(_) => break End::Upstream(None),
                };
                if sent.is_err() {
                    break End::Client(None);
                }
            };
            match settle(r) {
                End::Upstream(c) => {
                    let _ = cw.close(close_code(c));
                }
                _ => {
                    let _ = uw.close(1000);
                }
            }
        });
        let r = loop {
            let m = match client.next() {
                Ok(Msg::Close(c)) => break End::Client(c),
                Err(_) => break End::Client(None),
                Ok(m) => m,
            };
            let size = match &m {
                Msg::Text(t) => t.chars().count(),
                Msg::Binary(b) => b.len(),
                Msg::Close(_) => 0,
            };
            if max.is_some_and(|x| size > x) {
                break End::TooLarge;
            }
            if uw.send(&m).is_err() {
                break End::Upstream(None);
            }
        };
        match settle(r) {
            End::Client(c) => {
                let _ = uw.close(if pass_client_code { close_code(c) } else { 1000 });
            }
            End::TooLarge => {
                let _ = uw.close(1000);
                let _ = cw.text(&frame(&json!({"type": "error", "error": "frame_too_large"})));
                let _ = cw.close(4400);
            }
            End::Upstream(c) => {
                let _ = cw.close(close_code(c));
            }
        }
    });
    let end = first.lock().unwrap_or_else(|p| p.into_inner()).unwrap_or(End::Client(None));
    cw.shutdown();
    uw.shutdown();
    end
}

fn voice(edge: &Edge, sock: std::net::TcpStream, leftover: Vec<u8>, wskey: &str, headers: &[(String, String)], native_id: &str) {
    const PATH: &str = "/voice-notes/{native_meeting_id}/stream";
    let Ok((mut reader, w)) = ws::accept(sock, leftover, wskey, None) else { return };
    let get = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    let key = get("x-api-key").filter(|k| !k.is_empty()).map(str::to_owned).or_else(|| {
        let auth = get("authorization").unwrap_or("").trim();
        let (scheme, token) = auth.split_once(' ').unwrap_or((auth, ""));
        (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim().to_owned())
    });
    let err = |e: &str| json!({"type": "error", "error": e});
    let Some(key) = key else { return refuse(&mut reader, &err("missing_api_key"), 4401) };
    let user = match edge.resolve(&key) {
        Err(_) => {
            ev("auth_infra_unavailable", "system", "error", Some("voice-note")).fields(json!({"reason": "AuthUnavailable"})).emit();
            return refuse(&mut reader, &err("auth_unavailable"), 4503);
        }
        Ok(Some(u)) if !is_delegated(&key, &u) => u,
        _ => return refuse(&mut reader, &err("invalid_api_key"), 4401),
    };
    let uid = user.get("user_id").cloned().unwrap_or(Value::Null);
    obs::set_user(&user);
    if let Some(l) = &edge.limiter {
        if !l.allow(&py_str(&uid)) {
            ev("request_rate_limited", "user", "warning", Some("voice-note")).user(uid.clone()).fields(json!({"path": PATH})).emit();
            return refuse(&mut reader, &err("rate_limited"), 4429);
        }
    }
    let required = edge.asm.scopes.get(&("GET".to_owned(), PATH.to_owned())).cloned().unwrap_or_default();
    if scopes_of(&user).is_disjoint(&required) {
        ev("request_denied_scope", "user", "warning", Some("voice-note")).user(uid.clone())
            .fields(json!({"path": PATH, "required": required.iter().collect::<Vec<_>>()})).emit();
        return refuse(&mut reader, &err("insufficient_scope"), 4403);
    }
    let base = edge.meeting_url.trim_end_matches('/').replacen("http://", "ws://", 1).replacen("https://", "wss://", 1);
    let url = format!("{base}{}", PATH.replace("{native_meeting_id}", native_id));
    let mut up_headers = identity::identity_headers(edge.key.as_ref(), &user);
    up_headers.push((TRACE_HEADER.into(), obs::trace_or_empty()));
    ev("request_accepted", "user", "info", Some("voice-note")).user(uid.clone()).fields(json!({"path": PATH})).emit();
    let up = match ws::dial(&url, &up_headers, &[], Duration::from_secs(10), Some(256 * 1024)) {
        Ok(u) => u,
        Err(ws::DialError::Failed(e)) => {
            let name = if e.contains("refused") { "ConnectionRefusedError" } else { "OSError" };
            ev("voice_note_upstream_unreachable", "system", "error", Some("voice-note")).user(uid).fields(json!({"error": name})).emit();
            return refuse(&mut reader, &err("upstream_unavailable"), 4502);
        }
        Err(ws::DialError::Status(_)) => {
            let _ = w.close(1011);
            return;
        }
    };
    let (mut up_reader, up_writer) = (up.reader, up.writer);
    pump(&mut reader, &w, &mut up_reader, &up_writer, Some(VOICE_MAX_FRAME), true);
}

fn vnc(edge: &Edge, sock: std::net::TcpStream, leftover: Vec<u8>, wskey: &str, headers: &[(String, String)], query: &str, session_id: &str) {
    const PATH: &str = "/bot-accounts/sessions/{session_id}/vnc";
    let cred = credential(headers, query);
    let compact = |v: &Value| Dumps::COMPACT.ascii(false).text(v);
    let refuse_vnc = |sock: std::net::TcpStream, leftover: Vec<u8>, code: u16, body: Value| {
        if let Ok((mut r, w)) = ws::accept(sock, leftover, wskey, cred.subprotocol.as_deref()) {
            let _ = w.text(&compact(&body));
            let _ = w.close(code);
            ws::linger(&mut r);
        }
    };
    let err = |e: &str| json!({"type": "error", "error": e});
    if query_params(query).iter().any(|(k, _)| k == "api_key") || cred.source == "query" {
        ev("ws_query_key_refused", "system", "warning", Some("ws")).fields(json!({"path": PATH})).emit();
        return refuse_vnc(sock, leftover, 4401, Value::Object(refusal("api_key_query_removed", WS_KEY_HOW)));
    }
    let Some(key) = cred.key.clone() else { return refuse_vnc(sock, leftover, 4401, err("missing_api_key")) };
    let user = match edge.resolve(&key) {
        Err(e) => {
            ev("auth_infra_unavailable", "system", "error", Some("ws")).fields(json!({"reason": "AuthUnavailable", "detail": e})).emit();
            return refuse_vnc(sock, leftover, 4503, err("auth_unavailable"));
        }
        Ok(Some(u)) if !is_delegated(&key, &u) => u,
        _ => return refuse_vnc(sock, leftover, 4401, err("invalid_api_key")),
    };
    let uid = user.get("user_id").cloned().unwrap_or(Value::Null);
    obs::set_user(&user);
    let required = edge.asm.scopes.get(&("GET".to_owned(), "/bot-accounts/sessions/{session_id}".to_owned())).cloned().unwrap_or_default();
    if required.is_empty() || scopes_of(&user).is_disjoint(&required) {
        ev("request_denied_scope", "user", "warning", Some("ws")).user(uid.clone())
            .fields(json!({"path": PATH, "required": required.iter().collect::<Vec<_>>()})).emit();
        return refuse_vnc(sock, leftover, 4403, err("insufficient_scope"));
    }
    if !(session_id.len() == 32 && session_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
        return refuse_vnc(sock, leftover, 4404, err("not_found"));
    }
    let mut up_headers = vec![("x-api-key".to_owned(), key.clone())];
    up_headers.extend(identity::identity_headers(edge.key.as_ref(), &user));
    up_headers.push((TRACE_HEADER.into(), obs::trace_or_empty()));
    let base = edge.meeting_url.trim_end_matches('/');
    let base = if let Some(r) = base.strip_prefix("https://") { format!("wss://{r}") } else if let Some(r) = base.strip_prefix("http://") { format!("ws://{r}") } else { base.to_owned() };
    let url = format!("{base}{}", PATH.replace("{session_id}", session_id));
    let requested: Vec<String> = ws::offered(headers).into_iter().filter(|p| p != "vexa.v1" && !p.starts_with("vexa.key.")).collect();
    match ws::dial(&url, &up_headers, &requested, Duration::from_secs(10), None) {
        Ok(up) => {
            let proto = up.subprotocol.clone().or(cred.subprotocol.clone());
            let Ok((mut reader, w)) = ws::accept(sock, leftover, wskey, proto.as_deref()) else { return };
            ev("vnc_relay_opened", "system", "debug", Some("ws")).user(uid).fields(json!({"path": PATH})).emit();
            let (mut up_reader, up_writer) = (up.reader, up.writer);
            pump(&mut reader, &w, &mut up_reader, &up_writer, None, false);
        }
        Err(ws::DialError::Status(status)) => {
            ev("vnc_relay_refused", "system", "info", Some("ws")).user(uid).fields(json!({"path": PATH, "downstream_status": status})).emit();
            let code = match status {
                401 => 4401,
                403 => 4403,
                404 => 4404,
                _ => 1011,
            };
            refuse_vnc(sock, leftover, code, err("refused"));
        }
        Err(ws::DialError::Failed(e)) => {
            let reason = if e.contains("refused") { "ConnectionRefusedError" } else { "OSError" };
            ev("vnc_relay_unreachable", "system", "error", Some("ws")).user(uid).fields(json!({"path": PATH, "reason": reason})).emit();
            refuse_vnc(sock, leftover, 1011, err("upstream_unreachable"));
        }
    }
}

use crate::identity;
