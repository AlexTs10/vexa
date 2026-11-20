//! The service door: the flows tier's one way into the other domains, on a listener of its own.
//!
//! * Outbound `/{domain}/{path}`: a call on the flows allow-list (`OUTBOUND`), presented with
//!   `VEXA_FLOWS_SERVICE_KEY`, is forwarded over the internal tier; the meetings domain gets the
//!   subject's identity signed by this edge with the door's scopes. A call that acts for a person
//!   (`BOUND`) must carry a subject ticket that opens it (subject-ticket.v1).
//! * Inbound `/to-flows/{path}`: the internal tier's calls into flows-api, presented with
//!   `X-Internal-Secret` here and forwarded with the flows key.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use regex::Regex;
use serde_json::{json, Map, Value};
use vexa_native_kit::client::{self, Body, Timeouts};
use vexa_native_kit::httpd::{decode_path, Exchange};
use vexa_native_kit::pyjson::{py_dumps, py_str, truthy};

use crate::edge::{hop_url, query_params};
use crate::identity;
use crate::obs::{self, ev};
use crate::paths;
use crate::tickets::{self as t, Checks};

const SERVICE_KEY_HEADER: &str = "x-vexa-service-key";
const INTERNAL_SECRET_HEADER: &str = "x-internal-secret";
const DOOR_SCOPES: [&str; 2] = ["bot", "tx"];
const PLACEHOLDERS: [&str; 7] = ["vexa-internal-secret", "lite-internal-secret", "changeme", "change-me", "CHANGE-ME", "default", "secret"];
const TIMEOUT: Duration = Duration::from_secs(30);

/// The allow-list: every call the flows tier makes. `{}` is one opaque segment.
const OUTBOUND: [(&str, &[(&str, &str)]); 4] = [
    ("agent", &[
        ("POST", "/internal/scaffolds"),
        ("POST", "/internal/notifications"),
        ("POST", "/internal/notifications/state"),
        ("GET", "/internal/meetings/{}/listen"),
        ("POST", "/events"),
        ("GET", "/api/workspace/file"),
        ("PUT", "/api/workspace/file"),
        ("POST", "/api/workspace/init"),
        ("GET", "/api/workspace/git"),
        ("POST", "/api/workspace/git/reset"),
        ("GET", "/api/sessions/{}/history"),
        ("POST", "/api/sessions/{}/proposals"),
        ("POST", "/api/chat"),
        ("POST", "/api/chat/submit"),
        ("GET", "/api/chat/pending"),
        ("GET", "/api/chat/turn-outcome"),
        ("POST", "/api/meeting/note"),
        ("POST", "/api/proposals"),
        ("POST", "/api/home/compose"),
        ("POST", "/api/rooms/calendar-sync"),
    ]),
    ("identity", &[
        ("GET", "/internal/users/by-email/{}"),
        ("GET", "/internal/users/{}/email"),
        ("POST", "/internal/users"),
        ("GET", "/internal/users/{}/is-admin"),
        ("GET", "/internal/users/{}/settings"),
        ("POST", "/internal/principals/workspace"),
        ("POST", "/internal/validate"),
    ]),
    ("meetings", &[
        ("GET", "/meetings"),
        ("POST", "/meetings"),
        ("POST", "/meetings/{}/share"),
        ("GET", "/transcripts/by-id/{}"),
        ("GET", "/transcripts/{}/{}"),
        ("GET", "/bots"),
        ("POST", "/bots"),
        ("DELETE", "/bots/{}/{}"),
    ]),
    ("crm", &[("POST", "/internal/references"), ("POST", "/internal/cards/offer")]),
];

/// How a bound call names its meeting.
#[derive(Clone, Copy, PartialEq)]
enum Names {
    None,
    Mid,
    Native,
    NativeBody,
}

/// The calls that act for a person: (domain, method, template, class, meeting, subject field).
const BOUND: [(&str, &str, &str, &str, Names, Option<&str>); 14] = [
    ("agent", "PUT", "/api/workspace/file", t::DESK_WRITE, Names::None, None),
    ("agent", "POST", "/api/workspace/init", t::DESK_WRITE, Names::None, None),
    ("agent", "POST", "/api/workspace/git/reset", t::DESK_WRITE, Names::None, None),
    ("agent", "POST", "/api/chat", t::CHAT_AUTONOMOUS, Names::None, None),
    ("agent", "POST", "/api/chat/submit", t::ROUTINE_TURN, Names::None, None),
    ("agent", "GET", "/api/chat/pending", t::ROUTINE_TURN, Names::None, None),
    ("agent", "GET", "/api/chat/turn-outcome", t::ROUTINE_TURN, Names::None, None),
    ("identity", "POST", "/internal/principals/workspace", t::ROOM_BILLS_TO, Names::None, Some("bills_to")),
    ("meetings", "POST", "/meetings", t::BOT_DISPATCH, Names::NativeBody, None),
    ("meetings", "POST", "/meetings/{}/share", t::TRANSCRIPT_READ, Names::Mid, None),
    ("meetings", "GET", "/transcripts/by-id/{}", t::TRANSCRIPT_READ, Names::Mid, None),
    ("meetings", "GET", "/transcripts/{}/{}", t::TRANSCRIPT_READ, Names::Native, None),
    ("meetings", "POST", "/bots", t::BOT_DISPATCH, Names::NativeBody, None),
    ("meetings", "DELETE", "/bots/{}/{}", t::BOT_DISPATCH, Names::Native, None),
];

const INBOUND: [(&str, &str); 3] = [("POST", "/events/signal"), ("POST", "/mail/sign-in"), ("POST", "/mail/send")];
const OUTBOUND_HEADERS: [&str; 5] = ["content-type", "accept", "x-user-id", "x-trace-id", "x-vexa-internal-accepts-delegation"];
const OUTBOUND_PREFIXES: [&str; 3] = ["x-vexa-flow", "x-vexa-message-", "x-vexa-concern"];
const INBOUND_HEADERS: [&str; 4] = ["content-type", "accept", "x-trace-id", "x-vexa-service"];
const RESPONSE_DROP: [&str; 4] = ["content-length", "transfer-encoding", "connection", "content-encoding"];
const GATEWAY_EVENT_CLASSES: [&str; 3] = [t::DESK_WRITE, t::ROUTINE_TURN, t::BOT_DISPATCH];
const GRANT_CLASSES: [&str; 2] = [t::ROUTINE_TURN, t::BOT_DISPATCH];
const GRANT_REQUEST_HEADER: &str = "x-vexa-ticket-grant";
const GRANT_RESPONSE_HEADER: &str = "x-vexa-subject-grant";

fn template_matches(template: &str, path: &str) -> bool {
    let (ts, ps): (Vec<&str>, Vec<&str>) = (template.trim_matches('/').split('/').collect(), path.strip_prefix('/').unwrap_or("\u{0}").split('/').collect());
    ts.len() == ps.len() && ts.iter().zip(&ps).all(|(t, p)| if *t == "{}" { !p.is_empty() } else { t == p })
}

fn allowed(domain: &str, method: &str, path: &str) -> bool {
    OUTBOUND.iter().filter(|(d, _)| *d == domain).flat_map(|(_, rows)| rows.iter()).any(|(m, tpl)| *m == method && template_matches(tpl, path))
}

type Bound = (&'static str, &'static str, Names, Option<&'static str>);

fn bound_row(domain: &str, method: &str, path: &str) -> Option<Bound> {
    let literal = |tpl: &str| tpl.split('/').filter(|s| !s.is_empty() && *s != "{}").count();
    let mut best: Option<Bound> = None;
    for (d, m, tpl, cls, names, subject) in BOUND {
        if d == domain && m == method && template_matches(tpl, path) && best.is_none_or(|b| literal(tpl) > literal(b.0)) {
            best = Some((tpl, cls, names, subject));
        }
    }
    best
}

fn path_args(template: &str, path: &str) -> Vec<String> {
    template.trim_matches('/').split('/').zip(path.trim_matches('/').split('/')).filter(|(t, _)| *t == "{}").map(|(_, p)| p.to_owned()).collect()
}

pub fn usable_key(v: &str) -> String {
    let v = v.trim();
    if v.is_empty() || PLACEHOLDERS.contains(&v) { String::new() } else { v.to_owned() }
}

fn same(presented: Option<&str>, expected: &str) -> bool {
    !expected.is_empty() && presented.is_some_and(|p| !p.is_empty() && vexa_native_kit::sha256::constant_time_eq(p.as_bytes(), expected.as_bytes()))
}

struct Out {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn json_out(status: u16, body: &Value) -> Out {
    Out { status, headers: vec![("content-type".into(), "application/json".into())], body: py_dumps(body).into_bytes() }
}

fn refuse(status: u16, reason: &str, method: &str, path: &str, extra: &[(&str, Value)]) -> Out {
    let mut fields = Map::new();
    fields.insert("reason".into(), reason.into());
    fields.insert("method".into(), method.into());
    fields.insert("path".into(), path.into());
    let mut body = Map::new();
    body.insert("detail".into(), format!("service door: {reason}").into());
    body.insert("reason".into(), reason.into());
    body.insert("method".into(), method.into());
    body.insert("path".into(), path.into());
    for (k, v) in extra {
        fields.insert((*k).into(), v.clone());
        body.insert((*k).into(), v.clone());
    }
    ev("service_door_refused", "system", "warning", Some("auth")).fields(Value::Object(fields)).emit();
    json_out(status, &Value::Object(body))
}

fn pick(headers: &[(String, String)], names: &[&str], prefixes: &[&str]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in headers {
        if names.contains(&k.as_str()) || prefixes.iter().any(|p| k.starts_with(p)) {
            match out.iter_mut().find(|(n, _)| n == k) {
                Some(slot) => slot.1 = v.clone(),
                None => out.push((k.clone(), v.clone())),
            }
        }
    }
    out
}

/// The `once` uses already spent: `jti:class` until the ticket's expiry.
#[derive(Default)]
struct Seen(Mutex<HashMap<String, f64>>);

impl Seen {
    fn seen(&self, key: &str, now: f64) -> bool {
        self.0.lock().map(|m| m.get(key).is_some_and(|exp| *exp > now)).unwrap_or(false)
    }
    fn spend(&self, key: String, exp: f64, now: f64) {
        if let Ok(mut m) = self.0.lock() {
            if m.len() > 50000 {
                m.retain(|_, v| *v > now);
            }
            m.insert(key, exp);
        }
    }
}

pub struct Door {
    flows_key: String,
    internal_secret: String,
    bases: HashMap<&'static str, String>,
    flows_base: String,
    key: SigningKey,
    checks: Checks,
    seen: Seen,
}

impl Door {
    pub fn from_env(key: SigningKey) -> Result<Door, String> {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_owned());
        let flows_key = usable_key(&env("VEXA_FLOWS_SERVICE_KEY", ""));
        if flows_key.is_empty() {
            return Err("VEXA_FLOWS_SERVICE_KEY is a published placeholder — refusing to open the door".into());
        }
        let internal_secret = env("INTERNAL_API_SECRET", "");
        if usable_key(&internal_secret).is_empty() {
            return Err("INTERNAL_API_SECRET is unset — the service door forwards over the internal tier and cannot without it".into());
        }
        let mut bases = HashMap::new();
        for (d, k, default) in [("agent", "AGENT_API_URL", ""), ("identity", "ADMIN_API_URL", "http://admin-api:8001"), ("meetings", "MEETING_API_URL", "http://meeting-api:8080"), ("crm", "CRM_API_URL", "")] {
            bases.insert(d, env(k, default).trim_end_matches('/').to_owned());
        }
        let dir = env("VEXA_SUBJECT_TICKET_KEYS_DIR", "");
        let mut checks = Checks::new();
        for issuer in [t::MEETINGS, t::AGENT, t::MAIL] {
            if dir.is_empty() {
                continue;
            }
            let path = std::path::Path::new(&dir).join(format!("{issuer}.pem"));
            if !path.exists() {
                continue;
            }
            match identity::read_verify_key(&path.to_string_lossy()) {
                Ok(k) => {
                    checks.insert(issuer.into(), k);
                }
                Err(_) => ev("subject_ticket_key_unusable", "system", "warning", Some("auth"))
                    .fields(json!({"issuer": issuer, "error": "KeyUnavailable"}))
                    .emit(),
            }
        }
        checks.insert(t::GATEWAY.into(), key.verifying_key());
        if ![t::MEETINGS, t::AGENT, t::MAIL].iter().any(|i| checks.contains_key(*i)) {
            ev("subject_ticket_no_producer_keys", "system", "warning", Some("auth"))
                .fields(json!({"env": "VEXA_SUBJECT_TICKET_KEYS_DIR", "effect": "every bound flows call is refused"}))
                .emit();
        }
        Ok(Door { flows_key, internal_secret, bases, flows_base: env("FLOWS_API_URL", "").trim_end_matches('/').to_owned(), key, checks, seen: Seen::default() })
    }

    fn secret_header(&self) -> (String, String) {
        ("X-Internal-Secret".into(), self.internal_secret.clone())
    }

    fn relay(&self, method: &str, url: &str, query: &str, headers: &[(String, String)], body: &[u8]) -> Out {
        let target = hop_url(url, &query_params(query));
        let b = if body.is_empty() && !matches!(method, "POST" | "PUT" | "PATCH") { Body::None } else { Body::Bytes(body) };
        match client::request(method, &target, headers, b, Timeouts::all(TIMEOUT)) {
            Ok((status, up, content)) => {
                let mut out: Vec<(String, String)> = Vec::new();
                for (k, v) in up {
                    if RESPONSE_DROP.contains(&k.as_str()) {
                        continue;
                    }
                    match out.iter_mut().find(|(n, _)| *n == k) {
                        Some(slot) => slot.1 = format!("{}, {v}", slot.1),
                        None => out.push((k, v)),
                    }
                }
                Out { status, headers: out, body: content }
            }
            Err(e) if e.is_timeout() => json_out(504, &json!({"detail": "upstream timeout", "reason": "upstream_timeout"})),
            Err(e) => json_out(502, &json!({"detail": format!("upstream unreachable: {}", e.class_name()), "reason": "upstream_unreachable"})),
        }
    }

    fn get_json(&self, url: &str) -> Option<Value> {
        match client::request("GET", url, &[self.secret_header()], Body::None, Timeouts::all(TIMEOUT)) {
            Ok((200, _, body)) => serde_json::from_slice(&body).ok(),
            _ => None,
        }
    }

    fn subject_identity(&self, uid: &str) -> Option<Value> {
        let base = &self.bases["identity"];
        if base.is_empty() {
            return None;
        }
        self.get_json(&format!("{base}/internal/users/{uid}/identity")).filter(|b| b.get("user_id").is_some_and(|u| !u.is_null()))
    }

    fn address_of(&self, uid: &str, cache: &mut HashMap<String, String>) -> String {
        if let Some(a) = cache.get(uid) {
            return a.clone();
        }
        let base = &self.bases["identity"];
        let mut addr = String::new();
        if !base.is_empty() && !uid.is_empty() && uid.chars().all(|c| c.is_ascii_digit()) {
            if let Some(Value::Object(b)) = self.get_json(&format!("{base}/internal/users/{uid}/email")) {
                addr = b.get("email").filter(|e| truthy(Some(e))).map(py_str).unwrap_or_default().trim().to_lowercase();
            }
        }
        cache.insert(uid.to_owned(), addr.clone());
        addr
    }

    fn meeting_of(names: Names, template: &str, path: &str, body: &Option<Value>) -> (&'static str, String) {
        let args = path_args(template, path);
        match names {
            Names::Mid if !args.is_empty() => ("mid", args[0].clone()),
            Names::Native if args.len() >= 2 => ("native", t::native_of(&Value::String(args[0].clone()), &Value::String(args[1].clone()))),
            Names::NativeBody => match body {
                Some(Value::Object(b)) => {
                    let (p, n) = (b.get("platform").cloned().unwrap_or(Value::Null), b.get("native_meeting_id").cloned().unwrap_or(Value::Null));
                    if truthy(Some(&p)) && truthy(Some(&n)) {
                        return ("native", t::native_of(&p, &n));
                    }
                    let url = b.get("meeting_url").filter(|u| truthy(Some(u))).map(py_str).unwrap_or_default();
                    ("native", crate::link::parse_meeting_url(&url).map(|(p, n)| t::native_of(&p.into(), &n.into())).unwrap_or_default())
                }
                _ => ("", String::new()),
            },
            _ => ("", String::new()),
        }
    }

    /// Err(refusal) when no presented ticket opens the call; Ok(the `once` use to spend on a 2xx).
    #[allow(clippy::too_many_arguments)]
    fn admit(&self, domain: &str, method: &str, row: Bound, path: &str, headers: &[(String, String)], header: impl Fn(&str) -> Option<String>, raw: &[u8]) -> Result<Option<(String, f64)>, Out> {
        let (template, cls, names, field) = row;
        let _ = headers;
        let body: Option<Value> = if raw.is_empty() { None } else { serde_json::from_slice(raw).ok() };
        let header_subject = header("x-user-id").unwrap_or_default().trim().to_owned();
        let d = || ("domain", Value::from(domain));
        let subject = match field {
            Some(f) => {
                let s = match &body {
                    Some(Value::Object(b)) => b.get(f).filter(|v| truthy(Some(v))).map(py_str).unwrap_or_default().trim().to_owned(),
                    _ => String::new(),
                };
                if !header_subject.is_empty() && header_subject != s {
                    return Err(refuse(403, "subject_ticket_refused", method, path, &[d(), ("cls", cls.into()), ("why", json!(["subject_header_disagrees"]))]));
                }
                s
            }
            None => header_subject,
        };
        if subject.is_empty() {
            return Err(refuse(400, "subject_required", method, path, &[d()]));
        }
        let tickets = t::split(header(t::HEADER).as_deref());
        if tickets.is_empty() {
            return Err(refuse(403, "subject_ticket_required", method, path, &[d(), ("cls", cls.into())]));
        }
        let (kind, value) = Self::meeting_of(names, template, path, &body);
        let now = vexa_native_kit::ids::now();
        let (mut why, mut cache, mut replayed) = (Vec::<&str>::new(), HashMap::new(), false);
        let get_str = |c: &Map<String, Value>, k: &str| c.get(k).filter(|v| truthy(Some(v))).map(py_str).unwrap_or_default();
        for token in &tickets {
            let c = match t::read(token, &self.checks, now as i64) {
                Ok(c) => c,
                Err(reason) => {
                    why.push(reason);
                    continue;
                }
            };
            if !c["cls"].as_array().is_some_and(|a| a.iter().any(|x| x == cls)) {
                why.push("class_not_granted");
                continue;
            }
            let sub = c["sub"].as_str().unwrap_or("");
            let mut ok = !sub.is_empty() && sub == subject;
            let peers = c.get("peers").filter(|p| truthy(Some(p)));
            let peer_class = t::PEER_CLASSES.contains(&cls);
            if !ok && (truthy(c.get("addr")) || (peer_class && peers.is_some())) {
                let addr = self.address_of(&subject, &mut cache);
                let in_peers = peers.is_some_and(|p| match p {
                    Value::Array(a) => a.iter().any(|x| x.as_str() == Some(addr.as_str())),
                    Value::String(s) => s.contains(addr.as_str()),
                    Value::Object(o) => o.contains_key(&addr),
                    _ => false,
                });
                ok = !addr.is_empty() && (c.get("addr").and_then(Value::as_str) == Some(addr.as_str()) || (peer_class && in_peers));
            }
            if !ok {
                why.push("other_subject");
                continue;
            }
            if !kind.is_empty() {
                match c.get(kind).filter(|v| truthy(Some(v))) {
                    Some(claim) => {
                        if value.is_empty() || claim.as_str() != Some(value.as_str()) {
                            why.push("other_meeting");
                            continue;
                        }
                    }
                    None => {
                        if !get_str(&c, "mid").is_empty() || !get_str(&c, "native").is_empty() || cls == t::TRANSCRIPT_READ {
                            why.push("meeting_unchecked");
                            continue;
                        }
                    }
                }
            }
            let once = c.get("once").is_some_and(|o| match o {
                Value::Array(a) => a.iter().any(|x| x == cls),
                Value::String(s) => s.contains(cls),
                Value::Object(m) => m.contains_key(cls),
                _ => false,
            });
            let once_key = once.then(|| format!("{}:{cls}", c["jti"].as_str().unwrap_or("")));
            if let Some(k) = &once_key {
                if self.seen.seen(k, now) {
                    replayed = true;
                    why.push("replayed");
                    continue;
                }
            }
            ev("subject_ticket_admitted", "system", "debug", Some("auth"))
                .fields(json!({"domain": domain, "method": method, "path": path, "cls": cls, "iss": c["iss"], "evt": c.get("evt").cloned().unwrap_or_else(|| "".into())}))
                .emit();
            let exp = c["exp"].as_f64().unwrap_or(0.0);
            return Ok(once_key.map(|k| (k, exp)));
        }
        why.sort_unstable();
        why.dedup();
        if replayed && why.iter().all(|w| ["replayed", "other_meeting", "class_not_granted"].contains(w)) {
            return Err(refuse(403, "ticket_replayed", method, path, &[d(), ("cls", cls.into())]));
        }
        Err(refuse(403, "subject_ticket_refused", method, path, &[d(), ("cls", cls.into()), ("why", json!(why))]))
    }

    fn issue_on_validate(&self, header: impl Fn(&str) -> Option<String>, resp: &mut Out) {
        if resp.status != 200 {
            return;
        }
        let user: Value = match serde_json::from_slice(if resp.body.is_empty() { b"{}" } else { &resp.body }) {
            Ok(v) => v,
            Err(_) => return,
        };
        let Some(u) = user.as_object().filter(|u| u.get("user_id").is_some_and(|v| !v.is_null())) else { return };
        let dlg = u.get("delegation").and_then(Value::as_object).cloned().unwrap_or_default();
        if truthy(dlg.get("shared")) || u.get("principal_kind").filter(|v| truthy(Some(v))).map(py_str).as_deref() == Some("workspace") {
            return;
        }
        let uid = py_str(&u["user_id"]).trim().to_owned();
        let now = identity::now();
        resp.headers.push((t::HEADER.into(), t::mint(&self.key, t::EVENT, &uid, &GATEWAY_EVENT_CLASSES, "validate", 600, now)));
        let want = header(GRANT_REQUEST_HEADER).unwrap_or_default().trim().to_owned();
        static ROUTINE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let rx = ROUTINE.get_or_init(|| Regex::new(r"^user:(\d+)/[A-Za-z0-9._-]{1,128}$").expect("a valid pattern"));
        if let Some(m) = rx.captures(&want) {
            if m[1] == *uid && u.get("credential_class").and_then(Value::as_str) == Some("session") && dlg.is_empty() {
                resp.headers.push((GRANT_RESPONSE_HEADER.into(), t::mint(&self.key, t::GRANT, &uid, &GRANT_CLASSES, &want, 400 * 86400, now)));
            }
        }
    }

    fn inbound(&self, ex: &mut Exchange, method: &str, tail: &str) -> Out {
        let head = ex.head.clone();
        let target = format!("/{tail}");
        if !same(head.header(INTERNAL_SECRET_HEADER), &self.internal_secret) {
            return refuse(403, "internal_secret_required", method, &target, &[]);
        }
        if self.flows_base.is_empty() {
            return refuse(404, "flows_not_deployed", method, &target, &[]);
        }
        if !INBOUND.iter().any(|(m, p)| *m == method && *p == target) {
            return refuse(403, "not_on_the_allow_list", method, &target, &[("domain", "flows".into())]);
        }
        let mut headers = pick(&head.headers, &INBOUND_HEADERS, &[]);
        headers.push((SERVICE_KEY_HEADER.into(), self.flows_key.clone()));
        let Ok(body) = ex.read_body(None) else { return json_out(400, &json!({"detail": "There was an error parsing the body"})) };
        self.relay(method, &format!("{}{target}", self.flows_base), &head.query, &headers, &body)
    }

    fn outbound(&self, ex: &mut Exchange, method: &str, domain: &str, tail: &str) -> Out {
        let head = ex.head.clone();
        let header = |n: &str| head.header(n).map(str::to_owned);
        let target = format!("/{tail}");
        let d = || ("domain", Value::from(domain));
        if !same(head.header(SERVICE_KEY_HEADER), &self.flows_key) {
            return refuse(403, "service_key_required", method, &target, &[d()]);
        }
        if !OUTBOUND.iter().any(|(x, _)| *x == domain) {
            return refuse(404, "unknown_domain", method, &target, &[d()]);
        }
        if !allowed(domain, method, &target) {
            return refuse(403, "not_on_the_allow_list", method, &target, &[d()]);
        }
        let base = self.bases.get(domain).cloned().unwrap_or_default();
        if base.is_empty() {
            return refuse(404, "domain_not_deployed", method, &target, &[d()]);
        }
        let Ok(body) = ex.read_body(None) else { return json_out(400, &json!({"detail": "There was an error parsing the body"})) };
        let mut once = None;
        if let Some(row) = bound_row(domain, method, &target) {
            match self.admit(domain, method, row, &target, &head.headers, header, &body) {
                Ok(o) => once = o,
                Err(r) => return r,
            }
        }
        let mut headers = pick(&head.headers, &OUTBOUND_HEADERS, &OUTBOUND_PREFIXES);
        if domain != "identity" {
            headers.retain(|(k, _)| k != "x-vexa-internal-accepts-delegation");
        }
        if domain == "meetings" {
            let uid = headers.iter().find(|(k, _)| k == "x-user-id").map(|(_, v)| v.trim().to_owned()).unwrap_or_default();
            headers.retain(|(k, _)| k != "x-user-id");
            if uid.is_empty() || !uid.chars().all(|c| c.is_ascii_digit()) {
                return refuse(400, "subject_required", method, &target, &[d()]);
            }
            let Some(Value::Object(mut user)) = self.subject_identity(&uid) else {
                return refuse(403, "subject_unknown", method, &target, &[d()]);
            };
            user.insert("scopes".into(), json!(DOOR_SCOPES));
            user.remove("credential_class");
            for (k, v) in identity::identity_headers(Some(&self.key), &Value::Object(user)) {
                match headers.iter_mut().find(|(n, _)| *n == k) {
                    Some(slot) => slot.1 = v,
                    None => headers.push((k, v)),
                }
            }
        } else {
            headers.push((INTERNAL_SECRET_HEADER.into(), self.internal_secret.clone()));
        }
        ev("service_door_forwarded", "system", "debug", Some("proxy")).fields(json!({"domain": domain, "method": method, "path": target})).emit();
        let mut resp = self.relay(method, &format!("{base}{target}"), &head.query, &headers, &body);
        if let Some((k, exp)) = once {
            if (200..300).contains(&resp.status) {
                self.seen.spend(k, exp, vexa_native_kit::ids::now());
            }
        }
        if domain == "identity" && method == "POST" && target == "/internal/validate" {
            self.issue_on_validate(|n| head.header(n).map(str::to_owned), &mut resp);
        }
        resp
    }

    pub fn handle(&self, ex: &mut Exchange) {
        let head = ex.head.clone();
        let prev = obs::begin(None);
        let path = decode_path(&head.raw_path);
        let method = head.method.as_str();
        static OUT: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let outbound = OUT.get_or_init(|| Regex::new(r"^/([^/]+)/(.*)$").expect("a valid pattern"));
        let routed = |p: &str| p == "/health" || outbound.is_match(p);
        let door_methods = ["GET", "POST", "PUT", "DELETE"];
        let out = if path == "/health" {
            if method == "GET" {
                Out { status: 200, headers: vec![("content-type".into(), "application/json".into())], body: br#"{"status":"ok","service":"gateway-service-door"}"#.to_vec() }
            } else {
                not_allowed("GET")
            }
        } else if let Some(c) = outbound.captures(&path) {
            if !door_methods.contains(&method) {
                not_allowed("GET, POST, PUT, DELETE")
            } else if c[1] == *"to-flows" {
                let rest = path["/to-flows/".len()..].to_owned();
                match paths::tail_path(&rest, &head.raw_path) {
                    Ok(tail) => self.inbound(ex, method, &tail),
                    Err(()) => Out { status: 400, headers: vec![("content-type".into(), "application/json".into())], body: paths::INVALID.as_bytes().to_vec() },
                }
            } else {
                let (domain, rest) = (c[1].to_owned(), c[2].to_owned());
                match paths::tail_path(&rest, &head.raw_path) {
                    Ok(tail) => self.outbound(ex, method, &domain, &tail),
                    Err(()) => Out { status: 400, headers: vec![("content-type".into(), "application/json".into())], body: paths::INVALID.as_bytes().to_vec() },
                }
            }
        } else {
            let other = if path.ends_with('/') { path.trim_end_matches('/').to_owned() } else { format!("{path}/") };
            if routed(&other) {
                let host = head.header("host").unwrap_or("");
                let q = if head.query.is_empty() { String::new() } else { format!("?{}", head.query) };
                Out { status: 307, headers: vec![("location".into(), format!("http://{host}{other}{q}"))], body: Vec::new() }
            } else {
                Out { status: 404, headers: vec![("content-type".into(), "application/json".into())], body: br#"{"detail":"Not Found"}"#.to_vec() }
            }
        };
        let _ = ex.respond(out.status, &out.headers, &out.body);
        obs::restore(prev);
    }
}

fn not_allowed(allow: &str) -> Out {
    Out { status: 405, headers: vec![("allow".into(), allow.into()), ("content-type".into(), "application/json".into())], body: br#"{"detail":"Method Not Allowed"}"#.to_vec() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_and_bound_rows() {
        assert!(allowed("meetings", "GET", "/transcripts/zoom/123"));
        assert!(!allowed("meetings", "GET", "/transcripts/zoom"));
        assert!(!allowed("meetings", "GET", "/transcripts//1"));
        assert!(!allowed("nope", "GET", "/meetings"));
        assert_eq!(bound_row("meetings", "GET", "/transcripts/by-id/7").map(|b| b.0), Some("/transcripts/by-id/{}"));
        assert_eq!(bound_row("meetings", "GET", "/transcripts/zoom/7").map(|b| b.0), Some("/transcripts/{}/{}"));
        assert!(bound_row("meetings", "GET", "/meetings").is_none());
        assert_eq!(path_args("/bots/{}/{}", "/bots/zoom/9"), vec!["zoom", "9"]);
        assert_eq!(usable_key(" changeme "), "");
    }
}
