//! The public edge (api.v1): the guard, the body limit and the trace id in front of the router; the
//! one authorization every forward passes (`_authorize`); the buffered forward, the two stream
//! relays and the bundle relay; `/health`, `/auth/me` and `/internal/mcp/taint`.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
use vexa_native_kit::client::{self, Body, NetError, Timeouts};
use vexa_native_kit::httpd::{decode_path, BodyError, Exchange};
use vexa_native_kit::pyjson::{py_dumps, py_str, truthy, Dumps};

use crate::guard::{AgentAllow, Guard, UserLimiter};
use crate::identity;
use crate::manifest::{Assembly, Key, CATCH_ALL};
use crate::obs::{self, ev, TRACE_HEADER};
use crate::paths;
use crate::routes::{self, Handler, Match, Route};
use crate::taint::{self, Marker};

pub const MAX_BODY_BYTES: usize = 1024 * 1024;
const FORWARD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_RETRY_WINDOW_S: f64 = 20.0;
const CONNECT_BACKOFF_S: [f64; 4] = [0.25, 0.5, 1.0, 2.0];
const MCP_HEADERS: [&str; 2] = ["mcp-session-id", "mcp-protocol-version"];
const STREAM_TIMEOUTS: Timeouts = Timeouts { connect: Duration::from_secs(10), read: None, write: Duration::from_secs(10) };
const BUNDLE_TIMEOUTS: Timeouts = Timeouts { connect: Duration::from_secs(10), read: Some(Duration::from_secs(600)), write: Duration::from_secs(600) };

pub struct Edge {
    pub routes: Vec<Route>,
    pub asm: Assembly,
    pub admin_url: String,
    pub meeting_url: String,
    pub mcp_url: String,
    /// domain -> its door (agent, crm), for a forwarded domain.
    pub forward_base: HashMap<String, String>,
    pub key: Option<SigningKey>,
    pub vkey: Option<VerifyingKey>,
    pub internal_secret: String,
    pub limiter: Option<UserLimiter>,
    pub agent_allow: AgentAllow,
    pub marker: Marker,
    pub guard: Guard,
    pub redis: crate::redis::Target,
}

/// A whole answer.
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Resp {
        Resp { status, headers: vec![("content-type".into(), media(content_type))], body: body.into() }
    }
    /// A body written with `json.dumps` (the edge's own refusals).
    pub fn json_text(status: u16, text: String) -> Resp {
        Resp::new(status, "application/json", text)
    }
    pub fn detail(status: u16, detail: &str) -> Resp {
        Resp::json_text(status, py_dumps(&json!({"detail": detail})))
    }
    /// FastAPI's JSONResponse: compact, UTF-8.
    pub fn fastapi(status: u16, value: &Value) -> Resp {
        Resp::new(status, "application/json", Dumps::COMPACT.ascii(false).text(value))
    }
    pub fn header(mut self, k: &str, v: &str) -> Resp {
        self.headers.insert(self.headers.len() - 1, (k.into(), v.into()));
        self
    }
}

/// Starlette's media type: a `text/*` type without a charset gets `; charset=utf-8`.
pub fn media(t: &str) -> String {
    if t.starts_with("text/") && !t.to_lowercase().contains("charset=") {
        format!("{t}; charset=utf-8")
    } else {
        t.to_owned()
    }
}

pub enum Out {
    Whole(Resp),
    /// Written already (a streamed answer).
    Done,
    /// The body passed the limit while it was read: the 413 goes out without the trace header.
    TooLarge,
}

impl From<Resp> for Out {
    fn from(r: Resp) -> Out {
        Out::Whole(r)
    }
}

fn too_large() -> Resp {
    let body = py_dumps(&json!({"detail": format!("request body is larger than {MAX_BODY_BYTES} bytes")}));
    Resp { status: 413, headers: vec![("content-type".into(), "application/json".into())], body: body.into_bytes() }
}

fn invalid_path() -> Resp {
    Resp::json_text(400, paths::INVALID.into())
}

fn insufficient_scope() -> Resp {
    Resp::detail(403, "Insufficient scope for this endpoint")
}

pub fn auth_unavailable_body() -> Value {
    json!({
        "detail": "Authentication temporarily unavailable, retry",
        "code": "auth_unavailable",
        "reason": "vexa_sign_in_unavailable",
        "source": "vexa",
        "retry_after": 1,
        "message": "Vexa's own sign-in service is briefly unavailable (for example during an update). This is not your account and not Google or Microsoft: no provider was asked. Retry in a few seconds.",
    })
}

fn auth_unavailable(detail: &str, span: &str) -> Resp {
    ev("auth_infra_unavailable", "system", "error", Some(span))
        .fields(json!({"reason": "AuthUnavailable", "detail": detail}))
        .emit();
    Resp::json_text(503, py_dumps(&auth_unavailable_body())).header("retry-after", "1")
}

fn delegated_route() -> Resp {
    Resp::detail(403, "a worker's delegation token is accepted on /mcp only")
}

fn shared_route() -> Resp {
    Resp::json_text(403, py_dumps(&json!({"detail": identity::shared_refusal()})))
}

fn reentry_unlisted(method: &str, path: &str) -> Resp {
    Resp::json_text(403, py_dumps(&json!({"detail": {
        "reason": "route_not_listed_for_tools",
        "message": format!("This edge does not list {method} {path} as a route the MCP's tools call, so the call was refused and nothing was done. If a tool just called it, the gateway is older than the service that offers the tool: the gateway needs rebuilding with the current routes.v1 manifests."),
    }})))
}

fn mark_refused() -> Resp {
    Resp::json_text(503, py_dumps(&json!({"detail": taint::mark_unavailable_body()})))
}

/// The host of a hop's URL (`httpx.URL(url).host`).
fn host_of(url: &str) -> String {
    client::parse_url(url).map(|u| u.host.to_lowercase()).unwrap_or_else(|_| "the service".into())
}

fn upstream_fault(url: &str, err: &NetError) -> Resp {
    let service = host_of(url);
    let hop = format!("gateway → {service}");
    let body = if err.is_timeout() {
        (504, json!({"detail": "upstream timeout", "reason": "upstream_timeout", "source": "vexa", "hop": hop,
            "message": format!("Vexa's {service} did not answer the gateway in time. This is Vexa's own service, not the connected service or your account. Retry in a moment.")}))
    } else {
        (502, json!({"detail": format!("upstream unreachable: {}", err.class_name()), "reason": "upstream_unreachable", "source": "vexa", "hop": hop,
            "message": format!("Vexa's {service} could not be reached by the gateway. This is Vexa's own service, not the connected service or your account. Retry in a moment.")}))
    };
    Resp::json_text(body.0, Dumps::DEFAULT.ascii(false).text(&body.1))
}

/// A request's own facts, as the handlers read them.
pub struct Req {
    pub method: String,
    pub raw_path: String,
    /// `request.url.path`: the decoded path, cut at a `?` or `#` it decoded to.
    pub url_path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub key: Option<Key>,
    pub params: Vec<(String, String)>,
    pub body_capped: bool,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    fn param(&self, name: &str) -> String {
        self.params.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()).unwrap_or_default()
    }
}

/// `dict(request.query_params)`: parse_qsl with blank values kept, the last value of a repeated
/// name at the place of its first.
pub fn query_params(query: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (k, v) = (vexa_native_kit::http::decode(k), vexa_native_kit::http::decode(v));
        match out.iter_mut().find(|(n, _)| *n == k) {
            Some(slot) => slot.1 = v,
            None => out.push((k, v)),
        }
    }
    out
}

/// `urllib.parse.quote_plus` as httpx writes `params`.
fn quote_plus(v: &str) -> String {
    client::quote(v).replace("%20", "+")
}

/// The URL httpx requests for `url` with `params`: its path normalized, the params encoded.
pub fn hop_url(url: &str, params: &[(String, String)]) -> String {
    let (base, path) = match url.find("://").and_then(|i| url[i + 3..].find('/').map(|j| i + 3 + j)) {
        Some(cut) => (&url[..cut], &url[cut..]),
        None => (url, "/"),
    };
    let mut out = format!("{base}{}", paths::remove_dot_segments(path));
    if !params.is_empty() {
        out.push(if out.contains('?') { '&' } else { '?' });
        out.push_str(&params.iter().map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v))).collect::<Vec<_>>().join("&"));
    }
    out
}

fn set(h: &mut Vec<(String, String)>, k: &str, v: String) {
    match h.iter_mut().find(|(n, _)| n == k) {
        Some(slot) => slot.1 = v,
        None => h.push((k.to_owned(), v)),
    }
}

fn authority_header(name: &str) -> bool {
    ["x-admin-api-key", identity::HEADER, taint::STATE_HEADER].contains(&name)
        || name.starts_with("x-user-")
        || name.starts_with("x-internal-")
        || name.starts_with("x-vexa-internal-")
}

pub fn is_delegated(key: &str, user: &Value) -> bool {
    user.get("delegation").is_some_and(Value::is_object) || key.starts_with("vxd_")
}

fn shared_delegation(user: &Value) -> bool {
    match user.get("delegation") {
        Some(Value::Object(d)) => d.get("shared") == Some(&Value::Bool(true)) || d.get("principal_kind").and_then(Value::as_str) == Some("workspace"),
        _ => false,
    }
}

fn reported(user: &Value, delegated: bool, own: &str, person: &str) -> bool {
    if !delegated {
        return user.get(own) == Some(&Value::Bool(true));
    }
    match user.get("delegation") {
        Some(Value::Object(d)) => {
            let regime = d.get("regime").filter(|v| truthy(Some(v))).map(py_str).unwrap_or_default();
            regime == "human" && user.get(person) == Some(&Value::Bool(true))
        }
        _ => false,
    }
}

/// The client headers a forward carries: lower-cased, the last of a repeated name, without the hop's
/// own framing and without any authority header.
fn client_headers(req: &Req) -> Vec<(String, String)> {
    let mut h: Vec<(String, String)> = Vec::new();
    for (k, v) in &req.headers {
        if ["host", "content-length", "transfer-encoding", "accept-encoding", "connection"].contains(&k.as_str()) || authority_header(k) {
            continue;
        }
        set(&mut h, k, v.clone());
    }
    h
}

pub fn scopes_of(user: &Value) -> BTreeSet<String> {
    match user.get("scopes") {
        Some(v) if truthy(Some(v)) => match v {
            Value::Array(a) => a.iter().map(py_str).collect(),
            Value::String(s) => s.chars().map(|c| c.to_string()).collect(),
            Value::Object(m) => m.keys().cloned().collect(),
            _ => BTreeSet::new(),
        },
        _ => BTreeSet::new(),
    }
}

impl Edge {
    // ── the identity hop ──────────────────────────────────────────────────────────────────────
    /// `/internal/validate`: Ok(Some(user)), Ok(None) for a key identity refuses, Err when no
    /// verdict came back (the text `AuthUnavailable` carries).
    pub fn resolve(&self, key: &str) -> Result<Option<Value>, String> {
        let mut headers = vec![
            (TRACE_HEADER.to_owned(), obs::trace_or_empty()),
            ("x-vexa-internal-accepts-delegation".to_owned(), "1".to_owned()),
        ];
        if !self.internal_secret.is_empty() {
            headers.push(("X-Internal-Secret".into(), self.internal_secret.clone()));
        }
        headers.push(("content-type".into(), "application/json".into()));
        let body = Dumps::COMPACT.ascii(false).text(&json!({"token": key}));
        let url = format!("{}/internal/validate", self.admin_url.trim_end_matches('/'));
        let mut waits = [0.5, 1.5].into_iter();
        let answer = loop {
            match client::request("POST", &url, &headers, Body::Bytes(body.as_bytes()), Timeouts::all(Duration::from_secs(5))) {
                Err(NetError::Connect(_) | NetError::ConnectTimeout) if waits.len() > 0 => {
                    std::thread::sleep(Duration::from_secs_f64(waits.next().unwrap_or(0.5)));
                }
                other => break other,
            }
        };
        let (status, _, bytes) = answer.map_err(|e| format!("admin-api validate unreachable: {}({})", e.class_name(), vexa_native_kit::pyjson::py_str_repr(&e.to_string())))?;
        if status == 200 {
            return match serde_json::from_slice::<Value>(&bytes) {
                Ok(v) if truthy(Some(&v)) => Ok(Some(v)),
                Ok(_) => Ok(None),
                Err(e) => Err(format!("admin-api validate returned unparseable 200 body: JSONDecodeError('{e}')")),
            };
        }
        if (400..500).contains(&status) {
            return Ok(None);
        }
        Err(format!("admin-api validate returned {status}"))
    }

    /// meeting-api's `/ws/authorize-subscribe` for these meetings.
    pub fn authorize_subscribe(&self, key: &str, meetings: &Value) -> Value {
        let user = match self.resolve(key) {
            Ok(u) => u,
            Err(e) => return json!({"authorized": [], "errors": [format!("authorization_unavailable:{e}")]}),
        };
        let mut headers = vec![("X-API-Key".to_owned(), key.to_owned()), (TRACE_HEADER.to_owned(), obs::trace_or_empty())];
        if let Some(u) = &user {
            headers.extend(identity::identity_headers(self.key.as_ref(), u));
        }
        headers.push(("content-type".into(), "application/json".into()));
        let body = Dumps::COMPACT.ascii(false).text(&json!({"meetings": meetings}));
        let url = format!("{}/ws/authorize-subscribe", self.meeting_url.trim_end_matches('/'));
        match client::request("POST", &url, &headers, Body::Bytes(body.as_bytes()), Timeouts::all(Duration::from_secs(5))) {
            Ok((200, _, bytes)) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(v) => v,
                Err(e) => json!({"authorized": [], "errors": [format!("authorization_call_failed:{e}")]}),
            },
            Ok((status, _, _)) => json!({"authorized": [], "errors": [format!("authorization_service_error:{status}")]}),
            Err(e) => json!({"authorized": [], "errors": [format!("authorization_call_failed:{e}")]}),
        }
    }

    fn admits_reentry(&self, req: &Req, user: &Value) -> bool {
        req.key.as_ref().is_some_and(|k| self.asm.mcp_reentry.contains(k)) && self.reentry_valid(req, user)
    }

    fn reentry_valid(&self, req: &Req, user: &Value) -> bool {
        let Some(vk) = &self.vkey else { return false };
        let token = req.header("x-vexa-internal-mcp-identity").unwrap_or("").trim();
        if token.is_empty() {
            return false;
        }
        let Ok(claims) = identity::verify(vk, token, identity::now()) else { return false };
        let want = identity::claims_from_validation(user);
        claims.get("sub") == want.get("sub") && want.get("delegation").is_some_and(Value::is_object) && claims.get("delegation") == want.get("delegation")
    }

    fn owner(&self, req: &Req) -> Option<&str> {
        req.key.as_ref().and_then(|k| self.asm.owner_of.get(k)).map(String::as_str)
    }

    // ── _authorize ────────────────────────────────────────────────────────────────────────────
    /// Ok((forward headers, the delegated unit to mark)), or the refusal.
    fn authorize(&self, method: &str, req: &Req, api_key: Option<String>) -> Result<(Vec<(String, String)>, Option<String>), Resp> {
        let client_key = match api_key {
            Some(k) => Some(k),
            None => req.header("x-api-key").map(str::to_owned),
        };
        let Some(client_key) = client_key.filter(|k| !k.is_empty()) else {
            return Err(Resp::detail(401, "Missing API key"));
        };
        let user = match self.resolve(&client_key) {
            Err(e) => return Err(auth_unavailable(&e, "auth")),
            Ok(None) => return Err(Resp::detail(401, "Invalid API key")),
            Ok(Some(u)) => u,
        };
        let uid = user.get("user_id").cloned().unwrap_or(Value::Null);
        obs::set_user(&user);
        obs::set_session(obs::session_of_validation(&user).as_deref());
        if let Some(l) = &self.limiter {
            if !l.allow(&py_str(&uid)) {
                return Err(Resp::detail(429, "Rate limit exceeded").header("retry-after", "1"));
            }
        }
        let delegated = is_delegated(&client_key, &user);
        let fields = json!({"method": method, "path": req.url_path});
        if delegated && !req.key.as_ref().is_some_and(|k| self.asm.delegation.contains(k)) && !self.admits_reentry(req, &user) {
            let unlisted = self.reentry_valid(req, &user);
            ev(if unlisted { "request_denied_reentry_unlisted" } else { "request_denied_delegated_route" }, "user", "warning", Some("auth"))
                .user(uid.clone())
                .fields(fields.clone())
                .emit();
            return Err(if unlisted { reentry_unlisted(method, &req.url_path) } else { delegated_route() });
        }
        if delegated && shared_delegation(&user) && !req.key.as_ref().is_some_and(|k| self.asm.shared_allow.contains(k)) {
            ev("request_denied_shared_route", "user", "warning", Some("auth")).user(uid.clone()).fields(fields.clone()).emit();
            return Err(shared_route());
        }
        let Some(required) = req.key.as_ref().and_then(|k| self.asm.scopes.get(k)) else {
            ev("request_denied_undeclared_route", "system", "error", Some("auth")).user(uid.clone()).fields(fields.clone()).emit();
            return Err(insufficient_scope());
        };
        if scopes_of(&user).is_disjoint(required) {
            let req_sorted: Vec<&String> = required.iter().collect();
            ev("request_denied_scope", "user", "warning", Some("auth"))
                .user(uid.clone())
                .fields(json!({"method": method, "path": req.url_path, "required": req_sorted}))
                .emit();
            return Err(insufficient_scope());
        }
        if self.owner(req) == Some("agent") && !self.agent_allow.admits(&user) {
            ev("request_denied_agent_tier", "user", "warning", Some("auth")).user(uid.clone()).fields(fields.clone()).emit();
            return Err(Resp::json_text(403, py_dumps(&json!({"detail": "agent_tier_not_enabled"}))));
        }
        ev("request_accepted", "user", "info", Some("auth")).user(uid).fields(fields).emit();
        let mut headers = client_headers(req);
        set(&mut headers, "x-api-key", client_key.clone());
        for (k, v) in identity::identity_headers(self.key.as_ref(), &user) {
            set(&mut headers, &k, v);
        }
        set(&mut headers, TRACE_HEADER, obs::trace_or_empty());
        let unit = if delegated { obs::session_of_validation(&user) } else { None };
        if let Some(u) = &unit {
            set(&mut headers, taint::STATE_HEADER, self.marker.state_for(u));
        } else if delegated {
            set(&mut headers, taint::STATE_HEADER, taint::UNVERIFIABLE.into());
        }
        Ok((headers, unit))
    }

    fn mark_answer(&self, req: &Req, unit: &Option<String>, status: u16, label: Option<&str>) -> bool {
        let Some(unit) = unit else { return true };
        if !self.owner(req).is_some_and(|d| taint::MARKED_DOMAINS.contains(&d)) {
            return true;
        }
        let ok = self.marker.mark_from_response(unit, status, label);
        if !ok {
            ev("privacy_mark_unavailable", "system", "error", Some("proxy")).fields(json!({"method": req.method, "path": req.url_path})).emit();
        }
        ok
    }

    fn body(&self, ex: &mut Exchange, req: &Req) -> Result<Vec<u8>, Out> {
        ex.read_body(req.body_capped.then_some(MAX_BODY_BYTES)).map_err(|e| match e {
            BodyError::TooLarge => Out::TooLarge,
            BodyError::Io(_) => Out::Done,
        })
    }

    // ── the buffered forward ──────────────────────────────────────────────────────────────────
    fn forward(&self, ex: &mut Exchange, method: &str, url: &str, req: &Req, api_key: Option<String>) -> Out {
        let (headers, unit) = match self.authorize(method, req, api_key) {
            Ok(x) => x,
            Err(r) => return r.into(),
        };
        let content = match self.body(ex, req) {
            Ok(b) => b,
            Err(o) => return o,
        };
        let target = hop_url(url, &query_params(&req.query));
        let body = if content.is_empty() && !matches!(method, "POST" | "PUT" | "PATCH") { Body::None } else { Body::Bytes(&content) };
        let (mut waited, mut attempt) = (0.0, 0usize);
        let answer = loop {
            let b = match &body {
                Body::None => Body::None,
                Body::Bytes(c) => Body::Bytes(c),
                Body::Stream(_) => Body::None,
            };
            match client::request(method, &target, &headers, b, Timeouts::all(FORWARD_TIMEOUT)) {
                Err(NetError::Connect(_)) => {
                    let pause = CONNECT_BACKOFF_S[attempt.min(CONNECT_BACKOFF_S.len() - 1)];
                    if waited + pause > CONNECT_RETRY_WINDOW_S {
                        break Err(NetError::Connect(String::new()));
                    }
                    std::thread::sleep(Duration::from_secs_f64(pause));
                    waited += pause;
                    attempt += 1;
                }
                other => break other,
            }
        };
        let (status, up, bytes) = match answer {
            Ok(a) => a,
            Err(e) => return upstream_fault(url, &e).into(),
        };
        ev("downstream_forwarded", "system", "debug", Some("proxy"))
            .fields(json!({"method": method, "path": url, "downstream_status": status}))
            .emit();
        let get = |n: &str| up.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        if !self.mark_answer(req, &unit, status, get(taint::LABEL_HEADER).as_deref()) {
            return mark_refused().into();
        }
        let mut r = Resp::new(status, &get("content-type").unwrap_or_else(|| "application/json".into()), bytes);
        for k in ["content-range", "accept-ranges", "content-disposition"].into_iter().chain(MCP_HEADERS) {
            if let Some(v) = get(k) {
                r = r.header(k, &v);
            }
        }
        r.into()
    }

    /// An agent row that streams: an upstream 2xx event stream is relayed as SSE; any other answer
    /// is buffered with the upstream's status and type.
    fn forward_stream(&self, ex: &mut Exchange, method: &str, url: &str, req: &Req) -> Out {
        let (headers, unit) = match self.authorize(method, req, None) {
            Ok(x) => x,
            Err(r) => return r.into(),
        };
        let content = match self.body(ex, req) {
            Ok(b) => b,
            Err(o) => return o,
        };
        let target = hop_url(url, &query_params(&req.query));
        let body = if content.is_empty() && !matches!(method, "POST" | "PUT" | "PATCH") { Body::None } else { Body::Bytes(&content) };
        let mut up = match client::open(method, &target, &headers, body, STREAM_TIMEOUTS) {
            Ok(a) => a,
            Err(e) => return upstream_fault(url, &e).into(),
        };
        if !self.mark_answer(req, &unit, up.status, up.header(taint::LABEL_HEADER)) {
            return mark_refused().into();
        }
        let media_type = up.header("content-type").filter(|t| !t.is_empty()).unwrap_or("application/json").to_owned();
        if !((200..300).contains(&up.status) && media_type.starts_with("text/event-stream")) {
            let status = up.status;
            return match up.bytes() {
                Ok(b) => Resp::new(status, &media_type, b).into(),
                Err(_) => Out::Done,
            };
        }
        let head = vec![
            ("content-type".to_owned(), "text/event-stream".to_owned()),
            ("cache-control".to_owned(), "no-cache".to_owned()),
            ("x-accel-buffering".to_owned(), "no".to_owned()),
        ];
        relay(ex, 200, head, &mut up)
    }

    /// GET /mcp: the upstream's own head (status, type, MCP headers) and its body as it arrives.
    fn forward_stream_verbatim(&self, ex: &mut Exchange, url: &str, req: &Req, api_key: Option<String>) -> Out {
        let (headers, _) = match self.authorize("GET", req, api_key) {
            Ok(x) => x,
            Err(r) => return r.into(),
        };
        let content = match self.body(ex, req) {
            Ok(b) => b,
            Err(o) => return o,
        };
        let target = hop_url(url, &query_params(&req.query));
        let body = if content.is_empty() { Body::None } else { Body::Bytes(&content) };
        let mut up = match client::open("GET", &target, &headers, body, STREAM_TIMEOUTS) {
            Ok(a) => a,
            Err(e) => return upstream_fault(url, &e).into(),
        };
        ev("downstream_stream_opened", "system", "debug", Some("proxy"))
            .fields(json!({"method": "GET", "path": url, "downstream_status": up.status}))
            .emit();
        let mut head: Vec<(String, String)> = MCP_HEADERS.iter().filter_map(|k| up.header(k).map(|v| (k.to_string(), v.to_owned()))).collect();
        head.push(("cache-control".into(), "no-cache".into()));
        head.push(("x-accel-buffering".into(), "no".into()));
        head.push(("content-type".into(), media(up.header("content-type").filter(|t| !t.is_empty()).unwrap_or("application/json"))));
        let status = up.status;
        relay(ex, status, head, &mut up)
    }

    // ── meetings ──────────────────────────────────────────────────────────────────────────────
    fn meeting_target(&self, req: &Req) -> Result<String, Resp> {
        let Some(key) = req.key.as_ref().filter(|k| self.asm.owner_of.get(*k).map(String::as_str) == Some("meetings")) else {
            return Err(insufficient_scope());
        };
        if paths::encoded_separator(&req.raw_path) {
            return Err(invalid_path());
        }
        let mut target = self.asm.upstream.get(key).cloned().unwrap_or_else(|| key.1.clone());
        for name in crate::manifest::params_of(&target) {
            let seg = paths::forwarded_param(&req.param(&name), &req.raw_path).map_err(|_| invalid_path())?;
            target = target.replacen(&format!("{{{name}}}"), &seg, 1);
        }
        if let Some(stem) = target.strip_suffix(CATCH_ALL) {
            let tail = paths::tail_path(&req.param("path"), &req.raw_path).map_err(|_| invalid_path())?;
            target = format!("{stem}{tail}");
        }
        Ok(format!("{}{target}", self.meeting_url))
    }

    fn forward_bundle(&self, ex: &mut Exchange, req: &Req) -> Out {
        let url = match self.meeting_target(req) {
            Ok(u) => u,
            Err(r) => return r.into(),
        };
        let (headers, _) = match self.authorize(&req.method, req, None) {
            Ok(x) => x,
            Err(r) => return r.into(),
        };
        let target = hop_url(&url, &query_params(&req.query));
        let opened = if req.method == "POST" {
            let capped = req.body_capped;
            let mut limited = Limited { ex: &mut *ex, seen: 0, cap: capped.then_some(MAX_BODY_BYTES), over: false };
            let r = client::open("POST", &target, &headers, Body::Stream(&mut limited), BUNDLE_TIMEOUTS);
            if limited.over {
                return Out::TooLarge;
            }
            r
        } else {
            client::open(&req.method, &target, &headers, Body::None, BUNDLE_TIMEOUTS)
        };
        let mut up = match opened {
            Ok(a) => a,
            Err(e) => return upstream_fault(&url, &e).into(),
        };
        ev("downstream_stream_opened", "system", "debug", Some("proxy"))
            .fields(json!({"method": req.method, "path": url, "downstream_status": up.status}))
            .emit();
        let mut head: Vec<(String, String)> = ["content-length", "content-disposition", "x-content-type-options", "cache-control"]
            .iter()
            .filter_map(|k| up.header(k).map(|v| (k.to_string(), v.to_owned())))
            .collect();
        head.push(("content-type".into(), media(up.header("content-type").filter(|t| !t.is_empty()).unwrap_or("application/json"))));
        let status = up.status;
        relay(ex, status, head, &mut up)
    }

    // ── the edge's own routes ─────────────────────────────────────────────────────────────────
    fn auth_me(&self, req: &Req) -> Resp {
        let Some(key) = req.header("x-api-key").filter(|k| !k.is_empty()).map(str::to_owned) else {
            return Resp::detail(401, "Missing API key");
        };
        let user = match self.resolve(&key) {
            Err(e) => return auth_unavailable(&e, "auth"),
            Ok(None) => return Resp::detail(401, "Invalid API key"),
            Ok(Some(u)) => u,
        };
        let delegated = is_delegated(&key, &user);
        if delegated && !self.admits_reentry(req, &user) {
            return delegated_route();
        }
        if delegated && shared_delegation(&user) && !req.key.as_ref().is_some_and(|k| self.asm.shared_allow.contains(k)) {
            return shared_route();
        }
        obs::set_user(&user);
        obs::set_session(obs::session_of_validation(&user).as_deref());
        let mut m = Map::new();
        m.insert("user_id".into(), user.get("user_id").cloned().unwrap_or(Value::Null));
        m.insert("email".into(), user.get("email").cloned().unwrap_or_else(|| "".into()));
        m.insert("scopes".into(), user.get("scopes").cloned().unwrap_or_else(|| json!([])));
        m.insert("max_concurrent".into(), user.get("max_concurrent").cloned().unwrap_or_else(|| json!(3)));
        m.insert("is_admin".into(), reported(&user, delegated, "is_admin", "person_is_admin").into());
        m.insert("admin_account".into(), reported(&user, delegated, "admin_account", "person_admin_account").into());
        Resp::fastapi(200, &Value::Object(m))
    }

    fn mcp_taint(&self, ex: &mut Exchange, req: &Req) -> Out {
        let Some(key) = req.header("x-api-key").filter(|k| !k.is_empty()).map(str::to_owned) else {
            return Resp::detail(401, "Missing API key").into();
        };
        let user = match self.resolve(&key) {
            Err(e) => return auth_unavailable(&e, "auth").into(),
            Ok(None) => return Resp::detail(401, "Invalid API key").into(),
            Ok(Some(u)) => u,
        };
        if !is_delegated(&key, &user) {
            return Resp::fastapi(200, &json!({"marked": false, "state": "none"})).into();
        }
        if !self.admits_reentry(req, &user) {
            return delegated_route().into();
        }
        let Some(unit) = obs::session_of_validation(&user) else {
            return Resp::fastapi(200, &json!({"marked": false, "state": taint::UNVERIFIABLE})).into();
        };
        let content = match self.body(ex, req) {
            Ok(b) => b,
            Err(o) => return o,
        };
        let sources: BTreeSet<String> = match serde_json::from_slice::<Value>(&content) {
            Ok(Value::Object(m)) => match m.get("sources") {
                Some(v) if truthy(Some(v)) => match v {
                    Value::Array(a) => a.iter().map(py_str).collect(),
                    Value::String(s) => s.chars().map(|c| c.to_string()).collect(),
                    Value::Object(o) => o.keys().cloned().collect(),
                    _ => BTreeSet::new(),
                },
                _ => BTreeSet::new(),
            },
            _ => BTreeSet::new(),
        };
        if !sources.is_empty() && self.marker.mark(&unit, &sources).is_err() {
            return mark_refused().into();
        }
        Resp::fastapi(200, &json!({"marked": !sources.is_empty(), "state": self.marker.state_for(&unit)})).into()
    }

    fn mcp_key(req: &Req) -> Option<String> {
        let header = req.header("x-api-key").unwrap_or("").trim();
        if !header.is_empty() {
            return Some(header.to_owned());
        }
        let auth = req.header("authorization").unwrap_or("").trim();
        if auth.is_empty() {
            return None;
        }
        let (scheme, token) = auth.split_once(' ').unwrap_or((auth, ""));
        if scheme.eq_ignore_ascii_case("bearer") {
            let t = token.trim();
            return (!t.is_empty()).then(|| t.to_owned());
        }
        Some(auth.to_owned())
    }

    fn mcp(&self, path: &str) -> String {
        format!("{}{path}", self.mcp_url.trim_end_matches('/'))
    }

    fn admin(&self, path: &str) -> String {
        format!("{}{path}", self.admin_url)
    }

    fn dispatch(&self, ex: &mut Exchange, route: &Route, req: &Req) -> Out {
        let m = req.method.as_str();
        match &route.handler {
            Handler::Health => Resp::fastapi(200, &json!({"status": "ok", "service": "gateway"})).into(),
            Handler::AuthMe => self.auth_me(req).into(),
            Handler::McpTaint => self.mcp_taint(ex, req),
            Handler::Meeting => match self.meeting_target(req) {
                Ok(url) => self.forward(ex, m, &url, req, None),
                Err(r) => r.into(),
            },
            Handler::Bundle => self.forward_bundle(ex, req),
            Handler::Admin(path) => {
                let method = route.methods.iter().find(|x| *x != "HEAD").cloned().unwrap_or_default();
                self.forward(ex, &method, &self.admin(path), req, None)
            }
            Handler::AdminHandle => {
                let url = self.admin(&format!("/user/directory/profiles/{}", client::quote(&req.param("handle"))));
                self.forward(ex, "GET", &url, req, None)
            }
            Handler::AdminCalendar => match paths::path_segment(&req.param("calendar_id")) {
                Ok(seg) => {
                    let method = route.methods.iter().next().cloned().unwrap_or_default();
                    self.forward(ex, &method, &self.admin(&format!("/user/calendars/{seg}")), req, None)
                }
                Err(()) => invalid_path().into(),
            },
            Handler::McpStream => self.forward_stream_verbatim(ex, &self.mcp("/mcp"), req, Self::mcp_key(req)),
            Handler::McpStreamPath => match paths::tail_path(&req.param("path"), &req.raw_path) {
                Ok(tail) => self.forward_stream_verbatim(ex, &self.mcp(&format!("/mcp/{tail}")), req, Self::mcp_key(req)),
                Err(()) => invalid_path().into(),
            },
            Handler::McpMessage => self.forward(ex, m, &self.mcp("/mcp"), req, Self::mcp_key(req)),
            Handler::McpMessagePath => match paths::tail_path(&req.param("path"), &req.raw_path) {
                Ok(tail) => self.forward(ex, m, &self.mcp(&format!("/mcp/{tail}")), req, Self::mcp_key(req)),
                Err(()) => invalid_path().into(),
            },
            Handler::Literal { domain, template, method } => {
                if paths::encoded_separator(&req.raw_path) {
                    return invalid_path().into();
                }
                let (edge, upstream) = &self.asm.forwards[domain];
                let mut url = format!("{}{upstream}{}", self.forward_base[domain], &template[edge.len()..]);
                for name in crate::manifest::params_of(template) {
                    match paths::forwarded_param(&req.param(&name), &req.raw_path) {
                        Ok(seg) => url = url.replacen(&format!("{{{name}}}"), &seg, 1),
                        Err(()) => return invalid_path().into(),
                    }
                }
                if self.asm.stream.contains(&(method.clone(), template.clone())) {
                    self.forward_stream(ex, method, &url, req)
                } else {
                    self.forward(ex, method, &url, req, None)
                }
            }
            Handler::Tail { domain } => match paths::tail_path(&req.param("path"), &req.raw_path) {
                Ok(tail) => {
                    let (_, upstream) = &self.asm.forwards[domain];
                    let url = format!("{}{upstream}{tail}", self.forward_base[domain]);
                    self.forward(ex, m, &url, req, None)
                }
                Err(()) => invalid_path().into(),
            },
        }
    }

    // ── the request pipeline ──────────────────────────────────────────────────────────────────
    pub fn handle(&self, ex: &mut Exchange) {
        let head = ex.head.clone();
        let upgrade = head.header("upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
            && head.header("connection").is_some_and(|c| c.to_ascii_lowercase().contains("upgrade"));
        if upgrade {
            crate::multiplex::serve_upgrade(self, ex);
            return;
        }
        let peer = ex.peer.ip().to_string();
        if self.guard.enabled {
            let ip = self.guard.client_ip(&peer, head.header("x-forwarded-for"));
            if let Some((status, headers, body)) = self.guard.check(&ip) {
                let _ = ex.respond(status, &headers, &body);
                return;
            }
        }
        let content_type = head.header("content-type").unwrap_or("");
        let media_type = content_type.split(';').next().unwrap_or("").trim().to_lowercase();
        let capped = media_type.is_empty() || media_type.starts_with("text/") || media_type.ends_with("json") || media_type == "application/x-www-form-urlencoded";
        if capped {
            if let Some(n) = head.header("content-length").and_then(|v| v.trim().parse::<u64>().ok()) {
                if n > MAX_BODY_BYTES as u64 {
                    ex.close_after();
                    let r = too_large();
                    let _ = ex.respond(r.status, &r.headers, &r.body);
                    return;
                }
            }
        }
        let incoming = head.header(TRACE_HEADER).map(str::to_owned);
        let trace = incoming.clone().filter(|t| !t.is_empty()).unwrap_or_else(vexa_native_kit::ids::uuid_hex);
        let prev = obs::begin(Some(trace.clone()));
        let path = decode_path(&head.raw_path);
        let url_path = path.split(['?', '#']).next().unwrap_or("").to_owned();
        ev("request_received", "system", "debug", Some("edge"))
            .fields(json!({"method": head.method, "path": url_path, "minted": incoming.is_none()}))
            .emit();
        let mut req = Req {
            method: head.method.clone(),
            raw_path: head.raw_path.clone(),
            url_path,
            query: head.query.clone(),
            headers: head.headers.clone(),
            key: None,
            params: Vec::new(),
            body_capped: capped,
        };
        let out = match routes::find(&self.routes, &head.method, &path) {
            Match::Full(route, params) => {
                let errors = routes::validate(route, &params);
                if !errors.is_empty() {
                    Resp::fastapi(422, &json!({"detail": errors})).into()
                } else {
                    req.key = Some((head.method.clone(), route.path.clone()));
                    req.params = params;
                    STREAM_TRACE.with(|c| *c.borrow_mut() = Some(trace.clone()));
                    let out = self.dispatch(ex, route, &req);
                    STREAM_TRACE.with(|c| *c.borrow_mut() = None);
                    out
                }
            }
            Match::Partial(methods) => {
                let allow = methods.iter().cloned().collect::<Vec<_>>().join(", ");
                Resp::fastapi(405, &json!({"detail": "Method Not Allowed"})).header("allow", &allow).into()
            }
            Match::NotFound => match routes::redirect_path(&self.routes, &path) {
                Some(p) => {
                    let host = head.header("host").unwrap_or("");
                    let q = if head.query.is_empty() { String::new() } else { format!("?{}", head.query) };
                    Out::Whole(Resp { status: 307, headers: vec![("location".into(), format!("http://{host}{p}{q}"))], body: Vec::new() })
                }
                None => Resp::fastapi(404, &json!({"detail": "Not Found"})).into(),
            },
        };
        match out {
            Out::Whole(mut r) => {
                r.headers.push((TRACE_HEADER.into(), trace));
                let _ = ex.respond(r.status, &r.headers, &r.body);
            }
            Out::TooLarge => {
                ex.close_after();
                let r = too_large();
                let _ = ex.respond(r.status, &r.headers, &r.body);
            }
            Out::Done => {}
        }
        obs::restore(prev);
    }
}

thread_local! {
    /// The trace id a streamed answer's head carries.
    static STREAM_TRACE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// A request body relayed as it arrives, held to the body limit.
struct Limited<'a, 'b> {
    ex: &'a mut Exchange<'b>,
    seen: usize,
    cap: Option<usize>,
    over: bool,
}

impl std::io::Read for Limited<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.ex.read(buf)?;
        self.seen += n;
        if self.cap.is_some_and(|c| self.seen > c) {
            self.over = true;
            return Err(std::io::Error::other("request body is larger than the limit"));
        }
        Ok(n)
    }
}

/// Write the head, then the upstream body chunk by chunk as it arrives.
fn relay(ex: &mut Exchange, status: u16, mut head: Vec<(String, String)>, up: &mut client::Answer) -> Out {
    if let Some(t) = STREAM_TRACE.with(|c| c.borrow().clone()) {
        head.push((TRACE_HEADER.into(), t));
    }
    let Ok(mut s) = ex.stream(status, &head) else { return Out::Done };
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match up.chunk(&mut buf) {
            Ok(0) => {
                let _ = s.finish();
                return Out::Done;
            }
            Ok(n) => {
                if s.send(&buf[..n]).is_err() {
                    return Out::Done;
                }
            }
            Err(_) => return Out::Done,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_and_hops_like_httpx() {
        assert_eq!(query_params("a=1&a=2&b&c=%zz&d=x+y&e=%2B&=v&f==g"),
            vec![("a".into(), "2".into()), ("b".into(), "".into()), ("c".into(), "%zz".into()), ("d".into(), "x y".into()),
                 ("e".into(), "+".into()), ("".into(), "v".into()), ("f".into(), "=g".into())]);
        assert_eq!(hop_url("http://a/x", &[("a b".into(), "c d/é".into()), ("e".into(), "".into()), ("f".into(), "+&=".into())]),
            "http://a/x?a+b=c+d%2F%C3%A9&e=&f=%2B%26%3D");
        assert_eq!(hop_url("http://admin/user/directory/profiles/..", &[]), "http://admin/user/directory");
        assert_eq!(media("text/html"), "text/html; charset=utf-8");
    }
}
