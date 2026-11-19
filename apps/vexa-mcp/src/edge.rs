//! The edge's HTTP surface as FastAPI serves it: routing (404 / 405 / the trailing-slash 307),
//! the trace and re-entry middleware, the unknown-argument guard, the credential dependency,
//! request validation and its 422 rendering, and the assembled tools' routes. The built-in
//! tools' own logic is in `builtin.rs`; /mcp is in `mcp.rs`.

use std::sync::RwLock;
use std::time::Duration;

use serde_json::{json, Map, Value};
use vexa_native_kit::pyjson::{py_repr, py_str};

use crate::assembly::{self, Bound, Env};
use crate::mcp;
use crate::net;
use crate::pyd;
use crate::wire::{HttpError, Req, Resp};

pub struct Builtin {
    pub name: String,
    pub descriptor: Value,
    pub method: String,
    pub path: String,
    /// (name, required, schema) of each query parameter, in order.
    pub query: Vec<(String, bool, Value)>,
    pub body: Option<Value>,
    pub body_required: bool,
}

pub struct Assembled {
    pub bound: Bound,
    pub descriptor: Value,
}

pub struct Op {
    pub method: String,
    pub path: String,
    pub query: Vec<String>,
}

pub struct App {
    pub gateway: String,
    pub env: Env,
    pub builtins: Vec<Builtin>,
    pub assembled: RwLock<Vec<Assembled>>,
    /// The tools a shared caller may be shown (their manifest says `shared: allow`).
    pub shared: RwLock<Vec<String>>,
    pub policy: mcp::Policy,
    pub sessions: mcp::Sessions,
    pub instructions: String,
    pub surface: Value,
}

impl App {
    pub fn tools(&self) -> Vec<Value> {
        let mut out: Vec<Value> = self.builtins.iter().map(|b| b.descriptor.clone()).collect();
        out.extend(
            self.assembled
                .read()
                .unwrap()
                .iter()
                .map(|a| a.descriptor.clone()),
        );
        out
    }

    pub fn tool_schema(&self, name: &str) -> Option<Value> {
        if let Some(b) = self.builtins.iter().find(|b| b.name == name) {
            return Some(b.descriptor["inputSchema"].clone());
        }
        self.assembled
            .read()
            .unwrap()
            .iter()
            .find(|a| a.bound.name() == name)
            .map(|a| a.descriptor["inputSchema"].clone())
    }

    pub fn operation(&self, name: &str) -> Option<Op> {
        if let Some(b) = self.builtins.iter().find(|b| b.name == name) {
            return Some(Op {
                method: b.method.clone(),
                path: b.path.clone(),
                query: b.query.iter().map(|q| q.0.clone()).collect(),
            });
        }
        let list = self.assembled.read().unwrap();
        let a = list.iter().find(|a| a.bound.name() == name)?;
        let mut query = a.bound.path_params.clone();
        query.extend(a.bound.query_declared().into_iter().map(|(n, _)| n.clone()));
        Some(Op {
            method: a.bound.method().to_owned(),
            path: format!("/tools/{name}"),
            query,
        })
    }

    pub fn env(&self, key: &str) -> &str {
        assembly::env_str(&self.env, key)
    }
}

// ─── middleware ───────────────────────────────────────────────────────────────

/// One request through the whole app (TraceMiddleware → ReentryMiddleware → router).
pub fn handle(app: &'static App, mut req: Req) -> Resp {
    let mut trace = req.header("x-trace-id").unwrap_or("").trim().to_owned();
    if trace.is_empty() {
        trace = vexa_native_kit::ids::uuid_hex();
        req.headers.retain(|(k, _)| k != "x-trace-id");
        req.headers.push(("x-trace-id".into(), trace.clone()));
    }
    let identity = req
        .header("x-vexa-identity")
        .unwrap_or("")
        .trim()
        .to_owned();
    let held = crate::obs::bind(&trace, &identity);
    let mut resp = route(app, &req);
    crate::obs::restore(held);
    if !resp.untraced {
        resp.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("x-trace-id"));
        resp.headers.push(("x-trace-id".into(), trace));
    }
    resp
}

fn not_found() -> Resp {
    Resp::detail(404, "Not Found")
}

fn not_allowed(allow: &str) -> Resp {
    Resp::detail(405, "Method Not Allowed").header("allow", allow)
}

/// Does a route answer this path (any method)?
fn routed(app: &App, path: &str) -> bool {
    path == "/mcp"
        || path == "/health"
        || app.builtins.iter().any(|b| b.path == path)
        || path.strip_prefix("/tools/").is_some_and(|n| {
            app.assembled
                .read()
                .unwrap()
                .iter()
                .any(|a| a.bound.name() == n)
        })
}

fn route(app: &'static App, req: &Req) -> Resp {
    let path = req.path.as_str();
    let m = req.method.as_str();
    if path == "/health" {
        if m != "GET" {
            return not_allowed("GET");
        }
        if let Some(r) = unknown_arguments("health", &[], req) {
            return r;
        }
        return health(app);
    }
    if let Some(b) = app
        .builtins
        .iter()
        .find(|b| b.path == path && b.method == m)
    {
        return run_builtin(app, b, req);
    }
    if let Some(b) = app.builtins.iter().find(|b| b.path == path) {
        return not_allowed(&b.method);
    }
    if let Some(name) = path.strip_prefix("/tools/") {
        let found = app
            .assembled
            .read()
            .unwrap()
            .iter()
            .find(|a| a.bound.name() == name)
            .map(|a| a.bound.clone());
        if let Some(bound) = found {
            if bound.method() != m {
                return not_allowed(bound.method());
            }
            return run_assembled(app, &bound, req);
        }
    }
    if path == "/mcp" {
        if !matches!(m, "GET" | "POST" | "DELETE") {
            return not_allowed("POST, GET, DELETE");
        }
        if let Some(r) = unknown_arguments("mcp_http", &[], req) {
            return r;
        }
        return mcp::handle(app, req);
    }
    if path != "/" {
        let other = match path.strip_suffix('/') {
            Some(p) => p.to_owned(),
            None => format!("{path}/"),
        };
        if routed(app, &other) {
            let host = req.header("host").unwrap_or("localhost");
            let query = if req.raw_query.is_empty() {
                String::new()
            } else {
                format!("?{}", req.raw_query)
            };
            return Resp::new(307).header("location", &format!("http://{host}{other}{query}"));
        }
    }
    not_found()
}

fn health(app: &App) -> Resp {
    let state = |keys: &[&str], any: bool| {
        let set = keys
            .iter()
            .filter(|k| !app.env(k).trim().is_empty())
            .count();
        if set == 0 {
            "not_configured"
        } else if any || set == keys.len() {
            "configured"
        } else {
            "misconfigured"
        }
    };
    let assembly = state(
        &[
            "ADMIN_API_URL",
            "MEETING_API_URL",
            "FLOWS_API_URL",
            "VEXA_FLOWS_API_KEY",
            "AGENT_API_URL",
            "CRM_API_URL",
        ],
        true,
    );
    let private = state(&["VEXA_MCP_MANIFEST_DIR"], false);
    let sink = state(
        &[
            "VEXA_TICKET_SINK_URL",
            "VEXA_TICKET_SINK_TOKEN",
            "VEXA_TICKET_SINK_FORMAT",
            "VEXA_TICKET_SINK_LABELS",
        ],
        true,
    );
    Resp::json(
        200,
        &json!({"status": "ok", "service": "mcp",
        "capabilities": {"assembly": assembly, "private_domains": private, "ticket_sink": sink}}),
    )
}

// ─── the unknown-argument guard (difflib near-misses) ─────────────────────────

fn longest(
    a: &[char],
    b: &[char],
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> (usize, usize, usize) {
    let (mut bi, mut bj, mut bk) = (alo, blo, 0);
    let mut prev: std::collections::HashMap<usize, usize> = Default::default();
    for i in alo..ahi {
        let mut next = std::collections::HashMap::new();
        for j in blo..bhi {
            if b[j] != a[i] {
                continue;
            }
            let k = prev.get(&(j.wrapping_sub(1))).copied().unwrap_or(0) + 1;
            next.insert(j, k);
            if k > bk {
                (bi, bj, bk) = (i + 1 - k, j + 1 - k, k);
            }
        }
        prev = next;
    }
    (bi, bj, bk)
}

/// difflib.SequenceMatcher(None, a, b).ratio()
pub fn ratio(a: &str, b: &str) -> f64 {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let total = a.len() + b.len();
    if total == 0 {
        return 1.0;
    }
    let mut matches = 0;
    let mut queue = vec![(0, a.len(), 0, b.len())];
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = longest(&a, &b, alo, ahi, blo, bhi);
        if k > 0 {
            matches += k;
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
    }
    2.0 * matches as f64 / total as f64
}

fn close_match(word: &str, known: &[String]) -> Option<String> {
    let mut best: Option<(f64, &String)> = None;
    for x in known {
        let r = ratio(x, word);
        if r >= 0.5 && best.is_none_or(|(br, bx)| r > br || (r == br && x > bx)) {
            best = Some((r, x));
        }
    }
    best.map(|(_, x)| x.clone())
}

fn sorted_keys(req: &Req) -> Vec<String> {
    let mut keys: Vec<String> = req.query.iter().map(|(k, _)| k.clone()).collect();
    keys.sort();
    keys.dedup();
    keys
}

/// reject_unknown_arguments: a query parameter the route does not declare is a 422, by name.
fn unknown_arguments(tool: &str, known: &[String], req: &Req) -> Option<Resp> {
    let mut known: Vec<String> = known.to_vec();
    known.sort();
    known.dedup();
    let unknown: Vec<String> = sorted_keys(req)
        .into_iter()
        .filter(|k| !known.contains(k))
        .collect();
    if unknown.is_empty() {
        return None;
    }
    let mut hints = Vec::new();
    for got in &unknown {
        let near = close_match(got, &known).or_else(|| {
            known
                .iter()
                .find(|k| *k != got && (k.contains(got.as_str()) || got.contains(k.as_str())))
                .cloned()
        });
        if let Some(n) = near {
            hints.push(format!("`{got}` — did you mean `{n}`?"));
        }
    }
    let mut detail = Map::new();
    detail.insert("tool".into(), tool.into());
    detail.insert(
        "message".into(),
        format!(
            "{tool}: unknown argument(s) {}. This tool accepts {}.",
            py_repr(&json!(unknown)),
            py_repr(&json!(known))
        )
        .into(),
    );
    detail.insert("unknown".into(), json!(unknown));
    detail.insert("accepted".into(), json!(known));
    if !hints.is_empty() {
        let hint = hints.join("; ");
        detail.insert(
            "message".into(),
            format!("{tool}: unknown argument(s) — {hint}").into(),
        );
        detail.insert("hint".into(), hint.into());
    }
    Some(Resp::detail(422, Value::Object(detail)))
}

// ─── the credential dependency ────────────────────────────────────────────────

/// get_api_key: HTTPBearer's credentials, else the raw Authorization, else X-API-Key.
pub fn api_key(req: &Req) -> Result<String, HttpError> {
    let auth = req.header("authorization");
    if let Some(a) = auth.filter(|a| !a.is_empty()) {
        let (scheme, param) = a.split_once(' ').unwrap_or((a, ""));
        if !scheme.is_empty()
            && !param.is_empty()
            && scheme.to_lowercase() == "bearer"
            && !param.trim().is_empty()
        {
            return Ok(param.trim().to_owned());
        }
    }
    if let Some(a) = auth.filter(|a| !a.trim().is_empty()) {
        if a.to_lowercase().starts_with("bearer ") {
            let t = a.split_once(' ').map(|(_, t)| t.trim()).unwrap_or("");
            if !t.is_empty() {
                return Ok(t.to_owned());
            }
        } else {
            return Ok(a.trim().to_owned());
        }
    } else if let Some(k) = req.header("x-api-key").filter(|k| !k.trim().is_empty()) {
        return Ok(k.trim().to_owned());
    }
    Err(HttpError::new(
        401,
        "Missing credentials (send Authorization: Bearer <VEXA_API_KEY>).",
    )
    .with_header("www-authenticate", "Bearer"))
}

// ─── validation ───────────────────────────────────────────────────────────────

/// The RequestValidationError handler: name the tool, echo what was received, point at near-misses.
fn validation_error(tool: &str, req: &Req, errors: Vec<Value>) -> Resp {
    let received = sorted_keys(req);
    let missing: Vec<String> = errors
        .iter()
        .filter(|e| e["type"] == "missing")
        .filter_map(|e| e["loc"].as_array().and_then(|l| l.last()).map(py_str))
        .collect();
    let mut hints = Vec::new();
    for want in &missing {
        let near = received.iter().find(|got| {
            *got != want
                && (want.contains(got.as_str())
                    || got.contains(want.as_str())
                    || got.ends_with(want.as_str())
                    || want.ends_with(got.as_str()))
        });
        if let Some(n) = near {
            hints.push(format!("you sent `{n}` — this tool expects `{want}`"));
        }
    }
    let mut detail = Map::new();
    detail.insert("tool".into(), tool.into());
    detail.insert(
        "message".into(),
        format!("{tool}: invalid arguments.").into(),
    );
    detail.insert("missing".into(), json!(missing));
    detail.insert(
        "received".into(),
        if received.is_empty() {
            json!(["(none)"])
        } else {
            json!(received)
        },
    );
    detail.insert("errors".into(), Value::Array(errors));
    if !hints.is_empty() {
        let hint = hints.join("; ");
        detail.insert(
            "message".into(),
            format!("{tool}: invalid arguments — {hint}.").into(),
        );
        detail.insert("hint".into(), hint.into());
    }
    Resp::detail(422, Value::Object(detail))
}

/// FastAPI's body read for a route that declares a body: Ok(None) for no body, Err for bad JSON.
fn read_body(req: &Req) -> Result<Option<Value>, Value> {
    if req.body.is_empty() {
        return Ok(None);
    }
    let json_type = match req.header("content-type") {
        None => true,
        Some(ct) => {
            let main = ct.split(';').next().unwrap_or("").trim().to_lowercase();
            match main.split_once('/') {
                Some(("application", sub)) => sub == "json" || sub.ends_with("+json"),
                _ => false,
            }
        }
    };
    if !json_type {
        return Ok(Some(Value::String(
            String::from_utf8_lossy(&req.body).into_owned(),
        )));
    }
    crate::pyjson_decode::loads_bytes(&req.body).map(Some).map_err(|e| {
        json!({"type": "json_invalid", "loc": ["body", e.pos], "msg": "JSON decode error", "input": {}, "ctx": {"error": e.msg}})
    })
}

/// The query parameters a route declares, validated in order (defaults filled).
fn query_values(
    params: &[(String, bool, Value)],
    req: &Req,
    errs: &mut Vec<Value>,
) -> Map<String, Value> {
    let mut out = Map::new();
    for (name, required, schema) in params {
        let loc = [json!("query"), json!(name)];
        let is_list = assembly::edge_type(schema) == "array" && schema.get("anyOf").is_some();
        if is_list {
            let values: Vec<Value> = req
                .query
                .iter()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| Value::String(v.clone()))
                .collect();
            out.insert(
                name.clone(),
                if values.is_empty() {
                    Value::Null
                } else {
                    Value::Array(values)
                },
            );
            continue;
        }
        match req.param(name) {
            Some(text) => {
                if let Some(v) = pyd::text(schema, text, &loc, errs) {
                    out.insert(name.clone(), v);
                }
            }
            None if *required => errs.push(pyd::missing(&loc, Value::Null)),
            None => {
                out.insert(
                    name.clone(),
                    schema.get("default").cloned().unwrap_or(Value::Null),
                );
            }
        }
    }
    out
}

fn respond(result: Result<Value, HttpError>) -> Resp {
    match result {
        // A route annotated `-> Dict[str, Any]` that produced anything else fails its response model.
        Ok(v) if v.is_object() => Resp::json(200, &v),
        Ok(_) => Resp::internal_error(),
        Err(e) => e.into_resp(),
    }
}

fn run_builtin(app: &'static App, b: &Builtin, req: &Req) -> Resp {
    let body = if b.body.is_some() {
        match read_body(req) {
            Ok(v) => v,
            Err(e) => return validation_error(&b.name, req, vec![e]),
        }
    } else {
        None
    };
    let known: Vec<String> = b.query.iter().map(|q| q.0.clone()).collect();
    if let Some(r) = unknown_arguments(&b.name, &known, req) {
        return r;
    }
    let key = match api_key(req) {
        Ok(k) => k,
        Err(e) => return e.into_resp(),
    };
    let mut errs = Vec::new();
    let query = query_values(&b.query, req, &mut errs);
    let mut model = Map::new();
    if let Some(schema) = &b.body {
        match &body {
            None if b.body_required => errs.push(pyd::missing(&[json!("body")], Value::Null)),
            None => {}
            Some(v) => {
                let before = errs.len();
                if let Some(m) = pyd::model(schema, v, &[json!("body")], &mut errs) {
                    model = m;
                }
                if errs.len() == before {
                    if let Some(text) = crate::builtin::model_check(&b.name, &mut model) {
                        errs.push(pyd::value_error(&[json!("body")], &text, v.clone()));
                    }
                }
            }
        }
    }
    if !errs.is_empty() {
        return validation_error(&b.name, req, errs);
    }
    respond(crate::builtin::run(app, &b.name, &query, &model, &key, req))
}

// ─── the gateway hop the built-in tools make ──────────────────────────────────

pub fn gateway_headers(key: &str) -> Vec<(String, String)> {
    let mut h = vec![
        ("X-API-Key".to_owned(), key.to_owned()),
        ("Content-Type".to_owned(), "application/json".to_owned()),
    ];
    h.extend(crate::obs::reentry());
    h.extend(crate::obs::headers());
    h
}

fn url_path(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let path = rest.find('/').map_or("/", |i| &rest[i..]);
    path.split('?').next().unwrap_or("/").to_owned()
}

fn upstream_failed(method: &str, url: &str, what: (&str, Value)) {
    let mut f = Map::new();
    f.insert("method".into(), method.into());
    f.insert("path".into(), url_path(url).into());
    f.insert(what.0.into(), what.1);
    crate::obs::log("upstream_failed", "warning", Value::Object(f));
}

/// make_request: the caller's key to the gateway; a refusal re-raised with its detail unwrapped.
pub fn make_request(
    method: &str,
    url: &str,
    key: &str,
    payload: Option<&Value>,
    params: &[(String, Value)],
) -> Result<Value, HttpError> {
    let pairs: Vec<(String, String)> = params
        .iter()
        .flat_map(|(k, v)| mcp::query_text(v).into_iter().map(move |t| (k.clone(), t)))
        .collect();
    let full = net::with_query(url, &pairs);
    let body = payload.map(|p| crate::wire::compact(p).into_bytes());
    match net::request(
        method,
        &full,
        &gateway_headers(key),
        body.as_deref(),
        Duration::from_secs(10),
    ) {
        Err(net::NetError::Timeout) => {
            upstream_failed(method, url, ("error", "ReadTimeout".into()));
            Err(HttpError::new(504, "Request timed out"))
        }
        Err(net::NetError::Failed(e)) => {
            upstream_failed(method, url, ("error", "ConnectError".into()));
            Err(HttpError::new(503, format!("Request failed: {e}")))
        }
        Ok(r) if !(200..300).contains(&r.status) => {
            if r.status >= 500 {
                upstream_failed(method, url, ("status", r.status.into()));
            }
            let detail = match crate::pyjson_decode::loads_bytes(&r.body) {
                Ok(v) => mcp::unwrap_detail(v),
                Err(_) => Value::String(r.text()),
            };
            Err(HttpError::new(r.status, detail))
        }
        Ok(r) if r.body.is_empty() => Ok(json!({})),
        Ok(r) => crate::pyjson_decode::loads_bytes(&r.body)
            .map_err(|e| HttpError::new(500, format!("Unexpected error: {}", e.text()))),
    }
}

// ─── assembled routes (/tools/<name>) ─────────────────────────────────────────

const ADMIN_REFUSAL: &str = "this tool acts with the deployment's own operator key, so only the deployment's admin account, calling with its own credential, may use it — sign in as the admin account (an everyday account, the instance admin's included, cannot)";

fn require_admin(app: &App, key: &str) -> Result<(), HttpError> {
    if app.gateway.is_empty() || key.is_empty() {
        return Err(HttpError::new(403, ADMIN_REFUSAL));
    }
    let mut headers = vec![("X-API-Key".to_owned(), key.to_owned())];
    headers.extend(crate::obs::reentry());
    headers.extend(crate::obs::headers());
    let r = net::request(
        "GET",
        &format!("{}/auth/me", app.gateway),
        &headers,
        None,
        assembly::TOOL_TIMEOUT,
    )
    .map_err(|_| HttpError::new(503, "could not confirm who is calling; try again"))?;
    let me = if r.status == 200 {
        crate::pyjson_decode::loads_bytes(&r.body).unwrap_or(json!({}))
    } else {
        json!({})
    };
    if me.get("admin_account") != Some(&Value::Bool(true)) {
        return Err(HttpError::new(403, ADMIN_REFUSAL));
    }
    Ok(())
}

/// taint.py's POST to the gateway; None for every way it can fail.
fn taint_post(app: &App, key: &str, sources: &[String]) -> Option<Map<String, Value>> {
    if app.gateway.is_empty() || key.is_empty() {
        return None;
    }
    let mut headers = vec![("X-API-Key".to_owned(), key.to_owned())];
    headers.extend(crate::obs::reentry());
    headers.push(("Content-Type".into(), "application/json".into()));
    let body = crate::wire::compact(&json!({"sources": sources}));
    let r = net::request(
        "POST",
        &format!("{}/internal/mcp/taint", app.gateway),
        &headers,
        Some(body.as_bytes()),
        Duration::from_secs(5),
    )
    .ok()?;
    if r.status != 200 {
        return None;
    }
    match crate::pyjson_decode::loads_bytes(&r.body) {
        Ok(Value::Object(o)) => Some(o),
        _ => None,
    }
}

fn taint_clean(s: &str) -> String {
    let lower = s.trim().to_lowercase();
    let kept: String = lower
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.:() -".contains(*c))
        .collect();
    kept.chars().take(64).collect()
}

/// taint.parse_label: the private classes an answer's label names (sorted).
pub fn parse_label(value: Option<&str>) -> Vec<String> {
    let raw = value.unwrap_or("").trim().to_lowercase();
    if raw == "none" || raw == "shareable" {
        return Vec::new();
    }
    if !raw.starts_with("private") {
        return vec!["unlabelled".into()];
    }
    let rest = raw.split_once(';').map_or("", |(_, r)| r);
    let mut classes: Vec<String> = Vec::new();
    for part in rest.split(';') {
        let (k, v) = part.trim().split_once('=').unwrap_or((part.trim(), ""));
        if k.trim() == "class" {
            for c in v.split(',') {
                let c = taint_clean(c);
                if !c.is_empty() && !classes.contains(&c) {
                    classes.push(c);
                }
            }
        }
    }
    if classes.is_empty() {
        classes.push("private".into());
    }
    classes.sort();
    classes
}

fn withheld_body() -> Value {
    json!({"refused": "privacy_mark_unavailable",
           "fault": {"code": "privacy_mark_unavailable", "retry": "later"},
           "instruction": "This tool returns the person's private data, and the privacy mark that keeps it out of shared pages could not be recorded, so its answer was withheld. Tell the person in one line and try again later."})
}

/// path_segment: one caller value as one opaque, percent-encoded path segment.
pub fn path_segment(value: &str) -> String {
    let seg = net::quote(value);
    if !seg.is_empty() && seg.chars().all(|c| c == '.') {
        return seg.replace('.', "%2E");
    }
    seg
}

fn assembled_failed(b: &Bound, what: (&str, Value)) {
    let mut f = Map::new();
    f.insert("tool".into(), b.name().into());
    f.insert("domain".into(), b.tool.domain.clone().into());
    f.insert("method".into(), b.method().into());
    f.insert("route".into(), b.template().into());
    f.insert(what.0.into(), what.1);
    crate::obs::log("upstream_failed", "warning", Value::Object(f));
}

fn run_assembled(app: &'static App, b: &Bound, req: &Req) -> Resp {
    let body_decl = b.body_declared();
    let body = if body_decl.is_empty() {
        None
    } else {
        match read_body(req) {
            Ok(v) => v,
            Err(e) => return validation_error(b.name(), req, vec![e]),
        }
    };
    let mut params: Vec<(String, bool, Value)> = b
        .path_params
        .iter()
        .map(|p| (p.clone(), true, json!({"type": "string"})))
        .collect();
    params.extend(b.query_declared().into_iter().map(|(n, s)| {
        (
            n.clone(),
            false,
            assembly::optional_schema(assembly::edge_type(s)),
        )
    }));
    let known: Vec<String> = params.iter().map(|p| p.0.clone()).collect();
    if let Some(r) = unknown_arguments(b.name(), &known, req) {
        return r;
    }
    let mut errs = Vec::new();
    let mut argument = query_values(&params, req, &mut errs);
    for (name, schema) in &body_decl {
        let loc = [json!("body"), json!(name)];
        match &body {
            None => {}
            Some(Value::Object(o)) => {
                if let Some(v) = o.get(name) {
                    if let Some(got) = pyd::value(
                        &assembly::optional_schema(assembly::edge_type(schema)),
                        v,
                        &loc,
                        &mut errs,
                    ) {
                        argument.insert(name.clone(), got);
                    }
                }
            }
            Some(_) => errs.push(pyd::missing(&loc, Value::Null)),
        }
    }
    if !errs.is_empty() {
        return validation_error(b.name(), req, errs);
    }
    match assembled_endpoint(app, b, req, &argument) {
        Ok(r) => r,
        Err(e) => e.into_resp(),
    }
}

fn assembled_endpoint(
    app: &App,
    b: &Bound,
    req: &Req,
    argument: &Map<String, Value>,
) -> Result<Resp, HttpError> {
    let key = mcp::caller_key(req);
    if key.is_empty() && b.tool.identity != "none" {
        return Err(HttpError::new(401, "this tool needs your Vexa credential"));
    }
    if b.tool.auth == "admin" {
        require_admin(app, &key)?;
    }
    let method = b.method();
    let mut raw_body = Map::new();
    if matches!(method, "POST" | "PUT" | "PATCH") {
        if let Ok(Value::Object(o)) = crate::pyjson_decode::loads_bytes(&req.body) {
            raw_body = o;
        }
    }
    let mut path = b.template().to_owned();
    for name in &b.path_params {
        let value = argument.get(name).cloned().unwrap_or(Value::Null);
        if value.is_null() || value == Value::String(String::new()) {
            return Err(HttpError::new(422, format!("{} needs {name}", b.name())));
        }
        path = path.replace(&format!("{{{name}}}"), &path_segment(&py_str(&value)));
    }
    let query_decl = b.query_declared();
    let mut params: Vec<(String, Value)> = query_decl
        .iter()
        .filter_map(|(n, _)| {
            argument
                .get(n)
                .filter(|v| !v.is_null())
                .map(|v| (n.clone(), v.clone()))
        })
        .collect();
    for (n, _) in &query_decl {
        if !params.iter().any(|(k, _)| k == n) {
            if let Some(v) = raw_body.shift_remove(n) {
                params.push((n.clone(), v));
            }
        }
    }
    let body_decl = b.body_declared();
    let body = if body_decl.is_empty() {
        raw_body
    } else {
        body_decl
            .iter()
            .filter_map(|(n, _)| {
                argument
                    .get(n)
                    .filter(|v| !v.is_null())
                    .map(|v| (n.clone(), v.clone()))
            })
            .collect()
    };
    let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
    if b.tool.auth == "subject" {
        headers.push(("X-API-Key".into(), key.clone()));
    } else if let (true, Some((header, key_env))) = (b.tool.auth == "admin", &b.tool.admin_auth) {
        headers.push((header.clone(), app.env(key_env).to_owned()));
    }
    headers.extend(crate::obs::headers());
    let forwarded = b.tool.forward.as_ref().filter(|_| !app.gateway.is_empty());
    let url = match forwarded {
        Some((edge, upstream)) => {
            headers.extend(crate::obs::reentry());
            format!(
                "{}{edge}{}",
                app.gateway,
                &path[upstream.len().min(path.len())..]
            )
        }
        None => {
            let state = if !crate::obs::behind_gateway() {
                "unverifiable".to_owned()
            } else {
                taint_post(app, &key, &[])
                    .and_then(|o| {
                        o.get("state")
                            .filter(|s| vexa_native_kit::pyjson::truthy(Some(s)))
                            .map(py_str)
                    })
                    .unwrap_or_else(|| "unverifiable".into())
            };
            headers.push(("X-Vexa-Taint".into(), state));
            format!("{}{path}", b.base)
        }
    };
    let pairs: Vec<(String, String)> = params
        .iter()
        .flat_map(|(k, v)| mcp::query_text(v).into_iter().map(move |t| (k.clone(), t)))
        .collect();
    let full = net::with_query(&url, &pairs);
    let payload = matches!(method, "POST" | "PUT" | "PATCH")
        .then(|| crate::wire::compact(&Value::Object(body)).into_bytes());
    let r = match net::request(
        method,
        &full,
        &headers,
        payload.as_deref(),
        assembly::TOOL_TIMEOUT,
    ) {
        Err(net::NetError::Timeout) => {
            assembled_failed(b, ("error", "ReadTimeout".into()));
            return Err(HttpError::new(504, format!("{} timed out", b.tool.domain)));
        }
        Err(net::NetError::Failed(e)) => {
            assembled_failed(b, ("error", "ConnectError".into()));
            return Err(HttpError::new(
                503,
                format!("{} is unreachable: {e}", b.tool.domain),
            ));
        }
        Ok(r) => r,
    };
    if r.status >= 500 {
        assembled_failed(b, ("status", r.status.into()));
    }
    if forwarded.is_none() && (200..300).contains(&r.status) {
        let found = parse_label(r.header("x-vexa-privacy"));
        if !found.is_empty()
            && crate::obs::behind_gateway()
            && taint_post(app, &key, &found).is_none()
        {
            return Ok(Resp::json(503, &json!({"detail": withheld_body()})));
        }
    }
    let payload = if r.body.is_empty() {
        json!({})
    } else {
        crate::pyjson_decode::loads_bytes(&r.body)
            .unwrap_or_else(|_| json!({"detail": r.text().chars().take(2000).collect::<String>()}))
    };
    Ok(Resp::json(r.status, &payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difflib_ratio() {
        assert!((ratio("limit", "limitt") - 10.0 / 11.0).abs() < 1e-9);
        assert!((ratio("native_meeting_id", "meeting_id_native") - 0.588235294117647).abs() < 1e-9);
        assert_eq!(
            close_match("limitt", &["limit".into(), "offset".into()]),
            Some("limit".into())
        );
    }

    #[test]
    fn labels_and_segments() {
        assert_eq!(
            parse_label(Some("private; class=crm, Mail!")),
            vec!["crm", "mail"]
        );
        assert_eq!(parse_label(None), vec!["unlabelled"]);
        assert!(parse_label(Some("shareable")).is_empty());
        assert_eq!(path_segment(".."), "%2E%2E");
        assert_eq!(path_segment("a/b"), "a%2Fb");
    }
}
