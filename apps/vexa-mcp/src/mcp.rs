//! /mcp — the MCP streamable-HTTP transport (JSON answers, one SSE stream per session) and the
//! JSON-RPC server behind it, as the mcp 1.30 SDK and fastapi-mcp 0.4 answer: the same checks in
//! the same order, the same error envelopes, and every tool call replayed in process onto the
//! tool's own route.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use vexa_native_kit::pyjson::{py_repr, truthy};

use crate::edge::{self, App};
use crate::wire::{compact, indented, Req, Resp};

const SUPPORTED: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
const LATEST: &str = "2025-11-25";
const DEFAULT_NEGOTIATED: &str = "2025-03-26";
const SESSION_HEADER: &str = "mcp-session-id";
const IDLE: Duration = Duration::from_secs(1800);
const MAX_SESSIONS: usize = 10_000;
pub const MAX_BODY: usize = 4 * 1024 * 1024;
const PING_EVERY: Duration = Duration::from_secs(15);

// ─── sessions ─────────────────────────────────────────────────────────────────

struct Session {
    last: Instant,
    stream: bool,
}

#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    fn sweep(map: &mut HashMap<String, Session>) {
        map.retain(|_, s| s.stream || s.last.elapsed() < IDLE);
    }

    fn touch(&self, id: &str) -> bool {
        let mut map = self.map.lock().unwrap();
        Self::sweep(&mut map);
        match map.get_mut(id) {
            Some(s) => {
                s.last = Instant::now();
                true
            }
            None => false,
        }
    }

    fn alive(&self, id: &str) -> bool {
        self.map.lock().unwrap().contains_key(id)
    }
}

fn error_body(code: i64, message: &str) -> String {
    compact(
        &json!({"jsonrpc": "2.0", "id": "server-error", "error": {"code": code, "message": message}}),
    )
}

/// The transport's error answer, carrying the session it belongs to.
fn transport_error(status: u16, code: i64, message: &str, sid: &str) -> Resp {
    Resp::new(status)
        .header("content-type", "application/json")
        .header(SESSION_HEADER, sid)
        .body(error_body(code, message))
}

fn json_answer(status: u16, body: Option<&Value>, sid: &str) -> Resp {
    let r = Resp::new(status)
        .header("content-type", "application/json")
        .header(SESSION_HEADER, sid);
    match body {
        Some(v) => r.body(compact(v)),
        None => r,
    }
}

/// One request to /mcp (GET, POST or DELETE; the unknown-argument guard already ran).
pub fn handle(app: &'static App, req: &Req) -> Resp {
    match req.header(SESSION_HEADER) {
        Some(sid) => {
            if !app.sessions.touch(sid) {
                return Resp::new(404)
                    .header("content-type", "application/json")
                    .body(error_body(-32600, "Session not found"));
            }
            let sid = sid.to_owned();
            transport(app, req, &sid)
        }
        None => {
            let sid = vexa_native_kit::ids::uuid_hex();
            {
                let mut map = app.sessions.map.lock().unwrap();
                Sessions::sweep(&mut map);
                if map.len() >= MAX_SESSIONS {
                    return Resp::new(503)
                        .header("content-type", "application/json")
                        .body(error_body(-32603, "Too many open sessions"));
                }
                map.insert(
                    sid.clone(),
                    Session {
                        last: Instant::now(),
                        stream: false,
                    },
                );
            }
            let resp = transport(app, req, &sid);
            if resp.status >= 400 {
                app.sessions.map.lock().unwrap().remove(&sid);
            }
            resp
        }
    }
}

fn accepts(req: &Req) -> (bool, bool) {
    let accept = req.header("accept").unwrap_or("");
    let items: Vec<String> = accept.split(',').map(|a| a.trim().to_lowercase()).collect();
    (
        items.iter().any(|a| a.starts_with("application/json")),
        items.iter().any(|a| a.starts_with("text/event-stream")),
    )
}

/// Session id and protocol version of a request on an established session.
fn check_session(req: &Req, sid: &str) -> Option<Resp> {
    match req.header(SESSION_HEADER) {
        None => {
            return Some(transport_error(
                400,
                -32600,
                "Bad Request: Missing session ID",
                sid,
            ))
        }
        Some(got) if got != sid => {
            return Some(transport_error(
                404,
                -32600,
                "Not Found: Invalid or expired session ID",
                sid,
            ))
        }
        _ => {}
    }
    let version = req
        .header("mcp-protocol-version")
        .unwrap_or(DEFAULT_NEGOTIATED);
    if !SUPPORTED.contains(&version) {
        let msg = format!(
            "Bad Request: Unsupported protocol version: {version}. Supported versions: {}",
            SUPPORTED.join(", ")
        );
        return Some(transport_error(400, -32600, &msg, sid));
    }
    None
}

fn transport(app: &'static App, req: &Req, sid: &str) -> Resp {
    match req.method.as_str() {
        "POST" => post(app, req, sid),
        "GET" => get(app, req, sid),
        _ => {
            if let Some(r) = check_session(req, sid) {
                return r;
            }
            app.sessions.map.lock().unwrap().remove(sid);
            json_answer(200, None, sid)
        }
    }
}

fn get(app: &'static App, req: &Req, sid: &str) -> Resp {
    if !accepts(req).1 {
        return transport_error(
            406,
            -32600,
            "Not Acceptable: Client must accept text/event-stream",
            sid,
        );
    }
    if let Some(r) = check_session(req, sid) {
        return r;
    }
    {
        let mut map = app.sessions.map.lock().unwrap();
        match map.get_mut(sid) {
            Some(s) if s.stream => {
                return transport_error(
                    409,
                    -32600,
                    "Conflict: Only one SSE stream is allowed per session",
                    sid,
                )
            }
            Some(s) => s.stream = true,
            None => {}
        }
    }
    let sessions = &app.sessions;
    let id = sid.to_owned();
    let mut r = Resp::new(200)
        .header("cache-control", "no-cache, no-transform")
        .header("connection", "keep-alive")
        .header("content-type", "text/event-stream")
        .header(SESSION_HEADER, sid);
    r.stream = Some(Box::new(move |out: &mut std::net::TcpStream| {
        let step = Duration::from_millis(250);
        let mut waited = Duration::ZERO;
        loop {
            std::thread::sleep(step);
            waited += step;
            if !sessions.alive(&id) {
                break;
            }
            if waited >= PING_EVERY {
                waited = Duration::ZERO;
                let ping = format!(": ping - {}\r\n\r\n", py_datetime_now());
                if out
                    .write_all(format!("{:x}\r\n{ping}\r\n", ping.len()).as_bytes())
                    .and_then(|_| out.flush())
                    .is_err()
                {
                    break;
                }
            }
            let mut probe = [0u8; 1];
            out.set_nonblocking(true).ok();
            let gone = matches!(std::io::Read::read(out, &mut probe), Ok(0));
            out.set_nonblocking(false).ok();
            if gone {
                break;
            }
        }
        if let Some(s) = sessions.map.lock().unwrap().get_mut(&id) {
            s.stream = false;
            s.last = Instant::now();
        }
        let _ = out.write_all(b"0\r\n\r\n");
    }));
    r
}

/// str(datetime.now(timezone.utc)): "2026-11-19 12:00:00.123456+00:00".
fn py_datetime_now() -> String {
    vexa_native_kit::ids::utc_isoformat(vexa_native_kit::ids::now()).replacen('T', " ", 1)
}

fn post(app: &'static App, req: &Req, sid: &str) -> Resp {
    let ct = req.header("content-type").unwrap_or("");
    if !ct.to_lowercase().starts_with("application/json") {
        return Resp::bare(400, "Invalid Content-Type header");
    }
    if !accepts(req).0 {
        return transport_error(
            406,
            -32600,
            "Not Acceptable: Client must accept application/json",
            sid,
        );
    }
    let exact = ct
        .split(';')
        .next()
        .unwrap_or("")
        .split(',')
        .any(|p| p.trim() == "application/json");
    if !exact {
        return transport_error(
            415,
            -32600,
            "Unsupported Media Type: Content-Type must be application/json",
            sid,
        );
    }
    if req.body.len() > MAX_BODY {
        return Resp::new(413)
            .header("content-type", "text/plain; charset=utf-8")
            .body("Request body too large");
    }
    let raw = match crate::pyjson_decode::loads_bytes(&req.body) {
        Ok(v) => v,
        Err(e) => return transport_error(400, -32700, &format!("Parse error: {}", e.text()), sid),
    };
    let kind = match message_kind(&raw) {
        Ok(k) => k,
        Err(text) => {
            return transport_error(400, -32602, &format!("Validation error: {text}"), sid)
        }
    };
    let is_init =
        kind == Kind::Request && raw.get("method").and_then(Value::as_str) == Some("initialize");
    if is_init {
        if let Some(got) = req.header(SESSION_HEADER) {
            if !got.is_empty() && got != sid {
                return transport_error(
                    404,
                    -32600,
                    "Not Found: Invalid or expired session ID",
                    sid,
                );
            }
        }
    } else if let Some(r) = check_session(req, sid) {
        return r;
    }
    if kind != Kind::Request {
        return json_answer(202, None, sid);
    }
    let answer = serve(app, req, &raw);
    json_answer(200, Some(&answer), sid)
}

// ─── JSON-RPC message validation (pydantic's JSONRPCMessage union) ────────────

#[derive(PartialEq, Clone, Copy, Debug)]
enum Kind {
    Request,
    Notification,
    Response,
    Error,
}

const MODELS: [&str; 4] = [
    "JSONRPCRequest",
    "JSONRPCNotification",
    "JSONRPCResponse",
    "JSONRPCError",
];

fn py_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// pydantic-core's input_value: the repr, cut to 25 + "..." + 24 characters past 50.
fn input_repr(v: &Value) -> String {
    let r = py_repr(v);
    let chars: Vec<char> = r.chars().collect();
    if chars.len() <= 50 {
        return r;
    }
    format!(
        "{}...{}",
        chars[..25].iter().collect::<String>(),
        chars[chars.len() - 24..].iter().collect::<String>()
    )
}

struct PydErr {
    loc: String,
    msg: String,
    kind: &'static str,
    input: Value,
}

fn err(loc: String, msg: &str, kind: &'static str, input: &Value) -> PydErr {
    PydErr {
        loc,
        msg: msg.to_owned(),
        kind,
        input: input.clone(),
    }
}

fn id_errs(model: &str, v: Option<&Value>, out: &mut Vec<PydErr>, whole: &Value, nullable: bool) {
    match v {
        None => out.push(err(
            format!("{model}.id"),
            "Field required",
            "missing",
            whole,
        )),
        Some(Value::Null) if nullable => {}
        Some(Value::String(_)) => {}
        Some(Value::Number(n))
            if n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0) => {}
        Some(other) => {
            out.push(err(
                format!("{model}.id.int"),
                "Input should be a valid integer",
                "int_type",
                other,
            ));
            out.push(err(
                format!("{model}.id.str"),
                "Input should be a valid string",
                "string_type",
                other,
            ));
        }
    }
}

fn method_errs(model: &str, obj: &Map<String, Value>, whole: &Value, out: &mut Vec<PydErr>) {
    match obj.get("method") {
        None => out.push(err(
            format!("{model}.method"),
            "Field required",
            "missing",
            whole,
        )),
        Some(Value::String(_)) => {}
        Some(other) => out.push(err(
            format!("{model}.method"),
            "Input should be a valid string",
            "string_type",
            other,
        )),
    }
}

fn params_errs(model: &str, obj: &Map<String, Value>, out: &mut Vec<PydErr>) {
    match obj.get("params") {
        None | Some(Value::Null) | Some(Value::Object(_)) => {}
        Some(other) => out.push(err(
            format!("{model}.params"),
            "Input should be a valid dictionary",
            "dict_type",
            other,
        )),
    }
}

fn model_errs(model: &str, obj: &Map<String, Value>, whole: &Value) -> Vec<PydErr> {
    let mut out = Vec::new();
    match obj.get("jsonrpc") {
        None => out.push(err(
            format!("{model}.jsonrpc"),
            "Field required",
            "missing",
            whole,
        )),
        Some(Value::String(s)) if s == "2.0" => {}
        Some(other) => out.push(err(
            format!("{model}.jsonrpc"),
            "Input should be '2.0'",
            "literal_error",
            other,
        )),
    }
    match model {
        "JSONRPCRequest" => {
            id_errs(model, obj.get("id"), &mut out, whole, false);
            method_errs(model, obj, whole, &mut out);
            params_errs(model, obj, &mut out);
        }
        "JSONRPCNotification" => {
            method_errs(model, obj, whole, &mut out);
            params_errs(model, obj, &mut out);
        }
        "JSONRPCResponse" => {
            id_errs(model, obj.get("id"), &mut out, whole, false);
            match obj.get("result") {
                None => out.push(err(
                    format!("{model}.result"),
                    "Field required",
                    "missing",
                    whole,
                )),
                Some(Value::Object(_)) => {}
                Some(other) => out.push(err(
                    format!("{model}.result"),
                    "Input should be a valid dictionary",
                    "dict_type",
                    other,
                )),
            }
        }
        _ => {
            id_errs(model, obj.get("id"), &mut out, whole, true);
            match obj.get("error") {
                None => out.push(err(
                    format!("{model}.error"),
                    "Field required",
                    "missing",
                    whole,
                )),
                Some(e @ Value::Object(m)) => {
                    for k in ["code", "message"] {
                        if !m.contains_key(k) {
                            out.push(err(
                                format!("{model}.error.{k}"),
                                "Field required",
                                "missing",
                                e,
                            ));
                        }
                    }
                }
                Some(other) => out.push(err(
                    format!("{model}.error"),
                    "Input should be a valid dictionary or instance of ErrorData",
                    "model_type",
                    other,
                )),
            }
        }
    }
    out
}

fn message_kind(v: &Value) -> Result<Kind, String> {
    let kinds = [
        Kind::Request,
        Kind::Notification,
        Kind::Response,
        Kind::Error,
    ];
    let mut errs: Vec<PydErr> = Vec::new();
    match v.as_object() {
        None => {
            for m in MODELS {
                errs.push(err(
                    m.into(),
                    &format!("Input should be a valid dictionary or instance of {m}"),
                    "model_type",
                    v,
                ));
            }
        }
        Some(obj) => {
            for (i, m) in MODELS.iter().enumerate() {
                let e = model_errs(m, obj, v);
                if e.is_empty() {
                    return Ok(kinds[i]);
                }
                errs.extend(e);
            }
        }
    }
    let n = errs.len();
    let mut text = format!(
        "{n} validation error{} for JSONRPCMessage",
        if n == 1 { "" } else { "s" }
    );
    for e in errs {
        text.push_str(&format!(
            "\n{}\n  {} [type={}, input_value={}, input_type={}]\n    For further information visit https://errors.pydantic.dev/2.13/v/{}",
            e.loc,
            e.msg,
            e.kind,
            input_repr(&e.input),
            py_type(&e.input),
            e.kind
        ));
    }
    Err(text)
}

// ─── the server ───────────────────────────────────────────────────────────────

const UNION: [&str; 17] = [
    "ping",
    "initialize",
    "completion/complete",
    "logging/setLevel",
    "prompts/get",
    "prompts/list",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "resources/subscribe",
    "resources/unsubscribe",
    "tools/call",
    "tools/list",
    "tasks/get",
    "tasks/result",
    "tasks/list",
    "tasks/cancel",
];

fn is_str(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(_)))
}

/// ClientRequest.model_validate: does this method's params model accept these params?
fn params_valid(method: &str, params: Option<&Value>) -> bool {
    if params.is_some_and(|v| !v.is_object()) {
        return false;
    }
    let p = params.and_then(Value::as_object);
    let has = |k: &str| p.and_then(|m| m.get(k)).filter(|v| !v.is_null());
    match method {
        "ping"
        | "prompts/list"
        | "resources/list"
        | "resources/templates/list"
        | "tools/list"
        | "tasks/list" => has("cursor").is_none_or(|c| c.is_string()),
        "initialize" => {
            let info = has("clientInfo").and_then(Value::as_object);
            is_str(has("protocolVersion"))
                && has("capabilities").is_some_and(Value::is_object)
                && info.is_some_and(|i| is_str(i.get("name")) && is_str(i.get("version")))
        }
        "tools/call" => is_str(has("name")) && has("arguments").is_none_or(|a| a.is_object()),
        "prompts/get" => {
            is_str(has("name"))
                && has("arguments").is_none_or(|a| {
                    a.as_object()
                        .is_some_and(|m| m.values().all(Value::is_string))
                })
        }
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => is_str(has("uri")),
        "tasks/get" | "tasks/result" | "tasks/cancel" => is_str(has("taskId")),
        "logging/setLevel" => has("level").and_then(Value::as_str).is_some_and(|l| {
            [
                "debug",
                "info",
                "notice",
                "warning",
                "error",
                "critical",
                "alert",
                "emergency",
            ]
            .contains(&l)
        }),
        "completion/complete" => {
            has("ref").is_some_and(Value::is_object)
                && has("argument").is_some_and(Value::is_object)
        }
        _ => false,
    }
}

/// One JSON-RPC request -> its response message.
fn serve(app: &'static App, req: &Req, msg: &Value) -> Value {
    let id = match msg.get("id").cloned().unwrap_or(Value::Null) {
        Value::Number(n) if n.is_f64() => Value::from(n.as_f64().unwrap_or(0.0) as i64),
        other => other,
    };
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").filter(|p| !p.is_null());
    let ok = |result: Value| json!({"jsonrpc": "2.0", "id": id, "result": result});
    let fail = |code: i64, message: &str, data: Option<&str>| {
        let mut e = json!({"code": code, "message": message});
        if let Some(d) = data {
            e["data"] = d.into();
        }
        json!({"jsonrpc": "2.0", "id": id, "error": e})
    };
    if !UNION.contains(&method) || !params_valid(method, params) {
        return fail(-32602, "Invalid request parameters", Some(""));
    }
    let p = params.cloned().unwrap_or(json!({}));
    match method {
        "ping" => ok(json!({})),
        "initialize" => {
            let asked = p["protocolVersion"].as_str().unwrap_or("");
            let version = if SUPPORTED.contains(&asked) {
                asked
            } else {
                LATEST
            };
            ok(json!({
                "protocolVersion": version,
                "capabilities": {"experimental": {}, "prompts": {"listChanged": false}, "tools": {"listChanged": false}},
                "serverInfo": {"name": "Vexa MCP Service (v0.12)", "version": "1.30.0"},
                "instructions": app.instructions,
            }))
        }
        "tools/list" => {
            let tools: Vec<Value> = app
                .tools()
                .into_iter()
                .filter(|t| app.policy.shown(t["name"].as_str().unwrap_or(""), req, app))
                .collect();
            ok(json!({"tools": tools}))
        }
        "tools/call" => {
            let name = p["name"].as_str().unwrap_or("").to_owned();
            let args = p.get("arguments").and_then(Value::as_object).cloned();
            ok(call_tool(app, req, &name, args))
        }
        "prompts/list" => ok(json!({"prompts": app.surface["prompts"]})),
        "prompts/get" => {
            let name = p["name"].as_str().unwrap_or("");
            match prompt(app, name, p.get("arguments").and_then(Value::as_object)) {
                Some(r) => ok(r),
                None => fail(0, &format!("Unknown prompt: {name}"), None),
            }
        }
        _ => fail(-32601, "Method not found", None),
    }
}

/// get_prompt_result: the generated text with each argument's stripped value (or its fallback).
fn prompt(app: &App, name: &str, args: Option<&Map<String, Value>>) -> Option<Value> {
    let template = app.surface["prompt_results"].get(name)?;
    let fallback = match name {
        "vexa.meeting_prep" => "(none)",
        "vexa.teams_link_help" => "(none provided)",
        _ => "",
    };
    // The generator wrote each argument as NUL<name>NUL; compact JSON spells NUL as a 6-character escape.
    let nul = concat!("\\", "u", "0000");
    let mut text = compact(template);
    for p in app.surface["prompts"]
        .as_array()?
        .iter()
        .filter(|p| p["name"] == name)
    {
        for a in p["arguments"].as_array().into_iter().flatten() {
            let an = a["name"].as_str().unwrap_or("");
            let given = args
                .and_then(|m| m.get(an))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_owned();
            let value = if given.is_empty() {
                fallback.to_owned()
            } else {
                given
            };
            let quoted = compact(&Value::String(value));
            text = text.replace(&format!("{nul}{an}{nul}"), &quoted[1..quoted.len() - 1]);
        }
    }
    serde_json::from_str(&text).ok()
}

fn error_result(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": true})
}

// ─── tools/call ───────────────────────────────────────────────────────────────

fn branches(schema: &Value) -> impl Iterator<Item = &Value> {
    schema
        .get("anyOf")
        .filter(|b| truthy(Some(b)))
        .or_else(|| schema.get("oneOf"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn types_of(schema: &Value) -> HashSet<String> {
    let mut out = HashSet::new();
    match schema.get("type") {
        Some(Value::String(t)) => {
            out.insert(t.clone());
        }
        Some(Value::Array(ts)) => {
            out.extend(ts.iter().filter_map(|t| t.as_str().map(str::to_owned)))
        }
        _ => {}
    }
    for b in branches(schema) {
        out.extend(types_of(b));
    }
    out
}

fn array_of_strings(schema: &Value) -> bool {
    if !schema.is_object() {
        return false;
    }
    if schema.get("type").and_then(Value::as_str) == Some("array") {
        let items = types_of(schema.get("items").unwrap_or(&json!({})));
        return items.is_empty() || items.contains("string");
    }
    branches(schema).any(array_of_strings)
}

/// arguments.coerce: a stringified array/object argument read as the value it spells.
pub fn coerce(args: &Map<String, Value>, schema: &Value) -> Map<String, Value> {
    let props = schema.get("properties").and_then(Value::as_object);
    let mut out = args.clone();
    for (name, value) in args {
        let (Value::String(text), Some(prop)) = (value, props.and_then(|p| p.get(name))) else {
            continue;
        };
        let kinds = types_of(prop);
        if kinds.contains("string") || !(kinds.contains("array") || kinds.contains("object")) {
            continue;
        }
        match crate::pyjson_decode::loads(text).ok() {
            Some(Value::Array(a)) if kinds.contains("array") => {
                out.insert(name.clone(), Value::Array(a));
            }
            Some(Value::Object(o)) if kinds.contains("object") => {
                out.insert(name.clone(), Value::Object(o));
            }
            None | Some(Value::Null) if !text.trim().is_empty() && array_of_strings(prop) => {
                out.insert(name.clone(), json!([text]));
            }
            _ => {}
        }
    }
    out
}

fn call_tool(
    app: &'static App,
    outer: &Req,
    name: &str,
    args: Option<Map<String, Value>>,
) -> Value {
    let schema = app.tool_schema(name);
    let mut args = args.unwrap_or_default();
    if let Some(s) = &schema {
        if !args.is_empty() {
            args = coerce(&args, s);
        }
    }
    if !app.policy.shown(name, outer, app) {
        return error_result(&format!("Unknown tool: {name}"));
    }
    if let Some(s) = &schema {
        if let Some(msg) = crate::schema::validate(&Value::Object(args.clone()), s) {
            return error_result(&format!("Input validation error: {msg}"));
        }
    }
    let mut outcome = Map::new();
    outcome.insert("tool".into(), name.into());
    let result = execute(app, outer, name, args, &mut outcome);
    let level = if outcome.get("outcome").and_then(Value::as_str) == Some("ok") {
        "info"
    } else {
        "warning"
    };
    crate::obs::log("tool_called", level, Value::Object(outcome));
    match result {
        Ok(text) => json!({"content": [{"type": "text", "text": text}], "isError": false}),
        Err(text) => error_result(&text),
    }
}

const FORWARD: [&str; 4] = [
    "authorization",
    "x-api-key",
    "x-vexa-identity",
    "x-trace-id",
];
const CARRIES_NOTICES: [&str; 5] = [
    "request_meeting_bot",
    "get_meeting_transcript",
    "list_meetings",
    "get_bot_status",
    "stop_bot",
];

/// httpx's primitive_value_to_str, list items repeated.
pub fn query_text(v: &Value) -> Vec<String> {
    match v {
        Value::Array(items) => items.iter().map(prim).collect(),
        other => vec![prim(other)],
    }
}

fn prim(v: &Value) -> String {
    match v {
        Value::Bool(true) => "true".into(),
        Value::Bool(false) => "false".into(),
        Value::Null => String::new(),
        other => vexa_native_kit::pyjson::py_str(other),
    }
}

/// FastApiMCP._execute_api_tool with its two wrappers (tool_errors, notices): the call replayed
/// onto the tool's route, its answer as the agent reads it.
fn execute(
    app: &'static App,
    outer: &Req,
    name: &str,
    mut args: Map<String, Value>,
    outcome: &mut Map<String, Value>,
) -> Result<String, String> {
    let Some(op) = app.operation(name) else {
        outcome.insert("outcome".into(), "error".into());
        outcome.insert("error".into(), "Exception".into());
        return Err(format!("Unknown tool: {name}"));
    };
    let mut query = Vec::new();
    for q in &op.query {
        if let Some(v) = args.shift_remove(q) {
            for text in query_text(&v) {
                query.push((q.clone(), text));
            }
        }
    }
    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), "apiserver".into()),
        ("accept".into(), "*/*".into()),
        ("user-agent".into(), "python-httpx/0.28.1".into()),
    ];
    for (k, v) in &outer.headers {
        if FORWARD.contains(&k.as_str()) {
            headers.retain(|(h, _)| h != k);
            headers.push((k.clone(), v.clone()));
        }
    }
    let mut body = Vec::new();
    if matches!(op.method.as_str(), "POST" | "PUT" | "PATCH") {
        if !args.is_empty() {
            body = compact(&Value::Object(args)).into_bytes();
            headers.push(("content-length".into(), body.len().to_string()));
            headers.push(("content-type".into(), "application/json".into()));
        } else {
            headers.push(("content-length".into(), "0".into()));
        }
    }
    let raw_query = query
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                crate::net::quote_plus(k),
                crate::net::quote_plus(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let inner = Req {
        method: op.method.clone(),
        path: op.path.clone(),
        raw_query,
        query,
        headers,
        body,
    };
    let resp = edge::handle(app, inner);
    let text = resp.text();
    let notices = || -> Vec<String> {
        if CARRIES_NOTICES.contains(&name) {
            fetch_notices(app, outer)
        } else {
            Vec::new()
        }
    };
    if (400..600).contains(&resp.status) {
        let rendered = render_tool_error(resp.status, &text);
        outcome.insert("outcome".into(), "refused".into());
        outcome.insert("status".into(), resp.status.into());
        return Err(render_notices_error(&rendered, &notices()));
    }
    let out = match crate::pyjson_decode::loads(&text) {
        Ok(v) => indented(&v),
        Err(_) => text,
    };
    outcome.insert("outcome".into(), "ok".into());
    Ok(render_notices(&out, &notices()))
}

// ─── refusals and notices ─────────────────────────────────────────────────────

const MAX_BODY_CHARS: usize = 4096;

fn bounded(text: &str) -> String {
    let n = text.chars().count();
    if n <= MAX_BODY_CHARS {
        return text.to_owned();
    }
    let head: String = text.chars().take(MAX_BODY_CHARS).collect();
    format!(
        "{head}\u{2026} [{} more characters elided by vexa-mcp]",
        n - MAX_BODY_CHARS
    )
}

/// Peel nested `{"detail": …}` envelopes down to the innermost value.
pub fn unwrap_detail(mut body: Value) -> Value {
    for _ in 0..10 {
        let inner = match &body {
            Value::Object(o) if o.len() == 1 && o.contains_key("detail") => o["detail"].clone(),
            _ => break,
        };
        body = inner;
    }
    body
}

fn field_text(fields: &Map<String, Value>, k: &str) -> String {
    fields
        .get(k)
        .and_then(Value::as_str)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

pub fn render_tool_error(status: u16, body: &str) -> String {
    let Some(parsed) = crate::pyjson_decode::loads(body)
        .ok()
        .filter(|v| !v.is_null())
    else {
        let stripped = body.trim();
        return if stripped.is_empty() {
            format!("HTTP {status}")
        } else {
            format!("HTTP {status}\n{}", bounded(stripped))
        };
    };
    let inner = unwrap_detail(parsed);
    let empty = Map::new();
    let fields = inner.as_object().unwrap_or(&empty);
    let (reason, message, code, action) = (
        field_text(fields, "reason"),
        field_text(fields, "message"),
        field_text(fields, "code"),
        field_text(fields, "action_url"),
    );
    let mut lines = Vec::new();
    if !message.is_empty() {
        lines.push(if reason.is_empty() {
            message
        } else {
            format!("{reason}: {message}")
        });
    } else {
        let tail = if code.is_empty() { reason } else { code };
        lines.push(if tail.is_empty() {
            format!("HTTP {status}")
        } else {
            format!("HTTP {status} {tail}")
        });
    }
    if !action.is_empty() {
        lines.push(format!("action_url: {action}"));
    }
    lines.push(bounded(&match &inner {
        Value::String(s) => s.clone(),
        other => compact(other),
    }));
    lines.join("\n")
}

/// The credential the caller sent: x-api-key, else the bearer token, else the raw header.
pub fn caller_key(req: &Req) -> String {
    let key = req.header("x-api-key").unwrap_or("").trim();
    if !key.is_empty() {
        return key.to_owned();
    }
    let auth = req.header("authorization").unwrap_or("").trim();
    if auth.is_empty() {
        return String::new();
    }
    let (scheme, token) = auth.split_once(' ').unwrap_or((auth, ""));
    if scheme.to_lowercase() == "bearer" {
        token.trim().to_owned()
    } else {
        auth.to_owned()
    }
}

fn fetch_notices(app: &App, outer: &Req) -> Vec<String> {
    let base = crate::assembly::env_str(&app.env, "FLOWS_API_URL")
        .trim()
        .trim_end_matches('/')
        .to_owned();
    let key = caller_key(outer);
    if base.is_empty() || key.is_empty() {
        return Vec::new();
    }
    let mut headers = vec![
        ("X-API-Key".to_owned(), key),
        ("Content-Type".to_owned(), "application/json".to_owned()),
    ];
    headers.extend(crate::obs::headers());
    let Ok(r) = crate::net::request(
        "GET",
        &format!("{base}/queue/notices"),
        &headers,
        None,
        Duration::from_secs(2),
    ) else {
        return Vec::new();
    };
    if r.status != 200 || r.body.is_empty() {
        return Vec::new();
    }
    let Ok(Value::Object(body)) = crate::pyjson_decode::loads_bytes(&r.body) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for v in body
        .get("notices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(s) = v.as_str().map(str::trim).filter(|s| !s.is_empty()) {
            if !out.iter().any(|o| o == s) {
                out.push(s.to_owned());
            }
        }
    }
    out
}

fn with_field(v: Value, notices: &[String]) -> Option<Map<String, Value>> {
    match v {
        Value::Object(mut o) if !o.contains_key("notices") => {
            o.insert("notices".into(), json!(notices));
            Some(o)
        }
        _ => None,
    }
}

fn render_notices(text: &str, notices: &[String]) -> String {
    if notices.is_empty() {
        return text.to_owned();
    }
    let body = crate::pyjson_decode::loads(text)
        .ok()
        .and_then(|v| with_field(v, notices))
        .map(|o| indented(&Value::Object(o)))
        .unwrap_or_else(|| text.to_owned());
    let mut parts = vec![body];
    parts.extend(notices.iter().map(|n| format!("Notice: {n}")));
    parts.join("\n\n")
}

fn render_notices_error(text: &str, notices: &[String]) -> String {
    if notices.is_empty() {
        return text.to_owned();
    }
    let mut lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
    if let Some(last) = lines.last_mut() {
        if let Some(o) = crate::pyjson_decode::loads(last)
            .ok()
            .and_then(|v| with_field(v, notices))
        {
            *last = compact(&Value::Object(o));
        }
    }
    let mut parts = vec![lines.join("\n")];
    parts.extend(notices.iter().map(|n| format!("Notice: {n}")));
    parts.join("\n\n")
}

// ─── visibility (VEXA_MCP_TOOLS_*) ────────────────────────────────────────────

#[derive(Default)]
pub struct Policy {
    allow: HashSet<String>,
    deny: HashSet<String>,
    cohort_all: bool,
    cohort_ids: HashSet<String>,
    cohort_emails: HashSet<String>,
    cohort_domains: HashSet<String>,
}

fn names(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .collect()
}

impl Policy {
    pub fn from_env(env: &crate::assembly::Env) -> Self {
        let e = |k: &str| crate::assembly::env_str(env, k);
        let entries: Vec<String> = names(e("VEXA_MCP_TOOLS_COHORT"))
            .into_iter()
            .map(|x| x.to_lowercase())
            .collect();
        Policy {
            allow: names(e("VEXA_MCP_TOOLS_ALLOW")),
            deny: names(e("VEXA_MCP_TOOLS_DENY")),
            cohort_all: entries.iter().any(|x| x == "*"),
            cohort_ids: entries
                .iter()
                .filter(|x| !x.contains('@') && *x != "*")
                .cloned()
                .collect(),
            cohort_emails: entries
                .iter()
                .filter(|x| x.contains('@') && !x.starts_with('@'))
                .cloned()
                .collect(),
            cohort_domains: entries
                .iter()
                .filter(|x| x.starts_with('@') && x.len() > 1)
                .map(|x| x[1..].to_owned())
                .collect(),
        }
    }

    /// Allow/deny names this deployment does not serve (logged, never fatal: surfaces differ).
    pub fn unknown(&self, registered: &[String]) -> Vec<String> {
        let mut out: Vec<String> = self
            .allow
            .union(&self.deny)
            .filter(|n| !registered.contains(n))
            .cloned()
            .collect();
        out.sort();
        out
    }

    fn in_cohort(&self, req: &Req) -> bool {
        let uid = req.header("x-user-id").unwrap_or("").trim().to_lowercase();
        let email = req
            .header("x-user-email")
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if uid.is_empty() && email.is_empty() {
            return false;
        }
        if self.cohort_all || (!uid.is_empty() && self.cohort_ids.contains(&uid)) {
            return true;
        }
        if let Some((_, domain)) = email.rsplit_once('@') {
            return self.cohort_emails.contains(&email) || self.cohort_domains.contains(domain);
        }
        false
    }

    pub fn shown(&self, name: &str, req: &Req, app: &App) -> bool {
        if self.deny.contains(name) {
            return false;
        }
        let shared = req.header("x-user-delegation-shared").unwrap_or("").trim() == "1"
            || req.header("x-user-principal-kind").unwrap_or("").trim() == "workspace";
        if shared && !app.shared.read().unwrap().iter().any(|n| n == name) {
            return false;
        }
        if self.allow.is_empty() || self.allow.contains(name) {
            return true;
        }
        self.in_cohort(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_rendering() {
        let body =
            r#"{"detail":{"detail":{"code":"c","reason":"r","message":"m","action_url":"u"}}}"#;
        assert_eq!(render_tool_error(403, body), "r: m\naction_url: u\n{\"code\":\"c\",\"reason\":\"r\",\"message\":\"m\",\"action_url\":\"u\"}");
        assert_eq!(
            render_tool_error(500, "Internal Server Error"),
            "HTTP 500\nInternal Server Error"
        );
        assert_eq!(
            render_tool_error(404, r#"{"detail":"Not Found"}"#),
            "HTTP 404\nNot Found"
        );
        let with = render_notices_error("HTTP 403 c\n{\"code\":\"c\"}", &["n1".into()]);
        assert_eq!(
            with,
            "HTTP 403 c\n{\"code\":\"c\",\"notices\":[\"n1\"]}\n\nNotice: n1"
        );
    }

    #[test]
    fn coercion() {
        let schema = json!({"properties": {"facts": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}]},
                                            "o": {"type": "object"}, "s": {"type": "string"}}});
        let args = json!({"facts": "one fact", "o": "{\"a\":1}", "s": "[1]"});
        let out = coerce(args.as_object().unwrap(), &schema);
        assert_eq!(
            Value::Object(out),
            json!({"facts": ["one fact"], "o": {"a": 1}, "s": "[1]"})
        );
    }

    #[test]
    fn message_validation_text() {
        let e = message_kind(&json!({"jsonrpc": "2.0", "id": 1}))
            .err()
            .unwrap();
        assert!(e.starts_with("4 validation errors for JSONRPCMessage\nJSONRPCRequest.method\n  Field required [type=missing, input_value={'jsonrpc': '2.0', 'id': 1}, input_type=dict]"));
        assert_eq!(
            message_kind(&json!({"jsonrpc": "2.0", "method": "x"})).ok(),
            Some(Kind::Notification)
        );
    }
}
