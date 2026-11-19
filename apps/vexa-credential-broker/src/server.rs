//! The HTTP front door: one thread per connection on 127.0.0.1. The trace
//! layer (x-trace-id), the probes, the assertion boundary, and the rendering
//! of every answer the app's handlers give.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::broker::{route_of, Broker, Who};
use crate::fail::Fail;
use crate::routes::{self, Call};
use crate::{assertion, identity, obs, util};

pub struct Answer {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl Answer {
    fn json(status: u16, body: &Value) -> Self {
        Self { status, content_type: "application/json", body: serde_json::to_vec(body).unwrap_or_default(), headers: vec![] }
    }
    fn detail(status: u16, detail: &str) -> Self {
        Self::json(status, &json!({"detail": detail}))
    }
    fn internal() -> Self {
        Self { status: 500, content_type: "text/plain; charset=utf-8", body: b"Internal Server Error".to_vec(), headers: vec![] }
    }
    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

fn write(stream: &mut TcpStream, a: &Answer) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n", a.status, reason(a.status), a.content_type, a.body.len());
    for (k, v) in &a.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&a.body)?;
    stream.flush()
}

fn probe(b: &Broker, path: &str) -> Answer {
    if path == "/health" {
        return Answer::json(200, &json!({"status": "ok", "service": "credential-broker", "store": b.store.name()}));
    }
    let (healthy, kind) = match b.store.healthy() {
        Ok(h) => (h, "unhealthy"),
        Err(e) => (false, e.0),
    };
    if healthy {
        return Answer::json(200, &json!({"status": "ok", "service": "credential-broker", "store": b.store.name()})).header("cache-control", "no-store");
    }
    obs::fault("store", kind, Some("/ready"));
    Answer::json(503, &json!({"status": "unavailable", "reason": "store_unavailable", "kind": kind, "service": "credential-broker", "store": b.store.name()})).header("cache-control", "no-store")
}

/// The assertion boundary: the verified caller, or the refusal kind.
fn verify(b: &Broker, req: &vexa_native_kit::http::Request, path: &str) -> Result<Who, &'static str> {
    let header = req.header(assertion::HEADER).unwrap_or("");
    if header.is_empty() {
        return Err("missing");
    }
    let claims = assertion::verify(header, &|role| b.key_for(role), &req.method, path, &req.body, util::now(), &|nonce, expires| b.remember(nonce, expires))?;
    let person = if claims.role == "agent" || claims.role == "git" {
        b.person_signed(req.header(identity::HEADER).unwrap_or("").trim(), &claims.actor)?
    } else {
        serde_json::Map::new()
    };
    let unit = identity::signed_session(&person);
    if !unit.is_empty() && !util::ct_eq(claims.session.as_bytes(), unit.as_bytes()) {
        return Err("session_mismatch");
    }
    obs::set_session(&unit);
    Ok(Who {
        actor: claims.actor,
        session: claims.session,
        role: claims.role,
        memberships: identity::memberships(&person),
        unwatched: identity::unwatched(&person),
        delegated: person.contains_key("delegation"),
        shared: identity::shared(&person),
    })
}

pub fn handle(b: &Broker, req: &vexa_native_kit::http::Request) -> Answer {
    let path = util::unquote_path(&req.path);
    if req.method == "GET" && (path == "/health" || path == "/ready") {
        return probe(b, &path);
    }
    let signed = if req.query.is_empty() { path.clone() } else { format!("{path}?{}", req.query) };
    let who = match verify(b, req, &signed) {
        Ok(w) => w,
        Err(kind) => {
            obs::event("assertion_refused", "warning", None, Some(json!({"kind": kind, "method": req.method, "route": route_of(&signed)})));
            return Answer::detail(401, "Product identity refused");
        }
    };
    let found = routes::ROUTES.iter().find_map(|(m, p)| routes::matches(p, &path).map(|param| (*m, *p, param)));
    let answer = match found {
        None => Answer::detail(404, "Not Found"),
        Some(_) if !routes::ROUTES.iter().any(|(m, p)| *m == req.method && routes::matches(p, &path).is_some()) => Answer::detail(405, "Method Not Allowed"),
        Some(_) => {
            let (_, pattern, param) = routes::ROUTES.iter().find_map(|(m, p)| (*m == req.method).then(|| routes::matches(p, &path).map(|param| (*m, *p, param))).flatten()).unwrap_or(("", "", String::new()));
            let call = Call { method: &req.method, query: &req.query, body: &req.body, who: &who };
            match routes::dispatch(b, &call, pattern, &param) {
                Ok(v) => Answer::json(200, &v),
                Err(Fail::Service(_) | Fail::Internal) => return Answer::internal(),
                Err(f) => {
                    let (status, body) = f.render(&route_of(&path));
                    Answer::json(status, &body)
                }
            }
        }
    };
    answer.header("cache-control", "no-store").header("x-content-type-options", "nosniff")
}

fn serve(b: &Broker, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(60)));
    let Ok(req) = vexa_native_kit::http::read_request(&stream) else { return };
    let trace = req.header("x-trace-id").filter(|t| !t.is_empty()).map(str::to_owned).unwrap_or_else(util::uuid_hex);
    obs::set_trace(Some(trace.clone()));
    let mut answer = handle(b, &req);
    if answer.status != 500 || answer.content_type == "application/json" {
        answer.headers.push(("x-trace-id".into(), trace));
    }
    let _ = write(&mut stream, &answer);
    obs::clear();
}

pub fn run(b: Arc<Broker>, port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    obs::info("broker_listening", json!({"port": port}));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let b = b.clone();
        std::thread::spawn(move || serve(&b, stream));
    }
    Ok(())
}
