//! Structured logging: one logevent.v1 JSON line per event. A line names what
//! happened (event, actor, connection, kind, status), never a value.

use std::cell::RefCell;
use std::io::Write;
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::util;

pub const SERVICE: &str = "credential-broker";

static OUT: Mutex<()> = Mutex::new(());

thread_local! {
    /// (trace id, agent session) of the request this thread serves.
    static CONTEXT: RefCell<(Option<String>, Option<String>)> = const { RefCell::new((None, None)) };
}

/// Bind the trace id for the request this thread serves (None clears it).
pub fn set_trace(trace: Option<String>) {
    CONTEXT.with(|c| c.borrow_mut().0 = trace);
}

/// Bind the agent session the gateway's signed identity named.
pub fn set_session(session: &str) {
    let session = session.trim();
    CONTEXT.with(|c| c.borrow_mut().1 = (!session.is_empty()).then(|| session.to_owned()));
}

pub fn clear() {
    CONTEXT.with(|c| *c.borrow_mut() = (None, None));
}

pub fn event(name: &str, level: &str, user_id: Option<&str>, fields: Option<Value>) {
    let (trace, session) = CONTEXT.with(|c| c.borrow().clone());
    let mut line = Map::new();
    line.insert("ts".into(), json!(util::utc_stamp(util::now())));
    line.insert("level".into(), json!(level));
    line.insert("service".into(), json!(SERVICE));
    line.insert("trace_id".into(), json!(trace.unwrap_or_else(util::uuid_hex)));
    line.insert("audience".into(), json!("system"));
    line.insert("event".into(), json!(name));
    if let Some(user) = user_id {
        line.insert("user_id".into(), json!(user));
    }
    if let Some(session) = session {
        line.insert("session".into(), json!(session));
    }
    if let Some(fields) = fields.filter(|f| f.as_object().is_some_and(|o| !o.is_empty())) {
        line.insert("fields".into(), fields);
    }
    let text = util::py_dumps_compact(&Value::Object(line));
    let _guard = OUT.lock();
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
    let _ = out.flush();
}

pub fn info(name: &str, fields: Value) {
    event(name, "info", None, Some(fields));
}

pub fn warn(name: &str, fields: Value) {
    event(name, "warning", None, Some(fields));
}

/// Something failed that the person cannot fix.
pub fn fault(source: &str, kind: &str, route: Option<&str>) {
    let mut fields = json!({"source": source, "kind": kind});
    if let Some(route) = route {
        fields["route"] = json!(route);
    }
    warn("broker_fault", fields);
}

/// An upstream refused, and the answer tells the person what to do.
pub fn refused(source: &str, kind: &str, route: &str) {
    warn("upstream_refused", json!({"source": source, "kind": kind, "route": route}));
}
