//! Structured logging: one logevent.v1 JSON line per event. A line names what
//! happened (event, actor, connection, kind, status), never a value.

use std::cell::RefCell;
use serde_json::{json, Value};

pub const SERVICE: &str = "credential-broker";

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
    vexa_native_kit::logevent::Line {
        service: SERVICE,
        level,
        event: name,
        trace_id: trace.as_deref(),
        audience: "system",
        user_id,
        session: session.as_deref(),
        fields,
    }
    .emit();
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
