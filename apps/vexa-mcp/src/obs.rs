//! logevent.v1 lines and the two values a request carries to every hop it causes: the trace id
//! (`X-Trace-Id`) and the identity the gateway signed onto it (re-entry, `X-Vexa-Internal-Mcp-Identity`).
//! One request is served on one thread, and the tool call it replays runs on that thread too, so
//! both live in thread-locals for the length of the request.

use std::cell::RefCell;

use serde_json::Value;

thread_local! {
    static TRACE: RefCell<String> = const { RefCell::new(String::new()) };
    static IDENTITY: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Hold (trace, identity) for the request being served; returns what was held before.
pub fn bind(trace: &str, identity: &str) -> (String, String) {
    let t = TRACE.with(|c| c.replace(trace.to_owned()));
    let i = IDENTITY.with(|c| c.replace(identity.to_owned()));
    (t, i)
}

pub fn restore(prev: (String, String)) {
    TRACE.with(|c| *c.borrow_mut() = prev.0);
    IDENTITY.with(|c| *c.borrow_mut() = prev.1);
}

pub fn trace() -> String {
    TRACE.with(|c| c.borrow().clone())
}

/// The trace header for an outbound call, or nothing outside a request.
pub fn headers() -> Vec<(String, String)> {
    let t = trace();
    if t.is_empty() {
        Vec::new()
    } else {
        vec![("X-Trace-Id".into(), t)]
    }
}

/// The re-entry header for a call to the GATEWAY, or nothing when this request carried none.
pub fn reentry() -> Vec<(String, String)> {
    let i = IDENTITY.with(|c| c.borrow().clone());
    if i.is_empty() {
        Vec::new()
    } else {
        vec![("X-Vexa-Internal-Mcp-Identity".into(), i)]
    }
}

pub fn behind_gateway() -> bool {
    IDENTITY.with(|c| !c.borrow().is_empty())
}

pub fn log(event: &str, level: &str, fields: Value) {
    let t = trace();
    vexa_native_kit::logevent::Line {
        service: "mcp",
        level,
        event,
        trace_id: (!t.is_empty()).then_some(t.as_str()),
        audience: "system",
        user_id: None,
        session: None,
        fields: Some(fields),
    }
    .emit();
}
