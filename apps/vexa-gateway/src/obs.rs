//! logevent.v1 lines of the gateway, and the request context every line reads: the trace id, the
//! resolved user and the agent session. One request is served on one thread, so the context lives
//! in thread-locals for the length of the request.

use std::cell::RefCell;
use std::io::Write;
use std::sync::Mutex;

use serde_json::{Map, Value};
use vexa_native_kit::pyjson::py_dumps_compact;

pub const TRACE_HEADER: &str = "x-trace-id";
static OUT: Mutex<()> = Mutex::new(());

#[derive(Default, Clone)]
pub struct Ctx {
    pub trace: Option<String>,
    pub user: Option<Value>,
    pub session: Option<String>,
}

thread_local! {
    static CTX: RefCell<Ctx> = RefCell::new(Ctx::default());
}

/// Start a request's context; what was held before is returned for `restore`.
pub fn begin(trace: Option<String>) -> Ctx {
    CTX.with(|c| c.replace(Ctx { trace, user: None, session: None }))
}

pub fn restore(prev: Ctx) {
    CTX.with(|c| *c.borrow_mut() = prev);
}

pub fn trace() -> Option<String> {
    CTX.with(|c| c.borrow().trace.clone())
}

/// The trace id to forward (`get_trace_id() or ""`).
pub fn trace_or_empty() -> String {
    trace().unwrap_or_default()
}

pub fn set_user(user: &Value) {
    CTX.with(|c| c.borrow_mut().user = Some(user.clone()));
}

/// set_session: a blank value clears it.
pub fn set_session(session: Option<&str>) {
    let s = session.map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned);
    CTX.with(|c| c.borrow_mut().session = s);
}

/// `delegation.unit`, for a worker's token only.
pub fn session_of_validation(user: &Value) -> Option<String> {
    match user.get("delegation").and_then(|d| d.get("unit")) {
        Some(Value::String(u)) if !u.trim().is_empty() => Some(u.trim().to_owned()),
        _ => None,
    }
}

pub struct Event<'a> {
    pub event: &'a str,
    pub audience: &'a str,
    pub level: &'a str,
    pub span: Option<&'a str>,
    pub user_id: Option<Value>,
    pub fields: Option<Value>,
}

pub fn ev<'a>(event: &'a str, audience: &'a str, level: &'a str, span: Option<&'a str>) -> Event<'a> {
    Event { event, audience, level, span, user_id: None, fields: None }
}

impl Event<'_> {
    pub fn user(mut self, id: Value) -> Self {
        self.user_id = Some(id);
        self
    }
    pub fn fields(mut self, f: Value) -> Self {
        self.fields = Some(f);
        self
    }
    pub fn emit(self) {
        let ctx = CTX.with(|c| c.borrow().clone());
        let mut line = Map::new();
        line.insert("ts".into(), Value::String(vexa_native_kit::ids::utc_stamp(vexa_native_kit::ids::now())));
        line.insert("level".into(), self.level.into());
        line.insert("service".into(), "gateway".into());
        let trace = ctx.trace.filter(|t| !t.is_empty()).unwrap_or_else(vexa_native_kit::ids::uuid_hex);
        line.insert("trace_id".into(), trace.into());
        line.insert("audience".into(), self.audience.into());
        line.insert("event".into(), self.event.into());
        if let Some(span) = self.span {
            line.insert("span".into(), span.into());
        }
        let uid = self.user_id.or_else(|| ctx.user.as_ref().and_then(|u| u.get("user_id").cloned()));
        if let Some(uid) = uid.filter(|u| !u.is_null()) {
            line.insert("user_id".into(), uid);
        }
        if let Some(s) = ctx.session {
            line.insert("session".into(), s.into());
        }
        if let Some(f) = self.fields.filter(|f| f.as_object().is_some_and(|o| !o.is_empty())) {
            line.insert("fields".into(), f);
        }
        let text = py_dumps_compact(&Value::Object(line));
        let _guard = OUT.lock();
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{text}");
        let _ = out.flush();
    }
}
