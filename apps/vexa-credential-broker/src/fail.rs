//! Every non-2xx answer a route gives, and the exception handlers' rendering.

use serde_json::{json, Value};

use crate::obs;

/// The kinds of upstream fault and the status each answers with.
pub fn fault_status(kind: &str) -> u16 {
    match kind {
        "bad_answer" => 502,
        _ => 503,
    }
}

/// The sentences that ask for a reconnect (reasons.RECONNECT).
pub const RECONNECT: [&str; 6] = [
    "Authorization failed; reconnect this account",
    "Required permission was not granted; reconnect this account",
    "Authorization rejected; reconnect this account",
    "Authorization expired; reconnect this account",
    "Required permissions were not granted; reconnect",
    "Authorization expired; reconnect",
];

pub fn refusal_reason(sentence: &str) -> &'static str {
    if RECONNECT.contains(&sentence) {
        "reconnect_required"
    } else {
        "provider_error"
    }
}

#[derive(Debug, Clone)]
pub enum Fail {
    /// HTTPException(status, detail)
    Http(u16, String),
    /// HTTPException(status, <object detail>)
    Object(u16, Value),
    /// ReasonedError(status, detail, reason)
    Reasoned(u16, String, &'static str),
    /// providers.ProviderError: a refusal the person can act on (409).
    Provider(String),
    /// secret_service.ServiceError: a custom service's refusal; each route decides its status.
    Service(String),
    /// faults.UpstreamFault
    Upstream { source: &'static str, kind: &'static str, message: String },
    /// A body that does not validate (422 "Invalid request fields").
    Invalid,
    /// An unhandled failure (500).
    Internal,
}

pub type R<T> = Result<T, Fail>;

impl Fail {
    pub fn http(status: u16, detail: &str) -> Self {
        Fail::Http(status, detail.to_owned())
    }
    pub fn provider(sentence: &str) -> Self {
        Fail::Provider(sentence.to_owned())
    }
    pub fn service(sentence: &str) -> Self {
        Fail::Service(sentence.to_owned())
    }
    pub fn upstream(source: &'static str, kind: &'static str, message: &str) -> Self {
        Fail::Upstream { source, kind, message: message.to_owned() }
    }
    /// The sentence of a Service or Provider refusal.
    pub fn sentence(&self) -> String {
        match self {
            Fail::Service(s) | Fail::Provider(s) | Fail::Http(_, s) => s.clone(),
            _ => String::new(),
        }
    }
    pub fn store_unavailable() -> Self {
        Fail::Reasoned(503, "Credential store unavailable".into(), "store_unavailable")
    }

    /// The status and body the app's exception handlers answer with, logging
    /// what they log. route is the folded route.
    pub fn render(&self, route: &str) -> (u16, Value) {
        match self {
            Fail::Http(status, detail) => (*status, json!({"detail": detail})),
            Fail::Object(status, detail) => (*status, json!({"detail": detail})),
            Fail::Reasoned(status, detail, reason) => (*status, json!({"detail": detail, "reason": reason})),
            Fail::Provider(sentence) => {
                obs::refused("provider", "refused", route);
                (409, json!({"detail": sentence, "reason": refusal_reason(sentence)}))
            }
            Fail::Upstream { source, kind, message } => {
                obs::fault(source, kind, Some(route));
                (fault_status(kind), json!({"detail": message, "reason": "provider_error"}))
            }
            Fail::Invalid => (422, json!({"detail": "Invalid request fields"})),
            Fail::Service(_) | Fail::Internal => (500, Value::Null),
        }
    }
}

impl From<rusqlite::Error> for Fail {
    fn from(_: rusqlite::Error) -> Self {
        Fail::Internal
    }
}
