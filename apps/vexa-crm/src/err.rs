//! The CRM's exceptions as values: the Python class name (the audit's outcome is
//! `type(exc).__name__`), the status, and what the answer carries.

use serde_json::{json, Value};
use vexa_native_kit::pg::PgError;

#[derive(Debug, Clone)]
pub enum Detail {
    /// `{"detail": str(exc)}` (CRMError and its plain subclasses).
    Text(String),
    /// The body itself (Refused and its subclasses, PersonRefused).
    Body(Value),
    /// HTTPException(status, detail): `{"detail": detail}`, never audited as a CRM error.
    Http(Value),
    /// An unhandled exception: 500 "Internal Server Error".
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct CrmError {
    pub class: &'static str,
    pub status: u16,
    pub detail: Detail,
}

pub type R<T> = Result<T, CrmError>;

/// Each exception class and its base (Python's MRO, one step at a time).
const BASES: &[(&str, &str)] = &[
    ("Forbidden", "CRMError"),
    ("NotFound", "CRMError"),
    ("Conflict", "CRMError"),
    ("Refused", "CRMError"),
    ("SharedRefused", "NotFound"),
    ("DeskRefused", "Refused"),
    ("Invalid", "CRMError"),
    ("PersonOnly", "DeskRefused"),
    ("PersonError", "CRMError"),
    ("PersonRefused", "PersonError"),
    ("PersonNotFound", "PersonError"),
    ("BlockRefused", "CRMError"),
];

impl CrmError {
    pub fn new(class: &'static str, status: u16, detail: Detail) -> Self {
        CrmError { class, status, detail }
    }
    /// CRMError(message): 400.
    pub fn crm(msg: impl Into<String>) -> Self {
        Self::new("CRMError", 400, Detail::Text(msg.into()))
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new("Forbidden", 403, Detail::Text(msg.into()))
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new("NotFound", 404, Detail::Text(msg.into()))
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new("Conflict", 409, Detail::Text(msg.into()))
    }
    /// Refused(body): 403 with the body at the top level.
    pub fn refused(body: Value) -> Self {
        Self::new("Refused", 403, Detail::Body(body))
    }
    /// SharedRefused(): 403 with the shared-conversation refusal; a NotFound to every loop that
    /// skips unreadable records.
    pub fn shared() -> Self {
        Self::new("SharedRefused", 403, Detail::Body(crate::caller::shared_refusal()))
    }
    /// HTTPException(status, detail).
    pub fn http(status: u16, detail: impl Into<Value>) -> Self {
        Self::new("HTTPException", status, Detail::Http(detail.into()))
    }
    /// An exception no handler takes (a driver error, a bug): 500.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new("Exception", 500, Detail::Internal(msg.into()))
    }

    /// isinstance(exc, base).
    pub fn isa(&self, base: &str) -> bool {
        let mut class = self.class;
        loop {
            if class == base {
                return true;
            }
            match BASES.iter().find(|(c, _)| *c == class) {
                Some((_, parent)) => class = parent,
                None => return false,
            }
        }
    }
    /// isinstance(exc, CRMError): the errors `audited` records.
    pub fn is_crm(&self) -> bool {
        self.isa("CRMError")
    }
    pub fn is_not_found(&self) -> bool {
        self.isa("NotFound")
    }
    /// str(exc).
    pub fn message(&self) -> String {
        match &self.detail {
            Detail::Text(t) | Detail::Internal(t) => t.clone(),
            Detail::Body(b) => b.get("reason").and_then(Value::as_str).unwrap_or("").to_owned(),
            Detail::Http(v) => v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string()),
        }
    }
    /// The answer's status and JSON body (None: the plain-text 500).
    pub fn answer(&self) -> (u16, Option<Value>) {
        match &self.detail {
            Detail::Text(t) => (self.status, Some(json!({"detail": t}))),
            Detail::Body(b) => (self.status, Some(b.clone())),
            Detail::Http(v) => (self.status, Some(json!({"detail": v}))),
            Detail::Internal(_) => (500, None),
        }
    }
}

impl From<PgError> for CrmError {
    fn from(e: PgError) -> Self {
        let class = if e.is_integrity() { "IntegrityError" } else { "DatabaseError" };
        CrmError::new(class, 500, Detail::Internal(format!("{}: {}", e.code.as_deref().unwrap_or("-"), e.message)))
    }
}

impl CrmError {
    /// A database error that is SQLAlchemy's IntegrityError (a code that catches it reads this).
    pub fn is_integrity(&self) -> bool {
        self.class == "IntegrityError"
    }
}
