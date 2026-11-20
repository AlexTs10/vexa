//! Who is calling the CRM, as identity answered it at `/internal/validate` (caller.py).

use serde_json::{json, Map, Value};

use crate::net;
use crate::val::{g, s, truthy};

pub const VALIDATE_PATH: &str = "/internal/validate";
pub const ACCEPTS_DELEGATION_HEADER: &str = "x-vexa-internal-accepts-delegation";
pub const DELEGATION_TOKEN_PREFIX: &str = "vxd_";
pub const TIMEOUT_S: f64 = 5.0;

#[derive(Debug, Clone, Default)]
pub struct Caller {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub is_admin: bool,
    pub workspaces: Vec<String>,
    /// None when the caller did not come from identity.
    pub writable: Option<Vec<String>>,
    pub delegated: bool,
    pub regime: String,
    pub shared: bool,
    pub cross_org: bool,
    pub session: String,
    pub trace: String,
    pub internal: bool,
    pub org: String,
    pub credential_class: String,
    pub extra: Map<String, Value>,
}

impl Caller {
    /// as_caller(subject): a bare subject is a person with no memberships.
    pub fn subject(subject: impl Into<String>) -> Self {
        Caller { subject: subject.into(), ..Default::default() }
    }
    pub fn proven_email(&self) -> String {
        if self.email_verified {
            self.email.clone()
        } else {
            String::new()
        }
    }
    /// A worker with nobody in the loop.
    pub fn unwatched(&self) -> bool {
        self.delegated && self.regime != "human"
    }
    pub fn kind(&self) -> &'static str {
        if self.internal {
            "internal"
        } else if self.delegated {
            if self.shared {
                "agent-shared"
            } else if self.regime == "human" {
                "agent"
            } else {
                "agent-unwatched"
            }
        } else {
            "person"
        }
    }
    pub fn extra_str(&self, key: &str) -> String {
        crate::val::or_str(self.extra.get(key).unwrap_or(&Value::Null))
    }
    pub fn is_workspace_principal(&self) -> bool {
        self.extra.get("principal_kind").and_then(Value::as_str) == Some("workspace")
    }
}

#[derive(Debug)]
pub enum ResolveError {
    /// Identity could not be reached or refused our secret (503).
    Unavailable(String),
    /// Nobody answers to this credential (401).
    Unknown,
}

fn clean(v: &Value) -> String {
    crate::val::pystr(v)
}

/// caller.from_validate.
pub fn from_validate(token: &str, body: &Value, trace: &str) -> Result<Caller, ResolveError> {
    let uid = g(body, "user_id");
    if uid.is_null() || uid.as_str() == Some("") {
        return Err(ResolveError::Unavailable("identity answered with no user_id".into()));
    }
    let dlg_raw = g(body, "delegation");
    let delegated = dlg_raw.is_object() || token.starts_with(DELEGATION_TOKEN_PREFIX);
    let empty = json!({});
    let dlg = if dlg_raw.is_object() { dlg_raw } else { &empty };
    let ws_principal = g(dlg, "principal_kind").as_str() == Some("workspace");
    let principal_workspace = if ws_principal { crate::val::strip(&crate::val::or_str(g(dlg, "principal_workspace"))).to_owned() } else { String::new() };
    let shared = g(dlg, "shared") == &Value::Bool(true) || ws_principal;
    let person_admin = (truthy(g(body, "is_admin")) || (delegated && truthy(g(body, "person_is_admin")))) && !ws_principal;
    let admin = person_admin && !shared;
    let list = |v: &Value| -> Vec<String> {
        match v {
            Value::Array(a) if !a.is_empty() => a.iter().map(clean).filter(|w| !w.is_empty()).collect(),
            _ => Vec::new(),
        }
    };
    let workspaces = list(g(body, "workspaces"));
    let writable: Vec<String> = list(g(body, "writable_workspaces")).into_iter().filter(|w| workspaces.contains(w)).collect();
    let on_behalf_of = {
        let a = crate::val::or_str(g(dlg, "on_behalf_of"));
        let v = if a.is_empty() { crate::val::or_str(g(body, "on_behalf_of")) } else { a };
        crate::val::strip(&v).to_owned()
    };
    let cc = g(body, "credential_class");
    let credential_class = if delegated {
        "delegation".to_owned()
    } else if cc.as_str() == Some("session") || cc.as_str() == Some("key") {
        s(cc)
    } else {
        String::new()
    };
    let mut extra = Map::new();
    if !on_behalf_of.is_empty() {
        extra.insert("on_behalf_of".into(), on_behalf_of.into());
    }
    if shared && person_admin {
        extra.insert("person_admin".into(), true.into());
    }
    if ws_principal {
        extra.insert("principal_kind".into(), "workspace".into());
        extra.insert("principal_workspace".into(), principal_workspace.into());
    }
    Ok(Caller {
        subject: crate::val::pystr(uid),
        email: crate::val::lower(crate::val::strip(&crate::val::or_str(g(body, "email")))),
        email_verified: g(body, "email_verified") == &Value::Bool(true),
        is_admin: admin,
        workspaces,
        writable: Some(writable),
        delegated,
        regime: crate::val::lower(crate::val::strip(&crate::val::or_str(g(dlg, "regime")))),
        shared,
        cross_org: shared && g(dlg, "audience").as_str() == Some("cross_org"),
        session: crate::val::or_str(g(dlg, "unit")),
        trace: trace.to_owned(),
        internal: false,
        org: String::new(),
        credential_class,
        extra,
    })
}

/// caller.resolve: one POST to identity's `/internal/validate`.
pub fn resolve(base: &str, secret: &str, token: &str, trace: &str) -> Result<Caller, ResolveError> {
    let token = crate::val::strip(token);
    if token.is_empty() {
        return Err(ResolveError::Unknown);
    }
    let url = format!("{}{}", base.trim_end_matches('/'), VALIDATE_PATH);
    let reply = net::post_json(&url, &[("x-internal-secret", secret), (ACCEPTS_DELEGATION_HEADER, "1")], &json!({"token": token}), TIMEOUT_S)
        .map_err(|e| ResolveError::Unavailable(e.class_name().into()))?;
    if reply.status == 401 {
        return Err(ResolveError::Unknown);
    }
    if reply.status != 200 {
        return Err(ResolveError::Unavailable(format!("identity answered {}", reply.status)));
    }
    let body = reply.json().map_err(|_| ResolveError::Unavailable("identity answered a body that is not JSON".into()))?;
    if !body.is_object() {
        return Err(ResolveError::Unavailable("identity answered a body that is not an object".into()));
    }
    from_validate(token, &body, trace)
}

pub fn refusal() -> Value {
    json!({"status": "refused", "reason": "human_session_required",
           "instruction": "This session runs without a person in the loop. Record what you wanted to do and stop; do not retry it another way."})
}

pub fn shared_refusal() -> Value {
    json!({"status": "refused", "reason": "shared_conversation",
           "instruction": "Other people read this conversation, so its answer may use only what every one of them can read. Say you cannot use it here, and offer to answer in the person's private chat; do not retry it another way."})
}

pub fn session_refusal() -> Value {
    json!({"status": "refused", "reason": "session_required",
           "instruction": "A decision is made by the person at their own terminal, signed in — never with an API key or an agent's token. Tell them it is waiting on them and give them the link; do not retry it another way."})
}

pub fn confirm_refusal() -> Value {
    json!({"status": "refused", "reason": "person_confirmation_required",
           "instruction": "A person accepts or rejects a proposed change themselves. Tell them it is waiting and give them the record's link; do not retry it another way."})
}
