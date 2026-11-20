//! Which CRM org serves a caller (orgs.py): the install org, or with `personal_crm` on, a person's
//! own org of one as identity answers it at `GET /internal/users/{id}/org`.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

use serde_json::Value;

use crate::caller::Caller;

pub const ORG_PATH: &str = "/internal/users/{subject}/org";
pub const PERSONAL: &str = "personal";
pub const PERSONAL_PREFIX: &str = "p-";
pub const TTL_S: f64 = 30.0;
pub const TIMEOUT_S: f64 = 5.0;

/// ^p-[0-9]+$
pub fn is_personal_org(org: &str) -> bool {
    org.strip_prefix(PERSONAL_PREFIX).is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// The personal CRM's default policy: its one member administers it.
pub fn personal_policy() -> Value {
    serde_json::json!({"active": true, "admin": true})
}

/// Identity could not answer (503 "Identity service unavailable").
#[derive(Debug)]
pub struct IdentityUnavailable(pub String);

pub type EnsureOrg = Box<dyn Fn(&str, &str) -> crate::err::R<()> + Send + Sync>;

pub struct OrgResolver {
    pub install_org: String,
    base: String,
    secret: String,
    ensure_org: Option<EnsureOrg>,
    cache: Mutex<HashMap<String, (Instant, String)>>,
    made: Mutex<HashSet<String>>,
}

pub enum OrgError {
    Identity(IdentityUnavailable),
    Crm(crate::err::CrmError),
}

impl OrgResolver {
    pub fn new(install_org: &str, base: &str, secret: &str, ensure_org: Option<EnsureOrg>) -> Self {
        OrgResolver {
            install_org: install_org.to_owned(),
            base: base.trim_end_matches('/').to_owned(),
            secret: secret.to_owned(),
            ensure_org,
            cache: Mutex::new(HashMap::new()),
            made: Mutex::new(HashSet::new()),
        }
    }

    pub fn org_for(&self, caller: &Caller) -> Result<String, OrgError> {
        if caller.internal || caller.subject.is_empty() || !crate::features::personal_crm_on() {
            return Ok(self.install_org.clone());
        }
        let now = Instant::now();
        let hit = self.cache.lock().unwrap().get(&caller.subject).cloned();
        let org = match hit {
            Some((at, org)) if now.duration_since(at).as_secs_f64() < TTL_S => org,
            _ => {
                let org = self.ask(&caller.subject).map_err(OrgError::Identity)?;
                self.cache.lock().unwrap().insert(caller.subject.clone(), (now, org.clone()));
                org
            }
        };
        if org != self.install_org && !self.made.lock().unwrap().contains(&org) {
            if let Some(ensure) = &self.ensure_org {
                let name = if caller.email.is_empty() { org.clone() } else { caller.email.clone() };
                ensure(&org, &name).map_err(OrgError::Crm)?;
                self.made.lock().unwrap().insert(org.clone());
            }
        }
        Ok(org)
    }

    fn ask(&self, subject: &str) -> Result<String, IdentityUnavailable> {
        if self.base.is_empty() {
            return Err(IdentityUnavailable("no identity to ask for the caller's org".into()));
        }
        let url = format!("{}{}", self.base, ORG_PATH.replace("{subject}", subject));
        let r = crate::net::get(&url, &[("x-internal-secret", &self.secret)], TIMEOUT_S).map_err(|e| IdentityUnavailable(e.class_name().into()))?;
        if r.status != 200 {
            return Err(IdentityUnavailable(format!("identity answered {} for the caller's org", r.status)));
        }
        let body = r.json().map_err(|_| IdentityUnavailable("identity answered a body that is not JSON".into()))?;
        let org = if crate::val::truthy(&body) { crate::val::g(&body, "org").clone() } else { Value::Null };
        let org = if crate::val::truthy(&org) { org } else { serde_json::json!({}) };
        let oid = crate::val::or_str(crate::val::g(&org, "id"));
        if crate::val::g(&org, "kind").as_str() == Some(PERSONAL) && oid == format!("{PERSONAL_PREFIX}{subject}") {
            return Ok(oid);
        }
        Ok(self.install_org.clone())
    }
}
