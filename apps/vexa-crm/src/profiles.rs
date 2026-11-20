//! A contact links to a person's published public profile (profiles.py): identity's internal
//! profile doors, with the internal secret. Behind `public_profiles` (explicit).

use serde_json::{json, Map, Value};

use crate::net;
use crate::val::{g, truthy};

pub const FEATURE: &str = "public_profiles";
pub const SUMMARY: &str = "public profiles: contacts linked to a person's own published profile";
pub const PREFIX: &str = "/profile/";
pub const KIND: &str = "links_profile";
pub const DOMAIN: &str = "profile";

/// ^[A-Za-z0-9_-]{16,64}$
pub fn is_handle(h: &str) -> bool {
    (16..=64).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn switched_on() -> bool {
    crate::features::explicit_in(FEATURE, &std::env::var("VEXA_FEATURES").unwrap_or_default())
}

#[derive(Debug)]
pub struct ProfileUnavailable(pub String);

#[derive(Clone)]
pub struct ProfileClient {
    pub base: String,
    pub secret: String,
    pub timeout: f64,
}

fn dict(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(o.clone()),
        _ => Value::Object(Map::new()),
    }
}

impl ProfileClient {
    pub fn new(base: &str, secret: &str) -> Self {
        ProfileClient { base: base.trim_end_matches('/').to_owned(), secret: secret.to_owned(), timeout: 5.0 }
    }

    pub fn public(&self, handle: &str) -> Result<Option<Value>, ProfileUnavailable> {
        let url = format!("{}/internal/profiles/{}", self.base, net::quote(handle));
        let r = net::get(&url, &[("x-internal-secret", &self.secret)], self.timeout).map_err(|e| ProfileUnavailable(e.to_string()))?;
        if r.status == 404 {
            return Ok(None);
        }
        if r.status != 200 {
            return Err(ProfileUnavailable(format!("identity answered {}", r.status)));
        }
        let body = r.json().map_err(|_| ProfileUnavailable("identity answered a body that is not JSON".into()))?;
        Ok(Some(json!({"handle": g(&body, "handle"), "fields": dict(g(&body, "fields")), "company_verified": g(&body, "company_verified")})))
    }

    pub fn tell(&self, handle: &str, org: &str, linked: bool) -> Result<bool, ProfileUnavailable> {
        let url = format!("{}/internal/profiles/{}/links", self.base, net::quote(handle));
        let r = net::post_json(&url, &[("x-internal-secret", &self.secret)], &json!({"org": org, "linked": linked}), self.timeout)
            .map_err(|e| ProfileUnavailable(e.to_string()))?;
        if r.status == 404 {
            return Ok(false);
        }
        if r.status != 200 {
            return Err(ProfileUnavailable(format!("identity answered {}", r.status)));
        }
        Ok(true)
    }

    /// The person's retired identity profile, read once on a claim; None when there is none.
    pub fn legacy(&self, user_id: &str) -> Option<Value> {
        let url = format!("{}/internal/users/{}/legacy-profile", self.base, net::quote(user_id));
        let r = net::get(&url, &[("x-internal-secret", &self.secret)], self.timeout).ok()?;
        if r.status != 200 {
            return None;
        }
        let body = r.json().ok()?;
        Some(json!({"handle": g(&body, "handle"), "published": truthy(g(&body, "published")), "fields": dict(g(&body, "fields"))}))
    }
}
