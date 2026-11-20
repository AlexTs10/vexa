//! The desk's limits as the company holds them in `_global/POLICIES.md` (policies.py), read
//! through agent-api's door (`CRM_AGENT_API_URL`), failing soft to the defaults, kept 30 s.

use std::sync::Mutex;
use std::time::Instant;

use serde_json::{Map, Value};

pub const DOOR_ENV: &str = "CRM_AGENT_API_URL";
pub const POLICIES_FILE: &str = "POLICIES.md";
pub const GLOBAL_SLUG: &str = "_global";
pub const READER: &str = "crm";
pub const TTL_S: f64 = 30.0;
pub const TIMEOUT_S: f64 = 3.0;

/// The limits, with the values this service enforced before they were policy (DEFAULTS).
pub const DEFAULTS: [(&str, i64); 4] = [
    ("desk_placements_max", 50),
    ("card_proposals_pending_max", 5),
    ("card_proposals_per_agent_per_day", 20),
    ("card_proposal_ttl_days", 7),
];

pub fn default_of(key: &str) -> i64 {
    DEFAULTS.iter().find(|(k, _)| *k == key).map(|(_, v)| *v).unwrap_or(0)
}

pub fn defaults() -> Map<String, Value> {
    DEFAULTS.iter().map(|(k, v)| (k.to_string(), Value::from(*v))).collect()
}

fn minimum(key: &str) -> i64 {
    if key == "card_proposal_ttl_days" { 1 } else { 0 }
}

/// The `key: value` lines between the opening and closing fence.
pub fn front_matter(raw: &str) -> Vec<(String, String)> {
    let text = crate::val::strip(raw);
    if !text.starts_with("---") {
        return Vec::new();
    }
    let lines = crate::markdown_links::splitlines(text);
    let Some(close) = (1..lines.len()).find(|&i| crate::val::strip(lines[i]) == "---") else { return Vec::new() };
    let mut attrs: Vec<(String, String)> = Vec::new();
    for line in &lines[1..close] {
        if crate::val::strip(line).starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else { continue };
        let key = crate::val::strip(key);
        if key.is_empty() {
            continue;
        }
        let key = crate::val::lower(key);
        let value = crate::val::strip(value).trim_matches(['"', '\'']).to_owned();
        match attrs.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => attrs.push((key, value)),
        }
    }
    attrs
}

/// Python's str.isdigit() for the ASCII and Unicode decimal digits a file carries.
fn is_digits(v: &str) -> bool {
    !v.is_empty() && v.chars().all(|c| c.is_ascii_digit())
}

/// (limits, problems): every key in DEFAULTS, narrowed where the file narrows it.
pub fn resolve(raw: Option<&str>) -> (Map<String, Value>, Vec<String>) {
    let attrs = front_matter(raw.unwrap_or(""));
    let mut limits = defaults();
    let mut problems = Vec::new();
    for (key, default) in DEFAULTS {
        let value = attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).unwrap_or("");
        let value = crate::val::strip(value).replace(',', "");
        if value.is_empty() {
            continue;
        }
        let low = minimum(key);
        if !is_digits(&value) {
            problems.push(format!("{key}: {} is not a whole number — using the default {default}", vexa_native_kit::pyjson::py_str_repr(&value)));
            continue;
        }
        let n: i128 = value.parse().unwrap_or(i128::MAX);
        if n > default as i128 {
            problems.push(format!("{key}: {value} is above the default {default}, and a company may only narrow it — using {default}"));
        } else if n < low as i128 {
            problems.push(format!("{key}: {value} is below {low} — using the default {default}"));
        } else {
            limits.insert(key.to_owned(), Value::from(n as i64));
        }
    }
    (limits, problems)
}

pub struct Policies {
    base: String,
    secret: String,
    state: Mutex<(Option<Instant>, Map<String, Value>)>,
}

impl Policies {
    pub fn new(agent_url: &str, secret: &str) -> Self {
        Policies {
            base: crate::val::strip(agent_url).trim_end_matches('/').to_owned(),
            secret: secret.to_owned(),
            state: Mutex::new((None, defaults())),
        }
    }

    /// POLICIES.md from _global, or None for anything but a 200 with content.
    pub fn fetch(&self) -> Option<String> {
        if self.base.is_empty() {
            return None;
        }
        let url = format!("{}/api/workspace/file?{}", self.base, crate::val::urlencode(&[("path", POLICIES_FILE), ("slug", GLOBAL_SLUG)]));
        let r = match crate::net::get(&url, &[("x-user-id", READER), ("x-internal-secret", &self.secret)], TIMEOUT_S) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("INFO:crm.policies:policies: could not read {GLOBAL_SLUG}/{POLICIES_FILE} ({}) — using the default desk limits", e.class_name());
                return None;
            }
        };
        if r.status != 200 {
            return None;
        }
        let body = match r.json() {
            Ok(b) => b,
            Err(_) => {
                eprintln!("INFO:crm.policies:policies: could not read {GLOBAL_SLUG}/{POLICIES_FILE} (JSONDecodeError) — using the default desk limits");
                return None;
            }
        };
        body.get("content").and_then(Value::as_str).map(str::to_owned)
    }

    pub fn limits(&self) -> Map<String, Value> {
        let mut st = self.state.lock().unwrap();
        let fresh = st.0.is_some_and(|at| at.elapsed().as_secs_f64() < TTL_S);
        if !fresh {
            let (limits, problems) = resolve(self.fetch().as_deref());
            for p in problems {
                eprintln!("WARNING:crm.policies:policies: {p}");
            }
            *st = (Some(Instant::now()), limits);
        }
        st.1.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrows_only() {
        let (l, p) = resolve(Some("---\ndesk_placements_max: 10\ncard_proposal_ttl_days: 0\ncard_proposals_pending_max: 9\n---\n"));
        assert_eq!(l["desk_placements_max"], 10);
        assert_eq!(l["card_proposal_ttl_days"], 7);
        assert_eq!(l["card_proposals_pending_max"], 5);
        assert_eq!(p.len(), 2);
    }
}
