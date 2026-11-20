//! Whether this install serves the CRM at all (`VEXA_FEATURES`, features.py).

use serde_json::{json, Value};

pub const ENV: &str = "VEXA_FEATURES";
pub const FEATURE: &str = "crm";
pub const REASON: &str = "feature_disabled";
pub const SUMMARY: &str = "the CRM: the record page, crm_* tools, crm-api";
pub const DESKTOP: &str = "desktop";
pub const DESKTOP_SUMMARY: &str = "the desktop: workspaces, chosen agents and files, arranged by you or your agent";
pub const CARDS: &str = "desktop_cards";
pub const CARDS_SUMMARY: &str = "cards on the desktop: the CRM cards you are on, and the ones agents propose";
pub const CARD_PREFIX: &str = "/card/";
pub const CARD_TOOL_PREFIX: &str = "card_";
pub const DESK_PREFIX: &str = "/desk/";
pub const DESK_TOOL_PREFIX: &str = "desktop_";
pub const ALWAYS_SERVED: [&str; 3] = ["/health", "/.well-known/mcp-tools.json", "/openapi.json"];
pub const PERSONAL_CRM: &str = "personal_crm";

fn raw() -> String {
    std::env::var(ENV).unwrap_or_default()
}

/// ^/internal/orgs/p-[0-9]+/erase$
pub fn is_erase_path(path: &str) -> bool {
    path.strip_prefix("/internal/orgs/p-")
        .and_then(|r| r.strip_suffix("/erase"))
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Python's str.strip().lower() of one token.
fn tokens(raw: &str) -> Vec<String> {
    raw.split(',').map(|t| crate::val::lower(crate::val::strip(t))).collect()
}

pub fn switched_on_in(name: &str, raw: &str) -> bool {
    let mut on = false;
    for token in tokens(raw) {
        if token.is_empty() {
            continue;
        }
        let value = !token.starts_with('-');
        let t = token.trim_start_matches(['-', '+']);
        let t = crate::val::strip(t);
        if t == "all" || t == name {
            on = value;
        }
    }
    on
}

pub fn switched_on(name: &str) -> bool {
    switched_on_in(name, &raw())
}

/// Explicit only: `all` does not switch it on.
pub fn explicit_in(name: &str, raw: &str) -> bool {
    let mut on = false;
    for token in tokens(raw) {
        let value = !token.starts_with('-');
        if crate::val::strip(token.trim_start_matches(['-', '+'])) == name {
            on = value;
        }
    }
    on
}

pub fn personal_crm_on() -> bool {
    let r = raw();
    explicit_in(PERSONAL_CRM, &r) && switched_on_in(FEATURE, &r)
}

pub fn desk_served() -> bool {
    switched_on(FEATURE) && switched_on(DESKTOP)
}

pub fn cards_served() -> bool {
    desk_served() && switched_on(CARDS)
}

pub fn refusal(name: &str, summary: &str) -> Value {
    json!({
        "status": "refused",
        "reason": REASON,
        "feature": name,
        "instruction": format!("{name} is switched off on this deployment. Do not retry it another way; say it is not available here."),
        "tell_your_person": format!("This isn't switched on here yet ({summary}). An administrator can turn it on."),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rules() {
        assert!(!switched_on_in("crm", ""));
        assert!(switched_on_in("crm", "all"));
        assert!(!switched_on_in("crm", "all,-crm"));
        assert!(switched_on_in("crm", " CRM ,x"));
        assert!(!explicit_in("personal_crm", "all"));
        assert!(explicit_in("personal_crm", "crm,personal_crm"));
        assert!(is_erase_path("/internal/orgs/p-12/erase"));
        assert!(!is_erase_path("/internal/orgs/p-/erase"));
    }
}
