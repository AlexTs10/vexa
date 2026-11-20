//! The CRM's half of the private-data hold (privacy.py).

use serde_json::json;

use crate::caller::Caller;
use crate::err::{CrmError, R};

pub const LABEL_HEADER: &str = "x-vexa-privacy";
pub const CRM_LABEL: &str = "private; class=crm";
pub const STATE_HEADER: &str = "x-vexa-taint";
pub const REASON: &str = "private_sources_to_shared";
pub const FAULT: &str = "held_private_egress";

/// Refuse a worker's write into a multi-reader surface unless its session is unmarked.
pub fn hold(state: Option<&str>, caller: &Caller, surface: &str) -> R<()> {
    if !caller.delegated {
        return Ok(());
    }
    if state.is_some_and(|s| crate::val::lower(crate::val::strip(s)) == "none") {
        return Ok(());
    }
    let raw = match state {
        Some(s) if !s.is_empty() => s,
        _ => "unverifiable",
    };
    let mut sources: Vec<String> = raw.split(',').filter(|s| !crate::val::strip(s).is_empty()).map(str::to_owned).collect();
    sources.sort();
    if sources.is_empty() {
        sources = vec!["unverifiable".into()];
    }
    let unverifiable = sources == ["unverifiable"];
    Err(CrmError::http(409, json!({
        "refused": REASON,
        "fault": {"code": FAULT, "surface": surface, "held": false, "unverifiable": unverifiable},
        "surface": surface,
        "sources": sources,
        "instruction": format!("Nothing was written. This session read the person's private data ({}), and a CRM record or a card is read by other people. Tell the person in one line what you wanted to record and why it waits, and ask them to share it from their own chat. Do not write it another way.", sources.join(", ")),
    })))
}
