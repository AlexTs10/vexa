//! The connection policy, enforced at the broker as well: what agent-api
//! forwards with each action, held again here. Every refusal is a 409 whose
//! sentence names the policy key.

use serde_json::json;

use crate::broker::Who;
use crate::fail::{Fail, R};
use crate::models::{ActionPolicy, Attachment};
use crate::{obs, util};

pub fn refuse(key: &str, why: &str) -> Fail {
    obs::event("policy_refused", "warning", None, Some(json!({"policy_key": key})));
    Fail::Http(409, format!("Refused by policy {key}: {why}"))
}

/// An account read by a worker without a person in the loop is served only
/// when the forwarded policy allows it unattended.
pub fn require_regime(who: &Who, policy: &ActionPolicy, route: &str) -> R<()> {
    if who.role == "agent" && who.unwatched && !policy.unattended {
        obs::event("regime_refused", "warning", Some(&who.actor), Some(json!({"route": route})));
        return Err(Fail::http(403, "This session runs without a person in the loop"));
    }
    Ok(())
}

fn domain(address: &str) -> String {
    address.rsplit('@').next().unwrap_or("").trim().to_lowercase()
}

pub fn require_domains<'a>(addresses: impl IntoIterator<Item = &'a String>, allowed: &Option<Vec<String>>, key: &str) -> R<()> {
    let Some(allowed) = allowed else { return Ok(()) };
    let allowed: Vec<String> = allowed.iter().map(|d| d.to_lowercase()).collect();
    let mut outside: Vec<String> = addresses.into_iter().map(|a| domain(a)).filter(|d| !allowed.contains(d)).collect();
    outside.sort();
    outside.dedup();
    if !outside.is_empty() {
        return Err(refuse(key, &format!("{} is not an allowed domain", outside.join(", "))));
    }
    Ok(())
}

pub fn require_calendar(calendar_id: &str, policy: &ActionPolicy) -> R<()> {
    if policy.calendars.as_ref().is_some_and(|c| !c.iter().any(|x| x == calendar_id)) {
        return Err(refuse("calendar_ids", "this calendar is not one an agent may change"));
    }
    Ok(())
}

pub fn require_notify(notify: bool, policy: &ActionPolicy) -> R<()> {
    if notify && !policy.notify_attendees {
        return Err(refuse("calendar_notify_attendees", "agents may not ask Google to email attendees"));
    }
    Ok(())
}

/// Decode attachments, refusing them unless policy allows, and above the size cap.
pub fn attachments(items: &[Attachment], policy: &ActionPolicy) -> R<Vec<(String, String, Vec<u8>)>> {
    if items.is_empty() {
        return Ok(vec![]);
    }
    if !policy.attachments {
        return Err(refuse("draft_attachments", "drafts may not carry attachments"));
    }
    let mut out = Vec::new();
    let mut total = 0usize;
    for item in items {
        let data = util::b64decode_strict(&item.data).ok_or_else(|| Fail::http(422, "Attachment data is not base64"))?;
        total += data.len();
        out.push((item.filename.clone(), item.content_type.clone(), data));
    }
    if total as i64 > policy.attachment_max_bytes {
        return Err(refuse("draft_attachment_max_kb", &format!("attachments total {} KB, above the cap", total / 1024)));
    }
    Ok(out)
}
