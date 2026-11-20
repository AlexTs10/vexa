//! The privacy mark (D6): a worker's session is marked in Redis when a read forwarded for it returned
//! private data; its current mark rides to the service as `X-Vexa-Taint`.

use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Value};

use crate::redis::{self, Reply};

pub const TTL_SEC: i64 = 12 * 3600;
pub const LABEL_HEADER: &str = "x-vexa-privacy";
pub const STATE_HEADER: &str = "x-vexa-taint";
pub const UNVERIFIABLE: &str = "unverifiable";
pub const MARKED_DOMAINS: [&str; 3] = ["agent", "crm", "meetings"];

fn session_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?P<base>agent-.+?-(?:chat|room)-.+?)(?:-g[0-9A-Za-z]+)?(?:-read)?(?:-auto|-signal)?$").unwrap())
}

pub fn session_of_unit(unit: &str) -> String {
    let unit = unit.trim();
    session_re().captures(unit).and_then(|c| c.name("base")).map_or(unit.to_owned(), |m| m.as_str().to_owned())
}

pub fn keys_for(unit: &str) -> [String; 3] {
    let s = session_of_unit(unit);
    [format!("vexa:taint:unit:{unit}"), format!("vexa:taint:session:{s}"), format!("vexa:taint:wsession:{s}")]
}

/// `re.sub(r"[^a-z0-9_.:() -]", "", s.strip().lower())[:64]`
pub fn clean(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.:() -".contains(*c))
        .take(64)
        .collect()
}

pub fn parse_label(value: Option<&str>) -> BTreeSet<String> {
    let raw = value.unwrap_or("").trim().to_lowercase();
    if raw == "none" || raw == "shareable" {
        return BTreeSet::new();
    }
    if !raw.starts_with("private") {
        return ["unlabelled".to_owned()].into();
    }
    let rest = raw.split_once(';').map_or("", |(_, r)| r);
    let mut classes = BTreeSet::new();
    for part in rest.split(';') {
        let (k, v) = part.trim().split_once('=').unwrap_or((part.trim(), ""));
        if k.trim() == "class" {
            classes.extend(v.split(',').map(clean).filter(|c| !c.is_empty()));
        }
    }
    if classes.is_empty() {
        classes.insert("private".into());
    }
    classes
}

pub fn mark_unavailable_body() -> Value {
    json!({"refused": "privacy_mark_unavailable", "fault": {"code": "privacy_mark_unavailable", "retry": "later"},
           "instruction": "This read returns the person's private data, and the privacy mark that keeps it out of shared pages could not be recorded right now, so it was not returned. Tell the person in one line and try again later."})
}

/// The mark over Redis: one connection at a time, reopened after a failure.
pub struct Marker {
    target: redis::Target,
    conn: Mutex<Option<redis::Conn>>,
}

impl Marker {
    pub fn new(target: redis::Target) -> Marker {
        Marker { target, conn: Mutex::new(None) }
    }

    fn with<T>(&self, f: impl Fn(&mut redis::Conn) -> std::io::Result<T>) -> Result<T, ()> {
        let mut slot = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_none() {
            *slot = Some(redis::Conn::open(&self.target, Some(Duration::from_secs(10))).map_err(|_| ())?);
        }
        let result = f(slot.as_mut().ok_or(())?);
        if result.is_err() {
            *slot = None;
        }
        result.map_err(|_| ())
    }

    pub fn mark(&self, unit: &str, sources: &BTreeSet<String>) -> Result<(), ()> {
        let found: BTreeSet<String> = sources.iter().map(|s| clean(s)).filter(|s| !s.is_empty()).collect();
        let unit = unit.trim();
        if unit.is_empty() || found.is_empty() {
            return Ok(());
        }
        let now = (vexa_native_kit::ids::now().floor() as i64).to_string();
        let keys = keys_for(unit);
        let mut cmds = Vec::new();
        for key in &keys[..2] {
            let mut h = vec![b"HSET".to_vec(), key.as_bytes().to_vec()];
            for s in &found {
                h.push(s.as_bytes().to_vec());
                h.push(now.as_bytes().to_vec());
            }
            cmds.push(h);
            cmds.push(vec![b"EXPIRE".to_vec(), key.as_bytes().to_vec(), TTL_SEC.to_string().into_bytes()]);
        }
        let replies = self.with(|c| c.pipeline(&cmds))?;
        if replies.iter().any(|r| matches!(r, Reply::Error(_))) {
            return Err(());
        }
        Ok(())
    }

    pub fn read(&self, unit: &str) -> Result<BTreeSet<String>, ()> {
        let cutoff = vexa_native_kit::ids::now() - TTL_SEC as f64;
        let mut out = BTreeSet::new();
        for key in keys_for(unit) {
            let r = self.with(|c| c.cmd(&[b"HGETALL", key.as_bytes()]))?;
            if let Reply::Error(_) = r {
                return Err(());
            }
            for pair in r.items().chunks(2) {
                let (Some(src), Some(at)) = (pair.first().and_then(Reply::text), pair.get(1).and_then(Reply::text)) else { continue };
                match at.trim().parse::<f64>() {
                    Ok(t) if t < cutoff => {}
                    _ => {
                        out.insert(src);
                    }
                }
            }
        }
        Ok(out)
    }

    /// The `X-Vexa-Taint` value: `none`, the sources, or `unverifiable`.
    pub fn state_for(&self, unit: &str) -> String {
        match self.read(unit) {
            Err(()) => UNVERIFIABLE.into(),
            Ok(found) if found.is_empty() => "none".into(),
            Ok(found) => found.into_iter().collect::<Vec<_>>().join(","),
        }
    }

    /// Mark from a forwarded answer; false when the answer must be refused.
    pub fn mark_from_response(&self, unit: &str, status: u16, label: Option<&str>) -> bool {
        if unit.is_empty() || !(200..300).contains(&status) {
            return true;
        }
        let found = parse_label(label);
        found.is_empty() || self.mark(unit, &found).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_sessions() {
        assert!(parse_label(Some("None")).is_empty());
        assert_eq!(parse_label(None), ["unlabelled".to_owned()].into());
        assert_eq!(parse_label(Some("private; class=CRM, mail!")), ["crm".to_owned(), "mail".to_owned()].into());
        assert_eq!(parse_label(Some("private")), ["private".to_owned()].into());
        assert_eq!(session_of_unit("agent-7-chat-abc-g12-read-auto"), "agent-7-chat-abc");
    }
}
