//! report_issue's ticket: its bounds, its composition, and the sink's wire shape (`raw` or `github`).

use blake2::digest::{consts::U8, Mac};
use serde_json::{json, Map, Value};

pub const MAX_TEXT_CHARS: usize = 2000;
pub const MAX_LOGS_CHARS: usize = 4000;
const MAX_SUMMARY_CHARS: usize = 64;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_CALLER_SALT: &str = "vexa-mcp-report-issue";

/// The clipped report, field by field (`ReportIssue` after its validator).
pub struct Report {
    pub what_i_tried: String,
    pub what_happened: String,
    pub deployment: String,
    pub native_meeting_id: Option<String>,
    pub platform: Option<String>,
    pub severity: Value,
    pub version: Option<String>,
    pub logs: Option<String>,
    pub logs_truncated: bool,
}

/// Trim and cap a caller's string; None for blank.
pub fn clip(value: Option<&str>, limit: usize) -> Option<String> {
    let text = value?.trim();
    (!text.is_empty()).then(|| text.chars().take(limit).collect())
}

pub fn fingerprint(deployment: &str, what_happened: &str) -> String {
    let sample: String = what_happened.trim().chars().take(200).collect();
    let material = format!("{}|{sample}", deployment.trim().to_lowercase());
    vexa_native_kit::sha256::hex(&vexa_native_kit::sha256::digest(material.as_bytes()))[..16]
        .to_owned()
}

/// str.splitlines()'s first line.
fn first_line(text: &str) -> &str {
    text.split(|c| {
        matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        )
    })
    .next()
    .unwrap_or("")
}

pub fn summary_of(what_happened: &str) -> String {
    let line = first_line(what_happened.trim()).trim();
    if line.chars().count() <= MAX_SUMMARY_CHARS {
        return line.to_owned();
    }
    let cut: String = line.chars().take(MAX_SUMMARY_CHARS - 1).collect();
    format!("{}\u{2026}", cut.trim_end())
}

pub fn description_of(r: &Report) -> String {
    let mut parts = vec![
        format!("What I tried:\n{}", r.what_i_tried),
        format!("What happened:\n{}", r.what_happened),
    ];
    let mut place = r.deployment.clone();
    if let Some(v) = &r.version {
        place.push(' ');
        place.push_str(v);
    }
    parts.push(format!("Deployment: {place}"));
    if let Some(id) = &r.native_meeting_id {
        parts.push(format!(
            "Meeting: {} / {id}",
            r.platform.as_deref().unwrap_or("unknown platform")
        ));
    }
    if let Some(logs) = &r.logs {
        parts.push(format!("Logs:\n{logs}"));
    }
    parts.join("\n\n")
}

pub fn is_github(format: Option<&str>) -> bool {
    format.unwrap_or("").trim().to_lowercase() == "github"
}

fn labels(raw: Option<&str>) -> Vec<String> {
    let raw = match raw {
        Some(r) if !r.trim().is_empty() => r,
        _ => "state: incoming",
    };
    raw.split(',')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// str(value or fallback).
fn text_or(v: Option<&Value>, fallback: &str) -> String {
    if !vexa_native_kit::pyjson::truthy(v) {
        return fallback.to_owned();
    }
    vexa_native_kit::pyjson::py_str(v.unwrap_or(&Value::Null))
}

/// str(value), None included.
fn text(v: Option<&Value>) -> String {
    vexa_native_kit::pyjson::py_str(v.unwrap_or(&Value::Null))
}

fn github_body(p: &Map<String, Value>) -> String {
    let s = |k: &str| text(p.get(k));
    let mut l: Vec<String> = vec![
        "_Filed by a calling agent through the Vexa MCP `report_issue` tool._".into(),
        String::new(),
        "### What I tried".into(),
        text_or(p.get("what_i_tried"), "—"),
        String::new(),
        "### What happened".into(),
        text_or(p.get("what_happened"), "—"),
        String::new(),
        "### Join key".into(),
    ];
    if vexa_native_kit::pyjson::truthy(p.get("native_meeting_id")) {
        l.push(format!(
            "- **native_meeting_id:** `{}`",
            s("native_meeting_id")
        ));
        l.push(format!(
            "- **platform:** `{}`",
            text_or(p.get("platform"), "unknown")
        ));
        match p.get("entity") {
            Some(Value::Object(e)) => l.push(format!(
                "- **resolved entity:** `{}` → `{}`",
                text(e.get("type")),
                text(e.get("url"))
            )),
            _ => l.push(
                "- **resolved entity:** none (not owned by the calling key, or not found)".into(),
            ),
        }
    } else {
        l.push("- none supplied — this ticket is not bound to a meeting.".into());
    }
    l.push(String::new());
    l.push("### Deployment".into());
    l.push(format!("- **deployment:** {}", s("deployment")));
    l.push(format!(
        "- **version:** {}",
        text_or(p.get("version"), "not stated")
    ));
    let sev = match p.get("severity") {
        None | Some(Value::Null) => "not stated".to_owned(),
        Some(v) => vexa_native_kit::pyjson::py_str(v),
    };
    l.push(format!("- **severity:** {sev}"));
    l.push(String::new());
    if vexa_native_kit::pyjson::truthy(p.get("logs")) {
        l.push("### Logs".into());
        let truncated = if vexa_native_kit::pyjson::truthy(p.get("logs_truncated")) {
            " (truncated server-side)"
        } else {
            ""
        };
        l.push(format!("Pasted by the reporting agent{truncated}:"));
        l.push(String::new());
        l.push("```".into());
        l.push(s("logs"));
        l.push("```".into());
        l.push(String::new());
    }
    l.push("### Provenance".into());
    l.push(format!(
        "- **source:** `{}` · **tool:** `{}`",
        s("source"),
        s("tool")
    ));
    l.push(format!("- **reported_at:** `{}`", s("reported_at")));
    l.push(format!(
        "- **fingerprint:** `{}` (content-derived, for dedupe)",
        s("fingerprint")
    ));
    l.push(format!(
        "- **caller_fingerprint:** `{}` (salted hash of the calling key — never the key itself)",
        s("caller_fingerprint")
    ));
    l.join("\n")
}

/// (headers, body) for the sink hop.
pub fn sink_request(
    payload: &Map<String, Value>,
    token: &str,
    format: Option<&str>,
    labels_env: Option<&str>,
) -> (Vec<(String, String)>, Value) {
    let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
    if is_github(format) {
        headers.push(("Accept".into(), "application/vnd.github+json".into()));
        headers.push(("X-GitHub-Api-Version".into(), "2022-11-28".into()));
        if !token.is_empty() {
            headers.push(("Authorization".into(), format!("Bearer {token}")));
        }
        let mut body = Map::new();
        body.insert(
            "title".into(),
            payload.get("summary").cloned().unwrap_or(Value::Null),
        );
        body.insert("body".into(), github_body(payload).into());
        let labels = labels(labels_env);
        if !labels.is_empty() {
            body.insert("labels".into(), json!(labels));
        }
        return (headers, Value::Object(body));
    }
    if !token.is_empty() {
        headers.push(("Authorization".into(), format!("Bearer {token}")));
    }
    (headers, Value::Object(payload.clone()))
}

/// blake2b(key, key=salt[:64], digest_size=8): a stable handle for the caller, never the key.
pub fn caller_fingerprint(api_key: &str, salt: Option<&str>) -> String {
    let salt = match salt {
        Some(s) if !s.is_empty() => s,
        _ => DEFAULT_CALLER_SALT,
    };
    let key = &salt.as_bytes()[..salt.len().min(64)];
    let mut mac = <blake2::Blake2bMac<U8> as Mac>::new_from_slice(key)
        .expect("a blake2b key of at most 64 bytes");
    mac.update(api_key.as_bytes());
    vexa_native_kit::sha256::hex(&mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_match_python() {
        // hashlib's values for the parity key (default salt) and the parity report.
        assert_eq!(
            caller_fingerprint("parity-key-0123", None),
            "8275dfa1114ec453"
        );
        assert_eq!(fingerprint("cloud", "It broke\nbadly"), "1decf3130f5e02a7");
        assert_eq!(
            summary_of(&"b".repeat(80)),
            format!("{}\u{2026}", "b".repeat(63))
        );
    }
}
