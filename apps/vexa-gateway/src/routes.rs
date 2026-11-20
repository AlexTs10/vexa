//! The edge's route table, in registration order, and Starlette's matching over it: the first full
//! match wins; a path that matches with another method answers 405; a path one slash away answers
//! a 307 redirect; anything else 404. FastAPI validates a matched route's typed path parameters
//! (an int, a platform, a 32-hex id) before its handler runs, answering 422.

use std::collections::BTreeSet;

use regex::Regex;
use serde_json::{json, Value};

use crate::manifest::{Assembly, CATCH_ALL};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Param {
    Int,
    Platform,
    Hex32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Handler {
    Health,
    AuthMe,
    McpTaint,
    /// A meetings row, forwarded to its manifest target.
    Meeting,
    /// A meeting bundle row, streamed both ways.
    Bundle,
    /// An identity row forwarded to admin-api at this path.
    Admin(&'static str),
    /// `/user/directory/profiles/{handle}`.
    AdminHandle,
    /// `/user/calendars/{calendar_id}` (PATCH, DELETE).
    AdminCalendar,
    McpStream,
    McpStreamPath,
    McpMessage,
    McpMessagePath,
    /// A forwarded domain's literal row: (domain, upstream template, method it was registered for).
    Literal { domain: String, template: String, method: String },
    /// A forwarded domain's catch-all.
    Tail { domain: String },
}

#[derive(Debug)]
pub struct Route {
    pub path: String,
    pub methods: BTreeSet<String>,
    regex: Regex,
    names: Vec<String>,
    /// The typed parameters FastAPI validates, in the handler's signature order.
    pub checks: Vec<(String, Param)>,
    pub handler: Handler,
}

pub const PLATFORMS: [&str; 7] = ["google_meet", "zoom", "teams", "jitsi", "browser_session", "voice_note", "vexa_call"];
pub const HEX32: &str = "^[a-f0-9]{32}$";

/// Starlette's compile_path: `{x}` is one segment, `{x:path}` the rest.
fn compile(path: &str) -> (Regex, Vec<String>) {
    let mut re = String::from("^");
    let mut names = Vec::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        re.push_str(&regex::escape(&rest[..start]));
        let end = start + rest[start..].find('}').expect("a closed parameter");
        let inner = &rest[start + 1..end];
        let (name, conv) = inner.split_once(':').unwrap_or((inner, "str"));
        re.push_str(if conv == "path" { "(.*)" } else { "([^/]+)" });
        names.push(name.to_owned());
        rest = &rest[end + 1..];
    }
    re.push_str(&regex::escape(rest));
    re.push('$');
    (Regex::new(&re).expect("a route template compiles"), names)
}

fn route(methods: &[&str], path: &str, checks: &[(&str, Param)], handler: Handler) -> Route {
    let set: BTreeSet<String> = methods.iter().map(|m| m.to_string()).collect();
    let (regex, names) = compile(path);
    Route { path: path.to_owned(), methods: set, regex, names, checks: checks.iter().map(|(n, p)| (n.to_string(), *p)).collect(), handler }
}

/// The HTTP routes, in the order the Python edge registers them.
pub fn http_routes(asm: &Assembly, forwarded: &[(&str, String)]) -> Vec<Route> {
    use Handler::*;
    use Param::*;
    const P: (&str, Param) = ("platform", Platform);
    let mid = [("meeting_id", Int)];
    let mut r = vec![
        route(&["GET"], "/health", &[], Health),
        route(&["GET"], "/auth/me", &[], AuthMe),
        route(&["POST"], "/internal/mcp/taint", &[], McpTaint),
        route(&["GET"], "/bot-accounts", &[], Meeting),
        route(&["POST"], "/bot-accounts/sessions", &[], Meeting),
        route(&["GET"], "/bot-accounts/sessions/{session_id}", &[("session_id", Hex32)], Meeting),
        route(&["DELETE"], "/bot-accounts/sessions/{session_id}", &[("session_id", Hex32)], Meeting),
        route(&["GET"], "/bot-accounts/sessions/{session_id}/view/{path:path}", &[("session_id", Hex32)], Meeting),
        route(&["DELETE"], "/bot-accounts/{account_id}", &[("account_id", Hex32)], Meeting),
        route(&["POST"], "/bot-accounts/{account_id}/verify", &[("account_id", Hex32)], Meeting),
        route(&["GET"], "/bots", &[], Meeting),
        route(&["POST"], "/bots", &[], Meeting),
        route(&["GET"], "/bots/status", &[], Meeting),
        route(&["DELETE"], "/bots/{platform}/{native_meeting_id}", &[P], Meeting),
        route(&["PUT"], "/bots/{platform}/{native_meeting_id}/config", &[P], Meeting),
        route(&["POST"], "/bots/{platform}/{native_meeting_id}/speak", &[P], Meeting),
        route(&["GET"], "/transcripts/by-id/{meeting_id}", &mid, Meeting),
        route(&["POST"], "/transcripts/share/accept", &[], Meeting),
        route(&["POST"], "/transcripts/by-id/{meeting_id}/share", &mid, Meeting),
        route(&["POST"], "/transcripts/{platform}/{native_meeting_id}/share", &[P], Meeting),
        route(&["GET"], "/transcripts/search", &[], Meeting),
        route(&["GET"], "/transcripts/{platform}/{native_meeting_id}", &[P], Meeting),
        route(&["GET"], "/transcription/languages", &[], Meeting),
        route(&["GET"], "/recordings", &[], Meeting),
        route(&["GET"], "/recordings/{recording_id}", &[("recording_id", Int)], Meeting),
        route(&["DELETE"], "/recordings/{recording_id}", &[("recording_id", Int)], Meeting),
        route(&["GET"], "/recordings/{recording_id}/master", &[("recording_id", Int)], Meeting),
        route(&["GET"], "/recordings/{recording_id}/media/{media_file_id}/raw", &[("recording_id", Int), ("media_file_id", Int)], Meeting),
        route(&["GET"], "/recordings/{recording_id}/media/{media_file_id}/download", &[("recording_id", Int), ("media_file_id", Int)], Meeting),
        route(&["GET"], "/meetings", &[], Meeting),
        route(&["POST"], "/meetings", &[], Meeting),
        route(&["POST"], "/meetings/import", &[], Bundle),
        route(&["GET"], "/meetings/{meeting_id}", &mid, Meeting),
        route(&["GET"], "/meetings/{meeting_id}/export", &mid, Bundle),
        route(&["POST"], "/meetings/{meeting_id}/export", &mid, Bundle),
        route(&["GET"], "/meetings/{meeting_id}/ics", &mid, Bundle),
        route(&["PATCH"], "/meetings/{meeting_id}", &mid, Meeting),
        route(&["DELETE"], "/meetings/{meeting_id}", &mid, Meeting),
        route(&["POST"], "/meetings/{platform}/{native_meeting_id}/annotate", &[P], Meeting),
        route(&["POST"], "/meetings/{meeting_id}/annotate", &mid, Meeting),
        route(&["POST"], "/meetings/{meeting_id}/share", &mid, Meeting),
        route(&["GET"], "/meetings/{meeting_id}/access", &mid, Meeting),
        route(&["PATCH"], "/meetings/{meeting_id}/access", &mid, Meeting),
        route(&["DELETE"], "/meetings/{meeting_id}/share/{grant_id}", &mid, Meeting),
        route(&["DELETE"], "/meetings/{meeting_id}/viewers/{viewer_id}", &[("meeting_id", Int), ("viewer_id", Int)], Meeting),
        route(&["POST"], "/meetings/{meeting_id}/transcript-import", &mid, Meeting),
        route(&["POST"], "/meetings/{platform}/{native_meeting_id}/share", &[P], Meeting),
        route(&["POST"], "/meetings/{platform}/{native_meeting_id}/workspace", &[P], Meeting),
        route(&["GET"], "/meetings/{platform}/{native_meeting_id}/participants", &[P], Meeting),
        route(&["PUT"], "/meetings/{platform}/{native_meeting_id}/intent", &[P], Meeting),
        route(&["PATCH"], "/meetings/{platform}/{native_meeting_id}", &[P], Meeting),
        route(&["DELETE"], "/meetings/{platform}/{native_meeting_id}", &[P], Meeting),
        route(&["GET"], "/bots/{platform}/{native_meeting_id}/chat", &[P], Meeting),
        route(&["POST"], "/bots/{platform}/{native_meeting_id}/chat", &[P], Meeting),
        route(&["GET"], "/bots/{platform}/{native_meeting_id}/chat/{request_id}", &[P], Meeting),
        route(&["PUT"], "/user/webhook", &[], Admin("/user/webhook")),
        route(&["GET"], "/user/webhook", &[], Admin("/user/webhook")),
        route(&["GET"], "/user/settings", &[], Admin("/user/settings")),
        route(&["PUT"], "/user/settings", &[], Admin("/user/settings")),
        route(&["GET"], "/user/workspace-regime", &[], Admin("/user/workspace-regime")),
        route(&["PUT"], "/user/workspace-regime", &[], Admin("/user/workspace-regime")),
        route(&["GET"], "/user/photo", &[], Admin("/user/photo")),
        route(&["PUT"], "/user/photo", &[], Admin("/user/photo")),
        route(&["DELETE"], "/user/photo", &[], Admin("/user/photo")),
        route(&["GET"], "/user/notifications", &[], Admin("/user/notifications")),
        route(&["PUT"], "/user/notifications", &[], Admin("/user/notifications")),
        route(&["GET"], "/user/profile", &[], Admin("/user/profile")),
        route(&["PUT"], "/user/profile", &[], Admin("/user/profile")),
        route(&["POST"], "/user/profile/withdraw", &[], Admin("/user/profile/withdraw")),
        route(&["POST"], "/user/company-verification", &[], Admin("/user/company-verification")),
        route(&["POST"], "/user/company-verification/check", &[], Admin("/user/company-verification/check")),
        route(&["GET"], "/user/directory/profiles", &[], Admin("/user/directory/profiles")),
        route(&["GET"], "/user/directory/profiles/{handle}", &[], AdminHandle),
        route(&["GET"], "/user/webhook/deliveries", &[], Meeting),
        route(&["GET"], "/user/calendar/sync", &[], Meeting),
        route(&["POST"], "/user/calendar/sync", &[], Meeting),
        route(&["PUT"], "/user/calendar", &[], Admin("/user/calendar")),
        route(&["GET"], "/user/calendar", &[], Admin("/user/calendar")),
        route(&["GET"], "/user/calendars", &[], Admin("/user/calendars")),
        route(&["POST"], "/user/calendars", &[], Admin("/user/calendars")),
        route(&["PATCH"], "/user/calendars/{calendar_id}", &[], AdminCalendar),
        route(&["DELETE"], "/user/calendars/{calendar_id}", &[], AdminCalendar),
        route(&["GET"], "/user/calendars/{calendar_id}/sync", &[], Meeting),
        route(&["POST"], "/user/calendars/{calendar_id}/sync", &[], Meeting),
        route(&["PUT"], "/user/models", &[], Admin("/user/models")),
        route(&["GET"], "/user/models", &[], Admin("/user/models")),
        route(&["PUT"], "/user/transcription", &[], Admin("/user/transcription")),
        route(&["GET"], "/user/transcription", &[], Admin("/user/transcription")),
    ];
    // A forwarded domain: its literal rows in sorted (method, path) order, then its catch-all for
    // the methods its rows declare.
    for (domain, _) in forwarded {
        let (edge, _) = &asm.forwards[*domain];
        let rows: Vec<(String, String)> = asm.owner_of.iter().filter(|(_, d)| d.as_str() == *domain).map(|(k, _)| k.clone()).collect();
        for (method, path) in &rows {
            if !path.ends_with(CATCH_ALL) {
                r.push(route(&[method.as_str()], path, &[], Literal { domain: domain.to_string(), template: path.clone(), method: method.clone() }));
            }
        }
        let catch: Vec<&str> = rows.iter().filter(|(_, p)| p.ends_with(CATCH_ALL)).map(|(m, _)| m.as_str()).collect();
        if !catch.is_empty() {
            r.push(route(&catch, &format!("{edge}{CATCH_ALL}"), &[], Tail { domain: domain.to_string() }));
        }
    }
    let mcp_rest = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
    r.extend([
        route(&["GET"], "/mcp", &[], McpStream),
        route(&["GET"], "/mcp/{path:path}", &[], McpStreamPath),
        route(&mcp_rest, "/mcp", &[], McpMessage),
        route(&mcp_rest, "/mcp/{path:path}", &[], McpMessagePath),
        route(&["POST"], "/voice-notes/recorder", &[], Meeting),
        route(&["GET"], "/voice-notes/{native_meeting_id}/stream", &[], Meeting),
    ]);
    r
}

#[derive(Debug)]
pub enum WsRoute {
    Multiplex,
    Voice(String),
    Vnc(String),
}

pub fn ws_match(path: &str) -> Option<WsRoute> {
    if path == "/ws" {
        return Some(WsRoute::Multiplex);
    }
    let segs: Vec<&str> = path.split('/').collect();
    match segs.as_slice() {
        ["", "voice-notes", id, "stream"] if !id.is_empty() => Some(WsRoute::Voice(id.to_string())),
        ["", "bot-accounts", "sessions", id, "vnc"] if !id.is_empty() => Some(WsRoute::Vnc(id.to_string())),
        _ => None,
    }
}

pub enum Match<'a> {
    Full(&'a Route, Vec<(String, String)>),
    /// The path matched routes with other methods only: the first one's methods.
    Partial(&'a BTreeSet<String>),
    NotFound,
}

pub fn find<'a>(routes: &'a [Route], method: &str, path: &str) -> Match<'a> {
    let mut partial = None;
    for r in routes {
        if let Some(c) = r.regex.captures(path) {
            if r.methods.contains(method) {
                let params = r.names.iter().enumerate().map(|(i, n)| (n.clone(), c.get(i + 1).map_or("", |m| m.as_str()).to_owned())).collect();
                return Match::Full(r, params);
            }
            partial.get_or_insert(&r.methods);
        }
    }
    partial.map_or(Match::NotFound, Match::Partial)
}

/// Starlette's redirect_slashes: the path with its trailing slash removed (or one added) matches
/// some route.
pub fn redirect_path(routes: &[Route], path: &str) -> Option<String> {
    if path == "/" {
        return None;
    }
    let other = if path.ends_with('/') { path.trim_end_matches('/').to_owned() } else { format!("{path}/") };
    routes.iter().any(|r| r.regex.is_match(&other)).then_some(other)
}

/// pydantic's lax str -> int: surrounding whitespace, a sign, single underscores between digits,
/// and a fraction of zeros. Any size.
pub fn int_text(text: &str) -> bool {
    let t = text.trim();
    let t = match t.split_once('.') {
        Some((whole, frac)) if !frac.is_empty() && frac.bytes().all(|b| b == b'0') => whole,
        Some(_) => return false,
        None => t,
    };
    let digits = t.strip_prefix(['-', '+']).unwrap_or(t);
    !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
}

/// The 422 errors FastAPI answers for a matched route's typed path parameters, in signature order.
pub fn validate(route: &Route, params: &[(String, String)]) -> Vec<Value> {
    let mut errors = Vec::new();
    for (name, kind) in &route.checks {
        let value = params.iter().find(|(n, _)| n == name).map_or("", |(_, v)| v.as_str());
        let loc = json!(["path", name]);
        match kind {
            Param::Int if !int_text(value) => errors.push(json!({"type": "int_parsing", "loc": loc,
                "msg": "Input should be a valid integer, unable to parse string as an integer", "input": value})),
            Param::Platform if !PLATFORMS.contains(&value) => {
                let expected = "'google_meet', 'zoom', 'teams', 'jitsi', 'browser_session', 'voice_note' or 'vexa_call'";
                errors.push(json!({"type": "literal_error", "loc": loc, "msg": format!("Input should be {expected}"),
                    "input": value, "ctx": {"expected": expected}}))
            }
            Param::Hex32 if !(value.len() == 32 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) => {
                errors.push(json!({"type": "string_pattern_mismatch", "loc": loc, "msg": format!("String should match pattern '{HEX32}'"),
                    "input": value, "ctx": {"pattern": HEX32}}))
            }
            _ => {}
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ints_like_pydantic() {
        for ok in ["12", "0012", "-3", "+3", " 12 ", "1_000", "1.0", "1.00", "1_000.0", "-0.0", "\u{a0}1", "\u{b}1", "99999999999999999999999"] {
            assert!(int_text(ok), "{ok:?}");
        }
        for bad in ["1.5", "abc", "１２", "0x10", "1e3", " ", "1.", ".0", "_1", "1_", "1__0", "--1", "+-1", "1.0_0", "1 2", "+", "", "+_1", "\u{1c}1"] {
            assert!(!int_text(bad), "{bad:?}");
        }
    }

    #[test]
    fn matches_like_starlette() {
        let asm = Assembly::default();
        let routes = http_routes(&asm, &[]);
        assert!(matches!(find(&routes, "GET", "/meetings/12"), Match::Full(r, _) if r.path == "/meetings/{meeting_id}"));
        assert!(matches!(find(&routes, "POST", "/health"), Match::Partial(m) if m.contains("GET") && !m.contains("HEAD")));
        assert!(matches!(find(&routes, "GET", "/nope"), Match::NotFound));
        assert!(matches!(find(&routes, "GET", "/bot-accounts/sessions/x/view/"), Match::Full(_, p) if p[1].1.is_empty()));
        assert_eq!(redirect_path(&routes, "/bots/"), Some("/bots".into()));
        assert!(matches!(ws_match("/voice-notes/abc/stream"), Some(WsRoute::Voice(id)) if id == "abc"));
    }
}
