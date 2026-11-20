//! A pasted meeting link as `(platform, native_meeting_id)` (the door reads a bot call's
//! `meeting_url` with it): the same id formats and platforms as the terminal's parser.

use std::sync::OnceLock;

use regex::Regex;

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("a valid pattern"))
}

macro_rules! pattern {
    ($name:ident, $p:expr) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            re(&CELL, $p)
        }
    };
}

pattern!(gmeet_id, r"^[a-z]{3}-[a-z]{4}-[a-z]{3}$");
pattern!(zoom_id, r"\d{9,11}");
pattern!(teams_thread, r"(?i)19:meeting_[^@%\s/]{1,256}@thread\.v2");
pattern!(teams_short, r"(?i)/meet/([^/?#]+)");
pattern!(jitsi_room, r"^[^/?#\s]+$");
pattern!(zoom_hosted_path, r"(?i)^/(?:meeting|j)/(\d{10,11})/?$");
pattern!(bare_zoom, r"^\d{9,11}$");

fn host_is(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// `urllib.parse.urlparse`: (hostname, path, query) — the hostname empty when the text has no
/// `scheme://netloc`.
fn urlparse(value: &str) -> (String, String, String) {
    let cleaned: String = value.chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let mut rest = cleaned.as_str();
    if let Some(i) = rest.find(':') {
        let scheme = &rest[..i];
        if !scheme.is_empty() && scheme.as_bytes()[0].is_ascii_alphabetic() && scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) {
            rest = &rest[i + 1..];
        }
    }
    let mut host = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let netloc = &after[..end];
        rest = &after[end..];
        let hostport = netloc.rsplit_once('@').map(|(_, h)| h).unwrap_or(netloc);
        host = if let Some(v6) = hostport.strip_prefix('[') {
            v6.split(']').next().unwrap_or("").to_owned()
        } else {
            hostport.split(':').next().unwrap_or("").to_owned()
        }
        .to_lowercase();
    }
    let rest = rest.split('#').next().unwrap_or("");
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    (host, path.to_owned(), query.to_owned())
}

fn has_passcode(query: &str) -> bool {
    let mut first = std::collections::HashMap::new();
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if v.is_empty() {
            continue;
        }
        first.entry(vexa_native_kit::http::decode(k)).or_insert(v.to_owned());
    }
    first.contains_key("password") || first.contains_key("pwd")
}

fn jitsi_hosts() -> Vec<String> {
    std::env::var("VEXA_JITSI_HOSTS").unwrap_or_default().split(',').map(|h| h.trim().to_lowercase()).filter(|h| !h.is_empty()).collect()
}

/// `unquote`: %XX decoded, the result read as UTF-8 with replacement.
fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(0));
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_meeting_url(raw: &str) -> Option<(String, String)> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    if gmeet_id().is_match(&value.to_lowercase()) {
        return Some(("google_meet".into(), value.to_lowercase()));
    }
    let (host, path, query) = urlparse(value);
    if !host.is_empty() {
        if host_is(&host, "meet.google.com") {
            let code = path.split('/').rev().find(|p| !p.is_empty()).unwrap_or("").to_lowercase();
            return gmeet_id().is_match(&code).then(|| ("google_meet".into(), code));
        }
        if host.contains("zoom") {
            let m = zoom_id().find(&path).or_else(|| zoom_id().find(&query))?;
            return Some(("zoom".into(), m.as_str().to_owned()));
        }
        if host_is(&host, "teams.microsoft.com") || host_is(&host, "teams.live.com") {
            if let Some(t) = teams_thread().find(&unquote(value)) {
                return Some(("teams".into(), t.as_str().to_owned()));
            }
            return teams_short().captures(&path).map(|c| ("teams".into(), c[1].to_owned()));
        }
        let declared = jitsi_hosts();
        if !declared.contains(&host) && host != "meet.jit.si" {
            if let Some(c) = zoom_hosted_path().captures(&path) {
                if has_passcode(&query) {
                    return Some(("zoom".into(), c[1].to_owned()));
                }
            }
        }
        let jitsi = host == "meet.jit.si" || declared.contains(&host) || host.contains("jitsi") || host.split('.').any(|l| l == "meet");
        if jitsi {
            let room = path.trim_matches('/');
            if room.is_empty() || !jitsi_room().is_match(room) {
                return None;
            }
            return Some(("jitsi".into(), if host == "meet.jit.si" { room.to_owned() } else { format!("{room}@{host}") }));
        }
        return None;
    }
    bare_zoom().is_match(value).then(|| ("zoom".into(), value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::parse_meeting_url as p;

    fn s(a: &str, b: &str) -> Option<(String, String)> {
        Some((a.into(), b.into()))
    }

    #[test]
    fn reads_the_platforms() {
        assert_eq!(p("ABC-defg-hij"), s("google_meet", "abc-defg-hij"));
        assert_eq!(p("https://meet.google.com/abc-defg-hij?x=1"), s("google_meet", "abc-defg-hij"));
        assert_eq!(p("https://us02web.zoom.us/j/12345678901?pwd=x"), s("zoom", "12345678901"));
        assert_eq!(p("https://teams.microsoft.com/l/meetup-join/19%3ameeting_abc%40thread.v2/0"), s("teams", "19:meeting_abc@thread.v2"));
        assert_eq!(p("https://teams.live.com/meet/9876?p=x"), s("teams", "9876"));
        assert_eq!(p("https://corp.example/meeting/1234567890?password=u"), s("zoom", "1234567890"));
        assert_eq!(p("https://corp.example/meeting/1234567890"), None);
        assert_eq!(p("https://meet.jit.si/Room"), s("jitsi", "Room"));
        assert_eq!(p("https://meet.corp.example/Room"), s("jitsi", "Room@meet.corp.example"));
        assert_eq!(p("123456789"), s("zoom", "123456789"));
        assert_eq!(p("teams.live.com.evil.example/meet/1"), None);
    }
}
