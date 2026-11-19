//! parse_meeting_link: a meeting URL -> platform / native_meeting_id / passcode, the
//! Python service's `link_parser.parse_meeting_url` rule for rule (urllib.parse semantics).

use regex::Regex;
use serde_json::{json, Value};

use crate::wire::{unquote_plus, HttpError};

pub struct Parts {
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

/// urllib.parse.urlparse (Python 3.12): scheme, netloc, path (params cut), query, fragment.
pub fn urlparse(url: &str) -> Result<Parts, HttpError> {
    let mut url: String = url
        .trim_start_matches(|c: char| (c as u32) <= 0x20)
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut scheme = String::new();
    if let Some(i) = url.find(':') {
        let head = &url[..i];
        if i > 0
            && head.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && head
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = head.to_ascii_lowercase();
            url = url[i + 1..].to_owned();
        }
    }
    let mut netloc = String::new();
    if let Some(rest) = url.strip_prefix("//") {
        let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        netloc = rest[..cut].to_owned();
        url = rest[cut..].to_owned();
        if netloc.contains('[') != netloc.contains(']') {
            return Err(HttpError::internal());
        }
    }
    let mut fragment = String::new();
    if let Some((u, f)) = url.split_once('#') {
        fragment = f.to_owned();
        url = u.to_owned();
    }
    let mut query = String::new();
    if let Some((u, q)) = url.split_once('?') {
        query = q.to_owned();
        url = u.to_owned();
    }
    let uses_params = [
        "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu",
        "sip", "sips", "mms", "sftp", "tel",
    ];
    if uses_params.contains(&scheme.as_str()) && url.contains(';') {
        let from = url.rfind('/').unwrap_or(0);
        let cut = if url.contains('/') {
            url[from..].find(';').map(|j| from + j)
        } else {
            url.find(';')
        };
        if let Some(i) = cut {
            url.truncate(i);
        }
    }
    Ok(Parts {
        netloc,
        path: url,
        query,
        fragment,
    })
}

impl Parts {
    /// ParseResult.hostname, lower-cased ("" for none).
    pub fn hostname(&self) -> String {
        let info = self
            .netloc
            .rsplit_once('@')
            .map_or(self.netloc.as_str(), |(_, h)| h);
        let host = if let Some(inner) = info.strip_prefix('[') {
            inner.split(']').next().unwrap_or("")
        } else {
            info.split(':').next().unwrap_or("")
        };
        host.to_lowercase()
    }
}

/// parse_qs(query) as a lookup: the first non-blank value of `name`.
pub fn query_first(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (!v.is_empty() && unquote_plus(k) == name).then(|| unquote_plus(v))
    })
}

fn host_is(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn teams_enterprise(host: &str) -> bool {
    matches!(
        host,
        "teams.microsoft.com" | "gov.teams.microsoft.us" | "dod.teams.microsoft.us"
    ) || host_is(host, "teams.microsoft.us")
        || host_is(host, "teams.microsoft.com")
}

fn bad(detail: &str) -> HttpError {
    HttpError::new(422, detail)
}

const NO_PASSCODE: &str = "Teams meeting link has no ?p= passcode. Many Teams meetings require it.";

fn found(
    platform: &str,
    id: &str,
    passcode: Option<String>,
    meeting_url: Option<&str>,
    teams_host: Option<&str>,
    warnings: Vec<String>,
) -> Value {
    json!({"platform": platform, "native_meeting_id": id, "passcode": passcode, "meeting_url": meeting_url,
           "teams_base_host": teams_host, "warnings": warnings})
}

fn full(pattern: &str, text: &str) -> bool {
    Regex::new(&format!("^(?:{pattern})$")).is_ok_and(|r| r.is_match(text))
}

fn meet_id(path: &str) -> Option<String> {
    Regex::new(r"^/meet/(\d{10,17})/?$")
        .ok()?
        .captures(path)
        .map(|c| c[1].to_owned())
}

/// The jitsi hosts the deployment declares (VEXA_JITSI_HOSTS).
pub fn parse_meeting_url(meeting_url: &str, jitsi_hosts: &str) -> Result<Value, HttpError> {
    let url = meeting_url.trim();
    if url.is_empty() {
        return Err(bad("meeting_url cannot be empty"));
    }
    let parsed = urlparse(url)?;
    let host = parsed.hostname();
    let path = parsed.path.as_str();
    let mut warnings = Vec::new();

    if host == "meet.google.com" {
        if path.starts_with("/lookup/") {
            return Err(bad("Google Meet /lookup/ URLs cannot be joined directly. Use the standard meeting link from your calendar invite."));
        }
        let code = path.trim_matches('/').split('/').next().unwrap_or("");
        if full("[a-z]{3}-[a-z]{4}-[a-z]{3}", code) {
            return Ok(found("google_meet", code, None, None, None, warnings));
        }
        if full("[a-z0-9][a-z0-9-]{3,38}[a-z0-9]", code) {
            warnings.push("Custom Google Meet nickname URL detected. This works for Google Workspace accounts only.".into());
            return Ok(found("google_meet", code, None, None, None, warnings));
        }
        return Err(bad("Invalid Google Meet URL: expected https://meet.google.com/abc-defg-hij or a custom Workspace nickname."));
    }

    if host_is(&host, "teams.live.com") {
        let Some(id) = meet_id(path) else {
            return Err(bad(
                "Unsupported teams.live.com URL format. Expected /meet/<10-17 digit id>.",
            ));
        };
        let passcode = query_first(&parsed.query, "p");
        if passcode.is_none() {
            warnings.push(NO_PASSCODE.into());
        }
        return Ok(found("teams", &id, passcode, None, Some(&host), warnings));
    }

    if teams_enterprise(&host) {
        let fragment = parsed.fragment.as_str();
        if matches!(path.trim_end_matches('/'), "/v2" | "") && fragment.starts_with("/meet/") {
            let inner = urlparse(&format!("https://x{fragment}"))?;
            if let Some(id) = meet_id(&inner.path) {
                let passcode = query_first(&inner.query, "p");
                if passcode.is_none() {
                    warnings.push(NO_PASSCODE.into());
                }
                return Ok(found("teams", &id, passcode, None, Some(&host), warnings));
            }
        }
        if let Some(id) = meet_id(path) {
            let passcode = query_first(&parsed.query, "p");
            if passcode.is_none() {
                warnings.push(NO_PASSCODE.into());
            }
            return Ok(found("teams", &id, passcode, None, Some(&host), warnings));
        }
        if path.contains("/l/meetup-join/") {
            let hash =
                vexa_native_kit::sha256::hex(&vexa_native_kit::sha256::digest(url.as_bytes()));
            warnings.push("Legacy Teams enterprise URL detected. The full URL will be passed directly to the bot. The meeting ID shown is a stable hash of the URL used for deduplication.".into());
            return Ok(found("teams", &hash[..16], None, Some(url), None, warnings));
        }
        return Err(bad("Unsupported Teams enterprise URL format. Expected /meet/<id>?p=<passcode> or /l/meetup-join/..."));
    }

    if matches!(host.as_str(), "events.zoom.us" | "ev.zoom.com") || host_is(&host, "events.zoom.us")
    {
        return Err(bad("Zoom Events links are not supported. Attendees receive unique per-registrant join links via email; these cannot be shared with a bot."));
    }

    if host_is(&host, "zoom.us") || host_is(&host, "zoomgov.com") {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let mut id = "";
        if parts.len() >= 2 && matches!(parts[0], "j" | "w") {
            id = parts[1];
        } else if parts.len() >= 3 && parts[0] == "wc" && parts[1] == "join" {
            id = parts[2];
        } else if parts.len() >= 2 && parts[0] == "my" {
            return Err(bad("Zoom personal meeting room links (/my/...) are not supported. Ask the host to share a direct meeting link (/j/<id>)."));
        }
        if !full(r"\d{9,11}", id) {
            return Err(bad(
                "Unsupported Zoom URL format. Expected https://zoom.us/j/<9-11 digit id>.",
            ));
        }
        let passcode =
            query_first(&parsed.query, "pwd").or_else(|| query_first(&parsed.query, "password"));
        return Ok(found("zoom", id, passcode, None, None, warnings));
    }

    let configured: Vec<String> = jitsi_hosts
        .split(',')
        .map(|h| h.trim().to_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    let explicit = host == "meet.jit.si" || configured.contains(&host);
    if !explicit {
        let m = Regex::new(r"^/(?:meeting|j)/(\d{10,11})/?$")
            .ok()
            .and_then(|r| r.captures(path))
            .map(|c| c[1].to_owned());
        let passcode =
            query_first(&parsed.query, "password").or_else(|| query_first(&parsed.query, "pwd"));
        if let (Some(id), Some(code)) = (m, passcode) {
            warnings.push(format!(
                "'{host}' is not a Zoom hostname; the link was read as a Zoom meeting from its path shape (/meeting/<id> or /j/<id> with a passcode). The bot joins the meeting id on Zoom itself."
            ));
            return Ok(found("zoom", &id, Some(code), None, None, warnings));
        }
    }
    let inferred = host.contains("jitsi") || host.split('.').any(|p| p == "meet");
    if explicit || inferred {
        let room = path.trim_matches('/');
        if room.is_empty() || !full(r"[^/?#\s]+", room) {
            return Err(bad(
                "Unsupported Jitsi URL format. Expected https://<jitsi-host>/<RoomName>.",
            ));
        }
        if !explicit {
            warnings.push("Host inferred as a self-hosted Jitsi deployment from its name. If this is not a Jitsi meeting the bot will fail to join; declare the host in VEXA_JITSI_HOSTS to silence this warning.".into());
        }
        let id = if host == "meet.jit.si" {
            room.to_owned()
        } else {
            format!("{room}@{host}")
        };
        return Ok(found("jitsi", &id, None, Some(url), None, warnings));
    }
    Err(bad("Unsupported meeting URL (unknown provider)."))
}

#[cfg(test)]
mod tests {
    use super::parse_meeting_url as p;

    #[test]
    fn links() {
        assert_eq!(
            p("https://meet.google.com/abc-defg-hij", "").unwrap()["native_meeting_id"],
            "abc-defg-hij"
        );
        let t = p(
            "https://teams.microsoft.com/v2/?meetingjoin=true#/meet/9361792952021?p=a",
            "",
        )
        .unwrap();
        assert_eq!(
            (t["native_meeting_id"].as_str(), t["passcode"].as_str()),
            (Some("9361792952021"), Some("a"))
        );
        assert_eq!(
            p(
                "https://teams.microsoft.com/l/meetup-join/19%3ameeting_x/0",
                ""
            )
            .unwrap()["native_meeting_id"],
            "3f827b0408e80fee"
        );
        assert_eq!(
            p(
                "https://zoom-lfx.platform.linuxfoundation.org/meeting/1234567890?password=u",
                ""
            )
            .unwrap()["platform"],
            "zoom"
        );
        assert_eq!(
            p("https://meet.example.org/Room2", "").unwrap()["native_meeting_id"],
            "Room2@meet.example.org"
        );
        assert_eq!(
            p("https://evil.example/zoom.us/j/1", "")
                .unwrap_err()
                .detail,
            "Unsupported meeting URL (unknown provider)."
        );
        assert_eq!(
            p("https://x.example/Room", "x.example").unwrap()["platform"],
            "jitsi"
        );
    }
}
