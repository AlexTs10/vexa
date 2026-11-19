//! Google: the fixed OAuth endpoints, account reads (Gmail and Calendar) and
//! Gmail drafts. Hosts, methods and scopes are reviewed constants, never
//! caller arguments. A refusal the person can act on is Fail::Provider (409);
//! Google unreachable, rate limiting or answering unusably is Fail::Upstream.

use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::fail::{Fail, R};
use crate::net::{self, Answer, NetError, Request};
use crate::{calendar, models, tz, util};

pub const DRAFT_SCOPE: &str = "https://www.googleapis.com/auth/gmail.compose";
pub const READ_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub const CALENDAR_READ_SCOPE: &str = "https://www.googleapis.com/auth/calendar.events.readonly";
pub const CALENDAR_WRITE_SCOPE: &str = "https://www.googleapis.com/auth/calendar.events";
const AUTHORIZE: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN: &str = "https://oauth2.googleapis.com/token";
const GMAIL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/";

/// The catalog method of a provider: "oauth", "secret", or "" for an unknown one.
pub fn method(provider: &str) -> &'static str {
    match provider {
        "google_calendar" | "google_email" => "oauth",
        "custom_secret" => "secret",
        _ => "",
    }
}

pub fn scopes_for(provider: &str, grant: &str) -> R<Vec<&'static str>> {
    let mut scopes = match provider {
        "google_calendar" => vec![CALENDAR_READ_SCOPE],
        "google_email" => vec![READ_SCOPE, DRAFT_SCOPE],
        _ => return Err(Fail::Internal),
    };
    if !grant.is_empty() {
        if provider == "google_calendar" && grant == "calendar_write" {
            scopes.push(CALENDAR_WRITE_SCOPE);
        } else {
            return Err(Fail::provider("This permission does not apply to this connection"));
        }
    }
    Ok(scopes)
}

/// The optional permissions a stored grant carries, by name.
pub fn permissions(provider: &str, scope: &str) -> Vec<&'static str> {
    let granted: Vec<&str> = scope.split_whitespace().collect();
    match provider {
        "google_email" if granted.contains(&DRAFT_SCOPE) => vec!["drafts"],
        "google_calendar" if granted.contains(&CALENDAR_WRITE_SCOPE) => vec!["calendar_write"],
        _ => vec![],
    }
}

pub fn authorize(provider: &str, client: &(String, String), redirect: &str, state: &str, challenge: &str, grant: &str) -> R<String> {
    let mut args = vec![
        ("client_id", client.0.clone()),
        ("redirect_uri", redirect.to_owned()),
        ("response_type", "code".to_owned()),
        ("scope", scopes_for(provider, grant)?.join(" ")),
        ("state", state.to_owned()),
        ("code_challenge", challenge.to_owned()),
        ("code_challenge_method", "S256".to_owned()),
        ("access_type", "offline".to_owned()),
        ("prompt", "select_account consent".to_owned()),
    ];
    if !grant.is_empty() {
        args.push(("include_granted_scopes", "true".to_owned()));
    }
    Ok(format!("{AUTHORIZE}?{}", util::urlencode(&args)))
}

pub fn fault_for_status(status: u16, message: &str) -> Fail {
    Fail::upstream("provider", if status == 429 { "rate_limited" } else { "bad_answer" }, message)
}

fn net_fault(e: &NetError, unreachable: &str, bad: &str) -> Fail {
    if e.no_answer() {
        Fail::upstream("provider", "unreachable", unreachable)
    } else {
        Fail::upstream("provider", "bad_answer", bad)
    }
}

/// One request to a fixed Google endpoint.
pub fn call(method: &str, url: &str, params: &[(&str, String)], token: &str, payload: Option<&Value>, timeout: u64, limit: usize) -> Result<Answer, NetError> {
    let url = if params.is_empty() { url.to_owned() } else { format!("{url}?{}", util::urlencode(params)) };
    let mut req = Request::new(method, &url, Duration::from_secs(timeout));
    req.limit = limit;
    if !token.is_empty() {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }
    if let Some(p) = payload {
        req = req.json(p);
    }
    net::send(&req)
}

/// Python's int() of a JSON value (int, float truncated, or numeric text).
fn py_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc() as i64)),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

/// The token endpoint: an authorization code (with PKCE) or a refresh token.
pub fn tokens(provider: &str, client: &(String, String), code: &str, verifier: &str, redirect: &str, refresh: Option<&str>, grant: &str) -> R<Value> {
    let unavailable = "Provider authorization is unavailable; try again later";
    let mut form = vec![
        ("client_id", client.0.clone()),
        ("client_secret", client.1.clone()),
        ("grant_type", if refresh.is_some() { "refresh_token" } else { "authorization_code" }.to_owned()),
    ];
    match refresh {
        Some(r) => form.push(("refresh_token", r.to_owned())),
        None => form.extend([("code", code.to_owned()), ("code_verifier", verifier.to_owned()), ("redirect_uri", redirect.to_owned())]),
    }
    let req = Request::new("POST", TOKEN, Duration::from_secs(15)).form(&form);
    let answer = net::send(&req).map_err(|e| net_fault(&e, unavailable, unavailable))?;
    if answer.status == 429 || answer.status >= 500 {
        return Err(fault_for_status(answer.status, unavailable));
    }
    if answer.status != 200 {
        return Err(Fail::provider("Authorization failed; reconnect this account"));
    }
    let result = answer.json().filter(Value::is_object).ok_or_else(|| Fail::upstream("provider", "bad_answer", unavailable))?;
    let access = result.get("access_token").and_then(Value::as_str).unwrap_or("");
    let token_type = match result.get("token_type") {
        None => "",
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return Err(Fail::upstream("provider", "bad_answer", unavailable)),
    };
    if access.is_empty() || token_type.to_lowercase() != "bearer" {
        return Err(Fail::upstream("provider", "bad_answer", "Provider did not return a usable authorization; try again later"));
    }
    let scope = match result.get("scope") {
        None => "",
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return Err(Fail::upstream("provider", "bad_answer", unavailable)),
    };
    if refresh.is_none() {
        let granted: Vec<String> = scope.split_whitespace().map(str::to_lowercase).collect();
        if !scopes_for(provider, grant)?.iter().all(|s| granted.contains(&s.to_lowercase())) {
            return Err(Fail::provider("Required permission was not granted; reconnect this account"));
        }
    }
    let expires_in = match result.get("expires_in") {
        None => 0,
        Some(v) => py_int(v).ok_or_else(|| Fail::upstream("provider", "bad_answer", unavailable))?,
    };
    let refresh_token = match result.get("refresh_token") {
        Some(v) if util::truthy(Some(v)) => v.clone(),
        _ => refresh.map_or(Value::Null, |r| json!(r)),
    };
    Ok(json!({"access_token": access, "refresh_token": refresh_token, "expires_at": util::now() + expires_in.max(0) as f64, "scope": scope}))
}

pub fn refresh(provider: &str, client: &(String, String), value: &Value) -> R<Value> {
    let token = value.get("refresh_token").and_then(Value::as_str).ok_or(Fail::Internal)?;
    let mut result = tokens(provider, client, "", "", "", Some(token), "")?;
    if util::text(&result, "scope").is_empty() {
        result["scope"] = json!(util::text(value, "scope"));
    }
    Ok(result)
}

pub fn account_email(provider: &str, value: &Value) -> String {
    if provider != "google_email" || !util::text(value, "scope").split_whitespace().any(|s| s == READ_SCOPE) {
        return String::new();
    }
    let Ok(answer) = call("GET", &format!("{GMAIL}profile"), &[], util::text(value, "access_token"), None, 10, 1 << 20) else { return String::new() };
    if answer.status != 200 {
        return String::new();
    }
    match answer.json().as_ref().and_then(|v| v.get("emailAddress")) {
        Some(Value::String(s)) => s.chars().take(320).collect(),
        _ => String::new(),
    }
}

// ── reads ──────────────────────────────────────────────────────────────────

fn is_gmail_id(s: &str) -> bool {
    models::is_google_id(s)
}

/// The Gmail web address of a thread in the CONNECTED mailbox, or "".
pub fn gmail_web_url(account: &str, thread_id: Option<&Value>, message_id: Option<&Value>) -> String {
    let n = account.chars().count();
    if !(3..=320).contains(&n) || account.matches('@').count() != 1 || account.chars().any(|c| (c as u32) <= 32 || c as u32 == 127) {
        return String::new();
    }
    let target = match thread_id {
        Some(Value::String(t)) if !t.is_empty() => Some(t.as_str()),
        _ => message_id.and_then(Value::as_str),
    };
    match target {
        Some(t) if is_gmail_id(t) => format!("https://mail.google.com/mail/?authuser={}#all/{t}", util::quote(account, "@")),
        _ => String::new(),
    }
}

/// An event's htmlLink, passed through only as an https URL on a Google Calendar host.
pub fn calendar_web_url(link: Option<&Value>) -> String {
    let Some(link) = link.and_then(Value::as_str) else { return String::new() };
    if link.chars().count() > 2048 {
        return String::new();
    }
    let Ok(parts) = util::urlsplit(link) else { return String::new() };
    let Ok(port) = parts.port() else { return String::new() };
    let host = parts.hostname().unwrap_or_default();
    if parts.scheme != "https" || !["calendar.google.com", "www.google.com"].contains(&host.as_str()) || port.is_some() || parts.username().is_some() || parts.netloc != host {
        return String::new();
    }
    link.to_owned()
}

const READ_LIMIT: usize = 2_000_000;

fn provider_status(status: u16) -> Option<&'static str> {
    Some(match status {
        400 => "Provider rejected the request arguments; check query, page token and date range",
        401 => "Authorization rejected; reconnect this account",
        403 => "Provider refused access; check granted scopes and API enablement",
        404 => "Requested message or calendar was not found",
        _ => return None,
    })
}

fn read_get(token: &str, url: &str, params: &[(&str, String)]) -> R<Value> {
    let answer = call("GET", url, params, token, None, 15, READ_LIMIT).map_err(|e| {
        net_fault(&e, "Account read is unavailable; the provider could not be reached", "Account read is unavailable; the provider answered with an unreadable response")
    })?;
    if let Some(sentence) = provider_status(answer.status) {
        return Err(Fail::provider(sentence));
    }
    if answer.status == 429 {
        return Err(fault_for_status(429, "Provider rate limit reached; retry later"));
    }
    if answer.status != 200 {
        return Err(fault_for_status(answer.status, "Provider temporarily unavailable; retry later"));
    }
    if answer.over_limit {
        return Err(Fail::provider("Provider response too large; narrow the request"));
    }
    answer.json().ok_or_else(|| Fail::upstream("provider", "bad_answer", "Account read is unavailable; the provider answered with an unreadable response"))
}

/// Text of an HTML body: the data between tags, script and style left out,
/// character references decoded, one item per run of text.
pub fn html_text(html: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut hidden = 0usize;
    let mut rest = html;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            if hidden == 0 {
                out.push(unescape(rest));
            }
            break;
        };
        if lt > 0 && hidden == 0 {
            out.push(unescape(&rest[..lt]));
        }
        rest = &rest[lt..];
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = after.find("-->").map_or("", |i| &after[i + 3..]);
            continue;
        }
        let Some(gt) = rest.find('>') else {
            if hidden == 0 {
                out.push(unescape(rest));
            }
            break;
        };
        let tag = &rest[1..gt];
        let (closing, name) = match tag.strip_prefix('/') {
            Some(n) => (true, n),
            None => (false, tag),
        };
        let name: String = name.chars().take_while(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
        if name == "script" || name == "style" {
            if closing {
                hidden = hidden.saturating_sub(1);
            } else if !tag.ends_with('/') {
                hidden += 1;
            }
        }
        rest = &rest[gt + 1..];
    }
    out.join("\n")
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let named = [("amp", "&"), ("lt", "<"), ("gt", ">"), ("quot", "\""), ("apos", "'"), ("nbsp", "\u{a0}"), ("copy", "\u{a9}"), ("reg", "\u{ae}"), ("hellip", "\u{2026}"), ("mdash", "\u{2014}"), ("ndash", "\u{2013}"), ("rsquo", "\u{2019}"), ("lsquo", "\u{2018}"), ("rdquo", "\u{201d}"), ("ldquo", "\u{201c}"), ("euro", "\u{20ac}"), ("zwnj", "\u{200c}")];
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest[1..].find(|c: char| !(c.is_ascii_alphanumeric() || c == '#')).map(|e| e + 1).unwrap_or(rest.len());
        let body = &rest[1..end];
        let decoded = if let Some(num) = body.strip_prefix('#') {
            let n = match num.strip_prefix(['x', 'X']) {
                Some(h) => u32::from_str_radix(h, 16).ok(),
                None => num.parse().ok(),
            };
            n.and_then(char::from_u32).map(String::from)
        } else {
            named.iter().find(|(k, _)| *k == body).map(|(_, v)| v.to_string())
        };
        match decoded {
            Some(d) => {
                out.push_str(&d);
                rest = &rest[end..];
                if rest.starts_with(';') {
                    rest = &rest[1..];
                }
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn decode_part(raw: &str) -> String {
    util::b64url_decode_lenient(raw).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

fn collect_parts(part: &Value, depth: usize, plain: &mut Vec<String>, html: &mut Vec<String>) {
    if depth > 12 || util::truthy(part.get("filename")) {
        return;
    }
    let raw = part.get("body").map(|b| util::text(b, "data")).unwrap_or("");
    let mime = util::text(part, "mimeType");
    if !raw.is_empty() && (mime == "text/plain" || mime == "text/html") {
        let text = decode_part(raw);
        if mime == "text/plain" { plain.push(text) } else { html.push(text) }
    }
    for child in part.get("parts").and_then(Value::as_array).into_iter().flatten() {
        collect_parts(child, depth + 1, plain, html);
    }
}

fn message(token: &str, account: &str, mid: &str, full: bool, data: Option<Value>) -> R<Value> {
    if !is_gmail_id(mid) {
        return Err(Fail::provider("Invalid message ID"));
    }
    let data = match data {
        Some(d) => d,
        None => read_get(token, &format!("{GMAIL}messages/{mid}"), &[("format", if full { "full" } else { "metadata" }.into())])?,
    };
    let payload = data.get("payload").cloned().unwrap_or(json!({}));
    let mut headers = Map::new();
    for h in payload.get("headers").and_then(Value::as_array).into_iter().flatten() {
        let v: String = util::text(h, "value").chars().take(4000).collect();
        headers.insert(util::text(h, "name").to_lowercase(), json!(v));
    }
    let mut result = Map::new();
    for k in ["id", "threadId", "internalDate", "snippet"] {
        result.insert(k.into(), data.get(k).cloned().unwrap_or(Value::Null));
    }
    let labels: Vec<Value> = data.get("labelIds").and_then(Value::as_array).into_iter().flatten().filter(|x| x.is_string()).take(50).cloned().collect();
    let is_draft = labels.iter().any(|l| l == "DRAFT");
    result.insert("labels".into(), json!(labels));
    result.insert("is_draft".into(), json!(is_draft));
    let link = gmail_web_url(account, result.get("threadId"), result.get("id"));
    if !link.is_empty() {
        result.insert("web_url".into(), json!(link));
    }
    let mut picked = Map::new();
    for k in ["from", "to", "cc", "reply-to", "subject", "date", "message-id", "in-reply-to", "references"] {
        picked.insert(k.into(), headers.get(k).cloned().unwrap_or(json!("")));
    }
    result.insert("headers".into(), Value::Object(picked));
    if full {
        let (mut plain, mut html) = (vec![], vec![]);
        collect_parts(&payload, 0, &mut plain, &mut html);
        let body = if plain.is_empty() { html_text(&html.join("\n")) } else { plain.join("\n") };
        let n = body.chars().count();
        result.insert("body".into(), json!(body.chars().take(50000).collect::<String>()));
        result.insert("truncated".into(), json!(n > 50000));
        result.insert("attachments_included".into(), json!(false));
    }
    Ok(Value::Object(result))
}

/// Draft id by message id for the draft messages of one thread page.
fn thread_drafts(token: &str, ids: &[String]) -> R<Map<String, Value>> {
    let mut found = Map::new();
    let mut page = String::new();
    for _ in 0..5 {
        if ids.iter().all(|i| found.contains_key(i)) {
            break;
        }
        let mut params = vec![("maxResults", "500".to_owned())];
        if !page.is_empty() {
            params.push(("pageToken", page.clone()));
        }
        let data = read_get(token, &format!("{GMAIL}drafts"), &params)?;
        for d in data.get("drafts").and_then(Value::as_array).into_iter().flatten() {
            let mid = d.get("message").map(|m| util::text(m, "id")).unwrap_or("");
            let did = d.get("id").map(util::py_str).unwrap_or_default();
            if ids.iter().any(|i| i == mid) && is_gmail_id(&did) {
                found.insert(mid.to_owned(), json!(did));
            }
        }
        page = util::text(&data, "nextPageToken").to_owned();
        if page.is_empty() {
            break;
        }
    }
    Ok(found)
}

/// The read fields of AccountReadBody.
pub struct Read<'a> {
    pub action: &'a str,
    pub query: &'a str,
    pub message_id: &'a str,
    pub time_min: &'a str,
    pub time_max: &'a str,
    pub limit: i64,
    pub page_token: &'a str,
}

/// On-demand account reads. Fixed hosts and methods, never a general HTTP proxy.
pub fn read_account(provider: &str, value: &Value, account: &str, r: &Read) -> R<Map<String, Value>> {
    let expected = if r.action == "calendar.events" { "google_calendar" } else { "google_email" };
    if !["gmail.search", "gmail.read", "gmail.thread", "calendar.events"].contains(&r.action) || provider != expected {
        return Err(Fail::provider("Operation does not match this connection"));
    }
    if !(1..=20).contains(&r.limit) || r.query.chars().count() > 500 {
        return Err(Fail::provider("Invalid read limits"));
    }
    let token = util::text(value, "access_token");
    let limit = r.limit as usize;
    let mut out = Map::new();
    match r.action {
        "gmail.thread" => {
            if !is_gmail_id(r.message_id) {
                return Err(Fail::provider("Invalid thread ID"));
            }
            let data = read_get(token, &format!("{GMAIL}threads/{}", r.message_id), &[("format", "full".into())])?;
            let offset: i64 = if r.page_token.is_empty() { 0 } else { r.page_token.trim().parse().map_err(|_| Fail::provider("Invalid thread offset"))? };
            if offset < 0 {
                return Err(Fail::provider("Invalid thread offset"));
            }
            let offset = offset as usize;
            let mut rows = data.get("messages").and_then(Value::as_array).cloned().unwrap_or_default();
            for row in rows.iter_mut() {
                if let Some(o) = row.as_object_mut() {
                    if !util::truthy(o.get("threadId")) {
                        o.insert("threadId".into(), data.get("id").cloned().unwrap_or(Value::Null));
                    }
                }
            }
            let more = offset + limit < rows.len();
            let mut page = Vec::new();
            for m in rows.iter().skip(offset).take(limit) {
                page.push(message(token, account, util::text(m, "id"), true, Some(m.clone()))?);
            }
            let draft_ids: Vec<String> = page.iter().filter(|m| m["is_draft"] == json!(true)).map(|m| util::text(m, "id").to_owned()).collect();
            let drafts = if draft_ids.is_empty() { Map::new() } else { thread_drafts(token, &draft_ids)? };
            let mut listed = Vec::new();
            for m in page.iter_mut() {
                let id = util::text(m, "id").to_owned();
                if let Some(d) = drafts.get(&id) {
                    m["draft_id"] = d.clone();
                    listed.push(json!({"draft_id": d, "message_id": id}));
                }
            }
            out.insert("thread_id".into(), data.get("id").cloned().unwrap_or(Value::Null));
            out.insert("messages".into(), json!(page));
            out.insert("drafts".into(), json!(listed));
            out.insert("has_more".into(), json!(more));
            out.insert("next_page_token".into(), json!(if more { (offset + limit).to_string() } else { String::new() }));
            out.insert("total_messages".into(), json!(rows.len()));
        }
        "gmail.read" => {
            out.insert("message".into(), message(token, account, r.message_id, true, None)?);
        }
        "gmail.search" => {
            let mut params = vec![("q", r.query.to_owned()), ("maxResults", r.limit.to_string())];
            if !r.page_token.is_empty() {
                params.push(("pageToken", r.page_token.to_owned()));
            }
            let data = read_get(token, &format!("{GMAIL}messages"), &params)?;
            let mut messages = Vec::new();
            for m in data.get("messages").and_then(Value::as_array).into_iter().flatten().take(limit) {
                messages.push(message(token, account, util::text(m, "id"), false, None)?);
            }
            out.insert("messages".into(), json!(messages));
            out.insert("has_more".into(), json!(util::truthy(data.get("nextPageToken"))));
            out.insert("next_page_token".into(), data.get("nextPageToken").cloned().unwrap_or(json!("")));
        }
        _ => {
            let range = || -> Option<()> {
                let lo = tz::fromisoformat(&r.time_min.replace('Z', "+00:00"))?.utc_micros()?;
                let hi = tz::fromisoformat(&r.time_max.replace('Z', "+00:00"))?.utc_micros()?;
                let span = hi - lo;
                (span > 0 && span <= 366 * 86400 * 1_000_000).then_some(())
            };
            range().ok_or_else(|| Fail::provider("Use a timezone-qualified time range of at most one year"))?;
            let mut params = vec![
                ("timeMin", r.time_min.to_owned()),
                ("timeMax", r.time_max.to_owned()),
                ("maxResults", r.limit.to_string()),
                ("singleEvents", "true".to_owned()),
                ("orderBy", "startTime".to_owned()),
            ];
            if !r.page_token.is_empty() {
                params.push(("pageToken", r.page_token.to_owned()));
            }
            let data = read_get(token, "https://www.googleapis.com/calendar/v3/calendars/primary/events", &params)?;
            let keep = ["id", "summary", "description", "start", "end", "location", "htmlLink", "status", "attendees", "organizer", "creator", "recurringEventId", "originalStartTime", "updated", "attendeesOmitted"];
            let mut events = Vec::new();
            for e in data.get("items").and_then(Value::as_array).into_iter().flatten().take(limit) {
                let mut row = Map::new();
                for k in keep {
                    row.insert(k.into(), e.get(k).cloned().unwrap_or(Value::Null));
                }
                let link = calendar_web_url(e.get("htmlLink"));
                if !link.is_empty() {
                    row.insert("web_url".into(), json!(link));
                }
                if let Some(url) = calendar::video_link(e) {
                    row.insert("meeting_url".into(), json!(url));
                }
                events.push(Value::Object(row));
            }
            out.insert("events".into(), json!(events));
            out.insert("has_more".into(), json!(util::truthy(data.get("nextPageToken"))));
            out.insert("next_page_token".into(), data.get("nextPageToken").cloned().unwrap_or(json!("")));
        }
    }
    Ok(out)
}

// ── drafts ─────────────────────────────────────────────────────────────────

/// One bare address, or a refusal. No display names, no lists, no header breaks.
pub fn address(addr: &str) -> R<String> {
    let bad = addr.chars().any(|c| c.is_whitespace() || "\r\n,;<>()\"[]:\\".contains(c));
    let mut parts = addr.split('@');
    let (local, domain) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if bad || addr.matches('@').count() != 1 || local.is_empty() || !domain.contains('.') {
        return Err(Fail::provider("Use valid single email addresses (no names, lists or line breaks)"));
    }
    Ok(addr.to_owned())
}

fn is_message_id(s: &str) -> bool {
    let n = s.chars().count();
    s.starts_with('<') && s.ends_with('>') && (3..=902).contains(&n) && !s[1..s.len() - 1].chars().any(|c| c == '<' || c == '>' || c.is_whitespace())
}

pub struct Reply {
    pub message_id: String,
    pub references: String,
    pub subject: String,
}

fn reply_context(token: &str, thread_id: &str, in_reply_to: &str) -> R<Reply> {
    if !is_gmail_id(thread_id) || (!in_reply_to.is_empty() && !is_gmail_id(in_reply_to)) {
        return Err(Fail::provider("Invalid thread or message ID"));
    }
    let params = [("format", "metadata".to_owned()), ("metadataHeaders", "Message-ID".to_owned()), ("metadataHeaders", "References".to_owned()), ("metadataHeaders", "Subject".to_owned())];
    let url = if in_reply_to.is_empty() { format!("{GMAIL}threads/{thread_id}") } else { format!("{GMAIL}messages/{in_reply_to}") };
    let retry = "Thread could not be read; retry later";
    let answer = call("GET", &url, &params, token, None, 20, READ_LIMIT).map_err(|e| net_fault(&e, retry, retry))?;
    if answer.status == 404 {
        return Err(Fail::provider("Thread or message not found; use ids from a Gmail read"));
    }
    if [400, 401, 403].contains(&answer.status) {
        return Err(Fail::provider("Thread could not be read; check account permissions"));
    }
    if answer.status != 200 {
        return Err(fault_for_status(answer.status, retry));
    }
    let data = answer.json().filter(Value::is_object).ok_or_else(|| Fail::upstream("provider", "bad_answer", retry))?;
    let message = if in_reply_to.is_empty() { data.get("messages").and_then(Value::as_array).and_then(|m| m.last()).cloned() } else { Some(data) };
    let Some(message) = message.filter(|m| util::truthy(Some(m))) else {
        return Err(Fail::provider("That message is not in this thread"));
    };
    let thread = match message.get("threadId") {
        Some(t) => t.as_str().map(str::to_owned),
        None if in_reply_to.is_empty() => Some(thread_id.to_owned()),
        None => None,
    };
    if thread.as_deref() != Some(thread_id) {
        return Err(Fail::provider("That message is not in this thread"));
    }
    let mut headers = Map::new();
    for h in message.get("payload").and_then(|p| p.get("headers")).and_then(Value::as_array).into_iter().flatten() {
        headers.insert(util::text(h, "name").to_lowercase(), json!(util::text(h, "value")));
    }
    let header = |k: &str| headers.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let mid = header("message-id").trim().to_owned();
    if !is_message_id(&mid) {
        return Err(Fail::provider("The replied-to message has no usable Message-ID"));
    }
    let refs: Vec<String> = header("references").split_whitespace().filter(|r| is_message_id(r)).map(str::to_owned).collect();
    let all = format!("{} {mid}", refs.join(" ")).trim().to_owned();
    let chars: Vec<char> = all.chars().collect();
    let references: String = chars[chars.len().saturating_sub(8000)..].iter().collect();
    let subject = header("subject").replace(['\r', '\n'], " ").trim().to_owned();
    Ok(Reply { message_id: mid, references, subject })
}

/// A header line folded at spaces to lines of at most 78 characters.
fn fold(name: &str, value: &str) -> String {
    let mut out = format!("{name}:");
    let mut line_len = out.len();
    for (i, word) in value.split(' ').enumerate() {
        if i > 0 && line_len + 1 + word.len() > 78 {
            out.push_str("\r\n");
            line_len = 0;
        }
        out.push(' ');
        out.push_str(word);
        line_len += 1 + word.len();
    }
    out + "\r\n"
}

/// RFC 2047 for a header value that is not ASCII.
fn encoded_word(value: &str) -> String {
    if value.is_ascii() {
        return value.to_owned();
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in value.chars() {
        if chunk.len() + c.len_utf8() > 45 {
            words.push(format!("=?utf-8?b?{}?=", util::b64(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?utf-8?b?{}?=", util::b64(chunk.as_bytes())));
    }
    words.join(" ")
}

fn base64_lines(data: &[u8]) -> String {
    let text = util::b64(data);
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push_str("\r\n");
    }
    out
}

/// A text/plain part: headers and body, the transfer encoding chosen as
/// email.contentmanager does for short lines (7bit or 8bit), else base64.
fn text_part(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let short = lines.iter().all(|l| l.len() <= 78);
    let head = "Content-Type: text/plain; charset=\"utf-8\"\r\n";
    if short {
        let cte = if body.is_ascii() { "7bit" } else { "8bit" };
        format!("{head}Content-Transfer-Encoding: {cte}\r\n\r\n{}\r\n", lines.join("\r\n"))
    } else {
        format!("{head}Content-Transfer-Encoding: base64\r\n\r\n{}", base64_lines((lines.join("\n") + "\n").as_bytes()))
    }
}

/// The draft as Gmail's base64url raw.
pub fn draft_message(recipient: &str, subject: &str, body: &str, cc: &[String], bcc: &[String], reply: Option<&Reply>, attachments: &[(String, String, Vec<u8>)]) -> R<String> {
    if subject.contains(['\r', '\n']) {
        return Err(Fail::provider("Use one valid recipient and a single-line subject"));
    }
    let mut head = fold("To", &address(recipient)?);
    if !cc.is_empty() {
        head += &fold("Cc", &cc.iter().map(|a| address(a)).collect::<R<Vec<_>>>()?.join(", "));
    }
    if !bcc.is_empty() {
        head += &fold("Bcc", &bcc.iter().map(|a| address(a)).collect::<R<Vec<_>>>()?.join(", "));
    }
    let mut subject = subject.to_owned();
    if let Some(r) = reply {
        if subject.trim().is_empty() {
            subject = r.subject.clone();
        }
        if !subject.trim_start().to_lowercase().starts_with("re:") {
            subject = format!("Re: {subject}");
        }
        head += &fold("In-Reply-To", &r.message_id);
        head += &fold("References", &r.references);
    }
    head += &fold("Subject", &encoded_word(&subject));
    head += "MIME-Version: 1.0\r\n";
    let message = if attachments.is_empty() {
        head + &text_part(body)
    } else {
        let boundary = format!("==============={}==", util::uuid_hex());
        let mut m = head + &format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n");
        m += &format!("--{boundary}\r\n{}", text_part(body));
        for (filename, content_type, data) in attachments {
            let name = if filename.is_ascii() { format!("filename=\"{}\"", filename.replace('"', "\\\"")) } else { format!("filename*=utf-8''{}", util::quote(filename, "")) };
            m += &format!("--{boundary}\r\nContent-Type: {content_type}\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; {name}\r\nMIME-Version: 1.0\r\n\r\n{}", base64_lines(data));
        }
        m + &format!("--{boundary}--\r\n")
    };
    Ok(util::b64url(message.as_bytes()))
}

fn draft_call(method: &str, url: &str, token: &str, payload: &Value, created: bool) -> R<Value> {
    let unknown = "Draft outcome unknown; check Gmail Drafts before retrying";
    let answer = call(method, url, &[], token, Some(payload), 20, READ_LIMIT).map_err(|e| net_fault(&e, unknown, unknown))?;
    if answer.status == 404 && !created {
        return Err(Fail::provider("Draft not found in Gmail; it may have been sent or deleted"));
    }
    if [400, 401, 403].contains(&answer.status) {
        return Err(Fail::provider("Draft creation failed; check account permissions"));
    }
    if answer.status != 200 && answer.status != 201 {
        return Err(fault_for_status(answer.status, unknown));
    }
    let data = answer.json().filter(Value::is_object).ok_or_else(|| Fail::upstream("provider", "bad_answer", unknown))?;
    if !util::truthy(data.get("id")) {
        return Err(Fail::upstream("provider", "bad_answer", "Draft outcome unknown; do not retry automatically"));
    }
    let message = data.get("message").filter(|m| util::truthy(Some(m))).cloned().unwrap_or(json!({}));
    let mut out = json!({
        "draft_id": data["id"], "message_id": message.get("id").cloned().unwrap_or(Value::Null),
        "status": if created { "draft_created" } else { "draft_updated" }, "sent": false,
    });
    if util::truthy(message.get("threadId")) {
        out["thread_id"] = message["threadId"].clone();
    }
    Ok(out)
}

/// Create (or, with draft_id, replace) an unsent Gmail draft. Never sends.
#[allow(clippy::too_many_arguments)]
pub fn create_gmail_draft(value: &Value, recipient: &str, subject: &str, body: &str, cc: &[String], bcc: &[String], thread_id: &str, in_reply_to: &str, attachments: &[(String, String, Vec<u8>)], draft_id: &str) -> R<Value> {
    if !util::text(value, "scope").split_whitespace().any(|s| s == DRAFT_SCOPE) {
        return Err(Fail::provider("Draft permission required"));
    }
    if recipient.contains(['\r', '\n']) || subject.contains(['\r', '\n']) {
        return Err(Fail::provider("Use one valid recipient and a single-line subject"));
    }
    let token = util::text(value, "access_token");
    let reply = if thread_id.is_empty() { None } else { Some(reply_context(token, thread_id, in_reply_to)?) };
    let raw = draft_message(recipient, subject, body, cc, bcc, reply.as_ref(), attachments)?;
    let mut message = json!({"raw": raw});
    if reply.is_some() {
        message["threadId"] = json!(thread_id);
    }
    let base = format!("{GMAIL}drafts");
    if !draft_id.is_empty() {
        if !is_gmail_id(draft_id) {
            return Err(Fail::provider("Invalid draft ID"));
        }
        return draft_call("PUT", &format!("{base}/{draft_id}"), token, &json!({"id": draft_id, "message": message}), false);
    }
    draft_call("POST", &base, token, &json!({"message": message}), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_text_like_htmlparser() {
        assert_eq!(html_text("<p>Hi &amp; bye</p><script>x()</script><p>there&#33;</p>"), "Hi & bye\nthere!");
        assert_eq!(html_text("plain"), "plain");
    }

    #[test]
    fn web_urls() {
        assert_eq!(gmail_web_url("a+b@x.io", Some(&json!("t1")), None), "https://mail.google.com/mail/?authuser=a%2Bb@x.io#all/t1");
        assert_eq!(gmail_web_url("", Some(&json!("t1")), None), "");
        assert_eq!(gmail_web_url("a@x.io", Some(&json!("")), Some(&json!("m/1"))), "");
        assert_eq!(calendar_web_url(Some(&json!("https://www.google.com/calendar/event?eid=1"))), "https://www.google.com/calendar/event?eid=1");
        assert_eq!(calendar_web_url(Some(&json!("https://evil.example/x"))), "");
        assert_eq!(calendar_web_url(Some(&json!("https://calendar.google.com:443/x"))), "");
    }

    #[test]
    fn authorize_url_and_permissions() {
        let url = authorize("google_calendar", &("cid".into(), "s".into()), "https://app/api/auth/callback/google", "vxc_s", "ch", "calendar_write").unwrap();
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?client_id=cid&redirect_uri=https%3A%2F%2Fapp%2Fapi%2Fauth%2Fcallback%2Fgoogle&response_type=code&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcalendar.events.readonly+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcalendar.events&state=vxc_s"), "{url}");
        assert!(url.ends_with("&prompt=select_account+consent&include_granted_scopes=true"));
        assert!(matches!(authorize("google_email", &("c".into(), "s".into()), "r", "s", "c", "calendar_write"), Err(Fail::Provider(_))));
        assert_eq!(permissions("google_email", &format!("{READ_SCOPE} {DRAFT_SCOPE}")), vec!["drafts"]);
        assert!(permissions("google_calendar", CALENDAR_READ_SCOPE).is_empty());
    }

    #[test]
    fn a_draft_is_a_mime_message() {
        let raw = draft_message("a@x.io", "Héllo", "line\n", &["b@x.io".into()], &[], None, &[]).unwrap();
        let text = String::from_utf8(util::b64url_decode_lenient(&raw).unwrap()).unwrap();
        assert!(text.starts_with("To: a@x.io\r\nCc: b@x.io\r\nSubject: =?utf-8?b?SMOpbGxv?=\r\nMIME-Version: 1.0\r\n"), "{text}");
        assert!(text.ends_with("Content-Transfer-Encoding: 7bit\r\n\r\nline\r\n"));
        assert!(matches!(address("Name <a@x.io>"), Err(Fail::Provider(_))));
        assert!(matches!(address("a@x"), Err(Fail::Provider(_))));
    }
}
