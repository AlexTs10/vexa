//! Google Calendar: event changes (create, update, cancel) on the person's
//! calendar, idempotent by request key, and the incremental reads of flows'
//! calendar sensor (sync tokens; 410 is resync_required, never an error).

use serde_json::{json, Map, Value};

use crate::fail::{Fail, R};
use crate::google::{self, fault_for_status, CALENDAR_WRITE_SCOPE};
use crate::net::NetError;
use crate::tz::{self, DateTime};
use crate::util;

const CAL: &str = "https://www.googleapis.com/calendar/v3/calendars/";
const EVENTS: &str = "https://www.googleapis.com/calendar/v3/calendars/primary/events";
const LIMIT: usize = 8 * 1024 * 1024;

fn net_fault(e: &NetError, message: &str) -> Fail {
    Fail::upstream("provider", if e.no_answer() { "unreachable" } else { "bad_answer" }, message)
}

/// A CalendarTime as Google's EventDateTime, validated.
fn event_time(t: &Value, which: &str) -> R<Value> {
    let date = util::text(t, "date");
    let date_time = util::text(t, "date_time");
    if !date.is_empty() && !date_time.is_empty() {
        return Err(Fail::Provider(format!("Give {which} as date_time or date, not both")));
    }
    if !date.is_empty() {
        if date.len() != 10 || tz::parse_date(date).is_none() {
            return Err(Fail::Provider(format!("Invalid {which} date")));
        }
        return Ok(json!({"date": date}));
    }
    let moment = tz::fromisoformat(&date_time.replace('Z', "+00:00")).ok_or_else(|| Fail::Provider(format!("Invalid {which} time; use ISO 8601")))?;
    let zone = util::text(t, "time_zone");
    if !zone.is_empty() {
        if tz::zone(zone).is_none() {
            return Err(Fail::Provider(format!("Invalid {which} time zone; use an IANA name such as Europe/Lisbon")));
        }
    } else if moment.offset.is_none() {
        return Err(Fail::Provider(format!("Give {which} with an offset or a time_zone")));
    }
    let mut out = json!({"dateTime": moment.isoformat()});
    if !zone.is_empty() {
        out["timeZone"] = json!(zone);
    }
    Ok(out)
}

/// The instant of an EventDateTime, in microseconds.
fn instant(t: &Value) -> R<i128> {
    if let Some(d) = t.get("date").and_then(Value::as_str) {
        return tz::fromisoformat(&format!("{d}T00:00:00+00:00")).and_then(|m| m.utc_micros()).ok_or(Fail::Internal);
    }
    let mut moment: DateTime = tz::fromisoformat(util::text(t, "dateTime")).ok_or(Fail::Internal)?;
    if moment.offset.is_none() {
        let zone = tz::zone(util::text(t, "timeZone")).ok_or(Fail::Internal)?;
        moment.offset = Some(zone.offset_of_local(moment.wall_seconds()));
    }
    moment.utc_micros().ok_or(Fail::Internal)
}

fn span(start: &Value, end: &Value) -> R<()> {
    if start.get("date").is_some() != end.get("date").is_some() {
        return Err(Fail::provider("Start and end must both be all-day dates or both be times"));
    }
    if instant(end)? <= instant(start)? {
        return Err(Fail::provider("The event must end after it starts"));
    }
    Ok(())
}

/// A Google event id derived from the request: hex is a subset of base32hex,
/// so a create retried after an unknown outcome cannot make a second event.
pub fn event_id_for(request_key: &str) -> String {
    util::sha256_hex(request_key.as_bytes())[..40].to_owned()
}

fn request(method: &str, url: &str, token: &str, params: &[(&str, String)], payload: Option<&Value>, unknown: &str) -> R<crate::net::Answer> {
    google::call(method, url, params, token, payload, 20, LIMIT).map_err(|e| net_fault(&e, unknown))
}

/// The event as the person's calendar holds it.
fn calendar_event(token: &str, calendar_id: &str, event_id: &str) -> R<Value> {
    if !crate::models::is_event_id(event_id) {
        return Err(Fail::provider("Use an event id from a calendar read"));
    }
    let retry = "Calendar could not be read; retry later";
    let answer = request("GET", &format!("{CAL}{}/events/{event_id}", util::quote(calendar_id, "@.")), token, &[], None, retry)?;
    if answer.status == 404 || answer.status == 410 {
        return Err(Fail::provider("Event not found in this calendar; use an event id from a calendar read"));
    }
    if [400, 401, 403].contains(&answer.status) {
        return Err(Fail::provider("Calendar could not be read; check account permissions"));
    }
    if answer.status != 200 {
        return Err(fault_for_status(answer.status, retry));
    }
    let data = answer.json().filter(Value::is_object).ok_or_else(|| Fail::upstream("provider", "bad_answer", retry))?;
    if util::text(&data, "status") == "cancelled" {
        return Err(Fail::provider("That event is already cancelled"));
    }
    Ok(data)
}

fn conference_request(id: &str) -> Value {
    json!({"createRequest": {"requestId": id, "conferenceSolutionKey": {"type": "hangoutsMeet"}}})
}

fn time_fields(t: &Value) -> Value {
    let mut out = Map::new();
    if let Some(o) = t.as_object() {
        for (k, v) in o {
            if ["date", "dateTime", "timeZone"].contains(&k.as_str()) {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    Value::Object(out)
}

/// Create, update or cancel one event. fields holds the CalendarEventBody
/// fields (null = unchanged on update).
#[allow(clippy::too_many_arguments)]
pub fn write_calendar_event(value: &Value, action: &str, calendar_id: &str, event_id: &str, fields: &Value, notify: bool, conference: bool, request_key: &str) -> R<Value> {
    if !util::text(value, "scope").split_whitespace().any(|s| s == CALENDAR_WRITE_SCOPE) {
        return Err(Fail::provider("Calendar change permission required"));
    }
    let token = util::text(value, "access_token");
    let unknown = "Calendar change outcome unknown; check your calendar before retrying";
    let mut params = vec![("sendUpdates", if notify { "all" } else { "none" }.to_owned())];
    let events = format!("{CAL}{}/events", util::quote(calendar_id, "@."));
    let mut payload = Map::new();
    let set = |k: &str| fields.get(k).filter(|v| !v.is_null());
    if let Some(t) = set("title") {
        payload.insert("summary".into(), t.clone());
    }
    for key in ["description", "location"] {
        if let Some(v) = set(key) {
            payload.insert(key.into(), v.clone());
        }
    }
    if let Some(a) = set("attendees").and_then(Value::as_array) {
        let list = a.iter().map(|x| google::address(x.as_str().unwrap_or("")).map(|e| json!({"email": e}))).collect::<R<Vec<_>>>()?;
        payload.insert("attendees".into(), json!(list));
    }
    if let Some(s) = set("start") {
        payload.insert("start".into(), event_time(s, "start")?);
    }
    if let Some(e) = set("end") {
        payload.insert("end".into(), event_time(e, "end")?);
    }
    let status;
    let answer;
    if action == "calendar.event.create" {
        if !payload.contains_key("start") || !payload.contains_key("end") || !util::truthy(payload.get("summary")) {
            return Err(Fail::provider("A new event needs a title, a start and an end"));
        }
        span(&payload["start"], &payload["end"])?;
        let id = event_id_for(request_key);
        payload.insert("id".into(), json!(id));
        if conference {
            payload.insert("conferenceData".into(), conference_request(&id));
            params.push(("conferenceDataVersion", "1".into()));
        }
        answer = request("POST", &events, token, &params, Some(&Value::Object(payload)), unknown)?;
        if answer.status == 409 {
            return Err(Fail::provider("This request already created an event; check your calendar"));
        }
        status = "event_created";
    } else {
        let current = calendar_event(token, calendar_id, event_id)?;
        let organizer = current.get("organizer").is_some_and(|o| util::truthy(o.get("self")));
        if action == "calendar.event.cancel" {
            if !organizer {
                return Err(Fail::provider("Only events this person organizes can be cancelled"));
            }
            answer = request("DELETE", &format!("{events}/{event_id}"), token, &params, None, unknown)?;
            status = "event_cancelled";
        } else {
            if !organizer && !util::truthy(current.get("guestsCanModify")) {
                return Err(Fail::provider("This person cannot change that event; they do not organize it"));
            }
            if payload.is_empty() && !conference {
                return Err(Fail::provider("Give at least one field to change"));
            }
            let pick = |k: &str| payload.get(k).cloned().unwrap_or_else(|| current.get(k).filter(|v| util::truthy(Some(v))).cloned().unwrap_or(json!({})));
            let (start, end) = (pick("start"), pick("end"));
            if (payload.contains_key("start") || payload.contains_key("end")) && util::truthy(Some(&start)) && util::truthy(Some(&end)) {
                span(&time_fields(&start), &time_fields(&end))?;
            }
            if conference && !util::truthy(current.get("hangoutLink")) {
                payload.insert("conferenceData".into(), conference_request(&event_id_for(request_key)));
                params.push(("conferenceDataVersion", "1".into()));
            }
            answer = request("PATCH", &format!("{events}/{event_id}"), token, &params, Some(&Value::Object(payload)), unknown)?;
            status = "event_updated";
        }
    }
    if answer.status == 404 || answer.status == 410 {
        return Err(Fail::provider("Event not found in this calendar; use an event id from a calendar read"));
    }
    if [400, 401, 403].contains(&answer.status) {
        return Err(Fail::provider("Calendar change refused; check the event fields and account permissions"));
    }
    if ![200, 201, 204].contains(&answer.status) {
        return Err(fault_for_status(answer.status, unknown));
    }
    if status == "event_cancelled" {
        return Ok(json!({"status": status, "event_id": event_id, "calendar_id": calendar_id, "notified": notify}));
    }
    let data = answer.json().filter(|d| d.get("id").is_some()).ok_or_else(|| Fail::upstream("provider", "bad_answer", unknown))?;
    Ok(json!({
        "status": status, "event_id": data["id"], "calendar_id": calendar_id,
        "html_link": data.get("htmlLink").cloned().unwrap_or(json!("")),
        "meet_link": data.get("hangoutLink").cloned().unwrap_or(json!("")),
        "notified": notify,
    }))
}

// ── the sensor's incremental reads ─────────────────────────────────────────

const VIDEO_HOSTS: [&str; 5] = ["meet.google.com", "zoom.us", "teams.microsoft.com", "teams.live.com", "meet.jit.si"];
const PAGES_MAX: usize = 10;
const PAGE_SIZE: usize = 250;

/// The https links of text, as the pattern https://[^\s<>"')\]]{4,500} finds them.
fn urls(text: &str) -> Vec<String> {
    let stop = |c: char| c.is_whitespace() || "<>\"')]".contains(c);
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("https://") {
        let after = &rest[i + 8..];
        let tail: String = after.chars().take_while(|c| !stop(*c)).take(500).collect();
        if tail.chars().count() >= 4 {
            out.push(format!("https://{tail}"));
            rest = &after[tail.len()..];
        } else {
            rest = &rest[i + 1..];
        }
    }
    out
}

/// The event's meeting link: the conference's video entry point, Meet's
/// hangoutLink, then a meeting URL written into location or description.
pub fn video_link(e: &Value) -> Option<String> {
    let mut candidates: Vec<Option<String>> = Vec::new();
    let eps = e.get("conferenceData").filter(|c| util::truthy(Some(c))).and_then(|c| c.get("entryPoints")).and_then(Value::as_array).cloned().unwrap_or_default();
    for ep in eps {
        if util::text(&ep, "entryPointType") == "video" {
            candidates.push(ep.get("uri").and_then(Value::as_str).map(str::to_owned));
        }
    }
    candidates.push(e.get("hangoutLink").and_then(Value::as_str).map(str::to_owned));
    for key in ["location", "description"] {
        let text = e.get(key).map(|v| if util::truthy(Some(v)) { util::py_str(v) } else { String::new() }).unwrap_or_default();
        candidates.extend(urls(&text).into_iter().take(20).map(Some));
    }
    for url in candidates.into_iter().flatten() {
        let Ok(parts) = util::urlsplit(&url) else { continue };
        let host = parts.hostname().unwrap_or_default();
        let user = parts.username().is_some_and(|u| !u.is_empty());
        let pass = parts.password().is_some_and(|p| !p.is_empty());
        if parts.scheme == "https" && !user && !pass && VIDEO_HOSTS.iter().any(|h| host == *h || host.ends_with(&format!(".{h}"))) {
            return Some(url.chars().take(500).collect());
        }
    }
    None
}

fn when(t: Option<&Value>) -> Value {
    match t {
        Some(Value::Object(o)) => {
            for k in ["dateTime", "date"] {
                if let Some(v) = o.get(k).filter(|v| util::truthy(Some(v))) {
                    return v.clone();
                }
            }
            o.get("date").cloned().unwrap_or(Value::Null)
        }
        _ => Value::Null,
    }
}

fn clip(v: Option<&Value>, n: usize) -> String {
    let s = match v {
        Some(v) if util::truthy(Some(v)) => util::py_str(v),
        _ => String::new(),
    };
    s.chars().take(n).collect()
}

/// One event as CalendarChange (credential-broker.v1).
pub fn normalise(e: &Value) -> Value {
    let raw = util::text(e, "status");
    let status = if ["confirmed", "tentative", "cancelled"].contains(&raw) { raw } else { "confirmed" };
    let attendees = e.get("attendees").filter(|a| util::truthy(Some(a)));
    let me = attendees.and_then(Value::as_array).and_then(|a| a.iter().find(|x| x.is_object() && util::truthy(x.get("self"))));
    let organizer_self = e.get("organizer").filter(|o| util::truthy(Some(o))).is_some_and(|o| util::truthy(o.get("self")));
    let response = match me {
        Some(m) => {
            let r = util::text(m, "responseStatus");
            if ["accepted", "declined", "tentative", "needsAction"].contains(&r) { r } else { "none" }
        }
        None if organizer_self || attendees.is_none() => "organizer",
        None => "none",
    };
    let mut out = json!({
        "event_id": clip(e.get("id"), 1024), "status": status, "etag": clip(e.get("etag"), 200),
        "updated": clip(e.get("updated"), 40), "self_response": response, "organizer_self": organizer_self,
        "calendar_id": "primary",
    });
    if status != "cancelled" {
        out["title"] = json!(clip(e.get("summary"), 300));
        out["start"] = when(e.get("start"));
        out["end"] = when(e.get("end"));
        out["video_url"] = json!(video_link(e));
    }
    out
}

/// {items, cursor, resync_required}: what changed since cursor (or the bounded first read).
pub fn calendar_changes(value: &Value, cursor: Option<&str>, now: f64) -> R<Value> {
    let token = util::text(value, "access_token");
    let mut base = vec![("singleEvents", "true".to_owned()), ("showDeleted", "true".to_owned()), ("maxResults", PAGE_SIZE.to_string())];
    match cursor.filter(|c| !c.is_empty()) {
        Some(c) => base.push(("syncToken", c.to_owned())),
        None => {
            base.push(("timeMin", DateTime::from_unix(now - 86400.0, 0).isoformat()));
            base.push(("timeMax", DateTime::from_unix(now + 60.0 * 86400.0, 0).isoformat()));
        }
    }
    let mut items = Vec::new();
    let mut page = String::new();
    for _ in 0..PAGES_MAX {
        let mut params = base.clone();
        if !page.is_empty() {
            params.push(("pageToken", page.clone()));
        }
        let answer = google::call("GET", EVENTS, &params, token, None, 15, LIMIT).map_err(|e| {
            if e.no_answer() {
                Fail::upstream("provider", "unreachable", "Calendar is unavailable; the provider could not be reached")
            } else {
                Fail::upstream("provider", "bad_answer", "Calendar is unavailable; the provider answered unreadably")
            }
        })?;
        if answer.status == 410 {
            return Ok(json!({"items": [], "cursor": null, "resync_required": true}));
        }
        if answer.status == 401 || answer.status == 403 {
            return Err(Fail::provider("Authorization rejected; reconnect this account"));
        }
        if answer.status != 200 {
            return Err(fault_for_status(answer.status, "Calendar temporarily unavailable; retry later"));
        }
        let data = answer.json().ok_or_else(|| Fail::upstream("provider", "bad_answer", "Calendar answered unreadably"))?;
        for e in data.get("items").and_then(Value::as_array).into_iter().flatten() {
            if e.is_object() && util::truthy(e.get("id")) {
                items.push(normalise(e));
            }
        }
        if util::truthy(data.get("nextSyncToken")) {
            return Ok(json!({"items": items, "cursor": data["nextSyncToken"], "resync_required": false}));
        }
        page = util::text(&data, "nextPageToken").to_owned();
        if page.is_empty() {
            break;
        }
    }
    Ok(json!({"items": items, "cursor": cursor, "resync_required": false}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_times_and_spans() {
        assert_eq!(event_time(&json!({"date_time": "2026-11-20T10:00:00Z"}), "start").unwrap(), json!({"dateTime": "2026-11-20T10:00:00+00:00"}));
        assert_eq!(event_time(&json!({"date_time": "2026-11-20T10:00", "time_zone": "Europe/Lisbon"}), "start").unwrap(), json!({"dateTime": "2026-11-20T10:00:00", "timeZone": "Europe/Lisbon"}));
        assert!(matches!(event_time(&json!({"date_time": "2026-11-20T10:00"}), "start"), Err(Fail::Provider(s)) if s == "Give start with an offset or a time_zone"));
        assert!(matches!(event_time(&json!({"date_time": "x", "time_zone": "Mars/Base"}), "end"), Err(Fail::Provider(s)) if s == "Invalid end time; use ISO 8601"));
        assert!(matches!(event_time(&json!({"date_time": "2026-11-20T10:00", "time_zone": "Mars/Base"}), "end"), Err(Fail::Provider(s)) if s.starts_with("Invalid end time zone")));
        let a = json!({"dateTime": "2026-07-01T10:00:00", "timeZone": "Europe/Lisbon"});
        let b = json!({"dateTime": "2026-07-01T09:30:00+00:00"});
        assert!(span(&a, &b).is_ok());
        assert!(span(&b, &a).is_err());
        assert!(span(&json!({"date": "2026-01-01"}), &b).is_err());
        assert_eq!(event_id_for("42:req-0001"), util::sha256_hex(b"42:req-0001")[..40]);
    }

    #[test]
    fn video_links_and_normalise() {
        let e = json!({"id": "e1", "summary": "Sync", "location": "see https://acme.zoom.us/j/1 and https://evil.example/x", "start": {"dateTime": "2026-11-20T10:00:00Z"}, "end": {"date": "2026-11-21"}});
        assert_eq!(video_link(&e).as_deref(), Some("https://acme.zoom.us/j/1"));
        let n = normalise(&e);
        assert_eq!(n["self_response"], "organizer");
        assert_eq!(n["start"], "2026-11-20T10:00:00Z");
        assert_eq!(n["end"], "2026-11-21");
        let cancelled = normalise(&json!({"id": "e2", "status": "cancelled"}));
        assert!(cancelled.get("title").is_none());
        assert_eq!(video_link(&json!({"hangoutLink": "https://meet.google.com/abc"})).as_deref(), Some("https://meet.google.com/abc"));
        assert_eq!(video_link(&json!({"hangoutLink": "http://meet.google.com/abc"})), None);
    }
}
