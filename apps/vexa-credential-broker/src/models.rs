//! The request bodies every route accepts (credential-broker.v1), each
//! refusing a field the contract does not name. A body that does not validate
//! is a 422 "Invalid request fields" before the route runs. Scalars are read
//! the way the Python service's pydantic models read them (lax mode).

use serde_json::{json, Map, Value};

use crate::fail::{Fail, R};
use crate::util;

pub type Obj = Map<String, Value>;

pub fn object(v: &Value) -> R<&Obj> {
    v.as_object().ok_or(Fail::Invalid)
}

/// Refuse a key the model does not name.
pub fn only(o: &Obj, allowed: &[&str]) -> R<()> {
    if o.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(Fail::Invalid)
    }
}

fn len_ok(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.chars().count())
}

/// A str field: missing gives default (None = required); null is refused.
pub fn string(o: &Obj, key: &str, default: Option<&str>, min: usize, max: usize) -> R<String> {
    match o.get(key) {
        None => default.map(str::to_owned).ok_or(Fail::Invalid),
        Some(Value::String(s)) if len_ok(s, min, max) => Ok(s.clone()),
        _ => Err(Fail::Invalid),
    }
}

/// An Optional[str] field (absent or null is None).
pub fn opt_string(o: &Obj, key: &str, min: usize, max: usize) -> R<Option<String>> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if len_ok(s, min, max) => Ok(Some(s.clone())),
        _ => Err(Fail::Invalid),
    }
}

pub fn lax_int(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(b) => Some(*b as i64),
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0 && f.abs() < 9.2e18).map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

pub fn lax_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => match n.as_f64() {
            Some(0.0) => Some(false),
            Some(1.0) => Some(true),
            _ => None,
        },
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            _ => None,
        },
        _ => None,
    }
}

pub fn int(o: &Obj, key: &str, default: i64, min: i64, max: i64) -> R<i64> {
    match o.get(key) {
        None => Ok(default),
        Some(v) => lax_int(v).filter(|n| (min..=max).contains(n)).ok_or(Fail::Invalid),
    }
}

pub fn opt_int(o: &Obj, key: &str, min: i64, max: i64) -> R<Option<i64>> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => lax_int(v).filter(|n| (min..=max).contains(n)).map(Some).ok_or(Fail::Invalid),
    }
}

pub fn boolean(o: &Obj, key: &str, default: bool) -> R<bool> {
    match o.get(key) {
        None => Ok(default),
        Some(v) => lax_bool(v).ok_or(Fail::Invalid),
    }
}

pub fn opt_bool(o: &Obj, key: &str) -> R<Option<bool>> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => lax_bool(v).map(Some).ok_or(Fail::Invalid),
    }
}

pub fn literal(o: &Obj, key: &str, default: Option<&str>, choices: &[&str]) -> R<String> {
    let s = string(o, key, default, 0, usize::MAX)?;
    if choices.contains(&s.as_str()) {
        Ok(s)
    } else {
        Err(Fail::Invalid)
    }
}

fn list<'a>(o: &'a Obj, key: &str, max: usize) -> R<Option<&'a Vec<Value>>> {
    match o.get(key) {
        None => Ok(None),
        Some(Value::Array(a)) if a.len() <= max => Ok(Some(a)),
        _ => Err(Fail::Invalid),
    }
}

/// list[str] items each checked by ok.
fn strings(items: &[Value], ok: &dyn Fn(&str) -> bool) -> R<Vec<String>> {
    items.iter().map(|v| v.as_str().filter(|s| ok(s)).map(str::to_owned).ok_or(Fail::Invalid)).collect()
}

// ── patterns ───────────────────────────────────────────────────────────────

pub fn all_in(s: &str, ok: impl Fn(char) -> bool) -> bool {
    s.chars().all(ok)
}

/// ^[a-z0-9.-]+\.[a-z0-9-]+$ within 3..=253 characters.
pub fn is_domain(s: &str) -> bool {
    let class = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    len_ok(s, 3, 253)
        && all_in(s, |c| class(c) || c == '.')
        && s.rfind('.').is_some_and(|i| i > 0 && i + 1 < s.len())
}

/// ^[^\s/?#]+$ within 1..=256 characters.
pub fn is_calendar_id(s: &str) -> bool {
    len_ok(s, 1, 256) && all_in(s, |c| !c.is_whitespace() && !matches!(c, '/' | '?' | '#'))
}

pub fn is_email(s: &str) -> bool {
    len_ok(s, 3, 320)
}

fn id_chars(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// ^[a-zA-Z0-9-]{8,80}$
pub fn is_request_id(s: &str) -> bool {
    len_ok(s, 8, 80) && all_in(s, |c| c.is_ascii_alphanumeric() || c == '-')
}

/// ^[a-zA-Z0-9_-]{1,128}$
pub fn is_google_id(s: &str) -> bool {
    len_ok(s, 1, 128) && all_in(s, id_chars)
}

/// ^[a-v0-9_]{5,1024}$
pub fn is_event_id(s: &str) -> bool {
    len_ok(s, 5, 1024) && all_in(s, |c| matches!(c, 'a'..='v' | '0'..='9' | '_'))
}

/// ^[a-f0-9]{32}$
pub fn is_hex32(s: &str) -> bool {
    s.len() == 32 && all_in(s, |c| matches!(c, 'a'..='f' | '0'..='9'))
}

/// ^[a-z0-9][a-z0-9_.-]{0,62}$
pub fn is_service_name(s: &str) -> bool {
    let first = s.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first && len_ok(s, 1, 63) && all_in(s, |c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
}

fn is_digits(s: &str, min: usize, max: usize) -> bool {
    len_ok(s, min, max) && all_in(s, |c| c.is_ascii_digit())
}

/// ^(user:[0-9]{1,20}|company)$
pub fn is_bot_owner(s: &str) -> bool {
    s == "company" || s.strip_prefix("user:").is_some_and(|d| is_digits(d, 1, 20))
}

/// The Git credential names: pat/<person>[/<provider>] or deploy/(user|ws)-<id>.(priv|pub).
pub fn is_git_name(s: &str) -> bool {
    let name_class = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-');
    if let Some(rest) = s.strip_prefix("pat/") {
        let (person, provider) = match rest.split_once('/') {
            Some((p, v)) => (p, Some(v)),
            None => (rest, None),
        };
        let person_ok = len_ok(person, 1, 128) && all_in(person, name_class);
        let provider_ok = provider.is_none_or(|v| {
            v.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && len_ok(v, 1, 64)
                && all_in(v, |c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-'))
        });
        return person_ok && provider_ok;
    }
    let rest = match s.strip_prefix("deploy/user-").or_else(|| s.strip_prefix("deploy/ws-")) {
        Some(r) => r,
        None => return false,
    };
    let middle = rest.strip_suffix(".priv").or_else(|| rest.strip_suffix(".pub"));
    middle.is_some_and(|m| len_ok(m, 1, 120) && all_in(m, name_class))
}

// ── the models ─────────────────────────────────────────────────────────────

pub struct SetupBody {
    pub label: String,
    pub provider: String,
}

impl SetupBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["label", "provider"])?;
        Ok(Self {
            label: string(o, "label", Some("Connection"), 1, 80)?,
            provider: literal(o, "provider", None, &["custom_secret", "google_calendar", "google_email"])?,
        })
    }
}

pub struct CustomSecretBody {
    pub setup_request: String,
    pub confirmed_host: String,
    pub fields: Vec<(String, String)>,
    pub value: String,
    pub endpoint: String,
    pub header: String,
    pub scheme: String,
    pub method: String,
}

pub fn str_map(o: &Obj, key: &str, max: usize) -> R<Vec<(String, String)>> {
    match o.get(key) {
        None => Ok(vec![]),
        Some(Value::Object(m)) if m.len() <= max => {
            m.iter().map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())).ok_or(Fail::Invalid)).collect()
        }
        _ => Err(Fail::Invalid),
    }
}

impl CustomSecretBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["setup_request", "confirmed_host", "fields", "value", "endpoint", "header", "scheme", "method"])?;
        Ok(Self {
            setup_request: string(o, "setup_request", Some(""), 0, 80)?,
            confirmed_host: string(o, "confirmed_host", Some(""), 0, 253)?,
            fields: str_map(o, "fields", 10)?,
            value: string(o, "value", Some(""), 0, 65536)?,
            endpoint: string(o, "endpoint", Some(""), 0, 2000)?,
            header: string(o, "header", Some("Authorization"), 0, 64)?,
            scheme: literal(o, "scheme", Some("bearer"), &["bearer", "raw"])?,
            method: literal(o, "method", Some("GET"), &["GET", "POST"])?,
        })
    }
}

pub struct OAuthApplicationBody {
    pub client_id: String,
    pub client_secret: String,
    pub setup_request: String,
    pub confirmed_host: String,
    pub confirmed_hosts: Vec<String>,
}

impl OAuthApplicationBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["client_id", "client_secret", "setup_request", "confirmed_host", "confirmed_hosts"])?;
        Ok(Self {
            client_id: string(o, "client_id", None, 1, 200)?,
            client_secret: string(o, "client_secret", None, 1, 2000)?,
            setup_request: string(o, "setup_request", None, 0, 80)?,
            confirmed_host: string(o, "confirmed_host", Some(""), 0, 253)?,
            confirmed_hosts: match list(o, "confirmed_hosts", 4)? {
                Some(items) => strings(items, &|s| len_ok(s, 0, 253))?,
                None => vec![],
            },
        })
    }
}

pub fn prepared_setup(v: &Value) -> R<Value> {
    let o = object(v)?;
    only(o, &["setup"])?;
    match o.get("setup") {
        Some(s @ Value::Object(_)) => Ok(s.clone()),
        _ => Err(Fail::Invalid),
    }
}

#[derive(Clone, Debug)]
pub struct ActionPolicy {
    pub unattended: bool,
    pub notify_attendees: bool,
    pub attendee_domains: Option<Vec<String>>,
    pub calendars: Option<Vec<String>>,
    pub recipient_domains: Option<Vec<String>>,
    pub attachments: bool,
    pub attachment_max_bytes: i64,
}

impl Default for ActionPolicy {
    fn default() -> Self {
        Self {
            unattended: false,
            notify_attendees: false,
            attendee_domains: None,
            calendars: Some(vec!["primary".into()]),
            recipient_domains: None,
            attachments: false,
            attachment_max_bytes: 0,
        }
    }
}

fn opt_list(o: &Obj, key: &str, default: Option<Vec<String>>, max: usize, ok: &dyn Fn(&str) -> bool) -> R<Option<Vec<String>>> {
    match o.get(key) {
        None => Ok(default),
        Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) if a.len() <= max => strings(a, ok).map(Some),
        _ => Err(Fail::Invalid),
    }
}

impl ActionPolicy {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["unattended", "notify_attendees", "attendee_domains", "calendars", "recipient_domains", "attachments", "attachment_max_bytes"])?;
        Ok(Self {
            unattended: boolean(o, "unattended", false)?,
            notify_attendees: boolean(o, "notify_attendees", false)?,
            attendee_domains: opt_list(o, "attendee_domains", None, 100, &is_domain)?,
            calendars: opt_list(o, "calendars", Some(vec!["primary".into()]), 100, &is_calendar_id)?,
            recipient_domains: opt_list(o, "recipient_domains", None, 100, &is_domain)?,
            attachments: boolean(o, "attachments", false)?,
            attachment_max_bytes: int(o, "attachment_max_bytes", 0, 0, 20480 * 1024)?,
        })
    }

    pub fn optional(o: &Obj) -> R<Option<Self>> {
        match o.get("policy") {
            None | Some(Value::Null) => Ok(None),
            Some(v) => Self::parse(v).map(Some),
        }
    }
}

pub const ACTIONS: [&str; 9] = [
    "gmail.search",
    "gmail.read",
    "gmail.thread",
    "calendar.events",
    "gmail.draft",
    "gmail.draft.update",
    "calendar.event.create",
    "calendar.event.update",
    "calendar.event.cancel",
];

/// A person's own, narrower setting for the connection policy keys; the
/// dump leaves out what is unset (model_dump(exclude_none=True)).
pub fn action_preferences(v: &Value) -> R<Value> {
    let o = object(v)?;
    let keys = [
        "connection_actions",
        "connection_actions_unattended",
        "calendar_notify_attendees",
        "calendar_attendee_domains",
        "calendar_ids",
        "draft_recipient_domains",
        "draft_attachments",
        "draft_attachment_max_kb",
    ];
    only(o, &keys)?;
    let mut out = Map::new();
    for key in ["connection_actions", "connection_actions_unattended"] {
        if let Some(list) = opt_list(o, key, None, usize::MAX, &|s| ACTIONS.contains(&s))? {
            out.insert(key.into(), json!(list));
        }
    }
    if let Some(b) = opt_bool(o, "calendar_notify_attendees")? {
        out.insert("calendar_notify_attendees".into(), json!(b));
    }
    for (key, item) in [("calendar_attendee_domains", is_domain as fn(&str) -> bool), ("calendar_ids", is_calendar_id), ("draft_recipient_domains", is_domain)] {
        match o.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s == "any" => {
                out.insert(key.into(), json!("any"));
            }
            Some(Value::Array(a)) => {
                out.insert(key.into(), json!(strings(a, &item)?));
            }
            _ => return Err(Fail::Invalid),
        }
    }
    if let Some(b) = opt_bool(o, "draft_attachments")? {
        out.insert("draft_attachments".into(), json!(b));
    }
    if let Some(n) = opt_int(o, "draft_attachment_max_kb", 0, 20480)? {
        out.insert("draft_attachment_max_kb".into(), json!(n));
    }
    // Fields in the model's order.
    let mut ordered = Map::new();
    for key in keys {
        if let Some(v) = out.remove(key) {
            ordered.insert(key.into(), v);
        }
    }
    Ok(Value::Object(ordered))
}

/// AuthorizeBody: None for an absent body.
pub fn authorize_grant(body: Option<&Value>) -> R<String> {
    match body {
        None | Some(Value::Null) => Ok(String::new()),
        Some(v) => {
            let o = object(v)?;
            only(o, &["grant"])?;
            literal(o, "grant", Some(""), &["", "calendar_write"])
        }
    }
}

pub struct AccountReadBody {
    pub action: String,
    pub query: String,
    pub page_token: String,
    pub message_id: String,
    pub time_min: String,
    pub time_max: String,
    pub limit: i64,
    pub policy: Option<ActionPolicy>,
}

impl AccountReadBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["action", "query", "page_token", "message_id", "time_min", "time_max", "limit", "policy"])?;
        Ok(Self {
            action: literal(o, "action", None, &["gmail.search", "gmail.read", "gmail.thread", "calendar.events"])?,
            query: string(o, "query", Some(""), 0, 500)?,
            page_token: string(o, "page_token", Some(""), 0, 2048)?,
            message_id: string(o, "message_id", Some(""), 0, 128)?,
            time_min: string(o, "time_min", Some(""), 0, 40)?,
            time_max: string(o, "time_max", Some(""), 0, 40)?,
            limit: int(o, "limit", 10, 1, 20)?,
            policy: ActionPolicy::optional(o)?,
        })
    }
}

#[derive(Clone)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: String,
}

pub const ATTACHMENT_TYPES: [&str; 6] = ["application/pdf", "image/png", "image/jpeg", "text/plain", "text/csv", "text/markdown"];

impl Attachment {
    fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["filename", "content_type", "data"])?;
        let filename = string(o, "filename", None, 1, 200)?;
        if !all_in(&filename, |c| !(matches!(c, '/' | '\\') || (c as u32) <= 0x1f || c as u32 == 0x7f)) {
            return Err(Fail::Invalid);
        }
        Ok(Self { filename, content_type: literal(o, "content_type", None, &ATTACHMENT_TYPES)?, data: string(o, "data", None, 1, 28_000_000)? })
    }
    fn dump(&self) -> Value {
        json!({"filename": self.filename, "content_type": self.content_type, "data": self.data})
    }
}

pub struct GmailDraftBody {
    pub request_id: String,
    pub recipient: String,
    pub subject: String,
    pub body: String,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub thread_id: String,
    pub in_reply_to: String,
    pub attachments: Vec<Attachment>,
    pub policy: Option<ActionPolicy>,
    /// GmailDraftUpdateBody only.
    pub draft_id: String,
    pub replace_person_draft: bool,
}

fn opt_google_id(o: &Obj, key: &str) -> R<String> {
    let s = string(o, key, Some(""), 0, usize::MAX)?;
    if s.is_empty() || is_google_id(&s) {
        Ok(s)
    } else {
        Err(Fail::Invalid)
    }
}

impl GmailDraftBody {
    pub fn parse(v: &Value, update: bool) -> R<Self> {
        let o = object(v)?;
        let mut allowed = vec!["request_id", "recipient", "subject", "body", "cc", "bcc", "thread_id", "in_reply_to", "attachments", "policy"];
        if update {
            allowed.extend(["draft_id", "replace_person_draft"]);
        }
        only(o, &allowed)?;
        let request_id = string(o, "request_id", None, 0, usize::MAX)?;
        if !is_request_id(&request_id) {
            return Err(Fail::Invalid);
        }
        let recipient = string(o, "recipient", None, 3, 320)?;
        let emails = |key| -> R<Vec<String>> { Ok(list(o, key, 20)?.map(|a| strings(a, &is_email)).transpose()?.unwrap_or_default()) };
        let draft_id = if update {
            let d = string(o, "draft_id", None, 0, usize::MAX)?;
            if !is_google_id(&d) {
                return Err(Fail::Invalid);
            }
            d
        } else {
            String::new()
        };
        Ok(Self {
            request_id,
            recipient,
            subject: string(o, "subject", None, 0, 500)?,
            body: string(o, "body", None, 1, 50000)?,
            cc: emails("cc")?,
            bcc: emails("bcc")?,
            thread_id: opt_google_id(o, "thread_id")?,
            in_reply_to: opt_google_id(o, "in_reply_to")?,
            attachments: list(o, "attachments", 10)?.map(|a| a.iter().map(Attachment::parse).collect::<R<Vec<_>>>()).transpose()?.unwrap_or_default(),
            policy: ActionPolicy::optional(o)?,
            draft_id,
            replace_person_draft: if update { boolean(o, "replace_person_draft", false)? } else { false },
        })
    }

    /// model_dump(exclude={"policy"}), the idempotency fingerprint's input.
    pub fn content(&self, update: bool) -> Value {
        let mut m = json!({
            "request_id": self.request_id, "recipient": self.recipient, "subject": self.subject, "body": self.body,
            "cc": self.cc, "bcc": self.bcc, "thread_id": self.thread_id, "in_reply_to": self.in_reply_to,
            "attachments": self.attachments.iter().map(Attachment::dump).collect::<Vec<_>>(),
        });
        if update {
            m["draft_id"] = json!(self.draft_id);
            m["replace_person_draft"] = json!(self.replace_person_draft);
        }
        m
    }

    /// Only the fields a draft had before cc, threads and attachments existed.
    pub fn is_plain(&self) -> bool {
        self.cc.is_empty() && self.bcc.is_empty() && self.thread_id.is_empty() && self.in_reply_to.is_empty() && self.attachments.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct CalendarTime {
    pub date_time: String,
    pub date: String,
    pub time_zone: String,
}

impl CalendarTime {
    fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["date_time", "date", "time_zone"])?;
        let date = string(o, "date", Some(""), 0, usize::MAX)?;
        let date_ok = date.is_empty() || (date.len() == 10 && date.chars().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() }));
        if !date_ok {
            return Err(Fail::Invalid);
        }
        Ok(Self { date_time: string(o, "date_time", Some(""), 0, 40)?, date, time_zone: string(o, "time_zone", Some(""), 0, 64)? })
    }
    pub fn dump(&self) -> Value {
        json!({"date_time": self.date_time, "date": self.date, "time_zone": self.time_zone})
    }
}

pub struct CalendarEventBody {
    pub request_id: String,
    pub action: String,
    pub calendar_id: String,
    pub event_id: String,
    pub title: Option<String>,
    pub start: Option<CalendarTime>,
    pub end: Option<CalendarTime>,
    pub description: Option<String>,
    pub location: Option<String>,
    pub attendees: Option<Vec<String>>,
    pub conference: bool,
    pub notify: bool,
    pub policy: Option<ActionPolicy>,
}

impl CalendarEventBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["request_id", "action", "calendar_id", "event_id", "title", "start", "end", "description", "location", "attendees", "conference", "notify", "policy"])?;
        let request_id = string(o, "request_id", None, 0, usize::MAX)?;
        let calendar_id = string(o, "calendar_id", Some("primary"), 0, usize::MAX)?;
        let event_id = string(o, "event_id", Some(""), 0, usize::MAX)?;
        if !is_request_id(&request_id) || !is_calendar_id(&calendar_id) || !(event_id.is_empty() || is_event_id(&event_id)) {
            return Err(Fail::Invalid);
        }
        let time = |key| -> R<Option<CalendarTime>> {
            match o.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(v) => CalendarTime::parse(v).map(Some),
            }
        };
        Ok(Self {
            request_id,
            action: literal(o, "action", None, &["calendar.event.create", "calendar.event.update", "calendar.event.cancel"])?,
            calendar_id,
            event_id,
            title: opt_string(o, "title", 0, 1024)?,
            start: time("start")?,
            end: time("end")?,
            description: opt_string(o, "description", 0, 8000)?,
            location: opt_string(o, "location", 0, 1024)?,
            attendees: opt_list(o, "attendees", None, 100, &is_email)?,
            conference: boolean(o, "conference", false)?,
            notify: boolean(o, "notify", false)?,
            policy: ActionPolicy::optional(o)?,
        })
    }

    pub fn content(&self) -> Value {
        json!({
            "request_id": self.request_id, "action": self.action, "calendar_id": self.calendar_id, "event_id": self.event_id,
            "title": self.title, "start": self.start.as_ref().map(CalendarTime::dump), "end": self.end.as_ref().map(CalendarTime::dump),
            "description": self.description, "location": self.location, "attendees": self.attendees,
            "conference": self.conference, "notify": self.notify,
        })
    }
}

pub struct CustomCallBody {
    pub parameters: Vec<(String, String)>,
    pub body: Option<Obj>,
}

impl CustomCallBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["parameters", "body"])?;
        Ok(Self {
            parameters: str_map(o, "parameters", usize::MAX)?,
            body: match o.get("body") {
                None | Some(Value::Null) => None,
                Some(Value::Object(m)) => Some(m.clone()),
                _ => return Err(Fail::Invalid),
            },
        })
    }
}

pub struct GitSecretBody {
    pub name: String,
    pub action: String,
    pub value: Option<String>,
}

impl GitSecretBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["name", "action", "value"])?;
        let name = string(o, "name", None, 0, usize::MAX)?;
        if !is_git_name(&name) {
            return Err(Fail::Invalid);
        }
        Ok(Self { name, action: literal(o, "action", None, &["get", "put", "migrate"])?, value: opt_string(o, "value", 0, 32768)? })
    }
}

pub struct BotAccountSpec {
    pub owner: String,
    pub platform: String,
    pub display_name: String,
    pub created_by: String,
}

pub struct BotAccountBody {
    pub action: String,
    pub id: Option<String>,
    pub owners: Option<Vec<String>>,
    pub account: Option<BotAccountSpec>,
    pub files: Option<Vec<Value>>,
    pub state: Option<String>,
}

fn bot_file(v: &Value) -> R<Value> {
    let o = object(v)?;
    only(o, &["path", "data"])?;
    let path = string(o, "path", None, 1, 512)?;
    if path.starts_with('/') || path.contains('\\') || path.contains('\0') || path.split('/').any(|p| p == "..") {
        return Err(Fail::Invalid);
    }
    let data = string(o, "data", None, 0, 33_554_432)?;
    if util::b64decode_strict(&data).is_none() {
        return Err(Fail::Invalid);
    }
    Ok(json!({"path": path, "data": data}))
}

impl BotAccountBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["action", "id", "owners", "account", "files", "state"])?;
        let action = literal(o, "action", None, &["list", "get", "put", "state", "delete"])?;
        let id = opt_string(o, "id", 0, usize::MAX)?;
        if id.as_deref().is_some_and(|i| !is_hex32(i)) {
            return Err(Fail::Invalid);
        }
        let owners = opt_list(o, "owners", None, 64, &is_bot_owner)?;
        let account = match o.get("account") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let a = object(v)?;
                only(a, &["owner", "platform", "display_name", "created_by"])?;
                let owner = string(a, "owner", None, 0, usize::MAX)?;
                let created_by = string(a, "created_by", None, 0, usize::MAX)?;
                if !is_bot_owner(&owner) || !created_by.strip_prefix("user:").is_some_and(|d| is_digits(d, 1, 20)) {
                    return Err(Fail::Invalid);
                }
                Some(BotAccountSpec {
                    owner,
                    platform: literal(a, "platform", None, &["google", "microsoft", "zoom"])?,
                    display_name: string(a, "display_name", None, 1, 120)?,
                    created_by,
                })
            }
        };
        let files = match o.get("files") {
            None | Some(Value::Null) => None,
            Some(Value::Array(items)) if items.len() <= 128 => Some(items.iter().map(bot_file).collect::<R<Vec<_>>>()?),
            _ => return Err(Fail::Invalid),
        };
        let state = match o.get("state") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s == "ok" || s == "signed_out" => Some(s.clone()),
            _ => return Err(Fail::Invalid),
        };
        if action == "list" {
            if owners.is_none() {
                return Err(Fail::Invalid);
            }
        } else if id.is_none() {
            return Err(Fail::Invalid);
        }
        if action == "put" && (account.is_none() || files.is_none()) {
            return Err(Fail::Invalid);
        }
        if action == "state" && state.is_none() {
            return Err(Fail::Invalid);
        }
        Ok(Self { action, id, owners, account, files, state })
    }
}

pub struct CalendarChangesBody {
    pub owner: String,
    pub connection_id: Option<String>,
    pub cursor: Option<String>,
}

impl CalendarChangesBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["owner", "connection_id", "cursor"])?;
        Ok(Self { owner: string(o, "owner", None, 1, 64)?, connection_id: opt_string(o, "connection_id", 0, 64)?, cursor: opt_string(o, "cursor", 0, 4096)? })
    }
}

pub struct SensorGrantBody {
    pub connection_id: Option<String>,
    pub days: i64,
}

impl SensorGrantBody {
    pub fn parse(v: &Value) -> R<Self> {
        let o = object(v)?;
        only(o, &["connection_id", "days"])?;
        let connection_id = opt_string(o, "connection_id", 0, usize::MAX)?;
        if connection_id.as_deref().is_some_and(|c| !is_hex32(c)) {
            return Err(Fail::Invalid);
        }
        Ok(Self { connection_id, days: int(o, "days", 90, 1, 90)? })
    }
}

/// MailCredentialRequest and SignalsModelKeyRequest: { name }.
pub fn service_name(v: &Value) -> R<String> {
    let o = object(v)?;
    only(o, &["name"])?;
    let name = string(o, "name", None, 0, usize::MAX)?;
    if is_service_name(&name) {
        Ok(name)
    } else {
        Err(Fail::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Every request golden of the contract is accepted by its model.
    #[test]
    fn the_contract_request_goldens_validate() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/agent/contracts/credential-broker.v1/golden");
        let mut n = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().to_string();
            if !name.contains("Request.") {
                continue;
            }
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/agent/contracts/credential-broker.v1/golden").join(&name);
            let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let ok = match name.split('.').next().unwrap() {
                "SetupRequest" => SetupBody::parse(&v).is_ok(),
                "PrepareRequest" => prepared_setup(&v).is_ok(),
                "CustomSecretRequest" => CustomSecretBody::parse(&v).is_ok(),
                "OAuthApplicationRequest" => OAuthApplicationBody::parse(&v).is_ok(),
                "AccountReadRequest" => AccountReadBody::parse(&v).is_ok(),
                "GmailDraftRequest" => GmailDraftBody::parse(&v, false).is_ok(),
                "GmailDraftUpdateRequest" => GmailDraftBody::parse(&v, true).is_ok(),
                "CalendarEventRequest" => CalendarEventBody::parse(&v).is_ok(),
                "CustomCallRequest" => CustomCallBody::parse(&v).is_ok(),
                "GitSecretRequest" => GitSecretBody::parse(&v).is_ok(),
                "AuthorizeRequest" => authorize_grant(Some(&v)).is_ok(),
                "BotAccountRequest" => BotAccountBody::parse(&v).is_ok(),
                "CalendarChangesRequest" => CalendarChangesBody::parse(&v).is_ok(),
                "SensorGrantRequest" => SensorGrantBody::parse(&v).is_ok(),
                "SignalsModelKeyRequest" | "MailCredentialRequest" => service_name(&v).is_ok(),
                other => panic!("no model for {other}"),
            };
            assert!(ok, "{name}");
            n += 1;
        }
        assert!(n >= 20, "{n}");
    }

    #[test]
    fn patterns() {
        assert!(is_domain("a.io") && is_domain("x-y.z.co") && !is_domain("io") && !is_domain(".io") && !is_domain("a.") && !is_domain("A.io"));
        assert!(is_git_name("pat/42") && is_git_name("pat/42/gitlab.com") && is_git_name("deploy/ws-1.a.priv") && is_git_name("deploy/user-42.pub"));
        assert!(!is_git_name("pat/42/GitLab") && !is_git_name("deploy/ws-.pub") && !is_git_name("deploy/x-1.pub") && !is_git_name("pat/"));
        assert!(is_event_id("abc12") && !is_event_id("abcw1"));
        assert!(is_bot_owner("user:1") && is_bot_owner("company") && !is_bot_owner("user:"));
        let p = ActionPreferences_dump(json!({"draft_attachments": "yes", "calendar_ids": "any", "connection_actions": ["gmail.read"]}));
        assert_eq!(p, json!({"connection_actions": ["gmail.read"], "calendar_ids": "any", "draft_attachments": true}));
        assert!(action_preferences(&json!({"calendar_ids": "all"})).is_err());
        assert!(action_preferences(&json!({"x": 1})).is_err());
    }

    #[allow(non_snake_case)]
    fn ActionPreferences_dump(v: Value) -> Value {
        action_preferences(&v).unwrap()
    }
}
