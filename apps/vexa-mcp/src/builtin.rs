//! The edge's own eighteen tools: each one's model validator and its route body, as app.py
//! writes them. Validation of the arguments themselves is `pyd.rs`, driven by surface.json.

use serde_json::{json, Map, Value};
use vexa_native_kit::pyjson::{py_str, py_str_repr, truthy};

use crate::edge::{make_request, path_segment, App};
use crate::tickets;
use crate::wire::{HttpError, Req};

const VALID_PLATFORMS: [&str; 6] = [
    "google_meet",
    "teams",
    "zoom",
    "jitsi",
    "voice_note",
    "vexa_call",
];
const DELETE_REFUSED: &str = "delete_meeting: refused. Deleting a meeting destroys its transcript and recordings and cannot be undone. Set asked_by_a_human=true only when the person you work for asked you to delete this meeting; otherwise do not call this tool.";
const TRANSCRIPT_PAGE: i64 = 200;

fn text<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}

fn filled(v: Option<&str>) -> bool {
    v.is_some_and(|s| !s.trim().is_empty())
}

/// The model validators (mode="after"): None, or the ValueError's text. ReportIssue also clips.
pub fn model_check(tool: &str, m: &mut Map<String, Value>) -> Option<String> {
    match tool {
        "request_meeting_bot" => {
            let (url, id) = (filled(text(m, "meeting_url")), filled(text(m, "native_meeting_id")));
            if url && id {
                return Some("Provide either meeting_url OR native_meeting_id, not both.".into());
            }
            if !url && !id {
                return Some("Missing meeting identifier: provide meeting_url or native_meeting_id.".into());
            }
            None
        }
        "annotate_meeting" => {
            (m.get("title").is_none_or(Value::is_null) && m.get("metadata").is_none_or(Value::is_null))
                .then(|| "Nothing to annotate: provide title and/or metadata.".into())
        }
        "speak_in_meeting" => (m.get("asked_by_a_human") != Some(&Value::Bool(true))).then(|| {
            "speak_in_meeting: refused. This says words out loud to real people and cannot be undone. Set asked_by_a_human=true only when the person you work for asked you to say this; otherwise do not call this tool.".into()
        }),
        "report_issue" => {
            let missing: Vec<&str> = ["what_i_tried", "what_happened", "deployment"].into_iter().filter(|k| !filled(text(m, k))).collect();
            if !missing.is_empty() {
                return Some(format!("Empty required field(s): {}.", missing.join(", ")));
            }
            let logs = text(m, "logs").map(str::to_owned);
            for (k, limit) in [("what_i_tried", tickets::MAX_TEXT_CHARS), ("what_happened", tickets::MAX_TEXT_CHARS), ("deployment", 200),
                               ("native_meeting_id", 200), ("platform", 50), ("version", 100), ("logs", tickets::MAX_LOGS_CHARS)] {
                let clipped = tickets::clip(text(m, k), limit);
                m.insert(k.into(), clipped.map_or(Value::Null, Value::String));
            }
            let truncated = logs.is_some_and(|l| l.trim().chars().count() > tickets::MAX_LOGS_CHARS);
            m.insert("_logs_truncated".into(), truncated.into());
            None
        }
        _ => None,
    }
}

fn validate_platform(tool: &str, platform: Option<&str>, omitted: &str) -> Result<(), HttpError> {
    match platform {
        None => Ok(()),
        Some(p) if VALID_PLATFORMS.contains(&p) => Ok(()),
        Some(p) => Err(HttpError::new(
            422,
            format!(
                "{tool}: unknown platform {}. Valid values: {}. {omitted}",
                py_str_repr(p),
                VALID_PLATFORMS.join(", ")
            ),
        )),
    }
}

const SEARCH_EVERY: &str = "Omit `platform` to search every platform.";

/// Python's `a or b` over two optional strings.
fn or<'a>(a: Option<&'a str>, b: Option<&'a str>) -> Option<&'a str> {
    a.filter(|s| !s.is_empty()).or(b.filter(|s| !s.is_empty()))
}

fn resolve(
    tool: &str,
    q: &Map<String, Value>,
    legacy: bool,
    accepts_db_id: bool,
) -> Result<(String, String), HttpError> {
    let (lp, lid) = if legacy {
        (text(q, "meeting_platform"), text(q, "meeting_id"))
    } else {
        (None, None)
    };
    let mid = or(text(q, "native_meeting_id"), lid)
        .unwrap_or("")
        .trim()
        .to_owned();
    let plat = or(text(q, "platform"), lp)
        .unwrap_or("google_meet")
        .trim()
        .to_owned();
    if mid.is_empty() {
        let also = if accepts_db_id {
            " Or pass `meeting_db_id` — the exact row id every tool returns, which addresses ONE meeting rather than the newest one in a room."
        } else {
            ""
        };
        return Err(HttpError::new(422, format!(
            "{tool}: missing the meeting id. Pass `native_meeting_id` (the field request_meeting_bot / list_meetings / parse_meeting_link return), optionally with `platform`.{also} Received: native_meeting_id=None, meeting_id=None."
        )));
    }
    validate_platform(tool, Some(&plat), "Omit `platform` for google_meet.")?;
    Ok((plat, mid))
}

fn room(plat: &str, mid: &str) -> String {
    format!("{}/{}", path_segment(plat), path_segment(mid))
}

fn dump(m: &Map<String, Value>, exclude_none: bool) -> Map<String, Value> {
    m.iter()
        .filter(|(k, v)| !k.starts_with('_') && !(exclude_none && v.is_null()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn with_meeting_refs(mut result: Value) -> Value {
    if let Some(rows) = result.get_mut("meetings").and_then(Value::as_array_mut) {
        for m in rows.iter_mut() {
            if let Some(o) = m.as_object_mut() {
                if o.get("id").is_some_and(|v| !v.is_null()) && !o.contains_key("ref") {
                    let r = format!("[[meeting:{}]]", py_str(&o["id"]));
                    o.insert("ref".into(), r.into());
                }
            }
        }
    }
    result
}

fn int(q: &Map<String, Value>, k: &str) -> Option<i64> {
    q.get(k).and_then(Value::as_i64)
}

fn some(pairs: Vec<(&str, Option<Value>)>) -> Vec<(String, Value)> {
    pairs
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v)))
        .collect()
}

pub fn run(
    app: &App,
    tool: &str,
    q: &Map<String, Value>,
    body: &Map<String, Value>,
    key: &str,
    req: &Req,
) -> Result<Value, HttpError> {
    let base = app.gateway.as_str();
    let jitsi = app.env("VEXA_JITSI_HOSTS");
    match tool {
        "parse_meeting_link" => {
            crate::link::parse_meeting_url(text(body, "meeting_url").unwrap_or(""), jitsi)
        }
        "request_meeting_bot" => {
            let mut payload = dump(body, true);
            let meeting_url = payload
                .shift_remove("meeting_url")
                .and_then(|v| v.as_str().map(str::to_owned));
            if let Some(url) = meeting_url.filter(|u| !u.is_empty()) {
                let parsed = crate::link::parse_meeting_url(&url, jitsi)?;
                payload.insert("platform".into(), parsed["platform"].clone());
                payload.insert(
                    "native_meeting_id".into(),
                    parsed["native_meeting_id"].clone(),
                );
                payload
                    .entry("passcode")
                    .or_insert(parsed["passcode"].clone());
                if truthy(parsed.get("meeting_url")) {
                    payload.insert("meeting_url".into(), parsed["meeting_url"].clone());
                } else if parsed["platform"] == "zoom" {
                    payload.insert("meeting_url".into(), url.into());
                }
                if truthy(parsed.get("teams_base_host")) {
                    payload.insert("teams_base_host".into(), parsed["teams_base_host"].clone());
                }
            }
            let payload = Value::Object(payload);
            match make_request("POST", &format!("{base}/bots"), key, Some(&payload), &[]) {
                Err(e) if e.status == 409 => {
                    let meetings =
                        make_request("GET", &format!("{base}/meetings"), key, None, &[])?;
                    if let Some(rows) = meetings.as_array() {
                        for m in rows {
                            if m.is_object()
                                && m.get("platform") == payload.get("platform")
                                && m.get("native_meeting_id") == payload.get("native_meeting_id")
                            {
                                return Ok(json!({"status": "already_exists", "meeting": m}));
                            }
                        }
                    }
                    Ok(json!({"status": "already_exists", "detail": e.detail}))
                }
                other => other,
            }
        }
        "update_bot_config" => {
            let (p, m) = resolve(tool, q, true, false)?;
            make_request(
                "PUT",
                &format!("{base}/bots/{}/config", room(&p, &m)),
                key,
                Some(&Value::Object(dump(body, false))),
                &[],
            )
        }
        "stop_bot" => {
            let (p, m) = resolve(tool, q, true, false)?;
            make_request(
                "DELETE",
                &format!("{base}/bots/{}", room(&p, &m)),
                key,
                None,
                &[],
            )
        }
        "list_meetings" => {
            validate_platform(tool, text(q, "platform"), SEARCH_EVERY)?;
            let mut params = some(vec![
                ("limit", q.get("limit").filter(|v| !v.is_null()).cloned()),
                ("offset", q.get("offset").filter(|v| !v.is_null()).cloned()),
                (
                    "status",
                    q.get("status").filter(|v| truthy(Some(v))).cloned(),
                ),
                (
                    "platform",
                    q.get("platform").filter(|v| truthy(Some(v))).cloned(),
                ),
            ]);
            if let Some(f) = text(q, "metadata_filter").filter(|f| !f.is_empty()) {
                match crate::pyjson_decode::loads(f) {
                    Err(_) => return Err(HttpError::new(422, "list_meetings: 'metadata_filter' must be a JSON object string, e.g. {\"crm_deal\":\"acme-42\"}")),
                    Ok(v) if !v.is_object() => return Err(HttpError::new(422, "list_meetings: 'metadata_filter' must be a JSON OBJECT, not a bare value or array.")),
                    Ok(_) => params.push(("metadata".into(), f.into())),
                }
            }
            Ok(with_meeting_refs(make_request(
                "GET",
                &format!("{base}/meetings"),
                key,
                None,
                &params,
            )?))
        }
        "get_meeting_transcript" => transcript(app, q, key),
        "search_transcripts" => {
            validate_platform(tool, text(q, "platform"), SEARCH_EVERY)?;
            let params = some(vec![
                ("q", q.get("q").cloned()),
                ("limit", q.get("limit").cloned()),
                ("offset", q.get("offset").cloned()),
                (
                    "platform",
                    q.get("platform").filter(|v| truthy(Some(v))).cloned(),
                ),
                (
                    "native_meeting_id",
                    q.get("native_meeting_id")
                        .filter(|v| truthy(Some(v)))
                        .cloned(),
                ),
                (
                    "meeting_id",
                    q.get("meeting_db_id").filter(|v| !v.is_null()).cloned(),
                ),
            ]);
            make_request(
                "GET",
                &format!("{base}/transcripts/search"),
                key,
                None,
                &params,
            )
        }
        "annotate_meeting" => {
            let db = int(q, "meeting_db_id");
            let (mut plat, mut mid) = (Value::Null, Value::Null);
            let url = match db {
                Some(id) => format!("{base}/meetings/{}/annotate", path_segment(&id.to_string())),
                None => {
                    let (p, m) = resolve(tool, q, false, true)?;
                    let u = format!("{base}/meetings/{}/annotate", room(&p, &m));
                    (plat, mid) = (p.into(), m.into());
                    u
                }
            };
            let mut write = Map::new();
            for k in ["title", "metadata"] {
                if let Some(v) = body.get(k).filter(|v| !v.is_null()) {
                    write.insert(k.into(), v.clone());
                }
            }
            let row = make_request("POST", &url, key, Some(&Value::Object(write)), &[])?;
            let Some(r) = row.as_object() else {
                return Ok(row);
            };
            let empty = Map::new();
            let data = r.get("data").and_then(Value::as_object).unwrap_or(&empty);
            Ok(json!({
                "platform": r.get("platform").cloned().unwrap_or(plat),
                "native_meeting_id": r.get("native_meeting_id").cloned().unwrap_or(mid),
                "meeting_db_id": r.get("id").cloned().unwrap_or(db.map_or(Value::Null, Value::from)),
                "status": r.get("status").cloned().unwrap_or(Value::Null),
                "title": data.get("title").cloned().unwrap_or(Value::Null),
                "metadata": data.get("metadata").cloned().unwrap_or(json!({})),
            }))
        }
        "speak_in_meeting" => {
            let (p, m) = resolve(tool, q, false, false)?;
            make_request(
                "POST",
                &format!("{base}/bots/{}/speak", room(&p, &m)),
                key,
                Some(&Value::Object(dump(body, true))),
                &[],
            )
        }
        "get_meeting_chat" => {
            let (p, m) = resolve(tool, q, false, false)?;
            make_request(
                "GET",
                &format!("{base}/bots/{}/chat", room(&p, &m)),
                key,
                None,
                &[],
            )
        }
        "get_meeting" => {
            let id = int(q, "meeting_db_id").unwrap_or(0);
            make_request(
                "GET",
                &format!("{base}/meetings/{}", path_segment(&id.to_string())),
                key,
                None,
                &[],
            )
        }
        "delete_meeting" => {
            if q.get("asked_by_a_human") != Some(&Value::Bool(true)) {
                return Err(HttpError::new(422, DELETE_REFUSED));
            }
            let id = int(q, "meeting_db_id").unwrap_or(0);
            let r = make_request(
                "DELETE",
                &format!("{base}/meetings/{}", path_segment(&id.to_string())),
                key,
                None,
                &[],
            )?;
            if r.get("status").and_then(Value::as_str) == Some("deletion_scheduled") {
                return Ok(
                    json!({"deleted": false, "scheduled": true, "meeting_db_id": id, "detail": r.get("detail").cloned().unwrap_or(Value::Null)}),
                );
            }
            Ok(json!({"deleted": true, "meeting_db_id": id}))
        }
        "get_meeting_participants" => {
            let (p, m) = resolve(tool, q, false, false)?;
            make_request(
                "GET",
                &format!("{base}/meetings/{}/participants", room(&p, &m)),
                key,
                None,
                &[],
            )
        }
        "list_recordings" => {
            let params = some(vec![
                ("limit", q.get("limit").cloned()),
                ("offset", q.get("offset").cloned()),
                (
                    "meeting_id",
                    q.get("meeting_db_id").filter(|v| !v.is_null()).cloned(),
                ),
            ]);
            make_request("GET", &format!("{base}/recordings"), key, None, &params)
        }
        "browser_session_open" => {
            let result = make_request(
                "POST",
                &format!("{base}/bot-accounts/sessions"),
                key,
                Some(&Value::Object(dump(body, true))),
                &[],
            )?;
            let mut out = match result {
                Value::Object(o) => o,
                other => [("session".to_owned(), other)].into_iter().collect(),
            };
            out.insert("ui_action".into(), "open_browser_session".into());
            Ok(Value::Object(out))
        }
        "bot_accounts_list" => make_request("GET", &format!("{base}/bot-accounts"), key, None, &[]),
        "bot_account_verify" => {
            let id = text(body, "account_id").unwrap_or("");
            make_request(
                "POST",
                &format!("{base}/bot-accounts/{}/verify", path_segment(id)),
                key,
                None,
                &[],
            )
        }
        "report_issue" => report_issue(app, body, key, req),
        _ => Err(HttpError::internal()),
    }
}

fn transcript(app: &App, q: &Map<String, Value>, key: &str) -> Result<Value, HttpError> {
    let base = app.gateway.as_str();
    let (since, until, limit) = (
        int(q, "since_index"),
        int(q, "until_index"),
        int(q, "limit"),
    );
    if let (Some(s), Some(u)) = (since, until) {
        if u < s {
            return Err(HttpError::new(422, format!(
                "get_meeting_transcript: until_index ({u}) is before since_index ({s}); until_index is an exclusive upper bound."
            )));
        }
    }
    let url = match int(q, "meeting_db_id") {
        Some(id) => format!("{base}/transcripts/by-id/{}", path_segment(&id.to_string())),
        None => {
            let (p, m) = resolve("get_meeting_transcript", q, true, true)?;
            format!("{base}/transcripts/{}", room(&p, &m))
        }
    };
    let result = make_request("GET", &url, key, None, &[])?;
    let Some(obj) = result.as_object() else {
        return Ok(result);
    };
    let key_name = if obj.get("segments").is_some_and(Value::is_array) {
        "segments"
    } else if obj.get("transcripts").is_some_and(Value::is_array) {
        "transcripts"
    } else {
        return Ok(result);
    };
    let segments = obj[key_name].as_array().cloned().unwrap_or_default();
    let total = segments.len() as i64;
    let start = since.map_or(0, |s| s.min(total));
    let stop = until.map_or(total, |u| u.min(total));
    let page = limit.unwrap_or(TRANSCRIPT_PAGE);
    let end = stop.min(start + page);
    let has_more = end < stop;
    let slice: Vec<Value> = if end > start {
        segments[start as usize..end as usize].to_vec()
    } else {
        Vec::new()
    };
    let mut out = obj.clone();
    out.insert(key_name.into(), Value::Array(slice));
    out.insert("total_segments".into(), total.into());
    out.insert("next_index".into(), end.into());
    out.insert("has_more".into(), has_more.into());
    out.insert("complete".into(), (end >= total).into());
    if has_more {
        let bound = until.map_or(String::new(), |u| format!("&until_index={u}"));
        let what = if until.is_some() {
            "range you asked for"
        } else {
            "transcript"
        };
        out.insert("note".into(), format!(
            "Segments {start}-{} of {total}. This is NOT the whole {what}: call again with since_index={end}{bound} until has_more is false before you summarise it, and never say something was not discussed from a part of it.",
            end - 1
        ).into());
    }
    if since.is_some() {
        out.insert("since_index".into(), start.into());
    }
    if until.is_some() {
        out.insert("until_index".into(), stop.into());
    }
    if limit.is_some() || has_more {
        out.insert("limit".into(), page.into());
    }
    Ok(Value::Object(out))
}

fn report_issue(
    app: &App,
    d: &Map<String, Value>,
    key: &str,
    req: &Req,
) -> Result<Value, HttpError> {
    let base = app.gateway.as_str();
    if let Some(n) = req
        .header("content-length")
        .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    {
        if n.parse::<u128>()
            .is_ok_and(|n| n > tickets::MAX_BODY_BYTES as u128)
        {
            return Err(HttpError::new(
                413,
                format!(
                    "Ticket body too large (max {} bytes). Trim `logs`.",
                    tickets::MAX_BODY_BYTES
                ),
            ));
        }
    }
    let sink_url = app.env("VEXA_TICKET_SINK_URL").trim().to_owned();
    if sink_url.is_empty() {
        return Err(HttpError::new(503, "Ticketing is not configured on this Vexa deployment. Set VEXA_TICKET_SINK_URL on the MCP service to enable report_issue, or report the issue at https://github.com/Vexa-ai/vexa/issues."));
    }
    let meetings = match make_request("GET", &format!("{base}/meetings"), key, None, &[]) {
        Ok(m) => m,
        Err(e) if e.status == 401 || e.status == 403 => {
            return Err(HttpError::new(
                401,
                "Invalid credentials (send Authorization: Bearer <VEXA_API_KEY>).",
            )
            .with_header("www-authenticate", "Bearer"));
        }
        Err(_) => {
            return Err(HttpError::new(
                502,
                "Could not verify your credentials with the gateway; the ticket was not filed.",
            ))
        }
    };
    let s = |k: &str| text(d, k).map(str::to_owned);
    let (native, platform) = (s("native_meeting_id"), s("platform"));
    let mut entity = Value::Null;
    if let Some(id) = native.as_deref().filter(|i| !i.is_empty()) {
        let rows = match &meetings {
            Value::Array(_) => meetings.clone(),
            Value::Object(o) => o.get("meetings").cloned().unwrap_or(json!([])),
            Value::Null => json!([]),
            _ => return Err(HttpError::internal()),
        };
        for m in rows
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
        {
            if m.get("native_meeting_id").and_then(Value::as_str) != Some(id) {
                continue;
            }
            if let Some(p) = platform.as_deref().filter(|p| !p.is_empty()) {
                if m.get("platform").and_then(Value::as_str) != Some(p) {
                    continue;
                }
            }
            let mp = m.get("platform").cloned().unwrap_or(Value::Null);
            entity = json!({"type": "meeting", "id": id, "platform": mp,
                            "url": format!("/transcripts/{}/{}", path_segment(&py_str(&mp)), path_segment(id))});
            break;
        }
    }
    let report = tickets::Report {
        what_i_tried: s("what_i_tried").unwrap_or_default(),
        what_happened: s("what_happened").unwrap_or_default(),
        deployment: s("deployment").unwrap_or_default(),
        native_meeting_id: native.clone(),
        platform: platform.clone(),
        severity: d.get("severity").cloned().unwrap_or(Value::Null),
        version: s("version"),
        logs: s("logs"),
        logs_truncated: d.get("_logs_truncated") == Some(&Value::Bool(true)),
    };
    let fingerprint = tickets::fingerprint(&report.deployment, &report.what_happened);
    let opened = vexa_native_kit::ids::utc_isoformat(vexa_native_kit::ids::now());
    let salt = app.env("VEXA_TICKET_FINGERPRINT_SALT").to_owned();
    let caller = tickets::caller_fingerprint(key, Some(salt.as_str()));
    let opt = |v: &Option<String>| v.clone().map_or(Value::Null, Value::String);
    let payload: Map<String, Value> = [
        ("source", json!("vexa-mcp")),
        ("tool", json!("report_issue")),
        ("reported_at", json!(opened)),
        ("fingerprint", json!(fingerprint)),
        ("caller_fingerprint", json!(caller)),
        ("summary", json!(tickets::summary_of(&report.what_happened))),
        ("description", json!(tickets::description_of(&report))),
        ("what_i_tried", json!(report.what_i_tried)),
        ("what_happened", json!(report.what_happened)),
        ("deployment", json!(report.deployment)),
        ("version", opt(&report.version)),
        ("severity", report.severity.clone()),
        ("native_meeting_id", opt(&report.native_meeting_id)),
        ("platform", opt(&report.platform)),
        ("entity", entity.clone()),
        ("logs", opt(&report.logs)),
        ("logs_truncated", json!(report.logs_truncated)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    let format = app.env("VEXA_TICKET_SINK_FORMAT").to_owned();
    let labels = app.env.get("VEXA_TICKET_SINK_LABELS").cloned();
    let (mut headers, sink_payload) = tickets::sink_request(
        &payload,
        app.env("VEXA_TICKET_SINK_TOKEN").trim(),
        Some(&format),
        labels.as_deref(),
    );
    headers.extend(crate::obs::headers());
    let body = crate::wire::compact(&sink_payload);
    let r = match crate::net::request(
        "POST",
        &sink_url,
        &headers,
        Some(body.as_bytes()),
        std::time::Duration::from_secs(10),
    ) {
        Err(crate::net::NetError::Timeout) => {
            return Err(HttpError::new(504, "Ticket sink timed out"))
        }
        Err(crate::net::NetError::Failed(e)) => {
            return Err(HttpError::new(503, format!("Ticket sink unreachable: {e}")))
        }
        Ok(r) if !(200..300).contains(&r.status) => {
            return Err(HttpError::new(
                502,
                format!("Ticket sink rejected the report (status {}).", r.status),
            ));
        }
        Ok(r) => r,
    };
    let sink_body = if r.body.is_empty() {
        None
    } else {
        crate::pyjson_decode::loads_bytes(&r.body).ok()
    };
    let (mut ticket_id, mut ticket_url) = (Value::Null, Value::Null);
    if let Some(Value::Object(sb)) = &sink_body {
        let first = |a: &str, b: &str| {
            sb.get(a)
                .filter(|v| truthy(Some(v)))
                .or_else(|| sb.get(b))
                .cloned()
                .unwrap_or(Value::Null)
        };
        ticket_id = if tickets::is_github(Some(&format)) {
            first("number", "id")
        } else {
            first("id", "ticket_id")
        };
        ticket_url = first("html_url", "url");
    }
    let mut ack = Map::new();
    ack.insert(
        "id".into(),
        if ticket_id.is_null() {
            fingerprint.clone().into()
        } else {
            ticket_id
        },
    );
    ack.insert("status".into(), "new".into());
    ack.insert("severity".into(), report.severity);
    ack.insert("opened".into(), opened.clone().into());
    ack.insert("updated".into(), opened.into());
    ack.insert("opened_by".into(), caller.into());
    ack.insert("entity".into(), entity);
    ack.insert("fingerprint".into(), fingerprint.into());
    ack.insert(
        "message".into(),
        "Thanks — a human reads this. Quote the ticket id if you follow up.".into(),
    );
    if truthy(Some(&ticket_url)) {
        ack.insert("url".into(), ticket_url);
    }
    Ok(Value::Object(ack))
}
