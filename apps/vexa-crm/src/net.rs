//! The CRM's outbound calls (identity, agent-api, flows), as httpx sends them: a JSON body is
//! compact UTF-8 with `content-type: application/json`.

use std::time::Duration;

use serde_json::Value;
use vexa_native_kit::client::{request, Body, NetError, Timeouts};
use vexa_native_kit::pyjson::Dumps;

pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Reply {
    /// response.json(): the parsed body, or Err for a body that is not JSON.
    pub fn json(&self) -> Result<Value, ()> {
        vexa_native_kit::pyjson_decode::loads_bytes(&self.body).map_err(|_| ())
    }
}

fn headers(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut h: Vec<(String, String)> = vec![
        ("accept-encoding".into(), "identity".into()),
        ("user-agent".into(), "python-httpx/0.28.1".into()),
    ];
    h.extend(extra.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.to_string())));
    h
}

pub fn post_json(url: &str, extra: &[(&str, &str)], body: &Value, timeout: f64) -> Result<Reply, NetError> {
    let text = Dumps::COMPACT.ascii(false).text(body);
    let mut h = headers(extra);
    h.push(("content-type".into(), "application/json".into()));
    let (status, _, body) = request("POST", url, &h, Body::Bytes(text.as_bytes()), Timeouts::all(Duration::from_secs_f64(timeout)))?;
    Ok(Reply { status, body })
}

pub fn get(url: &str, extra: &[(&str, &str)], timeout: f64) -> Result<Reply, NetError> {
    let (status, _, body) = request("GET", url, &headers(extra), Body::None, Timeouts::all(Duration::from_secs_f64(timeout)))?;
    Ok(Reply { status, body })
}

/// urllib.parse.quote(value, safe="").
pub fn quote(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
