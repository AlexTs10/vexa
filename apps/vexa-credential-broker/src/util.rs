//! Small shared helpers: time, random ids, base64, Python-compatible JSON text,
//! URL splitting and quoting the way Python's urllib does it.

use serde_json::Value;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};


/// Seconds since the epoch, as Python's time.time().
pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Random bytes from the operating system.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut out))
        .expect("the operating system's random source is readable");
    out
}

/// uuid4().hex
pub fn uuid_hex() -> String {
    let mut b = random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    hex(&b)
}

/// secrets.token_urlsafe(n)
pub fn token_urlsafe(n: usize) -> String {
    b64url_nopad(&random_bytes(n))
}

pub fn hex(bytes: &[u8]) -> String {
    vexa_native_kit::sha256::hex(bytes)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&vexa_native_kit::sha256::digest(data))
}

pub fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    hex(&vexa_native_kit::sha256::hmac(key, data))
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    vexa_native_kit::sha256::constant_time_eq(a, b)
}

// ── base64 ─────────────────────────────────────────────────────────────────

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(STD[(n >> 18) as usize & 63] as char);
        out.push(STD[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { STD[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { STD[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn b64url(data: &[u8]) -> String {
    b64(data).replace('+', "-").replace('/', "_")
}

pub fn b64url_nopad(data: &[u8]) -> String {
    b64url(data).trim_end_matches('=').to_owned()
}

fn sextet(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard base64 whose characters are all of the alphabet, with
/// correct padding (Python's b64decode(validate=True)).
pub fn b64decode_strict(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let pad = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - pad];
    if body.iter().any(|&c| sextet(c).is_none()) {
        return None;
    }
    decode_sextets(body)
}

fn decode_sextets(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for chunk in body.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= sextet(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Python's base64.urlsafe_b64decode(text + padding): characters outside the
/// alphabet are discarded; a dangling single character is an error.
pub fn b64url_decode_lenient(text: &str) -> Option<Vec<u8>> {
    let mapped: Vec<u8> = text
        .bytes()
        .map(|c| match c {
            b'-' => b'+',
            b'_' => b'/',
            c => c,
        })
        .collect();
    let end = mapped.iter().position(|&c| c == b'=').unwrap_or(mapped.len());
    let body: Vec<u8> = mapped[..end].iter().copied().filter(|&c| sextet(c).is_some()).collect();
    decode_sextets(&body)
}

/// Strict, canonical base64url without padding (gateway-identity.v1 _unb64u).
pub fn b64url_decode_canonical(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return None;
    }
    let raw = b64url_decode_lenient(text)?;
    (b64url_nopad(&raw) == text).then_some(raw)
}

// ── Python-compatible JSON text ────────────────────────────────────────────

/// Python's float repr.
pub fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let text = format!("{f:?}");
    match text.split_once('e') {
        Some((mantissa, exp)) => {
            let (sign, digits) = match exp.strip_prefix('-') {
                Some(d) => ('-', d),
                None => ('+', exp),
            };
            let mantissa = mantissa.strip_suffix(".0").unwrap_or(mantissa);
            format!("{mantissa}e{sign}{digits:0>2}")
        }
        None => text,
    }
}

fn py_quote(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn py_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(u) = n.as_u64() {
        u.to_string()
    } else {
        py_float(n.as_f64().unwrap_or(0.0))
    }
}

fn py_write(value: &Value, sort: bool, out: &mut String) {
    py_write_sep(value, sort, ", ", ": ", out)
}

fn py_write_sep(value: &Value, sort: bool, sep_item: &str, sep_key: &str, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&py_number(n)),
        Value::String(s) => py_quote(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, entry) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(sep_item);
                }
                py_write_sep(entry, sort, sep_item, sep_key, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            if sort {
                keys.sort_by(|a, b| a.chars().cmp(b.chars()));
            }
            for (i, name) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(sep_item);
                }
                py_quote(name, out);
                out.push_str(sep_key);
                py_write_sep(&map[name.as_str()], sort, sep_item, sep_key, out);
            }
            out.push('}');
        }
    }
}

/// json.dumps(value) with Python's defaults (", " and ": ", ASCII only).
pub fn py_dumps(value: &Value) -> String {
    let mut out = String::new();
    py_write(value, false, &mut out);
    out
}

/// json.dumps(value, separators=(",", ":")): compact, ASCII only.
pub fn py_dumps_compact(value: &Value) -> String {
    let mut out = String::new();
    py_write_sep(value, false, ",", ":", &mut out);
    out
}

/// json.dumps(value, sort_keys=True).
pub fn py_dumps_sorted(value: &Value) -> String {
    let mut out = String::new();
    py_write(value, true, &mut out);
    out
}

/// str(value) for a JSON value, as Python prints the object json.loads made.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::Number(n) => py_number(n),
        Value::String(s) => s.clone(),
        other => py_dumps(other),
    }
}

/// Python truthiness of a JSON value.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// The text at key, or "" (Python's x.get(k) or "" for text).
pub fn text<'a>(obj: &'a Value, key: &str) -> &'a str {
    obj.get(key).and_then(Value::as_str).unwrap_or("")
}


// ── URLs ───────────────────────────────────────────────────────────────────

/// Python's urllib.parse.urlsplit, the parts this service reads.
#[derive(Debug, Default, Clone)]
pub struct Split {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

impl Split {
    fn hostinfo(&self) -> &str {
        self.netloc.rsplit_once('@').map_or(self.netloc.as_str(), |(_, h)| h)
    }
    fn host_and_port(&self) -> (String, String) {
        let info = self.hostinfo();
        if let Some((_, bracketed)) = info.split_once('[') {
            let (host, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            let port = rest.split_once(':').map_or("", |(_, p)| p);
            (host.to_owned(), port.to_owned())
        } else {
            let (host, port) = info.split_once(':').unwrap_or((info, ""));
            (host.to_owned(), port.to_owned())
        }
    }
    /// The lower-cased host name, or None.
    pub fn hostname(&self) -> Option<String> {
        let (host, _) = self.host_and_port();
        (!host.is_empty()).then(|| host.to_lowercase())
    }
    /// Ok(None) without a port; Err for a port Python refuses.
    pub fn port(&self) -> Result<Option<u16>, ()> {
        let (_, port) = self.host_and_port();
        if port.is_empty() {
            return Ok(None);
        }
        if !port.bytes().all(|c| c.is_ascii_digit()) {
            return Err(());
        }
        port.parse::<u32>().ok().filter(|p| *p <= 65535).map(|p| Some(p as u16)).ok_or(())
    }
    pub fn username(&self) -> Option<String> {
        let (info, _) = self.netloc.rsplit_once('@')?;
        Some(info.split_once(':').map_or(info, |(u, _)| u).to_owned())
    }
    pub fn password(&self) -> Option<String> {
        let (info, _) = self.netloc.rsplit_once('@')?;
        info.split_once(':').map(|(_, p)| p.to_owned())
    }
}

/// urlsplit(url); Err where Python raises ValueError.
pub fn urlsplit(url: &str) -> Result<Split, ()> {
    let trimmed = url.trim_start_matches(|c: char| (c as u32) <= 0x20);
    let cleaned: String = trimmed.chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let mut rest = cleaned.as_str();
    let mut out = Split::default();
    if let Some(i) = rest.find(':') {
        let candidate = &rest[..i];
        let first_alpha = candidate.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        if first_alpha && candidate.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            out.scheme = candidate.to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
    }
    let mut rest = rest.to_owned();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        out.netloc = after[..end].to_owned();
        rest = after[end..].to_owned();
        if out.netloc.contains('[') != out.netloc.contains(']') {
            return Err(());
        }
    }
    if let Some((before, fragment)) = rest.split_once('#') {
        out.fragment = fragment.to_owned();
        rest = before.to_owned();
    }
    if let Some((before, query)) = rest.split_once('?') {
        out.query = query.to_owned();
        rest = before.to_owned();
    }
    out.path = rest;
    Ok(out)
}

fn unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-' | b'~')
}

/// urllib.parse.quote(text, safe=safe).
pub fn quote(text: &str, safe: &str) -> String {
    let mut out = String::new();
    for &c in text.as_bytes() {
        if unreserved(c) || safe.as_bytes().contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

/// urllib.parse.quote_plus(text).
pub fn quote_plus(text: &str) -> String {
    quote(text, " ").replace(' ', "+")
}

/// urllib.parse.urlencode(pairs).
pub fn urlencode(pairs: &[(&str, String)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v))).collect::<Vec<_>>().join("&")
}

/// Percent-decode a request path (no '+' rule), as the ASGI server gives it.
pub fn unquote_path(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 && i + 3 <= bytes.len() {
            if let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// " ".join(text.split()).casefold(), for the label comparisons.
pub fn label_key(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// The UTC calendar date and time of a Unix second.
pub fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, (rem / 3600) as u32, (rem % 3600 / 60) as u32, (rem % 60) as u32)
}

/// Days since the epoch of a civil date.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// datetime.now(timezone.utc).isoformat() with the "+00:00" written as "Z".
pub fn utc_stamp(t: f64) -> String {
    let secs = t.floor() as i64;
    let micros = ((t - t.floor()) * 1e6).floor().min(999_999.0) as u32;
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{micros:06}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_json_text() {
        let v: Value = serde_json::from_str(r#"{"b":[1,2.5,"é😀"],"a":{"z":null,"y":true},"c":1e16,"d":1.0}"#).unwrap();
        assert_eq!(py_dumps_sorted(&v), r#"{"a": {"y": true, "z": null}, "b": [1, 2.5, "\u00e9\ud83d\ude00"], "c": 1e+16, "d": 1.0}"#);
        assert_eq!(py_float(1e-5), "1e-05");
        assert_eq!(py_float(1763550000.25), "1763550000.25");
    }

    #[test]
    fn base64_forms() {
        assert_eq!(b64(b"ab"), "YWI=");
        assert_eq!(b64url_nopad(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64decode_strict("YWI=").unwrap(), b"ab");
        assert!(b64decode_strict("YWI").is_none());
        assert!(b64decode_strict("Y$I=").is_none());
        assert_eq!(b64url_decode_lenient("-_8").unwrap(), vec![0xfb, 0xff]);
        assert!(b64url_decode_canonical("-_9").is_none());
    }

    #[test]
    fn splits_like_urllib() {
        let s = urlsplit("https://u:p@Host.Example:8443/a/b?x=1#f").unwrap();
        assert_eq!(s.scheme, "https");
        assert_eq!(s.hostname().as_deref(), Some("host.example"));
        assert_eq!(s.port(), Ok(Some(8443)));
        assert_eq!(s.username().as_deref(), Some("u"));
        assert_eq!(s.password().as_deref(), Some("p"));
        assert_eq!((s.path.as_str(), s.query.as_str(), s.fragment.as_str()), ("/a/b", "x=1", "f"));
        assert!(urlsplit("http://[::1").is_err());
        assert_eq!(urlsplit("http://[::1]:80/").unwrap().hostname().as_deref(), Some("::1"));
        assert!(urlsplit("https://h:x/").unwrap().port().is_err());
        assert_eq!(urlencode(&[("q", "a b&c".into()), ("s", "x/y".into())]), "q=a+b%26c&s=x%2Fy");
        assert_eq!(quote("a b@c", "@"), "a%20b@c");
        assert_eq!(utc_stamp(0.5), "1970-01-01T00:00:00.500000Z");
        assert_eq!(civil(days_from_civil(2026, 11, 19) * 86400), (2026, 11, 19, 0, 0, 0));
        assert_eq!(unquote_path("/a%20b%zz%"), "/a b%zz%");
    }
}
