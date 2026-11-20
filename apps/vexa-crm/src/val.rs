//! Python's view of JSON values: truthiness, equality, str(), and the few stdlib helpers the CRM
//! writes its answers with (json.dumps, urlencode, uuid4/uuid5, isoformat, casefold).

use serde_json::{Map, Value};
use vexa_native_kit::pyjson::{py_str, Dumps};

pub type Obj = Map<String, Value>;
pub static NULL: Value = Value::Null;

/// bool(value).
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// value.get(key) for a dict, None (null) otherwise.
pub fn g<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&NULL)
}

/// obj.get(key) on a map.
pub fn m<'a>(o: &'a Obj, key: &str) -> &'a Value {
    o.get(key).unwrap_or(&NULL)
}

/// The text of a string value, else "".
pub fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_owned()
}

/// str(value).
pub fn pystr(v: &Value) -> String {
    py_str(v)
}

/// str(value or ''): "" for every falsy value.
pub fn or_str(v: &Value) -> String {
    if truthy(v) {
        py_str(v)
    } else {
        String::new()
    }
}

/// value == other, as Python compares the objects json.loads makes (1 == 1.0 == True).
pub fn py_eq(a: &Value, b: &Value) -> bool {
    fn num(v: &Value) -> Option<f64> {
        match v {
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Number(n) => n.as_f64(),
            _ => None,
        }
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| py_eq(v, w)))
        }
        (Value::Number(x), Value::Number(y)) => match (x.as_i64(), y.as_i64()) {
            (Some(p), Some(q)) => p == q,
            _ => x.as_f64() == y.as_f64(),
        },
        _ => match (num(a), num(b)) {
            (Some(p), Some(q)) => p == q,
            _ => false,
        },
    }
}

/// json.dumps(value): ", " and ": ", ASCII only.
pub fn dumps(v: &Value) -> String {
    Dumps::DEFAULT.text(v)
}

/// json.dumps(value, separators=(",", ":")): ASCII only.
pub fn dumps_compact(v: &Value) -> String {
    Dumps::COMPACT.text(v)
}

/// The body FastAPI writes for a JSON answer (compact, not ASCII-escaped).
pub fn response_text(v: &Value) -> String {
    Dumps::COMPACT.ascii(false).text(v)
}

/// urllib.parse.quote_plus.
pub fn quote_plus(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// urllib.parse.urlencode of string pairs.
pub fn urlencode(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v))).collect::<Vec<_>>().join("&")
}

/// '/crm?' + urlencode({'record': id}).
pub fn record_href(id: &str) -> String {
    format!("/crm?{}", urlencode(&[("record", id)]))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn uuid_text(b: &[u8]) -> String {
    let h = hex(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// str(uuid4()).
pub fn uuid4() -> String {
    let mut b = vexa_native_kit::ids::random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid_text(&b)
}

/// str(uuid5(NAMESPACE_URL, name)).
pub fn uuid5_url(name: &str) -> String {
    const NAMESPACE_URL: [u8; 16] = [0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8];
    let mut data = NAMESPACE_URL.to_vec();
    data.extend_from_slice(name.as_bytes());
    let mut b = sha1(&data)[..16].to_vec();
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid_text(&b)
}

/// UUID(value): the canonical text of a UUID in any of the forms Python's UUID() reads.
pub fn parse_uuid(value: &str) -> Option<String> {
    let mut t = value.replace("urn:", "").replace("uuid:", "");
    t = t.trim_matches(|c| c == '{' || c == '}').replace('-', "");
    if t.len() != 32 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let t = t.to_ascii_lowercase();
    Some(format!("{}-{}-{}-{}-{}", &t[0..8], &t[8..12], &t[12..16], &t[16..20], &t[20..32]))
}

/// SHA-1 (FIPS 180-4), for uuid5.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// datetime.now(timezone.utc).isoformat().
pub fn now_iso() -> String {
    vexa_native_kit::ids::utc_isoformat(vexa_native_kit::ids::now())
}

/// str.casefold() (lower-case, with the full case folds of the Latin letters that have one).
pub fn casefold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            'ß' | 'ẞ' => out.push_str("ss"),
            'ſ' => out.push('s'),
            'ς' => out.push('σ'),
            'ﬀ' => out.push_str("ff"),
            'ﬁ' => out.push_str("fi"),
            'ﬂ' => out.push_str("fl"),
            'ﬃ' => out.push_str("ffi"),
            'ﬄ' => out.push_str("ffl"),
            'ﬅ' | 'ﬆ' => out.push_str("st"),
            'İ' => out.push_str("i\u{307}"),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// str.lower().
pub fn lower(text: &str) -> String {
    text.chars().flat_map(|c| if c == 'İ' { "i\u{307}".chars().collect::<Vec<_>>() } else { c.to_lowercase().collect() }).collect()
}

/// str.strip() (Python's whitespace).
pub fn strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// A JSON array of strings.
pub fn str_list<I: IntoIterator<Item = S>, S: Into<String>>(items: I) -> Value {
    Value::Array(items.into_iter().map(|x| Value::String(x.into())).collect())
}

/// The string items of a JSON value (a list), as Python iterates them with str().
pub fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().map(pystr).collect(),
        _ => Vec::new(),
    }
}

/// The keys of a dict value (empty for anything else).
pub fn keys(v: &Value) -> Vec<String> {
    v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_and_text_like_python() {
        // python3 -c "import uuid,json; print(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(['crm-create','one','owner','k'])))"
        assert_eq!(uuid5_url("[\"crm-create\", \"one\", \"owner\", \"k\"]"), "e1aa33b8-8d1c-5757-98b1-9923e46cd0bf");
        assert_eq!(uuid4().len(), 36);
        assert_eq!(quote_plus("a b/é"), "a+b%2F%C3%A9");
        assert!(py_eq(&serde_json::json!({"a": 1}), &serde_json::json!({"a": 1.0})));
        assert!(py_eq(&serde_json::json!([true]), &serde_json::json!([1])));
        assert!(!py_eq(&serde_json::json!("1"), &serde_json::json!(1)));
        assert_eq!(casefold("Straße"), "strasse");
        assert_eq!(parse_uuid("{12345678-1234-5678-1234-567812345678}").as_deref(), Some("12345678-1234-5678-1234-567812345678"));
    }
}
