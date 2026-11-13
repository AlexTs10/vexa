//! A small JSON value with a parser and a writer (no external crates).

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }
}

pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn write(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) if n.is_finite() => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                format!("{n}")
            }
        }
        Value::Number(_) => "null".to_owned(),
        Value::String(s) => quote(s),
        Value::Array(items) => format!("[{}]", items.iter().map(write).collect::<Vec<_>>().join(",")),
        Value::Object(items) => format!(
            "{{{}}}",
            items
                .iter()
                .map(|(k, v)| format!("{}:{}", quote(k), write(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

pub fn object(items: Vec<(&str, Value)>) -> Value {
    Value::Object(items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut parser = Parser { bytes: text.as_bytes(), pos: 0 };
    let value = parser.value()?;
    parser.ws();
    if parser.pos != parser.bytes.len() {
        return Err(format!("trailing data at {}", parser.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn expect(&mut self, literal: &str) -> Result<(), String> {
        if self.bytes[self.pos..].starts_with(literal.as_bytes()) {
            self.pos += literal.len();
            Ok(())
        } else {
            Err(format!("expected {literal} at {}", self.pos))
        }
    }
    fn value(&mut self) -> Result<Value, String> {
        self.ws();
        match self.peek().ok_or("unexpected end")? {
            b'n' => self.expect("null").map(|_| Value::Null),
            b't' => self.expect("true").map(|_| Value::Bool(true)),
            b'f' => self.expect("false").map(|_| Value::Bool(false)),
            b'"' => self.string().map(Value::String),
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Value::Array(items));
                        }
                        _ => return Err(format!("bad array at {}", self.pos)),
                    }
                }
            }
            b'{' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Value::Object(items));
                }
                loop {
                    self.ws();
                    let key = self.string()?;
                    self.ws();
                    self.expect(":")?;
                    let value = self.value()?;
                    items.push((key, value));
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Value::Object(items));
                        }
                        _ => return Err(format!("bad object at {}", self.pos)),
                    }
                }
            }
            _ => self.number(),
        }
    }
    fn number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|e| e.to_string())?;
        text.parse::<f64>().map(Value::Number).map_err(|_| format!("bad number {text:?}"))
    }
    fn string(&mut self) -> Result<String, String> {
        self.expect("\"")?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = self.peek().ok_or("unterminated string")?;
            self.pos += 1;
            match byte {
                b'"' => return String::from_utf8(out).map_err(|e| e.to_string()),
                b'\\' => {
                    let esc = self.peek().ok_or("bad escape")?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut code = self.hex4()?;
                            if (0xD800..0xDC00).contains(&code) {
                                self.expect("\\u")?;
                                let low = self.hex4()?;
                                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                            }
                            let c = char::from_u32(code).unwrap_or('\u{FFFD}');
                            let mut buf = [0; 4];
                            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err("bad escape".to_owned()),
                    }
                }
                other => out.push(other),
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let text = std::str::from_utf8(self.bytes.get(self.pos..self.pos + 4).ok_or("short \\u")?).map_err(|e| e.to_string())?;
        self.pos += 4;
        u32::from_str_radix(text, 16).map_err(|e| e.to_string())
    }
}

/// Collect a flat string map from an object (used in tests).
#[allow(dead_code)]
pub fn strings(value: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Value::Object(items) = value {
        for (k, v) in items {
            if let Some(s) = v.as_str() {
                out.insert(k.clone(), s.to_owned());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_writes_whisper_like_json() {
        let text = r#"{"text":" a\nb é","segments":[{"start":0.0,"end":3.11,"avg_logprob":-0.07,"tokens":[1,2]}],"ok":true,"none":null}"#;
        let value = parse(text).unwrap();
        assert_eq!(value.get("text").unwrap().as_str().unwrap(), " a\nb é");
        let seg = &value.get("segments").unwrap().as_array().unwrap()[0];
        assert_eq!(seg.get("end").unwrap().as_f64().unwrap(), 3.11);
        let out = write(&value);
        assert_eq!(parse(&out).unwrap(), value);
    }
}
