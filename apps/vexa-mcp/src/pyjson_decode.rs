//! `json.loads` as CPython 3.12's C scanner reads a document: the same values and, for a
//! document it refuses, the same message at the same character position.

use serde_json::{Map, Number, Value};

#[derive(Debug)]
pub struct DecodeError {
    pub msg: &'static str,
    /// The position in characters (code points), as Python counts it.
    pub pos: usize,
    doc: String,
}

impl DecodeError {
    /// str(JSONDecodeError): "Expecting value: line 1 column 1 (char 0)".
    pub fn text(&self) -> String {
        let before: Vec<char> = self.doc.chars().take(self.pos).collect();
        let line = before.iter().filter(|c| **c == '\n').count() + 1;
        let col = match before.iter().rposition(|c| *c == '\n') {
            Some(i) => self.pos - i,
            None => self.pos + 1,
        };
        format!("{}: line {line} column {col} (char {})", self.msg, self.pos)
    }
}

struct P<'a> {
    s: &'a [char],
}

type R<T> = Result<T, (&'static str, usize)>;

impl P<'_> {
    fn ws(&self, mut i: usize) -> usize {
        while i < self.s.len() && matches!(self.s[i], ' ' | '\t' | '\n' | '\r') {
            i += 1;
        }
        i
    }

    fn lit(&self, i: usize, word: &str) -> bool {
        let w: Vec<char> = word.chars().collect();
        self.s.len() >= i + w.len() && self.s[i..i + w.len()] == w[..]
    }

    fn value(&self, i: usize) -> R<(Value, usize)> {
        let Some(&c) = self.s.get(i) else {
            return Err(("Expecting value", i));
        };
        match c {
            '"' => {
                let (s, end) = self.string(i + 1)?;
                Ok((Value::String(s), end))
            }
            '{' => self.object(i + 1),
            '[' => self.array(i + 1),
            'n' if self.lit(i, "null") => Ok((Value::Null, i + 4)),
            't' if self.lit(i, "true") => Ok((Value::Bool(true), i + 4)),
            'f' if self.lit(i, "false") => Ok((Value::Bool(false), i + 5)),
            // Python reads these as floats; JSON has no spelling for them, so they arrive as null.
            'N' if self.lit(i, "NaN") => Ok((Value::Null, i + 3)),
            'I' if self.lit(i, "Infinity") => Ok((Value::Null, i + 8)),
            '-' if self.lit(i, "-Infinity") => Ok((Value::Null, i + 9)),
            _ => self.number(i).ok_or(("Expecting value", i)),
        }
    }

    fn number(&self, start: usize) -> Option<(Value, usize)> {
        let s = self.s;
        let mut i = start;
        if s.get(i) == Some(&'-') {
            i += 1;
        }
        match s.get(i) {
            Some('0') => i += 1,
            Some(c) if c.is_ascii_digit() => {
                while s.get(i).is_some_and(|c| c.is_ascii_digit()) {
                    i += 1;
                }
            }
            _ => return None,
        }
        let mut float = false;
        if s.get(i) == Some(&'.') && s.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
            float = true;
            i += 2;
            while s.get(i).is_some_and(|c| c.is_ascii_digit()) {
                i += 1;
            }
        }
        if matches!(s.get(i), Some('e' | 'E')) {
            let mut j = i + 1;
            if matches!(s.get(j), Some('+' | '-')) {
                j += 1;
            }
            if s.get(j).is_some_and(|c| c.is_ascii_digit()) {
                while s.get(j).is_some_and(|c| c.is_ascii_digit()) {
                    j += 1;
                }
                float = true;
                i = j;
            }
        }
        let text: String = s[start..i].iter().collect();
        let float_value = |t: &str| {
            t.parse::<f64>()
                .ok()
                .and_then(Number::from_f64)
                .map_or(Value::Null, Value::Number)
        };
        let v = if float {
            float_value(&text)
        } else if let Ok(v) = text.parse::<i64>() {
            Value::Number(Number::from(v))
        } else if let Ok(v) = text.parse::<u64>() {
            Value::Number(Number::from(v))
        } else {
            float_value(&text)
        };
        Some((v, i))
    }

    /// From just after the opening quote; returns the end after the closing one.
    fn string(&self, mut i: usize) -> R<(String, usize)> {
        let begin = i - 1;
        let s = self.s;
        let mut out = String::new();
        loop {
            let Some(&c) = s.get(i) else {
                return Err(("Unterminated string starting at", begin));
            };
            match c {
                '"' => return Ok((out, i + 1)),
                '\\' => {
                    let Some(&e) = s.get(i + 1) else {
                        return Err(("Unterminated string starting at", begin));
                    };
                    let simple = match e {
                        '"' => Some('"'),
                        '\\' => Some('\\'),
                        '/' => Some('/'),
                        'b' => Some('\u{8}'),
                        'f' => Some('\u{c}'),
                        'n' => Some('\n'),
                        'r' => Some('\r'),
                        't' => Some('\t'),
                        'u' => None,
                        _ => return Err(("Invalid \\escape", i)),
                    };
                    if let Some(ch) = simple {
                        out.push(ch);
                        i += 2;
                        continue;
                    }
                    let hex = |at: usize| -> Option<u32> {
                        if at + 4 > s.len() {
                            return None;
                        }
                        let t: String = s[at..at + 4].iter().collect();
                        if t.chars().all(|c| c.is_ascii_hexdigit()) {
                            u32::from_str_radix(&t, 16).ok()
                        } else {
                            None
                        }
                    };
                    let Some(mut code) = hex(i + 2) else {
                        return Err(("Invalid \\uXXXX escape", i + 1));
                    };
                    i += 6;
                    if (0xd800..0xdc00).contains(&code)
                        && s.get(i) == Some(&'\\')
                        && s.get(i + 1) == Some(&'u')
                    {
                        if let Some(low) = hex(i + 2) {
                            if (0xdc00..0xe000).contains(&low) {
                                code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                                i += 6;
                            }
                        }
                    }
                    out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                }
                c if (c as u32) < 0x20 => return Err(("Invalid control character at", i)),
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
    }

    fn object(&self, i: usize) -> R<(Value, usize)> {
        let mut map = Map::new();
        let mut i = self.ws(i);
        if self.s.get(i) == Some(&'}') {
            return Ok((Value::Object(map), i + 1));
        }
        loop {
            if self.s.get(i) != Some(&'"') {
                return Err(("Expecting property name enclosed in double quotes", i));
            }
            let (key, end) = self.string(i + 1)?;
            i = self.ws(end);
            if self.s.get(i) != Some(&':') {
                return Err(("Expecting ':' delimiter", i));
            }
            i = self.ws(i + 1);
            let (value, end) = self.value(i)?;
            map.insert(key, value);
            i = self.ws(end);
            match self.s.get(i) {
                Some('}') => return Ok((Value::Object(map), i + 1)),
                Some(',') => i = self.ws(i + 1),
                _ => return Err(("Expecting ',' delimiter", i)),
            }
        }
    }

    fn array(&self, i: usize) -> R<(Value, usize)> {
        let mut items = Vec::new();
        let mut i = self.ws(i);
        if self.s.get(i) == Some(&']') {
            return Ok((Value::Array(items), i + 1));
        }
        loop {
            let (value, end) = self.value(i)?;
            items.push(value);
            i = self.ws(end);
            match self.s.get(i) {
                Some(']') => return Ok((Value::Array(items), i + 1)),
                Some(',') => i = self.ws(i + 1),
                _ => return Err(("Expecting ',' delimiter", i)),
            }
        }
    }
}

/// json.loads(text).
pub fn loads(text: &str) -> Result<Value, DecodeError> {
    let chars: Vec<char> = text.chars().collect();
    let p = P { s: &chars };
    let fail = |(msg, pos): (&'static str, usize)| DecodeError {
        msg,
        pos,
        doc: text.to_owned(),
    };
    let (value, end) = p.value(p.ws(0)).map_err(fail)?;
    let end = p.ws(end);
    if end != chars.len() {
        return Err(fail(("Extra data", end)));
    }
    Ok(value)
}

/// json.loads(bytes): the body as UTF-8 (a UTF-8 BOM is skipped, as Python's detection does).
pub fn loads_bytes(body: &[u8]) -> Result<Value, DecodeError> {
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    loads(&String::from_utf8_lossy(body))
}

#[cfg(test)]
mod tests {
    use super::loads;

    fn err(t: &str) -> String {
        loads(t).err().map(|e| e.text()).unwrap_or_default()
    }

    #[test]
    fn errors_like_cpython() {
        assert_eq!(
            err("{not json"),
            "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"
        );
        assert_eq!(err(""), "Expecting value: line 1 column 1 (char 0)");
        assert_eq!(err("notjson"), "Expecting value: line 1 column 1 (char 0)");
        assert_eq!(
            err(r#"{"jsonrpc": "2.0", "id": 1, "method": "ping"} x"#),
            "Extra data: line 1 column 47 (char 46)"
        );
        assert_eq!(err("[1,]"), "Expecting value: line 1 column 4 (char 3)");
        assert_eq!(
            err("{\"a\" 1}"),
            "Expecting ':' delimiter: line 1 column 6 (char 5)"
        );
        assert_eq!(
            err("[1\n 2]"),
            "Expecting ',' delimiter: line 2 column 2 (char 4)"
        );
        assert_eq!(
            err("\"abc"),
            "Unterminated string starting at: line 1 column 1 (char 0)"
        );
        assert_eq!(
            loads(r#" {"a": [1, 2.5, -0, "é"], "a": true} "#).unwrap(),
            serde_json::json!({"a": true})
        );
        assert!(loads("1e400").unwrap().is_null());
    }
}
