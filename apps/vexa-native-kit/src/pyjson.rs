//! Python-compatible text of JSON values: what `json.dumps` writes (with its
//! separators, indent, ensure_ascii and sort_keys options), and what `repr` prints for
//! the object `json.loads` made.

use serde_json::{Number, Value};

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

pub fn py_number(n: &Number) -> String {
    if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(u) = n.as_u64() {
        u.to_string()
    } else {
        py_float(n.as_f64().unwrap_or(0.0))
    }
}

/// The options of one json.dumps call.
#[derive(Clone, Copy, Debug)]
pub struct Dumps {
    pub item_sep: &'static str,
    pub key_sep: &'static str,
    pub indent: Option<usize>,
    pub ensure_ascii: bool,
    pub sort_keys: bool,
}

impl Dumps {
    /// json.dumps(value): ", " and ": ", ASCII only.
    pub const DEFAULT: Dumps = Dumps { item_sep: ", ", key_sep: ": ", indent: None, ensure_ascii: true, sort_keys: false };
    /// json.dumps(value, separators=(",", ":")).
    pub const COMPACT: Dumps = Dumps { item_sep: ",", key_sep: ":", indent: None, ensure_ascii: true, sort_keys: false };

    pub fn ascii(mut self, on: bool) -> Self {
        self.ensure_ascii = on;
        self
    }
    pub fn sorted(mut self) -> Self {
        self.sort_keys = true;
        self
    }
    /// indent=n (Python then separates items with "," at line ends).
    pub fn indent(mut self, n: usize) -> Self {
        self.indent = Some(n);
        self.item_sep = ",";
        self
    }

    pub fn text(&self, value: &Value) -> String {
        let mut out = String::new();
        self.write(value, 0, &mut out);
        out
    }

    fn newline(&self, depth: usize, out: &mut String) {
        if let Some(n) = self.indent {
            out.push('\n');
            out.push_str(&" ".repeat(n * depth));
        }
    }

    fn write(&self, value: &Value, depth: usize, out: &mut String) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => out.push_str(&py_number(n)),
            Value::String(s) => quote_into(s, self.ensure_ascii, out),
            Value::Array(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, entry) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(self.item_sep);
                    }
                    self.newline(depth + 1, out);
                    self.write(entry, depth + 1, out);
                }
                self.newline(depth, out);
                out.push(']');
            }
            Value::Object(map) => {
                if map.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                let mut keys: Vec<&String> = map.keys().collect();
                if self.sort_keys {
                    keys.sort_by(|a, b| a.chars().cmp(b.chars()));
                }
                for (i, name) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push_str(self.item_sep);
                    }
                    self.newline(depth + 1, out);
                    quote_into(name, self.ensure_ascii, out);
                    out.push_str(self.key_sep);
                    self.write(&map[name.as_str()], depth + 1, out);
                }
                self.newline(depth, out);
                out.push('}');
            }
        }
    }
}

/// A JSON string literal as json.dumps writes it.
pub fn quote_into(text: &str, ensure_ascii: bool, out: &mut String) {
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
            c if (c as u32) < 0x20 || (ensure_ascii && (c as u32) > 0x7e) => {
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

/// json.dumps(value) with Python's defaults (", " and ": ", ASCII only).
pub fn py_dumps(value: &Value) -> String {
    Dumps::DEFAULT.text(value)
}

/// json.dumps(value, separators=(",", ":")): compact, ASCII only.
pub fn py_dumps_compact(value: &Value) -> String {
    Dumps::COMPACT.text(value)
}

/// json.dumps(value, sort_keys=True).
pub fn py_dumps_sorted(value: &Value) -> String {
    Dumps::DEFAULT.sorted().text(value)
}

/// str(value) for a JSON value, as Python prints the object json.loads made.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => py_repr(other),
    }
}

/// repr(value) for the object json.loads made: 'text', True, None, [1, 'a'], {'k': 1}.
pub fn py_repr(value: &Value) -> String {
    let mut out = String::new();
    repr_into(value, &mut out);
    out
}

fn repr_into(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("None"),
        Value::Bool(b) => out.push_str(if *b { "True" } else { "False" }),
        Value::Number(n) => out.push_str(&py_number_repr(n)),
        Value::String(s) => out.push_str(&py_str_repr(s)),
        Value::Array(items) => {
            out.push('[');
            for (i, entry) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                repr_into(entry, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&py_str_repr(k));
                out.push_str(": ");
                repr_into(v, out);
            }
            out.push('}');
        }
    }
}

fn py_number_repr(n: &Number) -> String {
    match n.as_f64() {
        Some(f) if n.as_i64().is_none() && n.as_u64().is_none() => {
            if f.is_nan() {
                "nan".into()
            } else if f.is_infinite() {
                if f > 0.0 { "inf".into() } else { "-inf".into() }
            } else {
                py_float(f)
            }
        }
        _ => py_number(n),
    }
}

/// Is this character printable by Python's str.isprintable() (approximately:
/// not a control, separator other than space, or unassigned format code)?
fn printable(c: char) -> bool {
    let u = c as u32;
    if c == ' ' {
        return true;
    }
    !(u < 0x20
        || (0x7f..0xa0).contains(&u)
        || u == 0xad
        || (0x2000..=0x200f).contains(&u)
        || (0x2028..=0x202f).contains(&u)
        || (0x205f..=0x206f).contains(&u)
        || u == 0x3000
        || u == 0xfeff
        || (0xd800..0xe000).contains(&u)
        || (0xfff9..=0xfffb).contains(&u)
        || u == 0xa0
        || u == 0x1680)
}

/// repr(text).
pub fn py_str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if !printable(c) => {
                let u = c as u32;
                if u < 0x100 {
                    out.push_str(&format!("\\x{u:02x}"));
                } else if u < 0x10000 {
                    out.push_str(&format!("\\u{u:04x}"));
                } else {
                    out.push_str(&format!("\\U{u:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn dumps_like_python() {
        let x = v(r#"{"b":[1,2.5,"é😀"],"a":{"z":null,"y":true},"c":1e16,"d":1.0}"#);
        assert_eq!(py_dumps_sorted(&x), r#"{"a": {"y": true, "z": null}, "b": [1, 2.5, "\u00e9\ud83d\ude00"], "c": 1e+16, "d": 1.0}"#);
        assert_eq!(Dumps::DEFAULT.indent(2).ascii(false).text(&v(r#"{"a":[1,{}],"b":[],"c":"é"}"#)),
                   "{\n  \"a\": [\n    1,\n    {}\n  ],\n  \"b\": [],\n  \"c\": \"é\"\n}");
        assert_eq!(Dumps::COMPACT.ascii(false).text(&v(r#"{"a":"é"}"#)), "{\"a\":\"é\"}");
        assert_eq!(py_float(1e-5), "1e-05");
    }

    #[test]
    fn repr_like_python() {
        assert_eq!(py_repr(&v(r#"{"a":[1,"it's",null,true,1.5]}"#)), r#"{'a': [1, "it's", None, True, 1.5]}"#);
        assert_eq!(py_str_repr("a'b\"c\n"), "'a\\'b\"c\\n'");
        assert_eq!(py_str_repr("\u{7}é"), "'\\x07é'");
    }
}
