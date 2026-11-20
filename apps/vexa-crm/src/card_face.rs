//! card_face: the card-face profile of blocks.v1 — sanitise a stored face, resolve it per viewer.
//!
//! A card face is composed from a small vocabulary. **Structural** blocks carry no value of their
//! own (`{"type": "stepper"}` and its siblings draw from the card's own record as the viewer reads
//! it); **data** blocks NAME a field (`{"type": "metric", "field": "Amount", "label": "Amount"}`) and
//! the value is read from the record per viewer. A block whose field the viewer may not read
//! resolves to `{"type": "locked", "label": …}`, so a face never shows what the record would not.
//! There is no block for literal text. Unknown blocks and unknown keys are dropped; sizes are capped.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::val::Obj;

pub const LIMIT_BLOCKS: usize = 8;
pub const LIMIT_LABEL: usize = 40;
pub const LIMIT_TEXT: usize = 160;
pub const LIMIT_ROWS: usize = 4;
pub const LIMIT_CHECKLIST: usize = 10;
pub const LIMIT_METRIC: usize = 24;
pub const LIMIT_ROW: usize = 80;
pub const STRUCTURAL: [&str; 8] = ["stepper", "people", "movement", "waiting", "next", "subcards", "ref", "status"];
pub const DATA: [&str; 6] = ["metric", "text", "progress", "due", "checklist", "list"];
pub const DEFAULT_FACE: [&str; 6] = ["stepper", "next", "waiting", "movement", "subcards", "people"];

fn field_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_]{0,63}$").unwrap())
}

fn control_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\x00-\x1f\x7f]+").unwrap())
}

fn date_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}").unwrap())
}

/// One line of plain text from a string, control characters folded to a space, at most `limit` characters.
pub fn plain_str(text: &str, limit: usize) -> String {
    let folded = control_re().replace_all(text, " ");
    crate::val::strip(&folded).chars().take(limit).collect()
}

/// One line of plain text (str(value), None as ""), at most `limit` characters.
pub fn plain(value: &Value, limit: usize) -> String {
    if value.is_null() {
        return String::new();
    }
    plain_str(&crate::val::pystr(value), limit)
}

/// The stored face: known blocks only, their own keys only, at most LIMIT_BLOCKS.
pub fn sanitize(face: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let Value::Array(items) = face else { return out };
    for raw in items {
        if out.len() >= LIMIT_BLOCKS {
            break;
        }
        let Value::Object(o) = raw else { continue };
        let kind = o.get("type").and_then(Value::as_str).unwrap_or("");
        let is_str = o.get("type").is_some_and(Value::is_string);
        if is_str && STRUCTURAL.contains(&kind) {
            out.push(json!({"type": kind}));
        } else if is_str && DATA.contains(&kind) {
            let Some(field) = o.get("field").and_then(Value::as_str) else { continue };
            if !field_re().is_match(field) {
                continue;
            }
            let mut block = Map::new();
            block.insert("type".into(), kind.into());
            block.insert("field".into(), field.into());
            let label = plain(o.get("label").unwrap_or(&Value::Null), LIMIT_LABEL);
            if !label.is_empty() {
                block.insert("label".into(), label.into());
            }
            out.push(Value::Object(block));
        }
    }
    out
}

fn number(v: &Value) -> bool {
    v.is_number()
}

/// round(x) for a float: half to even.
fn round_half_even(x: f64) -> f64 {
    let r = x.round();
    if (x - x.trunc()).abs() == 0.5 {
        2.0 * (x / 2.0).round()
    } else {
        r
    }
}

/// format(x, 'g'): six significant digits, trailing zeros dropped.
pub fn format_g(x: f64) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    let p: i32 = 6;
    let sci = format!("{:.*e}", (p - 1) as usize, x);
    let (mantissa, exp) = sci.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    if exp < -4 || exp >= p {
        let m = if mantissa.contains('.') { mantissa.trim_end_matches('0').trim_end_matches('.') } else { mantissa };
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{m}e{sign}{:02}", exp.abs())
    } else {
        let decimals = (p - 1 - exp).max(0) as usize;
        let fixed = format!("{:.*}", decimals, x);
        if fixed.contains('.') {
            fixed.trim_end_matches('0').trim_end_matches('.').to_owned()
        } else {
            fixed
        }
    }
}

fn metric(value: &Value, fmt: &Value) -> Option<String> {
    if let Value::Number(n) = value {
        if fmt.as_str() == Some("percent01") {
            let f = n.as_f64().unwrap_or(0.0).clamp(0.0, 1.0);
            return Some(format!("{}%", round_half_even(f * 100.0) as i64));
        }
        if n.is_f64() {
            return Some(format_g(n.as_f64().unwrap_or(0.0)));
        }
        return Some(vexa_native_kit::pyjson::py_number(n));
    }
    if let Value::String(s) = value {
        if !crate::val::strip(s).is_empty() {
            return Some(plain_str(s, LIMIT_METRIC));
        }
    }
    None
}

fn with_label(kind: &str, label: &str) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("type".into(), kind.into());
    if !label.is_empty() {
        o.insert("label".into(), label.into());
    }
    o
}

/// One stored block for one viewer: `fields` is what they read, `readable` the field names they
/// may read ('*' in it means all). None drops the block (no value to show).
pub fn resolve_block(block: &Value, fields: &Obj, readable: &BTreeSet<String>, formats: &Obj) -> Option<Value> {
    let kind = block.get("type").and_then(Value::as_str).unwrap_or("");
    if STRUCTURAL.contains(&kind) {
        return Some(json!({"type": kind}));
    }
    let name = block.get("field").and_then(Value::as_str).unwrap_or("");
    let label = block.get("label").and_then(Value::as_str).unwrap_or("");
    if !readable.contains("*") && !readable.contains(name) {
        return Some(json!({"type": "locked", "label": if label.is_empty() { name } else { label }}));
    }
    let value = fields.get(name).unwrap_or(&Value::Null);
    if value.is_null() {
        return None;
    }
    let mut out = with_label(kind, label);
    match kind {
        "metric" => {
            let text = metric(value, formats.get(name).unwrap_or(&Value::Null))?;
            if text.is_empty() {
                return None;
            }
            out.insert("value".into(), text.into());
        }
        "text" => {
            let text = plain(value, LIMIT_TEXT);
            if text.is_empty() {
                return None;
            }
            out.insert("text".into(), text.into());
        }
        "progress" => {
            if !number(value) {
                return None;
            }
            let f = value.as_f64().unwrap_or(0.0).clamp(0.0, 1.0);
            out.insert("value".into(), json!(f));
        }
        "due" => {
            let s = value.as_str()?;
            if !date_re().is_match(s) {
                return None;
            }
            out.insert("at".into(), s.chars().take(10).collect::<String>().into());
        }
        "checklist" => {
            let Value::Array(list) = value else { return None };
            let items: Vec<Value> = list
                .iter()
                .take(LIMIT_CHECKLIST)
                .filter_map(|i| {
                    let o = i.as_object()?;
                    let text = plain(o.get("text").unwrap_or(&Value::Null), LIMIT_ROW);
                    if text.is_empty() {
                        return None;
                    }
                    Some(json!({"text": text, "done": o.get("done") == Some(&Value::Bool(true))}))
                })
                .collect();
            if items.is_empty() {
                return None;
            }
            out.insert("items".into(), Value::Array(items));
        }
        "list" => {
            let rows: Vec<String> = match value {
                Value::Array(a) => a.iter().map(|r| plain(r, LIMIT_ROW)).collect(),
                other => crate::markdown_links::splitlines(&crate::val::pystr(other)).iter().map(|r| plain_str(r, LIMIT_ROW)).collect(),
            };
            let rows: Vec<Value> = rows.into_iter().filter(|r| !r.is_empty()).take(LIMIT_ROWS).map(Value::String).collect();
            if rows.is_empty() {
                return None;
            }
            out.insert("rows".into(), Value::Array(rows));
        }
        _ => return None,
    }
    Some(Value::Object(out))
}

/// The face one viewer sees: the stored face (or the default), sanitised, each block resolved.
pub fn resolve(face: &Value, fields: &Obj, readable: &BTreeSet<String>, formats: &Obj) -> Vec<Value> {
    let mut stored = sanitize(face);
    if stored.is_empty() {
        stored = DEFAULT_FACE.iter().map(|t| json!({"type": t})).collect();
    }
    stored.iter().filter_map(|b| resolve_block(b, fields, readable, formats)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitises_and_resolves_like_python() {
        let face = json!([{"type": "metric", "field": "Amount", "label": "Am\nount", "x": 1}, {"type": "bogus"}, {"type": "stepper", "field": "x"}, {"type": "text", "field": "9bad"}, "x"]);
        assert_eq!(Value::Array(sanitize(&face)), json!([{"type": "metric", "field": "Amount", "label": "Am ount"}, {"type": "stepper"}]));
        let fields: Obj = json!({"Amount": 1234567.0, "P": 2, "D": "2026-01-02T00", "C": [{"text": "a", "done": 1}, {"text": " "}, {"text": "b", "done": true}], "L": "x\n\ny\rz"}).as_object().unwrap().clone();
        let all: BTreeSet<String> = ["*".to_string()].into_iter().collect();
        let f = json!([{"type": "metric", "field": "Amount"}, {"type": "progress", "field": "P"}, {"type": "due", "field": "D"}, {"type": "checklist", "field": "C"}, {"type": "list", "field": "L"}, {"type": "text", "field": "Missing"}]);
        let out = resolve(&f, &fields, &all, &Obj::new());
        assert_eq!(Value::Array(out), json!([{"type": "metric", "value": "1.23457e+06"}, {"type": "progress", "value": 1.0}, {"type": "due", "at": "2026-01-02"}, {"type": "checklist", "items": [{"text": "a", "done": false}, {"text": "b", "done": true}]}, {"type": "list", "rows": ["x", "y", "z"]}]));
        let none: BTreeSet<String> = BTreeSet::new();
        assert_eq!(Value::Array(resolve(&json!([{"type": "metric", "field": "Amount"}]), &fields, &none, &Obj::new())), json!([{"type": "locked", "label": "Amount"}]));
        assert_eq!(format_g(0.5), "0.5");
        assert_eq!(format_g(100.0), "100");
        assert_eq!(format_g(0.0001234), "0.0001234");
        assert_eq!(format_g(0.00001234), "1.234e-05");
        let pct: Obj = json!({"Amount": "percent01"}).as_object().unwrap().clone();
        let f2: Obj = json!({"Amount": 0.125}).as_object().unwrap().clone();
        assert_eq!(resolve_block(&json!({"type": "metric", "field": "Amount"}), &f2, &all, &pct), Some(json!({"type": "metric", "value": "12%"})));
        assert_eq!(Value::Array(resolve(&Value::Null, &Obj::new(), &all, &Obj::new())).as_array().unwrap().len(), 6);
    }
}
