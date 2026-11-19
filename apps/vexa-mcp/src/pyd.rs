//! The request validation FastAPI runs before a route (pydantic v2, lax mode), driven by the
//! route's published schema: the same coercions, and the same error objects
//! (`type`, `loc`, `msg`, `input`, `ctx`) in the same order.

use serde_json::{json, Map, Number, Value};
use vexa_native_kit::pyjson::py_number;

pub fn error(kind: &str, loc: &[Value], msg: String, input: Value, ctx: Option<Value>) -> Value {
    let mut e = Map::new();
    e.insert("type".into(), kind.into());
    e.insert("loc".into(), Value::Array(loc.to_vec()));
    e.insert("msg".into(), msg.into());
    e.insert("input".into(), input);
    if let Some(c) = ctx {
        e.insert("ctx".into(), c);
    }
    Value::Object(e)
}

pub fn missing(loc: &[Value], input: Value) -> Value {
    error("missing", loc, "Field required".into(), input, None)
}

/// A model validator's refusal: "Value error, <text>".
pub fn value_error(loc: &[Value], text: &str, input: Value) -> Value {
    error(
        "value_error",
        loc,
        format!("Value error, {text}"),
        input,
        Some(json!({"error": {}})),
    )
}

fn push(loc: &[Value], part: impl Into<Value>) -> Vec<Value> {
    let mut l = loc.to_vec();
    l.push(part.into());
    l
}

/// The one non-null branch of `anyOf: [X, null]`, or None when the schema is not nullable.
fn nullable(schema: &Value) -> Option<&Value> {
    let branches = schema.get("anyOf")?.as_array()?;
    if !branches
        .iter()
        .any(|b| b.get("type").and_then(Value::as_str) == Some("null"))
    {
        return None;
    }
    branches
        .iter()
        .find(|b| b.get("type").and_then(Value::as_str) != Some("null"))
}

/// A constraint value as pydantic reports it in `ctx` (the declared int, not the schema's float).
fn bound(v: &Value) -> Value {
    match v.as_f64() {
        Some(f) if f.fract() == 0.0 && f.abs() < 1e15 => Value::from(f as i64),
        _ => v.clone(),
    }
}

/// pydantic's str -> int: surrounding whitespace, a sign, digit underscores, a zero fraction.
pub fn str_int(text: &str) -> Option<i64> {
    let t = text.trim();
    let t = match t.split_once('.') {
        Some((whole, frac)) if !frac.is_empty() && frac.chars().all(|c| c == '0') => whole,
        Some(_) => return None,
        None => t,
    };
    let (neg, digits) = match t.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let clean: String = digits.chars().filter(|c| *c != '_').collect();
    if !clean.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: i64 = clean.parse().ok()?;
    Some(if neg { -n } else { n })
}

fn str_bool(text: &str) -> Option<bool> {
    match text.to_ascii_lowercase().as_str() {
        "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
        "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
        _ => None,
    }
}

fn type_of(schema: &Value) -> &str {
    schema.get("type").and_then(Value::as_str).unwrap_or("")
}

fn literal_expected(options: &[Value]) -> String {
    let reprs: Vec<String> = options
        .iter()
        .map(vexa_native_kit::pyjson::py_repr)
        .collect();
    match reprs.len() {
        0 => String::new(),
        1 => reprs[0].clone(),
        n => format!("{} or {}", reprs[..n - 1].join(", "), reprs[n - 1]),
    }
}

/// Validate one JSON value (a body field) against its schema.
pub fn value(schema: &Value, v: &Value, loc: &[Value], errs: &mut Vec<Value>) -> Option<Value> {
    if let Some(inner) = nullable(schema) {
        if v.is_null() {
            return Some(Value::Null);
        }
        return value(inner, v, loc, errs);
    }
    if let Some(options) = schema.get("enum").and_then(Value::as_array) {
        if options.iter().any(|o| o == v) {
            return Some(v.clone());
        }
        let expected = literal_expected(options);
        errs.push(error(
            "literal_error",
            loc,
            format!("Input should be {expected}"),
            v.clone(),
            Some(json!({"expected": expected})),
        ));
        return None;
    }
    let out = match type_of(schema) {
        "string" => match v {
            Value::String(_) => v.clone(),
            _ => {
                return fail(
                    errs,
                    "string_type",
                    loc,
                    "Input should be a valid string",
                    v,
                )
            }
        },
        "integer" => match v {
            Value::Number(n) if n.is_i64() || n.is_u64() => v.clone(),
            Value::Number(n) => {
                let f = n.as_f64().unwrap_or(f64::NAN);
                if f.fract() == 0.0 && f.is_finite() {
                    Value::from(f as i64)
                } else {
                    return fail(
                        errs,
                        "int_from_float",
                        loc,
                        "Input should be a valid integer, got a number with a fractional part",
                        v,
                    );
                }
            }
            Value::Bool(b) => Value::from(*b as i64),
            Value::String(s) => match str_int(s) {
                Some(i) => Value::from(i),
                None => {
                    return fail(
                        errs,
                        "int_parsing",
                        loc,
                        "Input should be a valid integer, unable to parse string as an integer",
                        v,
                    )
                }
            },
            _ => return fail(errs, "int_type", loc, "Input should be a valid integer", v),
        },
        "number" => match v {
            Value::Number(_) => v.clone(),
            Value::Bool(b) => Value::from(*b as i64 as f64),
            Value::String(s) => match s.trim().parse::<f64>().ok().and_then(Number::from_f64) {
                Some(n) => Value::Number(n),
                None => {
                    return fail(
                        errs,
                        "float_parsing",
                        loc,
                        "Input should be a valid number, unable to parse string as a number",
                        v,
                    )
                }
            },
            _ => return fail(errs, "float_type", loc, "Input should be a valid number", v),
        },
        "boolean" => match v {
            Value::Bool(_) => v.clone(),
            Value::Number(n) if n.as_f64() == Some(0.0) => Value::Bool(false),
            Value::Number(n) if n.as_f64() == Some(1.0) => Value::Bool(true),
            Value::Number(_) => {
                return fail(
                    errs,
                    "bool_parsing",
                    loc,
                    "Input should be a valid boolean, unable to interpret input",
                    v,
                )
            }
            Value::String(s) => match str_bool(s) {
                Some(b) => Value::Bool(b),
                None => {
                    return fail(
                        errs,
                        "bool_parsing",
                        loc,
                        "Input should be a valid boolean, unable to interpret input",
                        v,
                    )
                }
            },
            _ => return fail(errs, "bool_type", loc, "Input should be a valid boolean", v),
        },
        "array" => match v {
            Value::Array(items) => {
                let item_schema = schema.get("items").cloned().unwrap_or(json!({}));
                let before = errs.len();
                let out: Vec<Value> = items
                    .iter()
                    .enumerate()
                    .filter_map(|(i, item)| value(&item_schema, item, &push(loc, i), errs))
                    .collect();
                if errs.len() > before {
                    return None;
                }
                Value::Array(out)
            }
            _ => return fail(errs, "list_type", loc, "Input should be a valid list", v),
        },
        "object" => match v {
            Value::Object(_) => v.clone(),
            _ => {
                return fail(
                    errs,
                    "dict_type",
                    loc,
                    "Input should be a valid dictionary",
                    v,
                )
            }
        },
        _ => v.clone(),
    };
    constrain(schema, out, v, loc, errs)
}

fn fail(errs: &mut Vec<Value>, kind: &str, loc: &[Value], msg: &str, v: &Value) -> Option<Value> {
    errs.push(error(kind, loc, msg.into(), v.clone(), None));
    None
}

/// minLength / maxLength / pattern / minimum / maximum, after the type is settled.
fn constrain(
    schema: &Value,
    out: Value,
    original: &Value,
    loc: &[Value],
    errs: &mut Vec<Value>,
) -> Option<Value> {
    let input = original.clone();
    if let Value::String(s) = &out {
        let n = s.chars().count() as u64;
        if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
            if n < min {
                let unit = if min == 1 { "character" } else { "characters" };
                errs.push(error(
                    "string_too_short",
                    loc,
                    format!("String should have at least {min} {unit}"),
                    input,
                    Some(json!({"min_length": min})),
                ));
                return None;
            }
        }
        if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
            if n > max {
                let unit = if max == 1 { "character" } else { "characters" };
                errs.push(error(
                    "string_too_long",
                    loc,
                    format!("String should have at most {max} {unit}"),
                    input,
                    Some(json!({"max_length": max})),
                ));
                return None;
            }
        }
        if let Some(p) = schema.get("pattern").and_then(Value::as_str) {
            if regex::Regex::new(p).is_ok_and(|re| !re.is_match(s)) {
                errs.push(error(
                    "string_pattern_mismatch",
                    loc,
                    format!("String should match pattern '{p}'"),
                    input,
                    Some(json!({"pattern": p})),
                ));
                return None;
            }
        }
    }
    if let Some(x) = out.as_f64().filter(|_| out.is_number()) {
        if let Some(min) = schema.get("minimum") {
            if min.as_f64().is_some_and(|m| x < m) {
                let b = bound(min);
                errs.push(error(
                    "greater_than_equal",
                    loc,
                    format!("Input should be greater than or equal to {}", num(&b)),
                    input,
                    Some(json!({"ge": b})),
                ));
                return None;
            }
        }
        if let Some(max) = schema.get("maximum") {
            if max.as_f64().is_some_and(|m| x > m) {
                let b = bound(max);
                errs.push(error(
                    "less_than_equal",
                    loc,
                    format!("Input should be less than or equal to {}", num(&b)),
                    input,
                    Some(json!({"le": b})),
                ));
                return None;
            }
        }
    }
    Some(out)
}

fn num(v: &Value) -> String {
    match v {
        Value::Number(n) => py_number(n),
        other => other.to_string(),
    }
}

/// Validate one query-string value against its schema (FastAPI hands pydantic the text).
pub fn text(schema: &Value, s: &str, loc: &[Value], errs: &mut Vec<Value>) -> Option<Value> {
    if let Some(inner) = nullable(schema) {
        return text(inner, s, loc, errs);
    }
    let v = Value::String(s.to_owned());
    if schema.get("enum").is_some() {
        return value(schema, &v, loc, errs);
    }
    match type_of(schema) {
        "integer" | "number" | "boolean" | "string" => value(schema, &v, loc, errs),
        _ => Some(v),
    }
}

/// A body model (a resolved schema with `properties`): every field in order, defaults filled.
pub fn model(
    schema: &Value,
    input: &Value,
    loc: &[Value],
    errs: &mut Vec<Value>,
) -> Option<Map<String, Value>> {
    let Some(obj) = input.as_object() else {
        errs.push(error(
            "model_attributes_type",
            loc,
            "Input should be a valid dictionary or object to extract fields from".into(),
            input.clone(),
            None,
        ));
        return None;
    };
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut out = Map::new();
    let before = errs.len();
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        for (name, prop) in props {
            let here = push(loc, name.as_str());
            match obj.get(name) {
                Some(v) => {
                    if let Some(got) = value(prop, v, &here, errs) {
                        out.insert(name.clone(), got);
                    }
                }
                None if required.contains(&name.as_str()) => {
                    errs.push(missing(&here, input.clone()))
                }
                None => {
                    out.insert(
                        name.clone(),
                        prop.get("default").cloned().unwrap_or(Value::Null),
                    );
                }
            }
        }
    }
    (errs.len() == before).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coercions_and_errors() {
        let int =
            json!({"anyOf": [{"type": "integer", "minimum": 1, "maximum": 100}, {"type": "null"}]});
        let mut e = Vec::new();
        assert_eq!(text(&int, " +5 ", &[], &mut e), Some(json!(5)));
        assert_eq!(text(&int, "1_0", &[], &mut e), Some(json!(10)));
        assert_eq!(text(&int, "5.0", &[], &mut e), Some(json!(5)));
        assert!(e.is_empty());
        assert_eq!(
            text(&int, "0", &[json!("query"), json!("limit")], &mut e),
            None
        );
        assert_eq!(
            e[0],
            json!({"type": "greater_than_equal", "loc": ["query", "limit"], "msg": "Input should be greater than or equal to 1", "input": "0", "ctx": {"ge": 1}})
        );
        let lit = json!({"type": "string", "enum": ["google", "microsoft", "zoom"]});
        let mut e = Vec::new();
        value(&lit, &json!("x"), &[], &mut e);
        assert_eq!(
            e[0]["msg"],
            "Input should be 'google', 'microsoft' or 'zoom'"
        );
        let sev = json!({"anyOf": [{"type": "integer", "maximum": 3.0, "minimum": 1.0}, {"type": "null"}]});
        let mut e = Vec::new();
        value(&sev, &json!(9), &[], &mut e);
        assert_eq!(e[0]["ctx"], json!({"le": 3}));
        assert_eq!(e[0]["msg"], "Input should be less than or equal to 3");
    }
}
