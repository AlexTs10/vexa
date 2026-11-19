//! The input check the MCP SDK runs before a tool is called: `jsonschema.validate`
//! (Draft 2020-12, python-jsonschema 4.26) over the keywords tool schemas use, with the
//! library's messages and its `best_match` choice of the one error to report.

use regex::Regex;
use serde_json::{Map, Value};
use vexa_native_kit::pyjson::{py_number, py_repr, py_str_repr};

#[derive(Debug, Clone)]
pub struct SchemaError {
    pub message: String,
    /// The instance path, relative to the schema that reported it.
    pub path: Vec<PathPart>,
    pub keyword: &'static str,
    /// The schema object that holds the keyword (for the type match).
    pub schema: Value,
    pub instance: Value,
    pub context: Vec<SchemaError>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathPart {
    Index(usize),
    Key(String),
}

/// The message `jsonschema.validate(instance, schema)` raises, or None when valid.
pub fn validate(instance: &Value, schema: &Value) -> Option<String> {
    let errors = errors(instance, schema);
    best_match(errors).map(|e| e.message)
}

pub fn errors(instance: &Value, schema: &Value) -> Vec<SchemaError> {
    let mut out = Vec::new();
    descend(instance, schema, &mut out);
    out
}

fn is_type(instance: &Value, kind: &str) -> bool {
    match kind {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        "number" => instance.is_number(),
        "integer" => match instance {
            Value::Number(n) => {
                n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0)
            }
            _ => false,
        },
        _ => false,
    }
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64()
}

fn repr_num(v: &Value) -> String {
    match v {
        Value::Number(n) => py_number(n),
        other => py_repr(other),
    }
}

/// Python's len() of a str: code points.
fn py_len(s: &str) -> usize {
    s.chars().count()
}

/// jsonschema's equal(): bool is not a number, and 1 == 1.0.
pub fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| equal(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| equal(v, w)))
        }
        _ => a == b,
    }
}

fn err(
    keyword: &'static str,
    message: String,
    schema: &Map<String, Value>,
    instance: &Value,
) -> SchemaError {
    SchemaError {
        message,
        path: Vec::new(),
        keyword,
        schema: Value::Object(schema.clone()),
        instance: instance.clone(),
        context: Vec::new(),
    }
}

fn descend(instance: &Value, schema: &Value, out: &mut Vec<SchemaError>) {
    let obj = match schema {
        Value::Bool(true) => return,
        Value::Bool(false) => {
            out.push(SchemaError {
                message: format!("False schema does not allow {}", py_repr(instance)),
                path: Vec::new(),
                keyword: "false",
                schema: schema.clone(),
                instance: instance.clone(),
                context: Vec::new(),
            });
            return;
        }
        Value::Object(o) => o,
        _ => return,
    };
    for (keyword, value) in obj {
        keyword_errors(keyword, value, instance, obj, out);
    }
}

fn under(instance: &Value, schema: &Value, part: PathPart) -> Vec<SchemaError> {
    let mut found = Vec::new();
    descend(instance, schema, &mut found);
    for e in &mut found {
        e.path.insert(0, part.clone());
    }
    found
}

fn keyword_errors(
    keyword: &str,
    value: &Value,
    instance: &Value,
    schema: &Map<String, Value>,
    out: &mut Vec<SchemaError>,
) {
    match keyword {
        "type" => {
            let types: Vec<&str> = match value {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => return,
            };
            if !types.iter().any(|t| is_type(instance, t)) {
                let reprs = types
                    .iter()
                    .map(|t| py_str_repr(t))
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push(err(
                    "type",
                    format!("{} is not of type {reprs}", py_repr(instance)),
                    schema,
                    instance,
                ));
            }
        }
        "properties" => {
            let (Some(props), Some(inst)) = (value.as_object(), instance.as_object()) else {
                return;
            };
            for (name, sub) in props {
                if let Some(v) = inst.get(name) {
                    out.extend(under(v, sub, PathPart::Key(name.clone())));
                }
            }
        }
        "required" => {
            let (Some(req), Some(inst)) = (value.as_array(), instance.as_object()) else {
                return;
            };
            for name in req.iter().filter_map(Value::as_str) {
                if !inst.contains_key(name) {
                    out.push(err(
                        "required",
                        format!("{} is a required property", py_str_repr(name)),
                        schema,
                        instance,
                    ));
                }
            }
        }
        "additionalProperties" => {
            let Some(inst) = instance.as_object() else {
                return;
            };
            let props = schema.get("properties").and_then(Value::as_object);
            let patterns: Vec<Regex> = schema
                .get("patternProperties")
                .and_then(Value::as_object)
                .map(|p| p.keys().filter_map(|k| Regex::new(k).ok()).collect())
                .unwrap_or_default();
            let extras: Vec<&String> = inst
                .keys()
                .filter(|k| {
                    !props.is_some_and(|p| p.contains_key(k.as_str()))
                        && !patterns.iter().any(|r| r.is_match(k))
                })
                .collect();
            match value {
                Value::Object(_) => {
                    for k in extras {
                        out.extend(under(&inst[k.as_str()], value, PathPart::Key(k.clone())));
                    }
                }
                Value::Bool(false) if !extras.is_empty() => {
                    let mut sorted: Vec<&String> = extras;
                    sorted.sort();
                    let verb = if sorted.len() == 1 { "was" } else { "were" };
                    let joined = sorted
                        .iter()
                        .map(|k| py_str_repr(k))
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push(err(
                        "additionalProperties",
                        format!(
                            "Additional properties are not allowed ({joined} {verb} unexpected)"
                        ),
                        schema,
                        instance,
                    ));
                }
                _ => {}
            }
        }
        "items" => {
            let Some(items) = instance.as_array() else {
                return;
            };
            let prefix = schema
                .get("prefixItems")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if value == &Value::Bool(false) {
                if items.len() > prefix {
                    let rest = Value::Array(items[prefix..].to_vec());
                    let item = if prefix == 1 { "item" } else { "items" };
                    out.push(err(
                        "items",
                        format!(
                            "Expected at most {prefix} {item} but found {} extra: {}",
                            items.len() - prefix,
                            py_repr(&rest)
                        ),
                        schema,
                        instance,
                    ));
                }
                return;
            }
            for (i, item) in items.iter().enumerate().skip(prefix) {
                out.extend(under(item, value, PathPart::Index(i)));
            }
        }
        "prefixItems" => {
            let (Some(subs), Some(items)) = (value.as_array(), instance.as_array()) else {
                return;
            };
            for (i, (sub, item)) in subs.iter().zip(items).enumerate() {
                out.extend(under(item, sub, PathPart::Index(i)));
            }
        }
        "anyOf" | "oneOf" => {
            let Some(subs) = value.as_array() else { return };
            let mut context = Vec::new();
            let mut valid = 0;
            for sub in subs {
                let found = errors(instance, sub);
                if found.is_empty() {
                    valid += 1;
                    if keyword == "anyOf" {
                        return;
                    }
                } else {
                    context.extend(found);
                }
            }
            let kw: &'static str = if keyword == "anyOf" { "anyOf" } else { "oneOf" };
            if valid == 0 {
                let mut e = err(
                    kw,
                    format!(
                        "{} is not valid under any of the given schemas",
                        py_repr(instance)
                    ),
                    schema,
                    instance,
                );
                e.context = context;
                out.push(e);
            } else if valid > 1 {
                let reprs = subs
                    .iter()
                    .filter(|s| errors(instance, s).is_empty())
                    .map(py_repr)
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push(err(
                    kw,
                    format!("{} is valid under each of {reprs}", py_repr(instance)),
                    schema,
                    instance,
                ));
            }
        }
        "allOf" => {
            let Some(subs) = value.as_array() else { return };
            for sub in subs {
                descend(instance, sub, out);
            }
        }
        "not" => {
            if errors(instance, value).is_empty() {
                out.push(err(
                    "not",
                    format!(
                        "{} should not be valid under {}",
                        py_repr(instance),
                        py_repr(value)
                    ),
                    schema,
                    instance,
                ));
            }
        }
        "enum" => {
            let Some(options) = value.as_array() else {
                return;
            };
            if !options.iter().any(|o| equal(o, instance)) {
                out.push(err(
                    "enum",
                    format!("{} is not one of {}", py_repr(instance), py_repr(value)),
                    schema,
                    instance,
                ));
            }
        }
        "const" => {
            if !equal(value, instance) {
                out.push(err(
                    "const",
                    format!("{} was expected", py_repr(value)),
                    schema,
                    instance,
                ));
            }
        }
        "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
            if !is_type(instance, "number") {
                return;
            }
            let (Some(x), Some(limit)) = (num(instance), num(value)) else {
                return;
            };
            let (failed, text, kw): (bool, &str, &'static str) = match keyword {
                "minimum" => (x < limit, "is less than the minimum of", "minimum"),
                "maximum" => (x > limit, "is greater than the maximum of", "maximum"),
                "exclusiveMinimum" => (
                    x <= limit,
                    "is less than or equal to the minimum of",
                    "exclusiveMinimum",
                ),
                _ => (
                    x >= limit,
                    "is greater than or equal to the maximum of",
                    "exclusiveMaximum",
                ),
            };
            if failed {
                out.push(err(
                    kw,
                    format!("{} {text} {}", py_repr(instance), repr_num(value)),
                    schema,
                    instance,
                ));
            }
        }
        "minLength" | "maxLength" => {
            let (Some(s), Some(limit)) = (instance.as_str(), value.as_u64()) else {
                return;
            };
            let n = py_len(s) as u64;
            if keyword == "minLength" && n < limit {
                let m = if limit == 1 {
                    "should be non-empty"
                } else {
                    "is too short"
                };
                out.push(err(
                    "minLength",
                    format!("{} {m}", py_repr(instance)),
                    schema,
                    instance,
                ));
            } else if keyword == "maxLength" && n > limit {
                let m = if limit == 0 {
                    "is expected to be empty"
                } else {
                    "is too long"
                };
                out.push(err(
                    "maxLength",
                    format!("{} {m}", py_repr(instance)),
                    schema,
                    instance,
                ));
            }
        }
        "minItems" | "maxItems" => {
            let (Some(a), Some(limit)) = (instance.as_array(), value.as_u64()) else {
                return;
            };
            let n = a.len() as u64;
            if keyword == "minItems" && n < limit {
                let m = if limit == 1 {
                    "should be non-empty"
                } else {
                    "is too short"
                };
                out.push(err(
                    "minItems",
                    format!("{} {m}", py_repr(instance)),
                    schema,
                    instance,
                ));
            } else if keyword == "maxItems" && n > limit {
                let m = if limit == 0 {
                    "is expected to be empty"
                } else {
                    "is too long"
                };
                out.push(err(
                    "maxItems",
                    format!("{} {m}", py_repr(instance)),
                    schema,
                    instance,
                ));
            }
        }
        "minProperties" | "maxProperties" => {
            let (Some(o), Some(limit)) = (instance.as_object(), value.as_u64()) else {
                return;
            };
            let n = o.len() as u64;
            if keyword == "minProperties" && n < limit {
                let m = if limit == 1 {
                    "should be non-empty"
                } else {
                    "does not have enough properties"
                };
                out.push(err(
                    "minProperties",
                    format!("{} {m}", py_repr(instance)),
                    schema,
                    instance,
                ));
            } else if keyword == "maxProperties" && n > limit {
                let m = if limit == 0 {
                    "is expected to be empty"
                } else {
                    "has too many properties"
                };
                out.push(err(
                    "maxProperties",
                    format!("{} {m}", py_repr(instance)),
                    schema,
                    instance,
                ));
            }
        }
        "uniqueItems" => {
            let (Some(true), Some(a)) = (value.as_bool(), instance.as_array()) else {
                return;
            };
            let dup = a
                .iter()
                .enumerate()
                .any(|(i, x)| a[i + 1..].iter().any(|y| equal(x, y)));
            if dup {
                out.push(err(
                    "uniqueItems",
                    format!("{} has non-unique elements", py_repr(instance)),
                    schema,
                    instance,
                ));
            }
        }
        "pattern" => {
            let (Some(s), Some(p)) = (instance.as_str(), value.as_str()) else {
                return;
            };
            if let Ok(re) = Regex::new(p) {
                if !re.is_match(s) {
                    out.push(err(
                        "pattern",
                        format!("{} does not match {}", py_repr(instance), py_str_repr(p)),
                        schema,
                        instance,
                    ));
                }
            }
        }
        "dependentRequired" => {
            let (Some(deps), Some(inst)) = (value.as_object(), instance.as_object()) else {
                return;
            };
            for (prop, needs) in deps {
                if inst.contains_key(prop) {
                    for each in needs
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                    {
                        if !inst.contains_key(each) {
                            out.push(err(
                                "dependentRequired",
                                format!(
                                    "{} is a dependency of {}",
                                    py_str_repr(each),
                                    py_str_repr(prop)
                                ),
                                schema,
                                instance,
                            ));
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn matches_type(e: &SchemaError) -> bool {
    match e.schema.get("type") {
        Some(Value::String(t)) => is_type(&e.instance, t),
        Some(Value::Array(ts)) => ts
            .iter()
            .filter_map(Value::as_str)
            .any(|t| is_type(&e.instance, t)),
        _ => false,
    }
}

/// by_relevance(): (-len(path), path, not weak, strong (none), not matches_type).
fn key(e: &SchemaError) -> (i64, Vec<PathPart>, bool, bool, bool) {
    (
        -(e.path.len() as i64),
        e.path.clone(),
        !matches!(e.keyword, "anyOf" | "oneOf"),
        false,
        !matches_type(e),
    )
}

/// exceptions.best_match: the most relevant error, then down its context while
/// the two least relevant children differ.
pub fn best_match(errors: Vec<SchemaError>) -> Option<SchemaError> {
    let mut best: Option<SchemaError> = None;
    for e in errors {
        // max() keeps the first of equal keys.
        if best.as_ref().map_or(true, |b| key(&e) > key(b)) {
            best = Some(e);
        }
    }
    let mut best = best?;
    while !best.context.is_empty() {
        let mut ctx = std::mem::take(&mut best.context);
        // heapq.nsmallest(2, ...) is stable: the first of equal keys comes first.
        let mut order: Vec<usize> = (0..ctx.len()).collect();
        order.sort_by(|&a, &b| key(&ctx[a]).cmp(&key(&ctx[b])));
        if order.len() >= 2 && key(&ctx[order[0]]) == key(&ctx[order[1]]) {
            best.context = ctx;
            return Some(best);
        }
        best = ctx.swap_remove(order[0]);
    }
    Some(best)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(schema: Value, instance: Value) -> Option<String> {
        validate(&instance, &schema)
    }

    #[test]
    fn messages_like_python_jsonschema() {
        let s = json!({"type": "object", "properties": {
            "q": {"type": "string", "minLength": 1},
            "limit": {"anyOf": [{"type": "integer", "maximum": 100, "minimum": 1}, {"type": "null"}], "type": "integer"},
            "sev": {"anyOf": [{"type": "integer", "maximum": 3.0, "minimum": 1.0}, {"type": "null"}], "type": "integer"},
            "p": {"type": "string", "enum": ["google", "microsoft", "zoom"]},
            "a": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
            "steps": {"type": "array", "items": {"type": "string"}, "minItems": 1}},
            "required": ["q"], "additionalProperties": false});
        assert_eq!(
            v(s.clone(), json!({})).unwrap(),
            "'q' is a required property"
        );
        assert_eq!(
            v(s.clone(), json!({"q": "", "zzz": 1, "aaa": 2})).unwrap(),
            "Additional properties are not allowed ('aaa', 'zzz' were unexpected)"
        );
        assert_eq!(
            v(s.clone(), json!({"q": ""})).unwrap(),
            "'' should be non-empty"
        );
        assert_eq!(
            v(s.clone(), json!({"q": "x", "limit": 0})).unwrap(),
            "0 is less than the minimum of 1"
        );
        assert_eq!(
            v(s.clone(), json!({"q": "x", "limit": "5"})).unwrap(),
            "'5' is not of type 'integer'"
        );
        assert_eq!(
            v(s.clone(), json!({"q": "x", "sev": 9})).unwrap(),
            "9 is greater than the maximum of 3.0"
        );
        assert_eq!(
            v(s.clone(), json!({"q": "x", "p": "x"})).unwrap(),
            "'x' is not one of ['google', 'microsoft', 'zoom']"
        );
        assert_eq!(
            v(s.clone(), json!({"q": "x", "a": "nope"})).unwrap(),
            "'nope' does not match '^[a-f0-9]{32}$'"
        );
        assert_eq!(
            v(s.clone(), json!({"q": "x", "steps": []})).unwrap(),
            "[] should be non-empty"
        );
        assert_eq!(
            v(s.clone(), json!({"q": 5})).unwrap(),
            "5 is not of type 'string'"
        );
        assert_eq!(v(s.clone(), json!({"q": "x", "limit": 1.0})), None);
        assert_eq!(
            v(
                json!({"anyOf": [{"type": "string"}, {"type": "integer"}]}),
                json!(null)
            )
            .unwrap(),
            "None is not valid under any of the given schemas"
        );
    }
}
