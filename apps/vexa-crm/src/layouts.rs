//! Declarative card layouts: field references only, never executable templates (cards.py).

use serde_json::{Map, Value};

/// visible_layout: the layout projected through the field set the caller reads.
pub fn visible_layout(layout: &Value, fields: &dyn Fn(&str) -> bool) -> Value {
    let mut out = layout.as_object().cloned().unwrap_or_default();
    let has = |v: &Value| v.as_str().is_some_and(fields);
    let title = crate::val::g(layout, "title_field");
    out.insert("title_field".into(), if has(title) { title.clone() } else { Value::String(String::new()) });
    let mut sections = Vec::new();
    for section in crate::val::g(layout, "sections").as_array().into_iter().flatten() {
        let fs: Vec<Value> = crate::val::g(section, "fields").as_array().into_iter().flatten().cloned().collect();
        if !fs.iter().any(|f| has(crate::val::g(f, "field"))) {
            continue;
        }
        let mut s: Map<String, Value> = section.as_object().cloned().unwrap_or_default();
        s.insert("fields".into(), Value::Array(fs.into_iter().filter(|f| has(crate::val::g(f, "field"))).collect()));
        sections.push(Value::Object(s));
    }
    out.insert("sections".into(), Value::Array(sections));
    Value::Object(out)
}

/// One pydantic error: where, the message, its type, the input.
struct PydErr {
    loc: Vec<String>,
    msg: String,
    kind: &'static str,
    input: Value,
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// pydantic's input_value: the repr, cut to its first 25 and last 24 characters past 50.
fn input_value(v: &Value) -> String {
    let r = vexa_native_kit::pyjson::py_repr(v);
    let chars: Vec<char> = r.chars().collect();
    if chars.len() <= 50 {
        return r;
    }
    let head: String = chars[..25].iter().collect();
    let tail: String = chars[chars.len() - 24..].iter().collect();
    format!("{head}...{tail}")
}

struct V {
    errs: Vec<PydErr>,
}

impl V {
    fn err(&mut self, loc: &[String], kind: &'static str, msg: String, input: &Value) {
        self.errs.push(PydErr { loc: loc.to_vec(), msg, kind, input: input.clone() });
    }

    fn string(&mut self, loc: &[String], v: &Value, min: usize, max: usize, pattern: Option<&regex::Regex>) -> Value {
        let Some(s) = v.as_str() else {
            self.err(loc, "string_type", "Input should be a valid string".into(), v);
            return Value::Null;
        };
        let n = s.chars().count();
        if n < min {
            let unit = if min == 1 { "character" } else { "characters" };
            self.err(loc, "string_too_short", format!("String should have at least {min} {unit}"), v);
        } else if n > max {
            let unit = if max == 1 { "character" } else { "characters" };
            self.err(loc, "string_too_long", format!("String should have at most {max} {unit}"), v);
        } else if let Some(p) = pattern {
            if !p.is_match(s) {
                self.err(loc, "string_pattern_mismatch", format!("String should match pattern '{}'", p.as_str()), v);
            }
        }
        v.clone()
    }

    fn boolean(&mut self, loc: &[String], v: &Value) -> Value {
        match v {
            Value::Bool(_) => v.clone(),
            Value::Number(n) => match n.as_f64() {
                Some(f) if f == 0.0 => Value::Bool(false),
                Some(f) if f == 1.0 => Value::Bool(true),
                _ => {
                    self.err(loc, "bool_parsing", "Input should be a valid boolean, unable to interpret input".into(), v);
                    Value::Null
                }
            },
            Value::String(s) => match crate::val::lower(s).as_str() {
                "0" | "off" | "f" | "false" | "n" | "no" => Value::Bool(false),
                "1" | "on" | "t" | "true" | "y" | "yes" => Value::Bool(true),
                _ => {
                    self.err(loc, "bool_parsing", "Input should be a valid boolean, unable to interpret input".into(), v);
                    Value::Null
                }
            },
            _ => {
                self.err(loc, "bool_type", "Input should be a valid boolean".into(), v);
                Value::Null
            }
        }
    }

    fn list(&mut self, loc: &[String], v: &Value, max: usize) -> Option<Vec<Value>> {
        let Some(items) = v.as_array() else {
            self.err(loc, "list_type", "Input should be a valid list".into(), v);
            return None;
        };
        if items.len() > max {
            self.err(loc, "too_long", format!("List should have at most {max} items after validation, not {}", items.len()), v);
            return None;
        }
        Some(items.clone())
    }

    /// A strict model: declared fields in order (default when absent), then every extra key refused.
    fn model(&mut self, loc: &[String], v: &Value, name: &str, fields: &[(&str, Option<Value>)], each: &mut dyn FnMut(&mut V, &str, &[String], &Value) -> Value) -> Value {
        let Some(o) = v.as_object() else {
            self.err(loc, "model_type", format!("Input should be a valid dictionary or instance of {name}"), v);
            return Value::Null;
        };
        let mut out = Map::new();
        for (key, default) in fields {
            let mut at = loc.to_vec();
            at.push(key.to_string());
            match (o.get(*key), default) {
                (Some(x), _) => {
                    let got = each(self, key, &at, x);
                    out.insert(key.to_string(), got);
                }
                (None, Some(d)) => {
                    out.insert(key.to_string(), d.clone());
                }
                (None, None) => self.err(&at, "missing", "Field required".into(), v),
            }
        }
        for (key, x) in o {
            if !fields.iter().any(|(k, _)| k == key) {
                let mut at = loc.to_vec();
                at.push(key.clone());
                self.err(&at, "extra_forbidden", "Extra inputs are not permitted".into(), x);
            }
        }
        Value::Object(out)
    }
}

const FORMATS: [&str; 7] = ["text", "markdown", "number", "currency", "percent", "date", "badge"];

fn card_field(v: &mut V, loc: &[String], x: &Value) -> Value {
    let currency = regex::Regex::new("^[A-Z]{3}$").unwrap();
    v.model(loc, x, "CardField", &[("field", None), ("label", Some("".into())), ("format", Some("text".into())), ("currency", Some("USD".into()))], &mut |v, key, at, x| match key {
        "field" => v.string(at, x, 1, 120, None),
        "label" => v.string(at, x, 0, 120, None),
        "format" => {
            if !x.as_str().is_some_and(|s| FORMATS.contains(&s)) {
                v.err(at, "literal_error", "Input should be 'text', 'markdown', 'number', 'currency', 'percent', 'date' or 'badge'".into(), x);
            }
            x.clone()
        }
        _ => v.string(at, x, 0, usize::MAX, Some(&currency)),
    })
}

fn card_section(v: &mut V, loc: &[String], x: &Value) -> Value {
    v.model(loc, x, "CardSection", &[("title", Some("".into())), ("fields", None)], &mut |v, key, at, x| match key {
        "title" => v.string(at, x, 0, 120, None),
        _ => match v.list(at, x, 40) {
            Some(items) => Value::Array(items.iter().enumerate().map(|(i, f)| {
                let mut a = at.to_vec();
                a.push(i.to_string());
                card_field(v, &a, f)
            }).collect()),
            None => Value::Null,
        },
    })
}

/// CardLayout.model_validate(layout).model_dump(), or str(ValidationError) (pydantic 2.14's text).
pub fn card_layout(layout: &Value) -> Result<Value, String> {
    let mut v = V { errs: Vec::new() };
    let out = v.model(&[], layout, "CardLayout", &[("title_field", Some("Name".into())), ("sections", None), ("show_narrative", Some(true.into())), ("show_related", Some(true.into()))], &mut |v, key, at, x| match key {
        "title_field" => v.string(at, x, 0, 120, None),
        "sections" => match v.list(at, x, 12) {
            Some(items) => Value::Array(items.iter().enumerate().map(|(i, s)| {
                let mut a = at.to_vec();
                a.push(i.to_string());
                card_section(v, &a, s)
            }).collect()),
            None => Value::Null,
        },
        _ => v.boolean(at, x),
    });
    if v.errs.is_empty() {
        return Ok(out);
    }
    let n = v.errs.len();
    let mut text = format!("{n} validation error{} for CardLayout", if n == 1 { "" } else { "s" });
    for e in &v.errs {
        text.push_str(&format!(
            "\n{}\n  {} [type={}, input_value={}, input_type={}]\n    For further information visit https://errors.pydantic.dev/2.14/v/{}",
            e.loc.join("."), e.msg, e.kind, input_value(&e.input), type_name(&e.input), e.kind
        ));
    }
    Err(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn like_pydantic() {
        let e = card_layout(&json!({"sections": [{"fields": [{"field": "", "format": "nope"}]}], "x": 1})).unwrap_err();
        assert_eq!(e, "3 validation errors for CardLayout\nsections.0.fields.0.field\n  String should have at least 1 character [type=string_too_short, input_value='', input_type=str]\n    For further information visit https://errors.pydantic.dev/2.14/v/string_too_short\nsections.0.fields.0.format\n  Input should be 'text', 'markdown', 'number', 'currency', 'percent', 'date' or 'badge' [type=literal_error, input_value='nope', input_type=str]\n    For further information visit https://errors.pydantic.dev/2.14/v/literal_error\nx\n  Extra inputs are not permitted [type=extra_forbidden, input_value=1, input_type=int]\n    For further information visit https://errors.pydantic.dev/2.14/v/extra_forbidden");
        let e = card_layout(&json!({"sections": vec![json!({"fields": [{"field": "a"}]}); 13]})).unwrap_err();
        assert!(e.contains("List should have at most 12 items after validation, not 13 [type=too_long, input_value=[{'fields': [{'field': 'a...lds': [{'field': 'a'}]}], input_type=list]"), "{e}");
        let e = card_layout(&json!({"sections": [{"fields": [{"field": "a".repeat(130), "currency": "usd", "label": 5}]}], "title_field": null, "show_narrative": "maybe"})).unwrap_err();
        assert!(e.starts_with("5 validation errors for CardLayout\ntitle_field\n  Input should be a valid string [type=string_type, input_value=None, input_type=NoneType]"), "{e}");
        assert!(e.contains("input_value='aaaaaaaaaaaaaaaaaaaaaaaa...aaaaaaaaaaaaaaaaaaaaaaa', input_type=str]"), "{e}");
        let ok = card_layout(&json!({"show_related": 0, "sections": [{"fields": [{"field": "a", "format": "date"}], "title": "T"}]})).unwrap();
        assert_eq!(serde_json::to_string(&ok).unwrap(), r#"{"title_field":"Name","sections":[{"title":"T","fields":[{"field":"a","label":"","format":"date","currency":"USD"}]}],"show_narrative":true,"show_related":false}"#);
    }
}
