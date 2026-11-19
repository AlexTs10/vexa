//! A custom service's setup proposal: its shape (setup_schema: every key a
//! proposal may carry, refusals naming the field as pydantic words them) and
//! what it means (connection_setup.validate).

use serde_json::{json, Map, Value};

use crate::fail::Fail;
use crate::service;

const SETUP_KEYS: [&str; 9] = ["oauth", "documentation_url", "endpoint", "header", "scheme", "prefix", "method", "secret_label", "fields"];
const OAUTH_KEYS: [&str; 4] = ["authorization_url", "token_url", "scopes", "token_auth"];
const FIELD_KEYS: [&str; 3] = ["name", "label", "location"];

/// One pydantic error: its location and message, or an extra key.
struct Problem {
    loc: Vec<String>,
    msg: String,
    extra: Option<&'static [&'static str]>,
}

#[derive(Default)]
struct Errors(Vec<Problem>);

impl Errors {
    fn push(&mut self, loc: &[String], msg: String) {
        self.0.push(Problem { loc: loc.to_vec(), msg, extra: None });
    }
}

fn at(loc: &[String], key: &str) -> Vec<String> {
    let mut l = loc.to_vec();
    l.push(key.to_owned());
    l
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

fn choices(options: &[&str]) -> String {
    let quoted: Vec<String> = options.iter().map(|o| format!("'{o}'")).collect();
    match quoted.len() {
        1 => quoted[0].clone(),
        n => format!("{} or {}", quoted[..n - 1].join(", "), quoted[n - 1]),
    }
}

/// A str field with length bounds; an absent one takes the default.
#[allow(clippy::too_many_arguments)]
fn string(o: &Map<String, Value>, key: &str, loc: &[String], required: bool, default: &str, min: usize, max: usize, errors: &mut Errors) -> String {
    let here = at(loc, key);
    match o.get(key) {
        None if required => {
            errors.push(&here, "Field required".into());
            String::new()
        }
        None => default.to_owned(),
        Some(Value::String(s)) => {
            let n = s.chars().count();
            if n < min {
                errors.push(&here, format!("String should have at least {}", plural(min, "character")));
            } else if n > max {
                errors.push(&here, format!("String should have at most {}", plural(max, "character")));
            }
            s.clone()
        }
        Some(_) => {
            errors.push(&here, "Input should be a valid string".into());
            String::new()
        }
    }
}

fn literal(o: &Map<String, Value>, key: &str, loc: &[String], default: &str, options: &[&str], errors: &mut Errors) -> String {
    match o.get(key) {
        None => default.to_owned(),
        Some(Value::String(s)) if options.contains(&s.as_str()) => s.clone(),
        Some(_) => {
            errors.push(&at(loc, key), format!("Input should be {}", choices(options)));
            String::new()
        }
    }
}

fn extras(o: &Map<String, Value>, loc: &[String], allowed: &'static [&'static str], errors: &mut Errors) {
    for k in o.keys() {
        if !allowed.contains(&k.as_str()) {
            errors.0.push(Problem { loc: at(loc, k), msg: String::new(), extra: Some(allowed) });
        }
    }
}

fn list<'a>(o: &'a Map<String, Value>, key: &str, loc: &[String], errors: &mut Errors) -> Option<&'a Vec<Value>> {
    match o.get(key) {
        None => None,
        Some(Value::Array(a)) => Some(a),
        Some(_) => {
            errors.push(&at(loc, key), "Input should be a valid list".into());
            None
        }
    }
}

fn length(items: &[Value], loc: &[String], min: usize, max: usize, errors: &mut Errors) {
    if items.len() < min {
        errors.push(loc, format!("List should have at least {} after validation, not {}", plural(min, "item"), items.len()));
    } else if items.len() > max {
        errors.push(loc, format!("List should have at most {} after validation, not {}", plural(max, "item"), items.len()));
    }
}

fn is_field_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && s.chars().count() <= 40 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn oauth(v: &Value, loc: &[String], errors: &mut Errors) -> Value {
    let Some(o) = v.as_object() else {
        errors.push(loc, "Input should be a valid dictionary or instance of OAuthSpec".into());
        return Value::Null;
    };
    let authorization_url = string(o, "authorization_url", loc, true, "", 0, 2000, errors);
    let token_url = string(o, "token_url", loc, true, "", 0, 2000, errors);
    let scopes_loc = at(loc, "scopes");
    let mut scopes = Vec::new();
    match o.get("scopes") {
        None => errors.push(&scopes_loc, "Field required".into()),
        Some(Value::Array(items)) => {
            let before = errors.0.len();
            for (i, item) in items.iter().enumerate() {
                let here = at(&scopes_loc, &i.to_string());
                match item {
                    Value::String(s) => {
                        let n = s.chars().count();
                        if n < 1 {
                            errors.push(&here, "String should have at least 1 character".into());
                        } else if n > 300 {
                            errors.push(&here, "String should have at most 300 characters".into());
                        }
                        scopes.push(json!(s));
                    }
                    _ => errors.push(&here, "Input should be a valid string".into()),
                }
            }
            if errors.0.len() == before {
                length(items, &scopes_loc, 1, 30, errors);
            }
        }
        Some(_) => errors.push(&scopes_loc, "Input should be a valid list".into()),
    }
    let token_auth = literal(o, "token_auth", loc, "client_secret_post", &["client_secret_post", "client_secret_basic"], errors);
    extras(o, loc, &OAUTH_KEYS, errors);
    json!({"authorization_url": authorization_url, "token_url": token_url, "scopes": scopes, "token_auth": token_auth})
}

fn input_field(v: &Value, loc: &[String], errors: &mut Errors) -> Value {
    let Some(o) = v.as_object() else {
        errors.push(loc, "Input should be a valid dictionary or instance of InputField".into());
        return Value::Null;
    };
    let name = match o.get("name") {
        None => {
            errors.push(&at(loc, "name"), "Field required".into());
            String::new()
        }
        Some(Value::String(s)) => {
            if !is_field_name(s) {
                errors.push(&at(loc, "name"), "String should match pattern '^[A-Za-z][A-Za-z0-9_]{0,39}$'".into());
            }
            s.clone()
        }
        Some(_) => {
            errors.push(&at(loc, "name"), "Input should be a valid string".into());
            String::new()
        }
    };
    let label = string(o, "label", loc, true, "", 1, 80, errors);
    let location = literal(o, "location", loc, "body", &["query", "body"], errors);
    extras(o, loc, &FIELD_KEYS, errors);
    json!({"name": name, "label": label, "location": location})
}

/// SetupSpec.model_validate(raw).model_dump(), or the describe() sentence.
pub fn parse(raw: &Value) -> Result<Value, String> {
    let root: Vec<String> = Vec::new();
    let mut errors = Errors::default();
    let Some(o) = raw.as_object() else {
        return Err("setup: Input should be a valid dictionary or instance of SetupSpec".into());
    };
    let oauth = match o.get("oauth") {
        None | Some(Value::Null) => Value::Null,
        Some(v) => oauth(v, &at(&root, "oauth"), &mut errors),
    };
    let documentation_url = string(o, "documentation_url", &root, false, "", 0, 2000, &mut errors);
    let endpoint = string(o, "endpoint", &root, false, "", 0, 2000, &mut errors);
    let header = string(o, "header", &root, false, "Authorization", 0, 64, &mut errors);
    let scheme = literal(o, "scheme", &root, "bearer", &["bearer", "raw", "telegram", "prefix"], &mut errors);
    let prefix = string(o, "prefix", &root, false, "", 0, 32, &mut errors);
    let method = literal(o, "method", &root, "GET", &["GET", "POST"], &mut errors);
    let secret_label = string(o, "secret_label", &root, false, "API token", 1, 80, &mut errors);
    let mut fields = Vec::new();
    if let Some(items) = list(o, "fields", &root, &mut errors) {
        let before = errors.0.len();
        for (i, item) in items.iter().enumerate() {
            fields.push(input_field(item, &at(&at(&root, "fields"), &i.to_string()), &mut errors));
        }
        if errors.0.len() == before {
            length(items, &at(&root, "fields"), 0, 10, &mut errors);
        }
    }
    extras(o, &root, &SETUP_KEYS, &mut errors);
    if !errors.0.is_empty() {
        return Err(describe(&errors));
    }
    Ok(json!({
        "oauth": oauth, "documentation_url": documentation_url, "endpoint": endpoint, "header": header,
        "scheme": scheme, "prefix": prefix, "method": method, "secret_label": secret_label, "fields": fields,
    }))
}

/// One sentence per rejected field, naming it, never the value sent.
fn describe(errors: &Errors) -> String {
    let parts: Vec<String> = errors
        .0
        .iter()
        .map(|e| {
            let mut where_ = vec!["setup".to_owned()];
            where_.extend(e.loc.iter().cloned());
            let where_ = where_.join(".");
            match e.extra {
                Some(allowed) => format!("{where_} is not a setup field (allowed: {})", allowed.join(", ")),
                None => format!("{where_}: {}", e.msg),
            }
        })
        .collect();
    if parts.is_empty() { "setup is invalid".into() } else { parts.join("; ") }
}

/// Why validate refused a proposal.
pub enum Refusal {
    /// The shape: describe()'s sentence.
    Shape(String),
    /// The meaning: a fixed sentence of this package's own.
    Meaning(String),
}

const TELEGRAM: [&str; 3] = [
    "https://api.telegram.org/bot{secret}/sendMessage",
    "https://api.telegram.org/bot{secret}/getMe",
    "https://api.telegram.org/bot{secret}/getUpdates",
];

/// connection_setup.validate: the proposal in today's shape, or why not.
pub fn validate(raw: &Value) -> Result<Value, Refusal> {
    let s = parse(raw).map_err(Refusal::Shape)?;
    let m = |t: &str| Refusal::Meaning(t.to_owned());
    let text = |k: &str| s[k].as_str().unwrap_or("").to_owned();
    let fields = s["fields"].as_array().cloned().unwrap_or_default();
    let (scheme, header, method, endpoint, prefix) = (text("scheme"), text("header"), text("method"), text("endpoint"), text("prefix"));
    if let Some(oauth) = s["oauth"].as_object() {
        if !fields.is_empty() {
            return Err(m("OAuth call arguments belong in each service call, not application setup"));
        }
        for key in ["authorization_url", "token_url"] {
            service::validate_endpoint(oauth[key].as_str().unwrap_or("")).map_err(|e| Refusal::Meaning(e.sentence()))?;
        }
        if scheme != "bearer" || header != "Authorization" {
            return Err(m("OAuth uses Bearer authorization"));
        }
        let scopes = oauth["scopes"].as_array().cloned().unwrap_or_default();
        if scopes.iter().any(|v| {
            let sc = v.as_str().unwrap_or("");
            sc.is_empty() || sc.chars().count() > 300 || sc.chars().any(char::is_whitespace)
        }) {
            return Err(m("Invalid OAuth scopes"));
        }
    }
    if !prefix.is_empty() && scheme != "prefix" {
        return Err(m("An authentication prefix needs scheme prefix"));
    }
    if scheme == "telegram" {
        if !TELEGRAM.contains(&endpoint.as_str()) {
            return Err(m("Choose a supported Telegram bot endpoint"));
        }
        let expected = if endpoint.ends_with("/sendMessage") { "POST" } else { "GET" };
        if method != expected {
            return Err(m("Telegram method does not match endpoint"));
        }
        if expected == "POST" && !fields.iter().any(|f| f["name"] == "chat_id" && f["location"] == "body") {
            return Err(m("Telegram sendMessage requires a chat_id field filled by the user"));
        }
    } else {
        service::configure("validation-only", &endpoint, &header, &scheme, &method, &prefix).map_err(|e| Refusal::Meaning(e.sentence()))?;
    }
    if endpoint.is_empty() {
        return Err(m("Prepare the HTTPS endpoint before requesting setup"));
    }
    let mut names: Vec<&str> = fields.iter().map(|f| f["name"].as_str().unwrap_or("")).collect();
    names.sort();
    names.dedup();
    if names.len() != fields.len() {
        return Err(m("Field names must be unique"));
    }
    if method == "GET" && fields.iter().any(|f| f["location"] == "body") {
        return Err(m("GET fields must use query placement"));
    }
    Ok(s)
}

/// A stored proposal in today's shape, so a key added since does not read as a change.
pub fn normalised(spec: &Value) -> Value {
    if !crate::util::truthy(Some(spec)) {
        return json!({});
    }
    parse(spec).unwrap_or_else(|_| spec.clone())
}

impl From<Refusal> for Fail {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::Shape(s) | Refusal::Meaning(s) => Fail::Http(422, format!("Invalid setup specification: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_each_rejected_field() {
        let e = parse(&json!({"endpoint": 5, "scheme": "basic", "colour": "x", "fields": [{"name": "1a"}]})).unwrap_err();
        assert_eq!(
            e,
            "setup.endpoint: Input should be a valid string; setup.scheme: Input should be 'bearer', 'raw', 'telegram' or 'prefix'; setup.fields.0.name: String should match pattern '^[A-Za-z][A-Za-z0-9_]{0,39}$'; setup.fields.0.label: Field required; setup.colour is not a setup field (allowed: oauth, documentation_url, endpoint, header, scheme, prefix, method, secret_label, fields)"
        );
        let ok = validate(&json!({"endpoint": "https://api.example.com/v1/me"})).ok().unwrap();
        assert_eq!(ok["header"], "Authorization");
        assert_eq!(ok["secret_label"], "API token");
        assert!(matches!(validate(&json!({"endpoint": "http://api.example.com/x"})), Err(Refusal::Meaning(_))));
        assert!(matches!(validate(&json!({})), Err(Refusal::Meaning(s)) if s == "Prepare the HTTPS endpoint before requesting setup"));
    }
}
