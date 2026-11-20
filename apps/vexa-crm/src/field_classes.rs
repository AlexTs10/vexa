//! Per-field classification and the field view one caller gets of one record (field_classes.py).

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};

use regex::Regex;
use serde_json::{Map, Value};

use crate::val::{g, Obj};

pub const CLASSES: [&str; 3] = ["private", "org", "ws"];
pub const NARRATIVE: &str = "$narrative";
pub const MATCH_IDS: &str = "$match_ids";
pub const PSEUDO: [&str; 2] = [NARRATIVE, MATCH_IDS];
pub const ROOM_RULE_KEY: &str = "room_fields";
pub const ROOM_RULES: [&str; 2] = ["intersection", "classified"];
pub const DEFAULT_ROOM_RULE: &str = "intersection";

pub type Set = BTreeSet<String>;

fn private_name() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new("(lastcontact|contacthistory|lastemail|lastmessage|lastmeeting|lastinteraction|lastreply|emailthread|mailthread|interactions|timeline|emailsnippet|emailbody|emailsubject|threadsummary)").unwrap()
    })
}

fn norm(name: &str) -> String {
    crate::val::lower(name).chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect()
}

/// (class, workspaces) for a field with no classification row.
pub fn default_class(name: &str, prop: &Value) -> (String, Vec<String>) {
    let empty = Value::Object(Map::new());
    let prop = if prop.is_object() { prop } else { &empty };
    let declared = g(prop, "x-class");
    if declared.as_str() == Some("private") || declared.as_str() == Some("org") {
        return (declared.as_str().unwrap().to_owned(), Vec::new());
    }
    if let Some(ws) = declared.get("ws").and_then(Value::as_array) {
        return ("ws".into(), ws.iter().map(crate::val::pystr).filter(|w| !w.is_empty()).collect());
    }
    if name == MATCH_IDS {
        return ("private".into(), Vec::new());
    }
    if name == NARRATIVE {
        return ("org".into(), Vec::new());
    }
    let source = crate::val::lower(&crate::val::or_str(g(prop, "x-source")));
    if ["email", "mail", "calendar"].contains(&source.as_str()) || private_name().is_match(&norm(name)) {
        return ("private".into(), Vec::new());
    }
    ("org".into(), Vec::new())
}

/// Every field's class for one organisation: rows first, then default_class.
pub struct Classes {
    rows: HashMap<(String, String), (String, Vec<String>)>,
    row_keys: Vec<(String, String)>,
    definitions: Obj,
    cache: RefCell<HashMap<(String, String), (String, Vec<String>)>>,
}

impl Classes {
    pub fn new(rows: &[Obj], definitions: Obj) -> Self {
        let mut map = HashMap::new();
        let mut keys = Vec::new();
        for r in rows {
            let kind = crate::val::s(crate::val::m(r, "object_type"));
            let field = crate::val::s(crate::val::m(r, "field"));
            let class = crate::val::s(crate::val::m(r, "class"));
            let class = if CLASSES.contains(&class.as_str()) { class } else { "private".into() };
            let ws = match crate::val::m(r, "workspaces") {
                Value::Array(a) => a.iter().filter_map(|w| w.as_str().map(str::to_owned)).collect(),
                _ => Vec::new(),
            };
            if !map.contains_key(&(kind.clone(), field.clone())) {
                keys.push((kind.clone(), field.clone()));
            }
            map.insert((kind, field), (class, ws));
        }
        Classes { rows: map, row_keys: keys, definitions, cache: RefCell::new(HashMap::new()) }
    }

    pub fn empty() -> Self {
        Classes::new(&[], Map::new())
    }

    /// The type's properties (an empty map when it has none).
    pub fn props(&self, kind: &str) -> Obj {
        match self.definitions.get(kind).and_then(|d| d.get("properties")) {
            Some(Value::Object(o)) => o.clone(),
            _ => Map::new(),
        }
    }

    pub fn prop_names(&self, kind: &str) -> Vec<String> {
        self.props(kind).keys().cloned().collect()
    }

    pub fn of(&self, kind: &str, name: &str) -> (String, Vec<String>) {
        let key = (kind.to_owned(), name.to_owned());
        if let Some(hit) = self.cache.borrow().get(&key) {
            return hit.clone();
        }
        let got = self.rows.get(&key).cloned().unwrap_or_else(|| {
            let props = self.props(kind);
            default_class(name, props.get(name).unwrap_or(&Value::Null))
        });
        self.cache.borrow_mut().insert(key, got.clone());
        got
    }

    pub fn names(&self, kind: &str) -> Set {
        let mut out: Set = self.prop_names(kind).into_iter().collect();
        for (k, f) in &self.row_keys {
            if k == kind {
                out.insert(f.clone());
            }
        }
        for p in PSEUDO {
            out.insert(p.to_owned());
        }
        out
    }

    pub fn private(&self, kind: &str) -> Set {
        self.names(kind).into_iter().filter(|n| self.of(kind, n).0 == "private").collect()
    }

    pub fn shared_with(&self, kind: &str, workspaces: &Set) -> Set {
        self.names(kind)
            .into_iter()
            .filter(|n| {
                let (c, ws) = self.of(kind, n);
                c == "ws" && ws.iter().any(|w| workspaces.contains(w))
            })
            .collect()
    }

    pub fn shared_elsewhere(&self, kind: &str, workspaces: &Set) -> Set {
        self.names(kind)
            .into_iter()
            .filter(|n| {
                let (c, ws) = self.of(kind, n);
                c == "ws" && !ws.iter().any(|w| workspaces.contains(w))
            })
            .collect()
    }
}

/// What one caller reads of one record. `allowed` None = every field, minus `excluded`.
#[derive(Debug, Clone, Default)]
pub struct FieldView {
    pub allowed: Option<Set>,
    pub excluded: Set,
    pub full: bool,
    pub narrative: bool,
    pub match_ids: bool,
    pub props: Vec<String>,
}

impl FieldView {
    pub fn has(&self, name: &str) -> bool {
        if self.excluded.contains(name) {
            return false;
        }
        self.allowed.as_ref().is_none_or(|a| a.contains(name))
    }

    pub fn filter(&self, values: &Value) -> Value {
        let mut out = Map::new();
        if let Value::Object(o) = values {
            for (k, v) in o {
                if self.has(k) {
                    out.insert(k.clone(), v.clone());
                }
            }
        }
        Value::Object(out)
    }

    /// Field names with '*' for all (card faces, layouts).
    pub fn readable(&self) -> Set {
        if self.allowed.is_none() && self.excluded.is_empty() {
            return ["*".to_owned()].into_iter().collect();
        }
        let base: Set = match &self.allowed {
            None => self.props.iter().cloned().collect(),
            Some(a) => a.clone(),
        };
        base.into_iter().filter(|n| !self.excluded.contains(n) && !PSEUDO.contains(&n.as_str())).collect()
    }

    pub fn partial(&self) -> bool {
        !(self.allowed.is_none() && self.excluded.is_empty())
    }
}

/// A policy's field list (['*'] for all) as FieldView.allowed.
pub fn as_set(fields: &[String]) -> Option<Set> {
    if fields.iter().any(|f| f == "*") {
        None
    } else {
        Some(fields.iter().cloned().collect())
    }
}

pub fn intersect(a: &Option<Set>, b: &Option<Set>) -> Option<Set> {
    match (a, b) {
        (None, None) => None,
        (None, Some(b)) => Some(b.clone()),
        (Some(a), None) => Some(a.clone()),
        (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
    }
}
