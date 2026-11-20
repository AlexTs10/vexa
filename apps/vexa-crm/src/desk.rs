//! The desk (desktop phase D1): one person's placements, arrangement versions and desk proposals.
//!
//! A desk is the person's own state, not shared organisation state, so it never touches a record:
//! - **placements** (\`crm_desk\`): which agents, files and cards are on this person's desk;
//! - **arrangement versions** (\`crm_desk_layouts\`, append-only): every applied change is a new version
//!   carrying the layout AND the placement set after it, so Undo restores both. Version 0 is the
//!   default (Workspaces, Agents, Files, Cards; stacked, shown, expanded) and has no row;
//! - **desk proposals** (\`crm_desk_proposals\`): what an agent may only suggest; the person applies or
//!   dismisses it with their own credential; pending for at most seven days, or fewer where the
//!   company's \`_global/POLICIES.md\` narrows it (\`policies.rs\`, as every desk limit).
//!
//! **Who arranges directly** is decided from the caller identity resolved, never from what an agent
//! says: the person themselves, or a worker in a turn the person typed in their own one-person chat
//! (\`regime == "human"\`, not \`shared\`). Anything else is refused with \`propose_instead\`. A person
//! only ever arranges their own desk: the person is the caller's subject, never an argument.
//!
//! Operations are declarative data, validated one by one; a bad one refuses the whole list with its
//! index, so nothing half-applies.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use regex::Regex;
use serde_json::{json, Map, Value};
use vexa_native_kit::pg::{Int, Tx};

use crate::caller::Caller;
use crate::err::{CrmError, Detail, R};
use crate::features;
use crate::policies::{default_of, DEFAULTS as LIMIT_DEFAULTS};
use crate::schema as s;
use crate::store::Store;
use crate::val::{g, m, py_eq, pystr, strip, truthy, Obj};

pub const DEFAULT_SECTIONS: [&str; 4] = ["workspaces", "agents", "files", "cards"];

/// TITLES[section].
pub fn title(sid: &str) -> &'static str {
    match sid {
        "workspaces" => "Workspaces",
        "agents" => "Agents",
        "files" => "Files",
        _ => "Cards",
    }
}

/// SECTION_OF_KIND[kind]: the section a ref kind is drawn in.
pub fn section_of_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "workspace" => Some("workspaces"),
        "agent" | "chat" => Some("agents"),
        "file" => Some("files"),
        "card" => Some("cards"),
        _ => None,
    }
}

/// The limits' defaults; a company narrows them in \`_global/POLICIES.md\`, read per call.
pub fn placements_max() -> i64 {
    default_of("desk_placements_max")
}
pub fn pending_max() -> i64 {
    default_of("card_proposals_pending_max")
}
pub fn per_session_per_day() -> i64 {
    default_of("card_proposals_per_agent_per_day")
}
pub const OPS_MAX: usize = 50;
pub const WHERE_MAX: usize = 300;
pub const NAME_MAX: usize = 80;
pub const IDS_MAX: usize = 200;

pub const GROUP_BY: [&str; 4] = ["workspace", "type", "state", "about"];
pub const SIZES: [&str; 3] = ["compact", "normal", "tall"];

const DAY_US: i64 = 86_400_000_000;

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).unwrap())
}

/// _SLUG.fullmatch(text).
pub fn slug_ok(text: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"\A[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}\z").is_match(text)
}

/// _ID.fullmatch(text).
pub fn id_ok(text: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"\A[A-Za-z0-9_][A-Za-z0-9_.:\-]{0,127}\z").is_match(text)
}

/// _CONTROL.search(text): a control character or a backslash.
fn has_control(text: &str) -> bool {
    text.chars().any(|c| ('\x00'..='\x1f').contains(&c) || c == '\x7f' || c == '\\')
}

fn chars(text: &str) -> usize {
    text.chars().count()
}

/// _refusal(reason, instruction, **extra).
pub fn refusal(reason: &str, instruction: &str, extra: &[(&str, Value)]) -> Value {
    let mut o = Map::new();
    o.insert("status".into(), "refused".into());
    o.insert("reason".into(), reason.into());
    o.insert("instruction".into(), instruction.into());
    for (k, v) in extra {
        o.insert((*k).to_owned(), v.clone());
    }
    Value::Object(o)
}

pub fn propose_instead() -> Value {
    refusal(
        "propose_instead",
        "Only the person, or you in a turn they typed in their own one-person chat, may change their \
         desktop directly. Call desktop_arrange_propose with the same ops and a one-line reason; the person \
         applies it from their desktop. Do not retry it another way.",
        &[],
    )
}

pub fn confirm() -> Value {
    refusal(
        "person_confirmation_required",
        "The person applies or dismisses a desktop suggestion themselves, on their desktop. Tell them it is \
         waiting; do not retry it another way.",
        &[],
    )
}

pub fn not_readable() -> Value {
    refusal(
        "not_readable",
        "That file is in a workspace this person cannot read here, so it cannot go on their desktop. Say so; \
         do not retry it another way.",
        &[],
    )
}

pub fn card_not_readable() -> Value {
    refusal("not_readable", "This person cannot read that card, so it cannot go on their desktop. Say so; do not retry it another way.", &[])
}

pub fn ref_kind() -> Value {
    refusal("ref_kind_not_enabled", "Cards are not on the desktop yet. Place an agent or a file instead.", &[])
}

pub fn placements_full(n: i64) -> Value {
    refusal("desk_placements_max", &format!("The desktop holds at most {n} placed items. Ask the person what to remove first."), &[])
}

pub fn pending_full(n: i64) -> Value {
    refusal(
        "proposals_pending_max",
        &format!("This person already has {n} desktop suggestions waiting. Do not add another; mention the waiting ones instead."),
        &[],
    )
}

pub fn daily_full(n: i64) -> Value {
    refusal("proposals_daily_max", &format!("This session has made its {n} desktop suggestions for today. Stop suggesting."), &[])
}

pub fn desk_changed(version: i64) -> Value {
    refusal(
        "desk_changed",
        "The desktop changed since you read it. Call desktop_read and apply your change to the version it returns.",
        &[("version", Value::from(version))],
    )
}

/// DeskRefused(body, status): a typed refusal with its own status (409 for a conflict, 422 for a
/// ref kind not enabled).
pub fn desk_refused(body: Value, status: u16) -> CrmError {
    CrmError::new("DeskRefused", status, Detail::Body(body))
}

/// Invalid(message): 422.
pub fn invalid(msg: impl Into<String>) -> CrmError {
    CrmError::new("Invalid", 422, Detail::Text(msg.into()))
}

fn key_error(k: &str) -> CrmError {
    CrmError::internal(format!("KeyError: '{k}'"))
}

/// op[k], a KeyError when it is absent.
fn key<'a>(op: &'a Value, k: &str) -> R<&'a Value> {
    op.get(k).ok_or_else(|| key_error(k))
}

/// A dict's membership test on a JSON value: an unhashable value is a TypeError.
fn hashable(v: &Value) -> R<()> {
    match v {
        Value::Array(_) => Err(CrmError::internal("TypeError: unhashable type: 'list'")),
        Value::Object(_) => Err(CrmError::internal("TypeError: unhashable type: 'dict'")),
        _ => Ok(()),
    }
}

fn is_section(v: &Value) -> bool {
    v.as_str().is_some_and(|t| DEFAULT_SECTIONS.contains(&t))
}

/// isinstance(v, int) and not isinstance(v, bool).
fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) if n.is_i64() || n.is_u64() => Some(n.as_i64().unwrap_or(i64::MAX)),
        _ => None,
    }
}

// ── refs ──────────────────────────────────────────────────────────────────────────────────────
const NOT_A_REF: &str = "not a ref (agent:<id>, chat:<session id>, file:<workspace>/<path>, workspace:<slug>, card:<id>)";

/// (kind, ref) for a well-formed ref; 422 naming \`at\` otherwise. \`card:<id>\` only while cards are
/// served (\`desktop_cards\`); \`ref_kind_not_enabled\` otherwise.
pub fn parse_ref(r: &Value, at: &str) -> R<(String, String)> {
    let text = match r {
        Value::String(t) if t.contains(':') && chars(t) <= 600 => t,
        _ => return Err(invalid(format!("{at}: {NOT_A_REF}"))),
    };
    let (kind, rest) = text.split_once(':').unwrap();
    let ok = |k: &str| Ok((k.to_owned(), text.clone()));
    if kind == "card" {
        if !features::cards_served() {
            return Err(desk_refused(ref_kind(), 422));
        }
        if id_ok(rest) {
            return ok(kind);
        }
    }
    if (kind == "agent" || kind == "chat") && id_ok(rest) {
        return ok(kind);
    }
    if kind == "workspace" && slug_ok(rest) && !rest.contains("..") {
        return ok(kind);
    }
    if kind == "file" {
        let (slug, path) = rest.split_once('/').unwrap_or((rest, ""));
        if slug_ok(slug)
            && !slug.contains("..")
            && !path.is_empty()
            && chars(path) <= 500
            && !has_control(path)
            && path.split('/').all(|p| !["", ".", ".."].contains(&p))
        {
            return ok(kind);
        }
    }
    Err(invalid(format!("{at}: {NOT_A_REF}")))
}

/// A file ref is placeable only from a workspace the caller reads now, or their own desk.
pub fn readable_file(caller: &Caller, r: &str) -> bool {
    let rest = r.split_once(':').map(|x| x.1).unwrap_or("");
    let slug = rest.split('/').next().unwrap_or("");
    caller.workspaces.iter().any(|w| w == slug) || (!caller.subject.is_empty() && slug == caller.subject)
}

fn upper_first(text: &str) -> String {
    let mut it = text.chars();
    match it.next() {
        Some(c) => c.to_uppercase().collect::<String>() + it.as_str(),
        None => String::new(),
    }
}

fn lower_first(text: &str) -> String {
    let mut it = text.chars();
    match it.next() {
        Some(c) => crate::val::lower(&c.to_string()) + it.as_str(),
        None => String::new(),
    }
}

/// The words a ref is named by in a summary.
pub fn label(r: &str) -> String {
    let (kind, rest) = r.split_once(':').unwrap_or((r, ""));
    match kind {
        "file" => {
            let mut base = rest.rsplit('/').next().unwrap_or("");
            let tail: String = base.chars().skip(1).collect();
            if tail.contains('.') {
                base = base.rsplit_once('.').map(|x| x.0).unwrap_or(base);
            }
            static RE: OnceLock<Regex> = OnceLock::new();
            let words: Vec<&str> = re(&RE, r"[-_\s\x1c-\x1f]+").split(base).collect();
            let joined = words.join(" ");
            let words = strip(&joined);
            if words.is_empty() {
                "a file".into()
            } else {
                upper_first(words)
            }
        }
        "agent" => "an agent".into(),
        "chat" => "a chat".into(),
        "workspace" => "a workspace".into(),
        "card" => "a card".into(),
        _ => "an item".into(),
    }
}

/// card_ops.card_id: the record id of a \`card:<id>\` desk ref.
fn card_id(r: &str) -> String {
    r.strip_prefix("card:").map(str::to_owned).unwrap_or_default()
}

// ── the layout document ─────────────────────────────────────────────────────────────────────────
pub fn default_section(sid: &str) -> Obj {
    let v = json!({"id": sid, "hidden": false, "collapsed": false, "column": 1, "span": 1, "size": "normal"});
    v.as_object().cloned().unwrap()
}

fn dict_of(v: &Value) -> Obj {
    v.as_object().cloned().unwrap_or_default()
}

/// A stored layout with every default filled in. A section type that appears later is appended at
/// the end, never above what the person arranged.
pub fn normalise(raw: &Value) -> Obj {
    let mut sections: Vec<Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    if let Some(list) = g(raw, "sections").as_array() {
        for sec in list {
            let Some(o) = sec.as_object() else { continue };
            let Some(sid) = o.get("id").and_then(Value::as_str) else { continue };
            if DEFAULT_SECTIONS.contains(&sid) && !seen.iter().any(|x| x == sid) {
                seen.push(sid.to_owned());
                let mut out = default_section(sid);
                for (k, v) in o {
                    if out.contains_key(k) {
                        out.insert(k.clone(), v.clone());
                    }
                }
                sections.push(Value::Object(out));
            }
        }
    }
    for sid in DEFAULT_SECTIONS {
        if !seen.iter().any(|x| x == sid) {
            sections.push(Value::Object(default_section(sid)));
        }
    }
    let hidden: Vec<Value> = g(raw, "hidden_cards").as_array().map(|a| a.iter().filter(|r| r.is_string()).take(500).cloned().collect()).unwrap_or_default();
    let mut columns = Map::new();
    columns.insert("phone".into(), 1.into());
    columns.insert("desktop".into(), 1.into());
    for (k, v) in dict_of(g(raw, "columns")) {
        columns.insert(k, v);
    }
    let mut out = Map::new();
    out.insert("sections".into(), Value::Array(sections));
    out.insert("order".into(), Value::Object(dict_of(g(raw, "order"))));
    out.insert("groups".into(), Value::Object(dict_of(g(raw, "groups"))));
    out.insert("filters".into(), Value::Object(dict_of(g(raw, "filters"))));
    // member cards the person took off their desk: their own view, the card is untouched
    out.insert("hidden_cards".into(), Value::Array(hidden));
    out.insert("columns".into(), Value::Object(columns));
    out
}

// ── op validation (shape only; effects are applied below) ──────────────────────────────────────
/// _KEYS: each op, its required keys and its optional keys.
const KEYS: [(&str, &[&str], &[&str]); 16] = [
    ("order", &["section", "ids"], &[]),
    ("move", &["id"], &["before", "after"]),
    ("group", &["section"], &["by", "named"]),
    ("show", &["section"], &[]),
    ("hide", &["section"], &[]),
    ("collapse", &["section"], &[]),
    ("expand", &["section"], &[]),
    ("section_top", &["section"], &[]),
    ("section_order", &["sections"], &[]),
    ("section_place", &["section", "column"], &["span", "side_by_side_with"]),
    ("section_size", &["section", "size"], &[]),
    ("place", &["ref"], &[]),
    ("remove", &["ref"], &[]),
    ("filter", &["section", "where"], &["until"]),
    ("save", &["name"], &[]),
    ("restore", &["name"], &[]),
];

fn section_of(op: &Value, at: &str, k: &str) -> R<String> {
    let sid = g(op, k);
    if !is_section(sid) {
        return Err(invalid(format!("{at}: {k} must be one of {}", DEFAULT_SECTIONS.join(", "))));
    }
    Ok(sid.as_str().unwrap().to_owned())
}

fn int_of(op: &Value, k: &str, at: &str, lo: i64, hi: i64) -> R<i64> {
    match as_int(g(op, k)) {
        Some(v) if lo <= v && v <= hi => Ok(v),
        _ => Err(invalid(format!("{at}: {k} must be a whole number {lo}..{hi}"))),
    }
}

/// _name: the op's name, stripped, 1..NAME_MAX characters.
pub fn name_of(op: &Value, at: &str) -> R<String> {
    match g(op, "name") {
        Value::String(n) if !strip(n).is_empty() && chars(strip(n)) <= NAME_MAX => Ok(strip(n).to_owned()),
        _ => Err(invalid(format!("{at}: name must be 1..{NAME_MAX} characters"))),
    }
}

/// _ids: distinct well-formed refs, each in \`section\` when one is given.
fn ids_of(value: &Value, at: &str, section: Option<&str>) -> R<Vec<String>> {
    let list = match value {
        Value::Array(a) if a.len() <= IDS_MAX => a,
        _ => return Err(invalid(format!("{at}: ids must be a list of at most {IDS_MAX} refs"))),
    };
    let mut out: Vec<String> = Vec::new();
    for (n, r) in list.iter().enumerate() {
        let (kind, r) = parse_ref(r, &format!("{at}.ids[{n}]"))?;
        if let Some(sec) = section.filter(|x| !x.is_empty()) {
            if section_of_kind(&kind) != Some(sec) {
                return Err(invalid(format!("{at}.ids[{n}]: a {kind} ref is not in {}", title(sec))));
            }
        }
        if !out.contains(&r) {
            out.push(r);
        }
    }
    Ok(out)
}

/// iso_datetime(text) parses as datetime.fromisoformat (the C implementation).
fn valid_iso(text: &str) -> bool {
    fromisoformat(text).is_some()
}

/// The op's shape: a known op, its own keys only, valid values. Returns it unchanged.
pub fn check_op(op: &Value, at: &str) -> R<Value> {
    let names: Vec<&str> = KEYS.iter().map(|k| k.0).collect();
    let known = match op {
        Value::Object(o) => {
            let kind = o.get("op").unwrap_or(&Value::Null);
            hashable(kind)?;
            kind.as_str().and_then(|k| KEYS.iter().find(|x| x.0 == k))
        }
        _ => None,
    };
    let Some((kind, required, optional)) = known else {
        let shown = vexa_native_kit::pyjson::py_repr(if op.is_object() { g(op, "op") } else { op });
        return Err(invalid(format!("{at}: unknown op {shown}; one of {}", names.join(", "))));
    };
    let kind = *kind;
    let o = op.as_object().unwrap();
    let keys: BTreeSet<&str> = o.keys().map(String::as_str).filter(|k| *k != "op").collect();
    let has_required = required.iter().all(|k| keys.contains(k));
    let extra = keys.iter().any(|k| !required.contains(k) && !optional.contains(k));
    if !has_required || extra {
        let mut req: Vec<&str> = required.to_vec();
        req.sort();
        let mut opt: Vec<&str> = optional.to_vec();
        opt.sort();
        let tail = if opt.is_empty() { String::new() } else { format!(" and optionally {}", opt.join(", ")) };
        return Err(invalid(format!("{at}: {kind} takes {}{tail}", req.join(", "))));
    }
    match kind {
        "order" => {
            let sid = section_of(op, at, "section")?;
            ids_of(&o["ids"], at, Some(&sid))?;
        }
        "move" => {
            if o.contains_key("before") == o.contains_key("after") {
                return Err(invalid(format!("{at}: move takes exactly one of before, after")));
            }
            let side = if o.contains_key("before") { "before" } else { "after" };
            let other = &o[side];
            if is_section(&o["id"]) || is_section(other) {
                section_of(op, at, "id")?;
                section_of(op, at, side)?;
            } else {
                let (a, _) = parse_ref(&o["id"], &format!("{at}.id"))?;
                let (b, _) = parse_ref(other, &format!("{at}.{side}"))?;
                if section_of_kind(&a) != section_of_kind(&b) {
                    return Err(invalid(format!("{at}: move within one section only")));
                }
            }
        }
        "group" => {
            let sid = section_of(op, at, "section")?;
            if o.contains_key("by") == o.contains_key("named") {
                return Err(invalid(format!("{at}: group takes exactly one of by, named")));
            }
            if let Some(by) = o.get("by") {
                if !by.as_str().is_some_and(|b| GROUP_BY.contains(&b)) {
                    return Err(invalid(format!("{at}: by must be one of {}", GROUP_BY.join(", "))));
                }
            }
            if let Some(named) = o.get("named") {
                let list = match named {
                    Value::Array(a) if (1..=20).contains(&a.len()) => a,
                    _ => return Err(invalid(format!("{at}: named must be a list of 1..20 groups"))),
                };
                for (n, grp) in list.iter().enumerate() {
                    let shape = grp.as_object().is_some_and(|x| x.len() == 2 && x.contains_key("title") && x.contains_key("ids"));
                    let title_ok = shape && matches!(&grp["title"], Value::String(t) if !strip(t).is_empty() && chars(t) <= NAME_MAX);
                    if !title_ok {
                        return Err(invalid(format!("{at}.named[{n}]: a group is {{title, ids}}")));
                    }
                    ids_of(&grp["ids"], &format!("{at}.named[{n}]"), Some(&sid))?;
                }
            }
        }
        "show" | "hide" | "collapse" | "expand" | "section_top" | "section_size" | "filter" => {
            section_of(op, at, "section")?;
            if kind == "section_size" && !o["size"].as_str().is_some_and(|x| SIZES.contains(&x)) {
                return Err(invalid(format!("{at}: size must be one of {}", SIZES.join(", "))));
            }
            if kind == "filter" {
                let w = &o["where"];
                let bad = match w {
                    Value::Null => false,
                    Value::String(t) => strip(t).is_empty() || chars(t) > WHERE_MAX,
                    _ => true,
                };
                if bad {
                    return Err(invalid(format!("{at}: where is a predicate of at most {WHERE_MAX} characters, or null")));
                }
                if let Some(until) = o.get("until") {
                    if !valid_iso(&pystr(until).replace('Z', "+00:00")) {
                        return Err(invalid(format!("{at}: until must be an ISO time")));
                    }
                }
            }
        }
        "section_order" => {
            let ok = match &o["sections"] {
                Value::Array(a) if !a.is_empty() => {
                    let distinct: BTreeSet<String> = a.iter().map(pystr).collect();
                    distinct.len() == a.len() && a.iter().all(is_section)
                }
                _ => false,
            };
            if !ok {
                return Err(invalid(format!("{at}: sections must list distinct sections of {}", DEFAULT_SECTIONS.join(", "))));
            }
        }
        "section_place" => {
            let sid = section_of(op, at, "section")?;
            int_of(op, "column", at, 1, 3)?;
            if o.contains_key("span") {
                int_of(op, "span", at, 1, 3)?;
            }
            if o.contains_key("side_by_side_with") && section_of(op, at, "side_by_side_with")? == sid {
                return Err(invalid(format!("{at}: a section is not beside itself")));
            }
        }
        "place" | "remove" => {
            let (k, _) = parse_ref(&o["ref"], &format!("{at}.ref"))?;
            if k == "workspace" {
                return Err(invalid(format!("{at}: workspaces are navigation and are never placed")));
            }
        }
        _ => {
            name_of(op, at)?;
        }
    }
    Ok(op.clone())
}

pub fn check_ops(ops: &Value) -> R<Vec<Value>> {
    let list = match ops {
        Value::Array(a) if (1..=OPS_MAX).contains(&a.len()) => a,
        _ => return Err(invalid(format!("ops must be a list of 1..{OPS_MAX} operations"))),
    };
    list.iter().enumerate().map(|(i, op)| check_op(op, &format!("ops[{i}]"))).collect()
}

// ── applying ops to a state ─────────────────────────────────────────────────────────────────────
fn index_of(list: &[String], x: &str) -> i64 {
    list.iter().position(|v| v == x).map(|p| p as i64).unwrap_or(0)
}

/// 'Moved Agents above Workspaces' when exactly one section moved; else a generic line.
pub fn moved(before: &[String], after: &[String]) -> String {
    if before == after {
        return "Kept the section order".into();
    }
    let without = |list: &[String], x: &str| list.iter().filter(|y| *y != x).cloned().collect::<Vec<_>>();
    let single: Vec<&String> = after.iter().filter(|x| without(before, x) == without(after, x)).collect();
    if single.is_empty() {
        return "Reordered the sections".into();
    }
    let mut x = single[0];
    let shift = |v: &str| index_of(after, v) - index_of(before, v);
    for v in &single[1..] {
        if shift(v) < shift(x) {
            x = v;
        }
    }
    let i = index_of(after, x) as usize;
    if i + 1 < after.len() {
        return format!("Moved {} above {}", title(x), title(&after[i + 1]));
    }
    format!("Moved {} below {}", title(x), title(&after[i.wrapping_sub(1).min(after.len() - 1)]))
}

/// _reposition: \`x\` moved just before (or after) \`other\`; \`other\` appended when absent.
fn reposition(list: &[Value], x: &Value, other: &Value, before: bool) -> Vec<Value> {
    let mut lst: Vec<Value> = list.iter().filter(|v| !py_eq(v, x)).cloned().collect();
    if !lst.iter().any(|v| py_eq(v, other)) {
        lst.push(other.clone());
    }
    let i = lst.iter().position(|v| py_eq(v, other)).unwrap();
    lst.insert(if before { i } else { i + 1 }, x.clone());
    lst
}

/// What applying an op needs from outside the state: a saved arrangement by name, and whether a
/// card ref is readable (None while cards are not served).
pub trait Lookup {
    fn saved(&mut self, name: &str) -> R<Option<Obj>>;
    fn card_readable(&mut self, r: &str) -> Option<R<bool>>;
}

pub struct State<'a> {
    pub layout: Obj,
    pub placements: Vec<Obj>,
    pub now: String,
    pub caller: &'a Caller,
    pub name: Option<String>,
    pub phrases: Vec<String>,
}

fn dicts(placements: &[Value]) -> R<Vec<Obj>> {
    placements
        .iter()
        .map(|p| p.as_object().cloned().ok_or_else(|| CrmError::internal("TypeError: cannot convert dictionary update sequence element")))
        .collect()
}

fn ref_of(p: &Obj) -> R<&Value> {
    p.get("ref").ok_or_else(|| key_error("ref"))
}

impl<'a> State<'a> {
    pub fn new(layout: &Value, placements: &[Value], now: String, caller: &'a Caller) -> R<Self> {
        Ok(State { layout: normalise(layout), placements: dicts(placements)?, now, caller, name: None, phrases: Vec::new() })
    }

    fn sections(&mut self) -> &mut Vec<Value> {
        self.layout.get_mut("sections").and_then(Value::as_array_mut).expect("normalise writes sections")
    }

    fn sec(&mut self, sid: &str) -> R<&mut Obj> {
        self.sections()
            .iter_mut()
            .filter_map(Value::as_object_mut)
            .find(|x| x.get("id").and_then(Value::as_str) == Some(sid))
            .ok_or_else(|| CrmError::internal("StopIteration"))
    }

    pub fn order(&self) -> Vec<String> {
        self.layout["sections"].as_array().map(|a| a.iter().map(|x| pystr(g(x, "id"))).collect()).unwrap_or_default()
    }

    fn set_order(&mut self, ids: &[String]) -> R<()> {
        let secs = self.sections().clone();
        let mut out = Vec::new();
        for i in ids {
            let found = secs.iter().rev().find(|x| g(x, "id").as_str() == Some(i)).ok_or_else(|| key_error(i))?;
            out.push(found.clone());
        }
        *self.sections() = out;
        Ok(())
    }

    fn map_mut(&mut self, k: &str) -> &mut Obj {
        if !self.layout.get(k).is_some_and(Value::is_object) {
            self.layout.insert(k.to_owned(), Value::Object(Map::new()));
        }
        self.layout.get_mut(k).and_then(Value::as_object_mut).unwrap()
    }

    fn hidden_cards(&mut self) -> &mut Vec<Value> {
        if !self.layout.get("hidden_cards").is_some_and(Value::is_array) {
            self.layout.insert("hidden_cards".into(), Value::Array(Vec::new()));
        }
        self.layout.get_mut("hidden_cards").and_then(Value::as_array_mut).unwrap()
    }

    fn say(&mut self, phrase: String) -> R<()> {
        self.phrases.push(phrase);
        Ok(())
    }

    pub fn apply(&mut self, op: &Value, at: &str, lookup: &mut dyn Lookup) -> R<()> {
        let kind = pystr(key(op, "op")?);
        let kind = kind.as_str();
        let text = |k: &str| -> R<String> { Ok(pystr(key(op, k)?)) };
        if matches!(kind, "show" | "hide" | "collapse" | "expand") {
            let (k, value, verb) = match kind {
                "show" => ("hidden", false, "Showed"),
                "hide" => ("hidden", true, "Hid"),
                "collapse" => ("collapsed", true, "Collapsed"),
                _ => ("collapsed", false, "Expanded"),
            };
            let sid = text("section")?;
            self.sec(&sid)?.insert(k.into(), value.into());
            return self.say(format!("{verb} {}", title(&sid)));
        }
        if kind == "section_top" || kind == "section_order" || (kind == "move" && is_section(key(op, "id")?)) {
            let before = self.order();
            let after: Vec<String> = match kind {
                "section_top" => {
                    let sid = text("section")?;
                    std::iter::once(sid.clone()).chain(before.iter().filter(|x| **x != sid).cloned()).collect()
                }
                "section_order" => {
                    let given: Vec<String> = key(op, "sections")?.as_array().map(|a| a.iter().map(pystr).collect()).unwrap_or_default();
                    given.iter().cloned().chain(before.iter().filter(|x| !given.contains(x)).cloned()).collect()
                }
                _ => {
                    let side = if op.get("before").is_some() { "before" } else { "after" };
                    let list: Vec<Value> = before.iter().map(|x| Value::String(x.clone())).collect();
                    reposition(&list, key(op, "id")?, g(op, side), side == "before").iter().map(pystr).collect()
                }
            };
            self.set_order(&after)?;
            return self.say(moved(&before, &after));
        }
        match kind {
            "section_place" => {
                let sid = text("section")?;
                let column = key(op, "column")?.clone();
                let sec = self.sec(&sid)?;
                sec.insert("column".into(), column.clone());
                let span = match op.get("span") {
                    Some(v) => v.clone(),
                    None => sec.get("span").cloned().unwrap_or(Value::from(1)),
                };
                sec.insert("span".into(), span);
                let other = g(op, "side_by_side_with");
                if truthy(other) {
                    let list: Vec<Value> = self.order().into_iter().map(Value::String).collect();
                    let after: Vec<String> = reposition(&list, &Value::String(sid.clone()), other, false).iter().map(pystr).collect();
                    self.set_order(&after)?;
                    return self.say(format!("Put {} beside {}", title(&sid), title(&pystr(other))));
                }
                self.say(format!("Put {} in column {}", title(&sid), pystr(&column)))
            }
            "section_size" => {
                let sid = text("section")?;
                let size = key(op, "size")?.clone();
                self.sec(&sid)?.insert("size".into(), size.clone());
                self.say(format!("Made {} {}", title(&sid), pystr(&size)))
            }
            "order" => {
                let sid = text("section")?;
                let ids = ids_of(key(op, "ids")?, at, Some(&sid))?;
                self.map_mut("order").insert(sid.clone(), crate::val::str_list(ids));
                self.say(format!("Reordered {}", title(&sid)))
            }
            "move" => {
                let id = key(op, "id")?;
                let idt = pystr(id);
                let sid = section_of_kind(idt.split(':').next().unwrap_or("")).ok_or_else(|| key_error(idt.split(':').next().unwrap_or("")))?;
                let side = if op.get("before").is_some() { "before" } else { "after" };
                let current: Vec<Value> = self.map_mut("order").get(sid).and_then(Value::as_array).cloned().unwrap_or_default();
                let next = reposition(&current, id, g(op, side), side == "before");
                self.map_mut("order").insert(sid.to_owned(), Value::Array(next));
                self.say(format!("Reordered {}", title(sid)))
            }
            "group" => {
                let sid = text("section")?;
                if let Some(by) = op.get("by") {
                    self.map_mut("groups").insert(sid.clone(), json!({"by": by}));
                    return self.say(format!("Grouped {} by {}", title(&sid), pystr(by)));
                }
                let named = key(op, "named")?.as_array().cloned().unwrap_or_default();
                let mut groups = Vec::new();
                for grp in &named {
                    let t = strip(&pystr(key(grp, "title")?)).to_owned();
                    let ids = ids_of(key(grp, "ids")?, at, Some(&sid))?;
                    groups.push(json!({"title": t, "ids": ids}));
                }
                self.map_mut("groups").insert(sid.clone(), json!({"named": groups}));
                let n = named.len();
                self.say(format!("Grouped {} into {n} group{}", title(&sid), if n != 1 { "s" } else { "" }))
            }
            "filter" => {
                let sid = text("section")?;
                let w = key(op, "where")?;
                if w.is_null() {
                    self.map_mut("filters").shift_remove(&sid);
                    return self.say(format!("Cleared the {} filter", title(&sid)));
                }
                let mut f = Map::new();
                f.insert("where".into(), w.clone());
                if let Some(u) = op.get("until") {
                    f.insert("until".into(), u.clone());
                }
                self.map_mut("filters").insert(sid.clone(), Value::Object(f));
                self.say(format!("Filtered {}", title(&sid)))
            }
            "place" => {
                let r = text("ref")?;
                if r.starts_with("file:") && !readable_file(self.caller, &r) {
                    return Err(desk_refused(not_readable(), 403));
                }
                if r.starts_with("card:") {
                    match lookup.card_readable(&r) {
                        None => return Err(desk_refused(ref_kind(), 422)),
                        Some(ok) => {
                            if !ok? {
                                return Err(desk_refused(card_not_readable(), 403));
                            }
                        }
                    }
                    self.hidden_cards().retain(|x| x.as_str() != Some(r.as_str()));
                }
                let mut present = false;
                for p in &self.placements {
                    if ref_of(p)?.as_str() == Some(r.as_str()) {
                        present = true;
                    }
                }
                if !present {
                    let mut p = Map::new();
                    p.insert("ref".into(), r.clone().into());
                    p.insert("placed_at".into(), self.now.clone().into());
                    self.placements.push(p);
                }
                self.say(format!("Placed {}", label(&r)))
            }
            "remove" => {
                let r = text("ref")?;
                let mut kept = Vec::new();
                for p in std::mem::take(&mut self.placements) {
                    if ref_of(&p)?.as_str() != Some(r.as_str()) {
                        kept.push(p);
                    }
                }
                self.placements = kept;
                if r.starts_with("card:") && !self.hidden_cards().iter().any(|x| x.as_str() == Some(r.as_str())) {
                    // a member card leaves my desk; I stay its member
                    self.hidden_cards().push(r.clone().into());
                }
                let k = r.split(':').next().unwrap_or("");
                let sid = section_of_kind(k).ok_or_else(|| key_error(k))?;
                let order = self.map_mut("order");
                if let Some(Value::Array(list)) = order.get_mut(sid) {
                    if list.iter().any(|v| v.as_str() == Some(r.as_str())) {
                        list.retain(|v| v.as_str() != Some(r.as_str()));
                    }
                }
                self.say(format!("Removed {}", label(&r)))
            }
            "save" => {
                let n = name_of(op, at)?;
                self.name = Some(n.clone());
                self.say(format!("Saved as \"{n}\""))
            }
            "restore" => {
                let n = name_of(op, at)?;
                let Some(found) = lookup.saved(&n)? else {
                    return Err(invalid(format!("{at}: no saved arrangement named \"{n}\"")));
                };
                self.layout = normalise(m(&found, "layout"));
                let list = m(&found, "placements").as_array().cloned().ok_or_else(|| CrmError::internal("TypeError: 'NoneType' object is not iterable"))?;
                self.placements = dicts(&list)?;
                self.say(format!("Restored \"{n}\""))
            }
            _ => Err(invalid(format!("{at}: unknown op"))),
        }
    }

    pub fn summary(&self) -> String {
        let mut phrases: Vec<&String> = Vec::new();
        for p in &self.phrases {
            if phrases.last().is_none_or(|l| *l != p) {
                phrases.push(p);
            }
        }
        if phrases.is_empty() {
            return "No change".into();
        }
        let rest: Vec<String> = phrases[1..].iter().map(|p| lower_first(p)).collect();
        if rest.is_empty() {
            return phrases[0].clone();
        }
        if rest.len() == 1 {
            return format!("{} and {}", phrases[0], rest[0]);
        }
        let more = rest.len() - 1;
        format!("{}, {} and {more} more change{}", phrases[0], rest[0], if more != 1 { "s" } else { "" })
    }

    fn placements_value(&self) -> Value {
        Value::Array(self.placements.iter().cloned().map(Value::Object).collect())
    }
}

/// Direct only for the person, or a worker with the person in the loop in their own chat.
pub fn may_arrange(caller: &Caller) -> bool {
    if caller.internal || caller.subject.is_empty() {
        return false;
    }
    if !caller.delegated {
        return true;
    }
    caller.regime == "human" && !caller.shared
}

pub fn author_of(caller: &Caller) -> String {
    if caller.delegated {
        format!("agent:{}", if caller.session.is_empty() { "unknown" } else { &caller.session })
    } else {
        "person".into()
    }
}

/// A change that leaves more placed items than \`cap\` AND more than before is refused. A desk
/// already above a cap the company has since narrowed may still be rearranged and thinned.
pub fn over(after: usize, before: usize, cap: i64) -> bool {
    (after as i64) > cap && after > before
}

// ── time: datetime.fromisoformat and isoformat, in microseconds since the epoch ────────────────
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        _ => 28,
    }
}

/// Monday = 0.
fn weekday(days: i64) -> i64 {
    (days + 3).rem_euclid(7)
}

fn at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

fn digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// parse_digits: \`n\` digits from \`p\` into \`var\` (accumulating), or None.
fn digits(b: &[u8], p: &mut usize, var: &mut i64, n: usize) -> Option<()> {
    for _ in 0..n {
        let c = at(b, *p);
        *p += 1;
        if !digit(c) {
            return None;
        }
        *var = *var * 10 + (c - b'0') as i64;
    }
    Some(())
}

fn separator(b: &[u8]) -> Option<usize> {
    let len = b.len();
    if len == 7 {
        return Some(7);
    }
    if at(b, 4) == b'-' {
        if at(b, 5) == b'W' {
            if len > 8 && at(b, 8) == b'-' {
                if len == 9 {
                    return None;
                }
                if len > 10 && digit(at(b, 10)) {
                    return Some(8);
                }
                return Some(10);
            }
            return Some(8);
        }
        return Some(10);
    }
    if at(b, 4) == b'W' {
        let mut idx = 7;
        while idx < len && digit(at(b, idx)) {
            idx += 1;
        }
        if idx < 9 {
            return Some(idx);
        }
        return Some(if idx % 2 == 0 { 7 } else { 8 });
    }
    Some(8)
}

fn parse_date(b: &[u8], len: usize) -> Option<(i64, i64, i64)> {
    let mut p = 0;
    let mut year = 0;
    digits(b, &mut p, &mut year, 4)?;
    let sep = at(b, p) == b'-';
    if sep {
        p += 1;
    }
    if at(b, p) == b'W' {
        p += 1;
        let (mut week, mut day) = (0, 0);
        digits(b, &mut p, &mut week, 2)?;
        if p < len {
            if sep {
                let c = at(b, p);
                p += 1;
                if c != b'-' {
                    return None;
                }
            }
            digits(b, &mut p, &mut day, 1)?;
        } else {
            day = 1;
        }
        if !(1..=9999).contains(&year) {
            return None;
        }
        let jan1 = days_from_civil(year, 1, 1);
        if week <= 0 || week >= 53 {
            let first = weekday(jan1);
            if !(week == 53 && (first == 3 || (first == 2 && is_leap(year)))) {
                return None;
            }
        }
        if day <= 0 || day >= 8 {
            return None;
        }
        let mut monday = jan1 - weekday(jan1);
        if weekday(jan1) > 3 {
            monday += 7;
        }
        let d = monday + (week - 1) * 7 + (day - 1);
        let (y, mo, dd, ..) = vexa_native_kit::ids::civil(d * 86_400);
        return Some((y, mo as i64, dd as i64));
    }
    let (mut month, mut day) = (0, 0);
    digits(b, &mut p, &mut month, 2)?;
    if sep {
        let c = at(b, p);
        p += 1;
        if c != b'-' {
            return None;
        }
    }
    digits(b, &mut p, &mut day, 2)?;
    Some((year, month, day))
}

/// parse_hh_mm_ss_ff over b[start..end]: (rv, [h, m, s, us]); rv 1 when it stopped short of the end.
fn parse_time_part(b: &[u8], start: usize, end: usize) -> Option<(bool, [i64; 4])> {
    let mut vals = [0i64; 4];
    let mut p = start;
    let mut has_sep = true;
    let mut fraction = false;
    for (i, val) in vals.iter_mut().take(3).enumerate() {
        digits(b, &mut p, val, 2)?;
        let c = at(b, p);
        p += 1;
        if i == 0 {
            has_sep = c == b':';
        }
        if p >= end {
            return Some((c != 0 && !(p > b.len() && c == 0), vals)).map(|(_, v)| (c != 0, v));
        } else if has_sep && c == b':' {
            continue;
        } else if c == b'.' || c == b',' {
            fraction = true;
            break;
        } else if !has_sep {
            p -= 1;
        } else {
            return None;
        }
    }
    let _ = fraction;
    let remains = end.saturating_sub(p);
    let to_parse = remains.min(6);
    let mut us = 0;
    digits(b, &mut p, &mut us, to_parse)?;
    const CORRECTION: [i64; 5] = [100000, 10000, 1000, 100, 10];
    if to_parse < 6 {
        us *= CORRECTION[to_parse.wrapping_sub(1).min(4)];
    }
    vals[3] = us;
    while digit(at(b, p)) {
        p += 1;
    }
    Some((at(b, p) != 0, vals))
}

/// datetime.fromisoformat(text) (CPython's C parser): (local microseconds, offset microseconds).
pub fn fromisoformat(text: &str) -> Option<(i64, Option<i64>)> {
    if text.chars().count() < 7 {
        return None;
    }
    let b = text.as_bytes();
    let sep = separator(b)?;
    let (year, month, day) = parse_date(b, sep)?;
    let (mut h, mut mi, mut sec, mut us, mut tz) = (0, 0, 0, 0, None);
    if b.len() > sep {
        let start = sep + 1;
        let end = b.len();
        let mut tzpos = start;
        loop {
            let c = at(b, tzpos);
            if c == b'Z' || c == b'+' || c == b'-' {
                break;
            }
            tzpos += 1;
            if tzpos >= end {
                break;
            }
        }
        let (rv, t) = parse_time_part(b, start, tzpos)?;
        [h, mi, sec, us] = t;
        if tzpos >= end {
            if rv {
                return None;
            }
        } else if at(b, tzpos) == b'Z' {
            if at(b, tzpos + 1) != 0 {
                return None;
            }
            tz = Some(0);
        } else {
            let sign = if at(b, tzpos) == b'-' { -1 } else { 1 };
            let (rv, z) = parse_time_part(b, tzpos + 1, end)?;
            if rv {
                return None;
            }
            let off = sign * ((z[0] * 3600 + z[1] * 60 + z[2]) * 1_000_000 + z[3]);
            if off.abs() >= DAY_US {
                return None;
            }
            tz = Some(off);
        }
    }
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let local = (days_from_civil(year, month, day) * 86_400 + h * 3600 + mi * 60 + sec) * 1_000_000 + us;
    Some((local, tz))
}

/// _at: a stored time as UTC microseconds; a naive time is UTC.
fn at_us(iso: &Value) -> R<i64> {
    let text = pystr(iso).replace('Z', "+00:00");
    match fromisoformat(&text) {
        Some((local, off)) => Ok(local - off.unwrap_or(0)),
        None => Err(CrmError::internal(format!("ValueError: Invalid isoformat string: {}", vexa_native_kit::pyjson::py_str_repr(&text)))),
    }
}

/// datetime.isoformat() of a UTC time.
pub fn isoformat(us: i64) -> String {
    let secs = us.div_euclid(1_000_000);
    let micros = us.rem_euclid(1_000_000);
    let (y, mo, d, h, mi, s) = vexa_native_kit::ids::civil(secs);
    let fraction = if micros == 0 { String::new() } else { format!(".{micros:06}") };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{fraction}+00:00")
}

/// datetime.now(timezone.utc), in microseconds.
pub fn now_us() -> i64 {
    let t = vexa_native_kit::ids::now();
    let secs = t.floor();
    secs as i64 * 1_000_000 + (((t - secs) * 1e6).floor() as i64).min(999_999)
}

// ── the service ─────────────────────────────────────────────────────────────────────────────────
pub type Clock = Box<dyn Fn() -> i64 + Send + Sync>;
pub type LimitsSource = Box<dyn Fn() -> Obj + Send + Sync>;

pub struct Desk {
    pub store: Arc<Store>,
    /// UTC microseconds now.
    pub clock: Clock,
    limits_source: Option<LimitsSource>,
}

/// The lookups of one transaction: saved arrangements and card reads.
struct TxLookup<'t> {
    c: &'t mut Tx,
    org: &'t str,
    person: &'t str,
    caller: &'t Caller,
    cards: Option<Arc<crate::card_ops::Cards>>,
}

impl Lookup for TxLookup<'_> {
    fn saved(&mut self, name: &str) -> R<Option<Obj>> {
        Ok(self.c.map(
            &format!("SELECT {} FROM crm_desk_layouts WHERE org_id = $1 AND person = $2 AND name = $3 ORDER BY version DESC LIMIT 1", s::DESK_LAYOUTS),
            &[&self.org, &self.person, &name],
        )?)
    }
    fn card_readable(&mut self, r: &str) -> Option<R<bool>> {
        let cards = self.cards.clone()?;
        Some(cards_readable(&cards, self.c, self.org, self.caller, &card_id(r)))
    }
}

impl Desk {
    /// The desk over \`store\`, with the company's limits from \`limits\` (the defaults without one).
    pub fn new(store: Arc<Store>, limits: Option<Arc<crate::policies::Policies>>) -> Self {
        let source: Option<LimitsSource> = limits.map(|p| Box::new(move || p.limits()) as LimitsSource);
        Desk { store, clock: Box::new(now_us), limits_source: source }
    }

    /// The desk with its own clock and limits source.
    pub fn with(store: Arc<Store>, clock: Clock, limits: Option<LimitsSource>) -> Self {
        Desk { store, clock, limits_source: limits }
    }

    /// The company's limits now; the defaults when none were given. A value is used only if it
    /// narrows its default.
    pub fn limits(&self) -> Obj {
        let mut out = crate::policies::defaults();
        let Some(source) = &self.limits_source else { return out };
        let got = source();
        for (k, default) in LIMIT_DEFAULTS {
            if let Some(v) = got.get(k).and_then(as_int) {
                if 0 <= v && v <= default {
                    out.insert(k.to_owned(), Value::from(v));
                }
            }
        }
        out
    }

    fn limit(limits: &Obj, k: &str) -> i64 {
        limits.get(k).and_then(Value::as_i64).unwrap_or_else(|| default_of(k))
    }

    fn ttl(&self, limits: Option<&Obj>) -> i64 {
        let days = match limits {
            Some(l) => Self::limit(l, "card_proposal_ttl_days"),
            None => Self::limit(&self.limits(), "card_proposal_ttl_days"),
        };
        days * DAY_US
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    fn cards(&self) -> Option<Arc<crate::card_ops::Cards>> {
        if !features::cards_served() {
            return None;
        }
        self.store.cards().cloned()
    }

    // ── reads ─────────────────────────────────────────────────────────────────────────────────
    fn current(&self, c: &mut Tx, org: &str, person: &str) -> R<(i64, Obj, Vec<Value>)> {
        let row = c.map(
            &format!("SELECT {} FROM crm_desk_layouts WHERE org_id = $1 AND person = $2 ORDER BY version DESC LIMIT 1", s::DESK_LAYOUTS),
            &[&org, &person],
        )?;
        Ok(match row {
            None => (0, normalise(&Value::Null), Vec::new()),
            Some(r) => (
                m(&r, "version").as_i64().unwrap_or(0),
                normalise(m(&r, "layout")),
                m(&r, "placements").as_array().cloned().unwrap_or_default(),
            ),
        })
    }

    fn version(&self, c: &mut Tx, org: &str, person: &str, version: i64) -> R<Option<Obj>> {
        if version == 0 {
            return Ok(json!({"layout": {}, "placements": []}).as_object().cloned());
        }
        Ok(c.map(
            &format!("SELECT {} FROM crm_desk_layouts WHERE org_id = $1 AND person = $2 AND version = $3", s::DESK_LAYOUTS),
            &[&org, &person, &Int(version)],
        )?)
    }

    fn pending(&self, c: &mut Tx, org: &str, person: &str, ttl: Option<i64>) -> R<Vec<Obj>> {
        let now = self.now();
        let ttl = match ttl {
            Some(t) if t != 0 => t,
            _ => self.ttl(None),
        };
        let rows = c.maps(
            &format!("SELECT {} FROM crm_desk_proposals WHERE org_id = $1 AND person = $2 AND status = 'pending'", s::DESK_PROPOSALS),
            &[&org, &person],
        )?;
        let mut live = Vec::new();
        for r in rows {
            if now - at_us(m(&r, "created_at"))? < ttl {
                live.push(r);
            }
        }
        live.sort_by(|a, b| pystr(m(b, "created_at")).cmp(&pystr(m(a, "created_at"))));
        Ok(live)
    }

    fn lookup<'t>(&self, c: &'t mut Tx, org: &'t str, caller: &'t Caller) -> TxLookup<'t> {
        TxLookup { c, org, person: &caller.subject, caller, cards: self.cards() }
    }

    pub fn read(&self, org: &str, caller: &Caller) -> R<Value> {
        let person = caller.subject.as_str();
        let (mut out, placements, layout) = self.store.connect(|c| {
            let (version, layout, placements) = self.current(c, org, person)?;
            let mut seen: Map<String, Value> = Map::new();
            for r in c.tuples("SELECT ref, seen_at FROM crm_desk WHERE org_id = $1 AND person = $2", &[&org, &person])? {
                seen.insert(pystr(&r[0]), r[1].clone());
            }
            let mut proposals = Vec::new();
            for p in self.pending(c, org, person, None)? {
                let summary = self.preview(c, org, caller, &layout, &placements, m(&p, "ops"))?;
                proposals.push(json!({"id": m(&p, "id"), "ops": m(&p, "ops"), "reason": m(&p, "reason"), "author": m(&p, "author"),
                    "created_at": m(&p, "created_at"), "summary": summary}));
            }
            let mut names: Vec<Value> = Vec::new();
            for name in c.column(
                "SELECT name FROM crm_desk_layouts WHERE org_id = $1 AND person = $2 AND name IS NOT NULL ORDER BY version DESC",
                &[&org, &person],
            )? {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            let mut placed = Vec::new();
            for p in &placements {
                let r = p.get("ref").ok_or_else(|| key_error("ref"))?;
                let at = p.get("placed_at").ok_or_else(|| key_error("placed_at"))?;
                placed.push(json!({"ref": r, "placed_at": at, "seen_at": seen.get(&pystr(r)).cloned().unwrap_or(Value::Null)}));
            }
            let mut out = Map::new();
            out.insert("version".into(), version.into());
            out.insert("layout".into(), Value::Object(layout.clone()));
            out.insert("placements".into(), Value::Array(placed));
            out.insert("proposals".into(), Value::Array(proposals));
            out.insert("saved".into(), Value::Array(names));
            out.insert("undo_version".into(), if version > 0 { Value::from(version - 1) } else { Value::Null });
            Ok((out, placements, layout))
        })?;
        if let Some(cards) = self.cards().filter(|_| crate::features::cards_served()) {
            for (k, v) in cards_desk(&cards, org, caller, &placements, &layout)? {
                out.insert(k, v);
            }
        }
        Ok(Value::Object(out))
    }

    fn preview(&self, c: &mut Tx, org: &str, caller: &Caller, layout: &Obj, placements: &[Value], ops: &Value) -> R<String> {
        let layout = Value::Object(layout.clone());
        let mut state = State::new(&layout, placements, isoformat(self.now()), caller)?;
        let mut lookup = self.lookup(c, org, caller);
        let empty = Vec::new();
        for (i, op) in ops.as_array().unwrap_or(&empty).iter().enumerate() {
            if let Err(e) = state.apply(op, &format!("ops[{i}]"), &mut lookup) {
                if e.is_crm() {
                    return Ok("Suggested a new arrangement".into());
                }
                return Err(e);
            }
        }
        Ok(state.summary())
    }

    // ── writes ────────────────────────────────────────────────────────────────────────────────
    #[allow(clippy::too_many_arguments)]
    fn apply(&self, c: &mut Tx, org: &str, caller: &Caller, ops: &[Value], base_version: i64, name: Option<String>, author: &str, trace: &str) -> R<Value> {
        let person = caller.subject.as_str();
        let (version, layout, placements) = self.current(c, org, person)?;
        if base_version != version {
            return Err(desk_refused(desk_changed(version), 409));
        }
        let mut state = State::new(&Value::Object(layout), &placements, isoformat(self.now()), caller)?;
        {
            let mut lookup = self.lookup(c, org, caller);
            for (i, op) in ops.iter().enumerate() {
                state.apply(op, &format!("ops[{i}]"), &mut lookup)?;
            }
        }
        if let Some(n) = name.filter(|n| !n.is_empty()) {
            state.phrases.push(format!("Saved as \"{n}\""));
            state.name = Some(n);
        }
        let cap = Self::limit(&self.limits(), "desk_placements_max");
        if over(state.placements.len(), placements.len(), cap) {
            return Err(desk_refused(placements_full(cap), 409));
        }
        let summary = state.summary();
        let placed = state.placements_value();
        self.commit(c, org, person, version, &Value::Object(state.layout), &placed, &Value::Array(ops.to_vec()), state.name.as_deref(), author, trace, &summary)
    }

    #[allow(clippy::too_many_arguments)]
    fn commit(&self, c: &mut Tx, org: &str, person: &str, version: i64, layout: &Value, placements: &Value, ops: &Value, name: Option<&str>, author: &str, trace: &str, summary: &str) -> R<Value> {
        let new = version + 1;
        let inserted = c.exec(
            &format!("INSERT INTO crm_desk_layouts ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", s::DESK_LAYOUTS),
            &[&org, &person, &Int(new), &name, layout, placements, ops, &author, &trace, &isoformat(self.now())],
        );
        if let Err(e) = inserted {
            if e.is_integrity() {
                return Err(desk_refused(desk_changed(version), 409));
            }
            return Err(e.into());
        }
        let list = placements.as_array().cloned().unwrap_or_default();
        let mut refs: Vec<String> = Vec::new();
        for p in &list {
            refs.push(pystr(p.get("ref").ok_or_else(|| key_error("ref"))?));
        }
        let have: Vec<String> = c.column("SELECT ref FROM crm_desk WHERE org_id = $1 AND person = $2", &[&org, &person])?.iter().map(pystr).collect();
        let gone: Vec<String> = have.iter().filter(|r| !refs.contains(r)).cloned().collect();
        if !gone.is_empty() {
            c.exec("DELETE FROM crm_desk WHERE org_id = $1 AND person = $2 AND ref = ANY($3)", &[&org, &person, &gone])?;
        }
        for (p, r) in list.iter().zip(&refs) {
            if !have.contains(r) {
                let placed_at = match g(p, "placed_at") {
                    Value::Null if p.get("placed_at").is_none() => return Err(key_error("placed_at")),
                    Value::Null => None,
                    v => Some(pystr(v)),
                };
                c.exec(
                    &format!("INSERT INTO crm_desk ({}) VALUES ($1, $2, $3, $4, NULL)", s::DESK),
                    &[&org, &person, r, &placed_at],
                )?;
            }
        }
        Ok(json!({"status": "applied", "version": new, "undo_version": version, "summary": summary}))
    }

    pub fn arrange(&self, org: &str, caller: &Caller, ops: &Value, base_version: i64, name: Option<&str>) -> R<Value> {
        let ops = check_ops(ops)?;
        if !may_arrange(caller) {
            return Err(desk_refused(propose_instead(), 403));
        }
        let name = match name {
            Some(n) if !n.is_empty() => Some(name_of(&json!({"name": n}), "name")?),
            _ => None,
        };
        self.store.engine_begin(|c| self.apply(c, org, caller, &ops, base_version, name, &author_of(caller), &caller.trace))
    }

    pub fn undo(&self, org: &str, caller: &Caller, version: i64, base_version: i64) -> R<Value> {
        if !may_arrange(caller) {
            return Err(desk_refused(propose_instead(), 403));
        }
        let person = caller.subject.as_str();
        self.store.engine_begin(|c| {
            let (current, _, _) = self.current(c, org, person)?;
            if base_version != current {
                return Err(desk_refused(desk_changed(current), 409));
            }
            if version < 0 || version > current {
                return Err(CrmError::not_found("No such desktop version"));
            }
            let Some(row) = self.version(c, org, person, version)? else {
                return Err(CrmError::not_found("No such desktop version"));
            };
            let summary = if version == 0 {
                "Restored the default desktop"
            } else if version == current - 1 {
                "Undid the last change"
            } else {
                "Restored an earlier arrangement"
            };
            let placements = Value::Array(m(&row, "placements").as_array().cloned().unwrap_or_default());
            self.commit(
                c, org, person, current, &Value::Object(normalise(m(&row, "layout"))), &placements,
                &json!([{"op": "undo", "version": version}]), None, &author_of(caller), &caller.trace, summary,
            )
        })
    }

    pub fn propose(&self, org: &str, caller: &Caller, ops: &Value, reason: &str) -> R<Value> {
        let ops = check_ops(ops)?;
        let reason = strip(reason).to_owned();
        if reason.is_empty() || chars(&reason) > 500 {
            return Err(invalid("reason must be 1..500 characters"));
        }
        if caller.internal || caller.subject.is_empty() {
            return Err(desk_refused(propose_instead(), 403));
        }
        let (person, author, now) = (caller.subject.as_str(), author_of(caller), self.now());
        let limits = self.limits();
        let cap = Self::limit(&limits, "desk_placements_max");
        let pending_cap = Self::limit(&limits, "card_proposals_pending_max");
        let daily_cap = Self::limit(&limits, "card_proposals_per_agent_per_day");
        let pid = self.store.engine_begin(|c| {
            let (_, layout, placements) = self.current(c, org, person)?;
            let mut state = State::new(&Value::Object(layout), &placements, isoformat(now), caller)?;
            {
                let mut lookup = self.lookup(c, org, caller);
                for (i, op) in ops.iter().enumerate() {
                    // refs the proposer cannot read are refused now
                    state.apply(op, &format!("ops[{i}]"), &mut lookup)?;
                }
            }
            if over(state.placements.len(), placements.len(), cap) {
                return Err(desk_refused(placements_full(cap), 409));
            }
            if self.pending(c, org, person, Some(self.ttl(Some(&limits))))?.len() as i64 >= pending_cap {
                return Err(desk_refused(pending_full(pending_cap), 409));
            }
            let mut day = 0i64;
            for r in c.column("SELECT created_at FROM crm_desk_proposals WHERE org_id = $1 AND author = $2 AND person = $3", &[&org, &author, &person])? {
                if now - at_us(&r)? < DAY_US {
                    day += 1;
                }
            }
            if caller.delegated && day >= daily_cap {
                return Err(desk_refused(daily_full(daily_cap), 409));
            }
            let pid = crate::val::uuid4();
            c.exec(
                &format!("INSERT INTO crm_desk_proposals ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)", s::DESK_PROPOSALS),
                &[&org, &pid, &person, &Value::Array(ops.clone()), &reason, &author, &caller.trace, &isoformat(now)],
            )?;
            Ok(pid)
        })?;
        Ok(json!({"status": "proposed", "proposal_id": pid}))
    }

    pub fn review(&self, org: &str, caller: &Caller, proposal_id: &str, apply: bool, base_version: i64) -> R<Value> {
        if caller.delegated || caller.internal || caller.subject.is_empty() {
            return Err(desk_refused(confirm(), 403));
        }
        self.store.engine_begin(|c| {
            let p = c.map(
                &format!("SELECT {} FROM crm_desk_proposals WHERE org_id = $1 AND id = $2 AND person = $3", s::DESK_PROPOSALS),
                &[&org, &proposal_id, &caller.subject],
            )?;
            let Some(p) = p else { return Err(CrmError::not_found("Proposal not found")) };
            let status = pystr(m(&p, "status"));
            if status != "pending" {
                return Err(CrmError::conflict(format!("Proposal already {status}")));
            }
            if self.now() - at_us(m(&p, "created_at"))? >= self.ttl(None) {
                return Err(CrmError::not_found("Proposal expired"));
            }
            let mut result = json!({"status": "dismissed"});
            if apply {
                let ops = check_ops(m(&p, "ops"))?;
                result = self.apply(c, org, caller, &ops, base_version, None, "person", &caller.trace)?;
            }
            c.exec(
                "UPDATE crm_desk_proposals SET status = $3 WHERE org_id = $1 AND id = $2",
                &[&org, &pystr(m(&p, "id")), &(if apply { "applied" } else { "dismissed" })],
            )?;
            Ok(result)
        })
    }
}

/// Cards.readable(c, org, caller, record_id): whether this caller may read this card now.
fn cards_readable(cards: &crate::card_ops::Cards, c: &mut Tx, org: &str, caller: &Caller, record_id: &str) -> R<bool> {
    let _ = (cards, c, org, caller, record_id);
    Ok(false)
}

/// Cards.desk(org, caller, placements, layout): the desk's card part.
fn cards_desk(cards: &crate::card_ops::Cards, org: &str, caller: &Caller, placements: &[Value], layout: &Obj) -> R<Obj> {
    cards.desk(org, caller, placements, &Value::Object(layout.clone()))
}
