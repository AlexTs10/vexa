//! Permission-aware record operations shared by HTTP, MCP and the record page (store.py).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::{Arc, OnceLock};

use serde_json::{json, Map, Value};
use vexa_native_kit::pg::{Int, Pool, Tx};

use crate::caller::{confirm_refusal, refusal, Caller};
use crate::card_ops::Cards;
use crate::db::{pending_get, pending_update, Sql};
use crate::err::{CrmError, R};
use crate::field_classes::{as_set, intersect, Classes, FieldView, Set, DEFAULT_ROOM_RULE, MATCH_IDS, NARRATIVE, PSEUDO, ROOM_RULES, ROOM_RULE_KEY};
use crate::schema as s;
use crate::val::{dumps, g, m, now_iso, or_str, py_eq, record_href, truthy, uuid4, uuid5_url, Obj};

/// The fields a record shows a cross-org room.
pub const PUBLIC_FIELDS: [&str; 8] = ["Name", "FirstName", "LastName", "Title", "Website", "Domain", "Industry", "LinkedIn"];
/// The roles whose members a binding gives a derived WRITE grant.
pub const WRITE_ROLES: [&str; 2] = ["owner", "contributor"];

/// Python's `needle in container` for a JSON container.
pub fn py_in(needle: &str, container: &Value) -> bool {
    match container {
        Value::Array(a) => a.iter().any(|v| v.as_str() == Some(needle)),
        Value::String(t) => t.contains(needle),
        Value::Object(o) => o.contains_key(needle),
        _ => false,
    }
}

/// The string items of a policy's field list.
pub fn field_list(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect(),
        _ => Vec::new(),
    }
}

/// The fields of this type a cross-org room reads.
pub fn public_fields(policy: &Policy, object_type: &str) -> Set {
    let rule = policy.rule(object_type);
    let mut out: Set = PUBLIC_FIELDS.iter().map(|x| x.to_string()).collect();
    out.extend(field_list(g(&rule, "public_fields")));
    out
}

fn cross_org_keys(kind: &str) -> &'static [&'static str] {
    match kind {
        "record" => &["id", "org_id", "object_type", "revision", "quarantined", "fields", "narrative", "audience", "card", "href", "links", "actions"],
        "link" => &["field", "record_id", "object_type", "label"],
        "revision" => &["revision", "created_at", "before", "after"],
        "history" => &["revisions"],
        "search" => &["records", "next_offset", "card", "href"],
        "resolve" => &["records"],
        _ => &[],
    }
}

fn cross_org_nested(kind: &str, key: &str) -> Option<&'static str> {
    match (kind, key) {
        ("record", "links") => Some("link"),
        ("revision", "before") | ("revision", "after") => Some("record"),
        ("history", "revisions") => Some("revision"),
        ("search", "records") | ("resolve", "records") => Some("record"),
        _ => None,
    }
}

fn blank(v: &Value) -> Value {
    match v {
        Value::Bool(_) => Value::Bool(false),
        Value::Array(_) => json!([]),
        Value::Object(_) => json!({}),
        _ => Value::Null,
    }
}

/// `answer` as a room with people from outside the org receives it.
pub fn cross_org_answer(kind: &str, answer: Value) -> Value {
    let Value::Object(o) = answer else { return answer };
    let keep = cross_org_keys(kind);
    let mut out = Map::new();
    for (key, value) in o {
        let v = if !keep.contains(&key.as_str()) {
            blank(&value)
        } else if let Some(n) = cross_org_nested(kind, &key) {
            match value {
                Value::Array(items) => Value::Array(items.into_iter().map(|i| cross_org_answer(n, i)).collect()),
                other => cross_org_answer(n, other),
            }
        } else {
            value
        };
        out.insert(key, v);
    }
    Value::Object(out)
}

/// The room a shared caller answers.
#[derive(Clone)]
pub struct Room {
    pub workspaces: Set,
    pub members: BTreeMap<String, Option<Policy>>,
    pub rule: String,
}

/// One caller's CRM policy in one org, with the facts its gates read (store._policy's dict).
#[derive(Clone)]
pub struct Policy {
    /// The policy document, with `subject_id` (and `admin`/`active` for an administrator).
    pub v: Obj,
    pub caller: Caller,
    pub bound: BTreeMap<String, BTreeSet<String>>,
    pub roles: HashMap<String, String>,
    pub members: BTreeMap<String, String>,
    pub classes: Option<Rc<Classes>>,
    pub room: Option<Rc<Room>>,
    /// Set for a shared caller only: whether the person behind it administers the CRM.
    pub person_admin: Option<bool>,
}

impl Policy {
    pub fn get(&self, key: &str) -> &Value {
        m(&self.v, key)
    }
    pub fn flag(&self, key: &str) -> bool {
        truthy(self.get(key))
    }
    pub fn admin(&self) -> bool {
        self.flag("admin")
    }
    pub fn subject_id(&self) -> String {
        crate::val::s(self.get("subject_id"))
    }
    /// policy.get('objects', {}).get(kind, {})
    pub fn rule(&self, kind: &str) -> Value {
        match self.get("objects").get(kind) {
            Some(v @ Value::Object(_)) => v.clone(),
            _ => json!({}),
        }
    }
    /// policy.get('records', {})
    pub fn records(&self) -> Obj {
        self.get("records").as_object().cloned().unwrap_or_default()
    }
    pub fn bound_of(&self, record_id: &str) -> BTreeSet<String> {
        self.bound.get(record_id).cloned().unwrap_or_default()
    }
    pub fn classes(&self) -> Rc<Classes> {
        self.classes.clone().unwrap_or_else(|| Rc::new(Classes::empty()))
    }
}

/// The record an object type's id names, as a JSON object.
pub type Row = Obj;

/// Text of a row's column.
pub fn col(row: &Row, key: &str) -> String {
    crate::val::s(m(row, key))
}

/// The record's label in a link: Name, else First Last, else Title, else its type.
fn link_label(fields: &Value, object_type: &Value, keys: &[&str]) -> Value {
    for k in keys {
        let v = g(fields, k);
        if truthy(v) {
            return v.clone();
        }
    }
    let full = ["FirstName", "LastName"].iter().map(|k| or_str(g(fields, k))).collect::<Vec<_>>().join(" ");
    let full = crate::val::strip(&full).to_owned();
    if !full.is_empty() {
        return Value::String(full);
    }
    let t = g(fields, "Title");
    if truthy(t) {
        return t.clone();
    }
    object_type.clone()
}

pub struct Store {
    pub pool: Arc<Pool>,
    /// The card service registers itself here (card_ops.Cards).
    pub cards: OnceLock<Arc<Cards>>,
    /// identity's retired profile, read once on a claim (profiles.ProfileClient.legacy).
    pub legacy: OnceLock<crate::profiles::ProfileClient>,
}

pub fn audit_principal(caller: &Caller) -> (String, String, String) {
    let subject = caller.subject.clone();
    let ceiling = caller.workspaces.join(",");
    let principal = if subject.starts_with("ws:") {
        subject.clone()
    } else if caller.shared {
        format!("ws:{}", caller.workspaces.first().map(String::as_str).unwrap_or("-"))
    } else if !subject.is_empty() {
        subject.clone()
    } else if caller.internal {
        "internal".into()
    } else {
        "-".into()
    };
    let mut on_behalf_of = caller.extra_str("on_behalf_of");
    if on_behalf_of.is_empty() && caller.delegated && !subject.starts_with("ws:") {
        on_behalf_of = subject.clone();
    }
    (principal, on_behalf_of, if caller.delegated { ceiling } else { String::new() })
}

fn workspace_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}$").unwrap())
}

pub fn check_workspace(workspace: &str) -> R<String> {
    let w = crate::val::strip(workspace).to_owned();
    if !workspace_re().is_match(&w) || w.contains("..") || w.ends_with('\n') {
        return Err(CrmError::crm("Not a workspace slug"));
    }
    Ok(w)
}

/// email:a@b.c, domain:b.c, calendar:<event id>.
pub fn normalise_match(raw: &Value) -> R<String> {
    let text = or_str(raw);
    let (kind, value) = text.split_once(':').unwrap_or((&text, ""));
    let kind = crate::val::lower(crate::val::strip(kind));
    let value = crate::val::strip(value).to_owned();
    if !["email", "domain", "calendar"].contains(&kind.as_str()) || value.is_empty() || value.chars().count() > 300 {
        return Err(CrmError::crm("A match identifier is email:…, domain:… or calendar:…"));
    }
    let value = if kind == "email" || kind == "domain" { crate::val::lower(&value) } else { value };
    Ok(format!("{kind}:{value}"))
}

impl Store {
    pub fn new(pool: Arc<Pool>) -> Self {
        Store { pool, cards: OnceLock::new(), legacy: OnceLock::new() }
    }

    pub fn cards(&self) -> Option<&Arc<Cards>> {
        self.cards.get()
    }

    // ── transactions ─────────────────────────────────────────────────────────────────────────
    /// engine.begin(): commit when `f` returns Ok, roll back otherwise.
    pub fn engine_begin<T>(&self, f: impl FnOnce(&mut Tx) -> R<T>) -> R<T> {
        let mut tx = self.pool.begin()?;
        let out = f(&mut tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// engine.connect(): a transaction that is never committed.
    pub fn connect<T>(&self, f: impl FnOnce(&mut Tx) -> R<T>) -> R<T> {
        let mut tx = self.pool.begin()?;
        let out = f(&mut tx);
        tx.rollback();
        out
    }

    /// Store.begin: engine.begin() that writes the pending audit row inside the same transaction.
    pub fn begin<T>(&self, f: impl FnOnce(&mut Tx) -> R<T>) -> R<T> {
        let mut tx = self.pool.begin()?;
        let out = f(&mut tx)?;
        if let Some(p) = pending_get().filter(|p| !p.written) {
            self.write_audit(&mut tx, &p.org, &p.caller, &p.op, &p.record_id, "ok")?;
            pending_update(|p| p.written = true);
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn audit_names(&self, record_id: &str) {
        pending_update(|p| {
            if !p.written && p.record_id.is_empty() {
                p.record_id = record_id.to_owned();
            }
        });
    }

    fn write_audit(&self, c: &mut Tx, org: &str, caller: &Caller, op: &str, record_id: &str, outcome: &str) -> R<()> {
        let (principal, on_behalf_of, workspace) = audit_principal(caller);
        let subject = if caller.subject.is_empty() { "-".to_owned() } else { caller.subject.clone() };
        c.exec(
            &format!("INSERT INTO crm_audit ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)", s::AUDIT),
            &[&org, &uuid4(), &now_iso(), &subject, &caller.kind(), &caller.session, &caller.trace, &op, &record_id, &outcome, &principal, &on_behalf_of, &workspace],
        )?;
        Ok(())
    }

    /// One audit row in its own transaction.
    pub fn audit(&self, org: &str, caller: &Caller, op: &str, record_id: &str, outcome: &str) -> R<()> {
        self.engine_begin(|c| self.write_audit(c, org, caller, op, record_id, outcome))
    }

    // ── the two gates ────────────────────────────────────────────────────────────────────────
    pub fn policy(&self, c: &mut Tx, org: &str, caller: &Caller, context: bool) -> R<Policy> {
        let mut value: Option<Value> = if caller.is_workspace_principal() {
            Some(json!({"active": true, "objects": {}, "records": {}, "_principal": "workspace"}))
        } else {
            c.scalar("SELECT policy FROM crm_access_policies WHERE org_id = $1 AND subject_id = $2", &[&org, &caller.subject])?
        };
        if value.as_ref().is_none_or(Value::is_null) && !caller.internal {
            value = self.org_policy(c, org)?;
        }
        if caller.is_admin && !caller.shared {
            let mut o = value.as_ref().and_then(Value::as_object).cloned().unwrap_or_default();
            o.insert("active".into(), true.into());
            o.insert("admin".into(), true.into());
            value = Some(Value::Object(o));
        }
        let value = match value {
            Some(v) if truthy(&v) && truthy(g(&v, "active")) => v,
            _ => return Err(CrmError::forbidden("No active CRM membership")),
        };
        let mut v = value.as_object().cloned().unwrap_or_default();
        let mut person_admin = None;
        if caller.shared {
            let pa = truthy(m(&v, "admin")) || truthy(caller.extra.get("person_admin").unwrap_or(&Value::Null));
            v.remove("admin");
            v.remove("reviewer");
            person_admin = Some(pa);
        }
        let mut bound: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut roles = HashMap::new();
        if !caller.workspaces.is_empty() {
            let ws: Vec<String> = caller.workspaces.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
            for r in c.tuples("SELECT workspace, record_id FROM crm_workspace_bindings WHERE org_id = $1 AND workspace = ANY($2)", &[&org, &ws])? {
                bound.entry(crate::val::s(&r[1])).or_default().insert(crate::val::s(&r[0]));
            }
            for r in c.tuples("SELECT workspace, role FROM crm_workspace_rosters WHERE org_id = $1 AND subject = $2 AND workspace = ANY($3)", &[&org, &caller.subject, &ws])? {
                roles.insert(crate::val::s(&r[0]), crate::val::s(&r[1]));
            }
        }
        let mut members = BTreeMap::new();
        if !caller.subject.is_empty() {
            for r in c.tuples("SELECT record_id, status FROM crm_card_members WHERE org_id = $1 AND subject = $2", &[&org, &caller.subject])? {
                members.insert(crate::val::s(&r[0]), crate::val::s(&r[1]));
            }
        }
        // the dict's own order: the policy's keys, then subject_id
        v.insert("subject_id".into(), Value::String(caller.subject.clone()));
        let mut policy = Policy { v, caller: caller.clone(), bound, roles, members, classes: None, room: None, person_admin };
        if context {
            policy.classes = Some(Rc::new(self.classes_of(c, org)?));
            if caller.shared {
                policy.room = Some(Rc::new(self.room(c, org, caller)?));
            }
        }
        Ok(policy)
    }

    pub fn classes_of(&self, c: &mut Tx, org: &str) -> R<Classes> {
        let rows = c.maps("SELECT object_type, field, class, workspaces FROM crm_field_classes WHERE org_id = $1", &[&org])?;
        let mut defs = Map::new();
        for r in c.tuples("SELECT name, definition FROM crm_object_definitions WHERE org_id = $1", &[&org])? {
            defs.insert(crate::val::s(&r[0]), r[1].clone());
        }
        Ok(Classes::new(&rows, defs))
    }

    fn room(&self, c: &mut Tx, org: &str, caller: &Caller) -> R<Room> {
        let ceiling: Set = caller.workspaces.iter().cloned().collect();
        let mut roster: BTreeMap<String, Set> = BTreeMap::new();
        if !ceiling.is_empty() {
            let ws: Vec<String> = ceiling.iter().cloned().collect();
            for r in c.tuples("SELECT workspace, subject FROM crm_workspace_rosters WHERE org_id = $1 AND workspace = ANY($2)", &[&org, &ws])? {
                roster.entry(crate::val::s(&r[1])).or_default().insert(crate::val::s(&r[0]));
            }
        }
        let mut members = BTreeMap::new();
        for (subject, workspaces) in roster {
            if subject.starts_with("ws:") {
                continue;
            }
            let member = Caller { workspaces: workspaces.into_iter().collect(), ..Caller::subject(subject.clone()) };
            match self.policy(c, org, &member, false) {
                Ok(p) => {
                    members.insert(subject, Some(p));
                }
                Err(e) if e.class == "Forbidden" => {
                    members.insert(subject, None);
                }
                Err(e) => return Err(e),
            }
        }
        let rule_v = self.org_policy(c, org)?.map(|p| g(&p, ROOM_RULE_KEY).clone()).unwrap_or(Value::Null);
        let rule = match rule_v {
            Value::Null => DEFAULT_ROOM_RULE.to_owned(),
            Value::String(r) if ROOM_RULES.contains(&r.as_str()) => r,
            _ => "classified".to_owned(),
        };
        Ok(Room { workspaces: ceiling, members, rule })
    }

    /// (allowed, excluded, explicit) for a shared caller.
    fn room_allowed(&self, policy: &Policy, kind: &str, member_fields: &dyn Fn(&Policy) -> Option<Set>) -> (Option<Set>, Set, Set) {
        let classes = policy.classes();
        let empty = Rc::new(Room { workspaces: Set::new(), members: BTreeMap::new(), rule: "classified".into() });
        let room = policy.room.clone().unwrap_or(empty);
        let explicit = classes.shared_with(kind, &room.workspaces);
        if room.rule == "classified" {
            return (Some(explicit.iter().filter(|n| !PSEUDO.contains(&n.as_str())).cloned().collect()), Set::new(), explicit);
        }
        let mut allowed = member_fields(policy);
        if room.members.is_empty() {
            allowed = Some(Set::new());
        }
        for member in room.members.values() {
            let f = match member {
                Some(p) => member_fields(p),
                None => Some(Set::new()),
            };
            allowed = intersect(&allowed, &f);
        }
        let mut excluded: Set = classes.private(kind);
        excluded.extend(classes.shared_elsewhere(kind, &room.workspaces));
        let excluded: Set = excluded.difference(&explicit).cloned().collect();
        if let Some(a) = allowed.as_mut() {
            a.extend(explicit.iter().filter(|n| !PSEUDO.contains(&n.as_str())).cloned());
        }
        (allowed, excluded, explicit)
    }

    /// What this caller reads of this record, or NotFound / SharedRefused.
    pub fn view(&self, policy: &Policy, row: &Row) -> R<FieldView> {
        let raw = self.rights(policy, row, "read")?;
        let caller = &policy.caller;
        let classes = policy.classes();
        let kind = col(row, "object_type");
        let props = classes.prop_names(&kind);
        if caller.shared {
            let fields_of = |p: &Policy| -> Option<Set> {
                match self.rights(p, row, "read") {
                    Ok(f) => as_set(&f),
                    Err(e) if e.is_not_found() => Some(Set::new()),
                    Err(_) => Some(Set::new()),
                }
            };
            let (allowed, excluded, explicit) = self.room_allowed(policy, &kind, &fields_of);
            return Ok(FieldView {
                allowed,
                excluded,
                full: false,
                narrative: explicit.contains(NARRATIVE),
                match_ids: explicit.contains(MATCH_IDS),
                props,
            });
        }
        let allowed = as_set(&raw);
        let owner = !caller.subject.is_empty() && m(row, "owner_id").as_str() == Some(caller.subject.as_str());
        let excluded = if policy.admin() || owner { Set::new() } else { classes.private(&kind) };
        let full = allowed.is_none();
        Ok(FieldView {
            narrative: full && !excluded.contains(NARRATIVE),
            match_ids: full && !excluded.contains(MATCH_IDS),
            allowed,
            excluded,
            full,
            props,
        })
    }

    /// The fields of a type this caller may filter or lay out by.
    pub fn type_view(&self, policy: &Policy, kind: &str) -> FieldView {
        let classes = policy.classes();
        let props = classes.prop_names(kind);
        if policy.caller.shared {
            let fields_of = |p: &Policy| -> Option<Set> {
                if p.admin() {
                    return None;
                }
                let rule = p.rule(kind);
                let f = rule.get("read_fields").map(field_list).unwrap_or_else(|| vec!["*".into()]);
                as_set(&f)
            };
            let (allowed, excluded, _) = self.room_allowed(policy, kind, &fields_of);
            return FieldView { allowed, excluded, props, ..Default::default() };
        }
        let allowed = if policy.admin() { None } else { as_set(&field_list(g(&policy.rule(kind), "read_fields"))) };
        let excluded = if policy.admin() { Set::new() } else { classes.private(kind) };
        FieldView { allowed, excluded, props, ..Default::default() }
    }

    pub fn definition(&self, c: &mut Tx, org: &str, kind: &str) -> R<Value> {
        match c.scalar("SELECT definition FROM crm_object_definitions WHERE org_id = $1 AND name = $2", &[&org, &kind])? {
            Some(v) if !v.is_null() => Ok(v),
            _ => Err(CrmError::not_found("Unknown object type")),
        }
    }

    /// The fields this caller may read or write on this record, or NotFound.
    pub fn rights(&self, policy: &Policy, row: &Row, permission: &str) -> R<Vec<String>> {
        let caller = &policy.caller;
        let id = col(row, "id");
        let bound = policy.bound_of(&id);
        let fields;
        if policy.admin() {
            fields = vec!["*".to_owned()];
        } else {
            if caller.shared && policy.person_admin == Some(true) && bound.is_empty() {
                return Err(CrmError::shared());
            }
            if truthy(m(row, "quarantined")) {
                return Err(CrmError::not_found("Record not found"));
            }
            let rule = policy.rule(&col(row, "object_type"));
            let scope = g(&rule, permission).as_str().map(str::to_owned).unwrap_or_else(|| if rule.get(permission).is_some() { String::new() } else { "none".into() });
            let records = policy.records();
            let granted = records.get(&id).cloned().unwrap_or(json!([]));
            let mut allowed = scope == "all" || (scope == "own" && py_eq(m(row, "owner_id"), policy.get("subject_id"))) || py_in(permission, &granted);
            let key = format!("{permission}_fields");
            let mut f = field_list(g(&rule, &key));
            let membership = policy.members.get(&id).cloned().unwrap_or_default();
            if !allowed && !membership.is_empty() && (permission == "read" || membership == "member") {
                allowed = true;
                f = rule.get(&key).map(field_list).unwrap_or_else(|| vec!["*".into()]);
            }
            if !allowed && !bound.is_empty() {
                let writes = match &caller.writable {
                    Some(w) => bound.iter().any(|b| w.contains(b)),
                    None => bound.iter().any(|b| policy.roles.get(b).is_some_and(|r| WRITE_ROLES.contains(&r.as_str()))),
                };
                if permission == "read" || writes {
                    allowed = true;
                    f = rule.get(&key).map(field_list).unwrap_or_else(|| vec!["*".into()]);
                }
            }
            if !allowed {
                return Err(CrmError::not_found("Record not found"));
            }
            fields = f;
        }
        if caller.shared && bound.is_empty() {
            return Err(CrmError::shared());
        }
        Ok(fields)
    }

    /// The record, or the record it was merged into.
    pub fn row(&self, c: &mut Tx, org: &str, record_id: &str) -> R<Row> {
        let mut id = record_id.to_owned();
        let mut row = None;
        for _ in 0..8 {
            row = c.map(&format!("SELECT {} FROM crm_records WHERE org_id = $1 AND id = $2", s::RECORDS), &[&org, &id])?;
            if let Some(r) = &row {
                if truthy(m(r, "merged_into")) {
                    id = col(r, "merged_into");
                    continue;
                }
            }
            break;
        }
        match row {
            Some(r) if !truthy(m(&r, "deleted")) && !truthy(m(&r, "merged_into")) => Ok(r),
            _ => Err(CrmError::not_found("Record not found")),
        }
    }

    pub fn visible(&self, policy: &Policy, row: &Row) -> R<Obj> {
        let view = self.view(policy, row)?;
        let mut out = Map::new();
        for k in ["id", "org_id", "object_type", "revision"] {
            match row.get(k) {
                Some(v) => out.insert(k.into(), v.clone()),
                None => return Err(CrmError::internal(format!("KeyError: '{k}'"))),
            };
        }
        out.insert("quarantined".into(), m(row, "quarantined").clone());
        out.insert("fields".into(), view.filter(m(row, "fields")));
        out.insert("narrative".into(), if view.narrative { m(row, "narrative").clone() } else { Value::Null });
        if policy.caller.cross_org {
            let public = public_fields(policy, &col(row, "object_type"));
            let fields: Obj = out["fields"].as_object().cloned().unwrap_or_default().into_iter().filter(|(k, _)| public.contains(k)).collect();
            out.insert("fields".into(), Value::Object(fields));
            out.insert("narrative".into(), Value::Null);
            out.insert("audience".into(), "cross_org".into());
        }
        Ok(out)
    }

    pub fn card(&self, c: &mut Tx, org: &str, kind: &str) -> R<Value> {
        let row = c.map("SELECT version, layout FROM crm_card_layouts WHERE org_id = $1 AND object_type = $2 ORDER BY version DESC LIMIT 1", &[&org, &kind])?;
        Ok(match row {
            Some(r) => json!({"version": m(&r, "version"), "layout": m(&r, "layout")}),
            None => json!({"version": 0, "layout": null}),
        })
    }

    fn card_with(&self, card: Value, readable: &dyn Fn(&str) -> bool) -> Value {
        let layout = if truthy(g(&card, "layout")) { crate::layouts::visible_layout(g(&card, "layout"), readable) } else { Value::Null };
        let mut o = card.as_object().cloned().unwrap_or_default();
        o.insert("layout".into(), layout);
        Value::Object(o)
    }

    pub fn configure(&self, org: &str, caller: &Caller, object_type: &str, layout: Option<&Value>, expected_version: i64, reason: &str) -> R<Value> {
        self.begin(|c| {
            let policy = self.policy(c, org, caller, true)?;
            if !policy.admin() {
                return Err(CrmError::forbidden("CRM administrator rights required to configure shared cards"));
            }
            let digest = vexa_native_kit::sha256::digest(dumps(&json!([org, object_type])).as_bytes());
            let key = i64::from_be_bytes(digest[..8].try_into().unwrap());
            c.exec("SELECT pg_advisory_xact_lock($1)", &[&key])?;
            let definition = c.scalar("SELECT definition FROM crm_object_definitions WHERE org_id = $1 AND name = $2", &[&org, &object_type])?;
            let Some(definition) = definition.filter(|d| !d.is_null()) else {
                return Err(CrmError::not_found("Unknown object type"));
            };
            let current = self.card(c, org, object_type)?;
            let Some(layout) = layout else { return Ok(current) };
            if caller.unwatched() {
                return Err(CrmError::refused(refusal()));
            }
            if Some(expected_version) != current["version"].as_i64() {
                return Err(CrmError::conflict("Card layout changed; read configuration again"));
            }
            if crate::val::strip(reason).is_empty() {
                return Err(CrmError::crm("Configuration changes require a reason"));
            }
            let layout = crate::layouts::card_layout(layout).map_err(|e| CrmError::crm(format!("Invalid card layout: {e}")))?;
            let properties = g(&definition, "properties");
            let mut references = vec![g(&layout, "title_field").clone()];
            for sec in g(&layout, "sections").as_array().into_iter().flatten() {
                for f in g(sec, "fields").as_array().into_iter().flatten() {
                    references.push(g(f, "field").clone());
                }
            }
            if references.iter().any(|n| truthy(n) && !n.as_str().is_some_and(|n| properties.get(n).is_some())) {
                return Err(CrmError::crm("Unknown field in card layout"));
            }
            let version = current["version"].as_i64().unwrap_or(0) + 1;
            c.exec(
                &format!("INSERT INTO crm_card_layouts ({}) VALUES ($1, $2, $3, $4, $5, $6, $7)", s::CARD_LAYOUTS),
                &[&org, &object_type, &Int(version), &layout, &caller.subject, &reason, &now_iso()],
            )?;
            Ok(json!({"version": version, "layout": layout}))
        })
    }

    pub fn describe(&self, org: &str, caller: &Caller, object_type: Option<&str>) -> R<Value> {
        self.connect(|c| {
            let policy = self.policy(c, org, caller, true)?;
            let rows = c.maps(&format!("SELECT {} FROM crm_object_definitions WHERE org_id = $1", s::OBJECT_TYPES), &[&org])?;
            let mut result = Vec::new();
            for row in rows {
                let kind = col(&row, "name");
                if object_type.is_some_and(|o| !o.is_empty() && o != kind) {
                    continue;
                }
                let rule = policy.rule(&kind);
                if !policy.admin() && g(&rule, "read").as_str().unwrap_or(if rule.get("read").is_some() { "" } else { "none" }) == "none" {
                    continue;
                }
                let allowed = if policy.admin() { vec!["*".to_owned()] } else { field_list(g(&rule, "read_fields")) };
                let mut fields = Map::new();
                if let Some(props) = m(&row, "definition").get("properties").and_then(Value::as_object) {
                    for (k, v) in props {
                        if allowed.iter().any(|a| a == "*" || a == k) {
                            fields.insert(k.clone(), v.clone());
                        }
                    }
                }
                if policy.caller.shared {
                    let view = self.type_view(&policy, &kind);
                    fields.retain(|k, _| view.has(k));
                }
                result.push(json!({"object_type": kind, "fields": fields}));
            }
            Ok(json!({"objects": result}))
        })
    }

    pub fn get(&self, org: &str, caller: &Caller, record_id: &str) -> R<Value> {
        let actor = caller.subject.clone();
        self.connect(|c| {
            let policy = self.policy(c, org, caller, true)?;
            let row = self.row(c, org, record_id)?;
            let record_id = col(&row, "id");
            let mut result = self.visible(&policy, &row)?;
            let card = self.card(c, org, &col(&row, "object_type"))?;
            let fields_now = result["fields"].clone();
            result.insert("card".into(), self.card_with(card, &|f| fields_now.get(f).is_some()));
            result.insert("href".into(), record_href(&record_id).into());
            let sources = c.maps("SELECT system, source_org, object_type, source_id FROM crm_source_mappings WHERE org_id = $1 AND record_id = $2", &[&org, &record_id])?;
            result.insert("sources".into(), Value::Array(sources.into_iter().map(Value::Object).collect()));
            let mut links = Vec::new();
            for link in c.maps(&format!("SELECT {} FROM crm_relationships WHERE org_id = $1 AND record_id = $2", s::RELATIONSHIPS), &[&org, &record_id])? {
                if col(&link, "target_domain") != "crm" {
                    continue;
                }
                let kind = col(&link, "kind");
                if kind == "Description" {
                    if result["narrative"].is_null() {
                        continue;
                    }
                } else if result["fields"].get(&kind).is_none() {
                    continue;
                }
                let target = match self.row(c, org, &col(&link, "target_id")).and_then(|r| self.visible(&policy, &r)) {
                    Ok(t) => t,
                    Err(e) if e.is_not_found() => continue,
                    Err(e) => return Err(e),
                };
                links.push(json!({"field": kind, "record_id": target["id"], "object_type": target["object_type"],
                                  "label": link_label(&target["fields"], &target["object_type"], &["Name"])}));
            }
            for link in c.maps(&format!("SELECT {} FROM crm_relationships WHERE org_id = $1 AND target_domain = 'crm' AND target_id = $2", s::RELATIONSHIPS), &[&org, &record_id])? {
                let source = match self.row(c, org, &col(&link, "record_id")).and_then(|r| self.visible(&policy, &r)) {
                    Ok(t) => t,
                    Err(e) if e.is_not_found() => continue,
                    Err(e) => return Err(e),
                };
                let kind = col(&link, "kind");
                if kind == "Description" {
                    if source["narrative"].is_null() {
                        continue;
                    }
                } else if source["fields"].get(&kind).is_none() {
                    continue;
                }
                let field = if kind == "Description" { "Referenced by".to_owned() } else { format!("Related via {kind}") };
                links.push(json!({"field": field, "record_id": source["id"], "object_type": source["object_type"],
                                  "label": link_label(&source["fields"], &source["object_type"], &["Name", "name", "Subject"])}));
            }
            result.insert("links".into(), Value::Array(links));
            let can_write = match self.rights(&policy, &row, "write") {
                Ok(f) => !f.is_empty(),
                Err(e) if e.is_not_found() => false,
                Err(e) => return Err(e),
            };
            let sees_all = can_write && (policy.admin() || policy.flag("reviewer") || self.is_card(c, org, &record_id)?);
            let can_review = sees_all && !caller.delegated;
            result.insert("actions".into(), json!({"can_review": can_review,
                "can_update": can_write && !caller.delegated && !policy.flag("review_required"), "can_propose": true}));
            result.insert("mentioned_in".into(), self.mentioned_in(c, org, &policy, &row)?);
            let bound_to = if policy.admin() && !caller.delegated {
                crate::val::str_list(self.bindings(c, org, &record_id)?)
            } else {
                crate::val::str_list(policy.bound_of(&record_id))
            };
            result.insert("bound_to".into(), bound_to);
            let view = self.view(&policy, &row)?;
            if view.match_ids {
                let mut ids: Vec<String> = c.column("SELECT identifier FROM crm_match_ids WHERE org_id = $1 AND record_id = $2", &[&org, &record_id])?.iter().map(crate::val::s).collect();
                ids.sort();
                result.insert("match_ids".into(), crate::val::str_list(ids));
                result.insert("account_id".into(), m(&row, "account_id").clone());
            }
            let mut q = Sql::new(&format!("SELECT {} FROM crm_change_proposals WHERE org_id = ", s::CHANGE_PROPOSALS));
            let a = q.p(org.to_owned());
            q.push(&a).push(" AND record_id = ");
            let b = q.p(record_id.clone());
            q.push(&b).push(" AND status = 'pending'");
            if !sees_all {
                let a = q.p(actor.clone());
                q.push(" AND author_id = ").push(&a);
            }
            q.push(" LIMIT 50");
            let mut proposals = Vec::new();
            for p in q.maps(c)? {
                let patch = m(&p, "patch");
                let author_kind = patch.get("author_kind").cloned().unwrap_or_else(|| "person".into());
                let pf = patch.get("fields").ok_or_else(|| CrmError::internal("KeyError: 'fields'"))?;
                proposals.push(json!({"id": m(&p, "id"), "base_revision": m(&p, "base_revision"), "author_kind": author_kind,
                    "fields": view.filter(pf),
                    "narrative": if view.narrative { g(patch, "narrative").clone() } else { Value::Null },
                    "reason": if view.full { m(&p, "reason").clone() } else { Value::Null },
                    "evidence": if view.full { m(&p, "evidence").clone() } else { json!([]) }}));
            }
            result.insert("proposals".into(), Value::Array(proposals));
            let out = Value::Object(result);
            Ok(if caller.cross_org { cross_org_answer("record", out) } else { out })
        })
    }

    pub fn search(&self, org: &str, caller: &Caller, object_type: &str, filters: &Obj, limit: i64, offset: i64) -> R<Value> {
        let actor = caller.subject.clone();
        if !(1..=100).contains(&limit) || offset < 0 {
            return Err(CrmError::crm("Limit must be 1..100 and offset nonnegative"));
        }
        self.connect(|c| {
            let policy = self.policy(c, org, caller, true)?;
            let definition = self.definition(c, org, object_type)?;
            let props = g(&definition, "properties").clone();
            let allowed = if policy.admin() { vec!["*".to_owned()] } else { field_list(g(&policy.rule(object_type), "read_fields")) };
            let public = if caller.cross_org { Some(public_fields(&policy, object_type)) } else { None };
            let tview = self.type_view(&policy, object_type);
            for name in filters.keys() {
                if props.get(name).is_none()
                    || (!allowed.iter().any(|a| a == "*") && !allowed.contains(name))
                    || !tview.has(name)
                    || public.as_ref().is_some_and(|p| !p.contains(name))
                {
                    return Err(CrmError::forbidden("Filter field unavailable"));
                }
            }
            let mut q = Sql::new(&format!("SELECT {} FROM crm_records WHERE ", s::RECORDS));
            let po = q.p(org.to_owned());
            let pt = q.p(object_type.to_owned());
            q.push(&format!("org_id = {po} AND object_type = {pt} AND deleted = false"));
            if !policy.admin() {
                let rule = policy.rule(object_type);
                let scope = g(&rule, "read").as_str().map(str::to_owned).unwrap_or_else(|| if rule.get("read").is_some() { String::new() } else { "none".into() });
                let granted: Vec<String> = policy.records().iter().filter(|(_, rights)| py_in("read", rights)).map(|(k, _)| k.clone()).collect();
                let mut access = if granted.is_empty() { "false".to_owned() } else { format!("id = ANY({})", q.p(granted)) };
                if scope == "all" {
                    access = format!("org_id = {}", q.p(org.to_owned()));
                } else if scope == "own" {
                    access = format!("{access} OR owner_id = {}", q.p(actor.clone()));
                }
                let derived: Vec<String> = policy.bound.keys().cloned().collect();
                if !derived.is_empty() {
                    access = format!("{access} OR id = ANY({})", q.p(derived));
                }
                q.push(&format!(" AND ({access}) AND quarantined = false"));
            }
            if caller.shared {
                let derived: Vec<String> = policy.bound.keys().cloned().collect();
                if derived.is_empty() {
                    q.push(" AND false");
                } else {
                    let p = q.p(derived);
                    q.push(&format!(" AND id = ANY({p})"));
                }
            }
            for (name, value) in filters {
                let errors = vexa_native_kit::schema::errors(value, &props[name.as_str()]);
                if !errors.is_empty() {
                    return Err(CrmError::crm(format!("Invalid filter value for {name}")));
                }
                let key = q.p(name.clone());
                match value {
                    Value::Bool(b) => {
                        let v = q.p(*b);
                        q.push(&format!(" AND CAST((fields ->> {key}) AS BOOLEAN) = {v}"));
                    }
                    Value::Number(n) if n.is_i64() || n.is_u64() => {
                        let v = q.p(n.as_i64().unwrap_or(i64::MAX));
                        q.push(&format!(" AND CAST((fields ->> {key}) AS INTEGER) = {v}"));
                    }
                    Value::Number(n) => {
                        let v = q.p(n.as_f64().unwrap_or(0.0));
                        q.push(&format!(" AND CAST((fields ->> {key}) AS FLOAT) = {v}"));
                    }
                    Value::Null => {
                        q.push(&format!(" AND (fields ->> {key}) IS NULL"));
                    }
                    Value::String(t) => {
                        let v = q.p(t.clone());
                        q.push(&format!(" AND (fields ->> {key}) = {v}"));
                    }
                    _ => return Err(CrmError::internal("a list or dict filter value has no SQL comparison")),
                }
            }
            let pl = q.p(limit + 1);
            let pf = q.p(offset);
            q.push(&format!(" ORDER BY id LIMIT {pl} OFFSET {pf}"));
            let rows = q.maps(c)?;
            let mut result: Vec<Obj> = Vec::new();
            for row in rows.iter().take(limit as usize) {
                let mut r = self.visible(&policy, row)?;
                r.insert("href".into(), record_href(&col(row, "id")).into());
                result.push(r);
            }
            let ids: Vec<String> = result.iter().map(|r| crate::val::s(&r["id"])).collect();
            let links = if ids.is_empty() {
                Vec::new()
            } else {
                c.maps(&format!("SELECT {} FROM crm_relationships WHERE org_id = $1 AND record_id = ANY($2) AND target_domain = 'crm'", s::RELATIONSHIPS), &[&org, &ids])?
            };
            let target_ids: Vec<String> = links.iter().map(|l| col(l, "target_id")).collect::<BTreeSet<_>>().into_iter().collect();
            let mut targets: HashMap<String, Obj> = HashMap::new();
            if !target_ids.is_empty() {
                for t in c.maps(&format!("SELECT {} FROM crm_records WHERE org_id = $1 AND id = ANY($2) AND deleted = false", s::RECORDS), &[&org, &target_ids])? {
                    match self.visible(&policy, &t) {
                        Ok(v) => {
                            targets.insert(col(&t, "id"), v);
                        }
                        Err(e) if e.is_not_found() => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            for link in &links {
                let rid = col(link, "record_id");
                let Some(record) = result.iter_mut().find(|r| r["id"].as_str() == Some(rid.as_str())) else { continue };
                let kind = col(link, "kind");
                if let Some(target) = targets.get(&col(link, "target_id")) {
                    if record["fields"].get(&kind).is_some() {
                        let entry = json!({"field": kind, "record_id": target["id"],
                                           "label": link_label(&target["fields"], &target["object_type"], &["Name"])});
                        match record.get_mut("links") {
                            Some(Value::Array(a)) => a.push(entry),
                            _ => {
                                record.insert("links".into(), json!([entry]));
                            }
                        }
                    }
                }
            }
            let card = self.card(c, org, object_type)?;
            let mut readable: Set = if allowed.iter().any(|a| a == "*") { crate::val::keys(&props).into_iter().collect() } else { allowed.iter().cloned().collect() };
            if caller.shared {
                readable = crate::val::keys(&props).into_iter().filter(|n| tview.has(n)).collect();
            }
            if let Some(p) = &public {
                readable = readable.intersection(p).cloned().collect();
            }
            let next = if rows.len() as i64 > limit { json!(offset + limit) } else { Value::Null };
            let href = format!("/crm?{}", crate::val::urlencode(&[("object", object_type), ("filters", &crate::val::dumps_compact(&Value::Object(filters.clone())))]));
            let out = json!({"records": result, "next_offset": next, "card": self.card_with(card, &|f| readable.contains(f)), "href": href});
            Ok(if caller.cross_org { cross_org_answer("search", out) } else { out })
        })
    }

    pub fn resolve_name(&self, org: &str, caller: &Caller, name: &str) -> R<Value> {
        let name = crate::val::casefold(crate::val::strip(name));
        if name.is_empty() {
            return Err(CrmError::crm("Entity name is required"));
        }
        let like = name.replace('/', "//").replace('%', "/%").replace('_', "/_");
        self.connect(|c| {
            let policy = self.policy(c, org, caller, true)?;
            let sql = format!(
                "SELECT {} FROM crm_records WHERE org_id = $1 AND deleted = false AND (lower((fields ->> 'Name')) LIKE $2 || '%' ESCAPE '/' OR lower((fields ->> 'name')) LIKE $2 || '%' ESCAPE '/' OR lower((fields ->> 'Subject')) LIKE $2 || '%' ESCAPE '/' OR lower(trim(coalesce((fields ->> 'FirstName'), '') || ' ' || coalesce((fields ->> 'LastName'), ''))) LIKE $2 || '%' ESCAPE '/') ORDER BY id",
                s::RECORDS
            );
            let mut matches = Vec::new();
            let mut prefixes = Vec::new();
            for row in c.maps(&sql, &[&org, &like])? {
                let mut record = match self.visible(&policy, &row) {
                    Ok(r) => r,
                    Err(e) if e.is_not_found() => continue,
                    Err(e) => return Err(e),
                };
                let visible = record["fields"].clone();
                let mut labels: Vec<String> = ["Name", "name", "Subject"].iter().map(|k| or_str(g(&visible, k))).collect();
                let full = ["FirstName", "LastName"].iter().map(|k| or_str(g(&visible, k))).collect::<Vec<_>>().join(" ");
                labels.push(crate::val::strip(&full).to_owned());
                let exact = labels.iter().any(|l| crate::val::casefold(l) == name);
                if !exact && !labels.iter().any(|l| crate::val::casefold(l).starts_with(&name)) {
                    continue;
                }
                record.insert("href".into(), record_href(&col(&row, "id")).into());
                if exact {
                    matches.push(Value::Object(record));
                } else {
                    prefixes.push(Value::Object(record));
                }
            }
            let out = json!({"records": if matches.is_empty() { prefixes } else { matches }});
            Ok(if caller.cross_org { cross_org_answer("resolve", out) } else { out })
        })
    }

    pub fn validate(&self, definition: &Value, fields: &Value) -> R<()> {
        let mut errors = vexa_native_kit::schema::errors(fields, definition);
        if errors.is_empty() {
            return Ok(());
        }
        let key = |e: &vexa_native_kit::schema::SchemaError| -> String {
            let parts: Vec<String> = e
                .path
                .iter()
                .map(|p| match p {
                    vexa_native_kit::schema::PathPart::Key(k) => vexa_native_kit::pyjson::py_str_repr(k),
                    vexa_native_kit::schema::PathPart::Index(i) => i.to_string(),
                })
                .collect();
            format!("deque([{}])", parts.join(", "))
        };
        errors.sort_by_key(|e| key(e));
        Err(CrmError::crm(format!("Invalid fields: {}", errors[0].message)))
    }

    pub fn sync_relationships(&self, c: &mut Tx, row: &Row) -> R<()> {
        let org = col(row, "org_id");
        let id = col(row, "id");
        let definition = self.definition(c, &org, &col(row, "object_type"))?;
        c.exec("DELETE FROM crm_relationships WHERE org_id = $1 AND record_id = $2 AND target_domain = 'crm'", &[&org, &id])?;
        let fields = m(row, "fields").clone();
        if let Some(props) = definition.get("properties").and_then(Value::as_object) {
            for (name, field) in props {
                let targets = field_list(g(field, "referenceTo"));
                let value = g(&fields, name);
                if targets.is_empty() || !truthy(value) {
                    continue;
                }
                let value = crate::val::pystr(value);
                let target = c.scalar("SELECT id FROM crm_records WHERE org_id = $1 AND id = $2 AND object_type = ANY($3) AND deleted = false", &[&org, &value, &targets])?;
                if let Some(t) = target {
                    c.exec(
                        &format!("INSERT INTO crm_relationships ({}) VALUES ($1, $2, $3, $4, 'crm', $5)", s::RELATIONSHIPS),
                        &[&org, &uuid4(), &id, name, &crate::val::s(&t)],
                    )?;
                    continue;
                }
                let sources = c.tuples("SELECT system, source_org FROM crm_source_mappings WHERE org_id = $1 AND record_id = $2", &[&org, &id])?;
                for src in sources {
                    let (system, source_org) = (crate::val::s(&src[0]), crate::val::s(&src[1]));
                    let target = c.scalar(
                        "SELECT record_id FROM crm_source_mappings WHERE org_id = $1 AND system = $2 AND source_org = $3 AND object_type = ANY($4) AND source_id = $5",
                        &[&org, &system, &source_org, &targets, &value],
                    )?;
                    if let Some(t) = target {
                        c.exec(
                            &format!("INSERT INTO crm_relationships ({}) VALUES ($1, $2, $3, $4, 'crm', $5)", s::RELATIONSHIPS),
                            &[&org, &uuid4(), &id, name, &crate::val::s(&t)],
                        )?;
                    }
                }
            }
        }
        for target in crate::markdown_links::crm_references(m(row, "narrative").as_str().unwrap_or("")) {
            let exists = c.scalar("SELECT id FROM crm_records WHERE org_id = $1 AND id = $2 AND deleted = false", &[&org, &target])?;
            if exists.is_some() {
                c.exec(
                    &format!("INSERT INTO crm_relationships ({}) VALUES ($1, $2, $3, 'Description', 'crm', $4)", s::RELATIONSHIPS),
                    &[&org, &uuid4(), &id, &target],
                )?;
            }
        }
        Ok(())
    }

    /// One append-only revision and its fact. `decision` makes it a decision record.
    pub fn revision(&self, c: &mut Tx, org: &str, actor: &str, before: Option<&Row>, after: &Row, reason: &str, evidence: &Value, decision: Option<&Value>) -> R<()> {
        let rec = |k: &str| -> String { decision.map(|d| or_str(g(d, k))).unwrap_or_default() };
        let before_v = before.map(|b| Value::Object(b.clone())).unwrap_or(Value::Null);
        let after_v = Value::Object(after.clone());
        let rid = col(after, "id");
        let revision = m(after, "revision").as_i64().unwrap_or(0);
        c.exec(
            &format!("INSERT INTO crm_revisions ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)", s::REVISIONS),
            &[&org, &rid, &Int(revision), &actor, &now_iso(), &reason, &before_v, &after_v, evidence,
              &rec("decision"), &rec("credential_class"), &rec("nonce"), &rec("content_hash")],
        )?;
        let event_id = uuid4();
        let envelope = self.envelope(c, org, after)?;
        let event = json!({"event_type": "crm.record.changed", "source_event_id": event_id,
            "subject_refs": {"org_id": org, "record_id": rid, "revision": revision, "uid": actor},
            "envelope": envelope});
        c.exec(
            &format!("INSERT INTO crm_outbox ({}) VALUES ($1, $2, $3, $4, $5, false)", s::OUTBOX),
            &[&org, &event_id, &rid, &Int(revision), &event],
        )?;
        Ok(())
    }

    /// D8: who a fact reaches (event.v2's envelope, before it is sealed).
    pub fn envelope(&self, c: &mut Tx, org: &str, row: &Row) -> R<Value> {
        let empty = json!({});
        let fields = match m(row, "fields") {
            v if truthy(v) => v,
            _ => &empty,
        };
        let owner = crate::val::pystr(m(row, "owner_id"));
        let is_card = truthy(g(&self.definition(c, org, &col(row, "object_type"))?, "x-card"));
        if !is_card {
            return Ok(json!({"v": 2, "producer": "crm", "object": "record", "owner": owner, "visibility": "owner", "audience": [owner]}));
        }
        let id = col(row, "id");
        let members: Vec<Value> = c.column("SELECT subject FROM crm_card_members WHERE org_id = $1 AND record_id = $2 ORDER BY subject", &[&org, &id])?;
        let bindings = self.bindings(c, org, &id)?;
        let mut people: Vec<Value> = vec![g(fields, "NextActor").clone(), g(fields, "Requester").clone(), m(row, "owner_id").clone()];
        people.extend(members);
        let mut audience: Vec<String> = Vec::new();
        for p in people.iter().filter(|p| truthy(p)) {
            let t = crate::val::pystr(p);
            if !audience.contains(&t) {
                audience.push(t);
            }
        }
        audience.extend(bindings.iter().map(|w| format!("ws:{w}")));
        audience.truncate(200);
        let mut lifecycle = Map::new();
        for (k, f) in [("kind", "Kind"), ("state", "State"), ("next_actor", "NextActor"), ("next_check_at", "NextCheckAt"), ("handoff", "Handoff")] {
            let v = g(fields, f);
            if truthy(v) {
                lifecycle.insert(k.into(), crate::val::pystr(v).into());
            }
        }
        Ok(json!({"v": 2, "producer": "crm", "object": "card", "owner": owner,
                  "visibility": if bindings.is_empty() { "members" } else { "workspace" },
                  "audience": audience, "lifecycle": lifecycle}))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create(&self, org: &str, caller: &Caller, object_type: &str, fields: &Obj, narrative: &str, reason: &str, evidence: &Value, idempotency_key: &str, matches: &[Value]) -> R<Value> {
        let actor = caller.subject.clone();
        self.begin(|c| {
            let policy = self.policy(c, org, caller, true)?;
            if caller.unwatched() {
                return Err(CrmError::refused(refusal()));
            }
            let rule = policy.rule(object_type);
            if !policy.admin() && !truthy(g(&rule, "create")) {
                return Err(CrmError::forbidden("Create not permitted"));
            }
            let allowed = if policy.admin() { vec!["*".to_owned()] } else { field_list(g(&rule, "write_fields")) };
            if !allowed.iter().any(|a| a == "*") && (fields.keys().any(|k| !allowed.contains(k)) || !narrative.is_empty()) {
                return Err(CrmError::forbidden("Field write not permitted"));
            }
            let fields = self.card_fields(c, org, object_type, fields, None, Some(&actor))?;
            self.validate(&self.definition(c, org, object_type)?, &Value::Object(fields.clone()))?;
            let record_id = if idempotency_key.is_empty() {
                uuid4()
            } else {
                uuid5_url(&dumps(&json!(["crm-create", org, actor, idempotency_key])))
            };
            if !idempotency_key.is_empty() {
                c.exec("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", &[&record_id])?;
                let original = c.scalar("SELECT \"after\" FROM crm_revisions WHERE org_id = $1 AND record_id = $2 AND revision = 1", &[&org, &record_id])?;
                if let Some(original) = original.filter(truthy) {
                    if g(&original, "object_type").as_str() != Some(object_type)
                        || !py_eq(g(&original, "fields"), &Value::Object(fields.clone()))
                        || g(&original, "narrative").as_str() != Some(narrative)
                    {
                        return Err(CrmError::conflict("Idempotency key was used for a different create request"));
                    }
                    let row = self.row(c, org, &record_id)?;
                    self.rights(&policy, &row, "read")?;
                    return Ok(json!({"status": "saved", "record_id": record_id, "revision": 1, "replayed": true}));
                }
            }
            let mut row = Map::new();
            row.insert("org_id".into(), org.into());
            row.insert("id".into(), record_id.clone().into());
            row.insert("object_type".into(), object_type.into());
            row.insert("owner_id".into(), actor.clone().into());
            row.insert("revision".into(), 1.into());
            row.insert("fields".into(), Value::Object(fields.clone()));
            row.insert("narrative".into(), narrative.into());
            row.insert("quarantined".into(), false.into());
            row.insert("deleted".into(), false.into());
            c.exec(
                "INSERT INTO crm_records (org_id, id, object_type, owner_id, revision, fields, narrative, quarantined, deleted) VALUES ($1, $2, $3, $4, 1, $5, $6, false, false)",
                &[&org, &record_id, &object_type, &actor, &Value::Object(fields.clone()), &narrative],
            )?;
            self.add_match_ids(c, org, &record_id, matches)?;
            self.audit_names(&record_id);
            self.sync_relationships(c, &row)?;
            self.revision(c, org, &actor, None, &row, reason, evidence, None)?;
            Ok(json!({"status": "saved", "record_id": record_id, "revision": 1}))
        })
    }

    /// Store._edit: a direct write of fields and/or the narrative at the expected revision.
    #[allow(clippy::too_many_arguments)]
    pub fn edit(&self, c: &mut Tx, org: &str, actor: &str, policy: &Policy, record_id: &str, expected_revision: i64, fields: &Obj, narrative: Option<&str>, reason: &str, evidence: &Value) -> R<Value> {
        let row = self.row(c, org, record_id)?;
        self.rights(policy, &row, "read")?;
        let allowed = self.rights(policy, &row, "write")?;
        if !allowed.iter().any(|a| a == "*") && (fields.keys().any(|k| !allowed.contains(k)) || narrative.is_some()) {
            return Err(CrmError::forbidden("Field write not permitted"));
        }
        if m(&row, "revision").as_i64() != Some(expected_revision) {
            return Err(CrmError::conflict("Record changed; read the current revision"));
        }
        let before_fields = m(&row, "fields").clone();
        let fields = self.card_fields(c, org, &col(&row, "object_type"), fields, Some(&before_fields), Some(actor))?;
        let mut after = row.clone();
        let mut merged = before_fields.as_object().cloned().unwrap_or_default();
        for (k, v) in fields {
            merged.insert(k, v);
        }
        after.insert("fields".into(), Value::Object(merged));
        after.insert("revision".into(), json!(expected_revision + 1));
        if let Some(n) = narrative {
            after.insert("narrative".into(), n.into());
        }
        self.validate(&self.definition(c, org, &col(&row, "object_type"))?, &after["fields"])?;
        let changed = c.exec(
            "UPDATE crm_records SET org_id = $1, id = $2, object_type = $3, owner_id = $4, revision = $5, fields = $6, narrative = $7, quarantined = $8, deleted = $9, account_id = $10, merged_into = $11 WHERE org_id = $12 AND id = $13 AND revision = $14",
            &[&col(&after, "org_id"), &col(&after, "id"), &col(&after, "object_type"), &col(&after, "owner_id"), &Int(expected_revision + 1),
              &after["fields"], &col(&after, "narrative"), &truthy(m(&after, "quarantined")), &truthy(m(&after, "deleted")),
              &m(&after, "account_id").as_str(), &m(&after, "merged_into").as_str(), &org, &record_id, &Int(expected_revision)],
        )?;
        if changed != 1 {
            return Err(CrmError::conflict("Record changed; read the current revision"));
        }
        self.sync_relationships(c, &after)?;
        self.revision(c, org, actor, Some(&row), &after, reason, evidence, None)?;
        Ok(json!({"status": "saved", "record_id": record_id, "revision": expected_revision + 1}))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn change(&self, org: &str, caller: &Caller, record_id: &str, expected_revision: i64, fields: &Obj, narrative: Option<&str>, reason: &str, evidence: &Value, propose: bool) -> R<Value> {
        let actor = caller.subject.clone();
        self.begin(|c| {
            let policy = self.policy(c, org, caller, true)?;
            let mut propose = propose;
            if caller.delegated && !propose {
                let direct: Set = field_list(policy.get("agent_direct_fields")).into_iter().collect();
                if caller.unwatched() || narrative.is_some() || fields.is_empty() || !fields.keys().all(|k| direct.contains(k)) {
                    propose = true;
                } else if fields.contains_key("State") && self.is_card(c, org, record_id)? {
                    propose = true;
                }
            }
            if propose {
                let row = self.row(c, org, record_id)?;
                let view = self.view(&policy, &row)?;
                if m(&row, "revision").as_i64() != Some(expected_revision) {
                    return Err(CrmError::conflict("Record changed; read the current revision"));
                }
                if fields.keys().any(|k| !view.has(k)) || (!view.narrative && narrative.is_some()) {
                    return Err(CrmError::forbidden("Cannot propose changes to unreadable fields"));
                }
                let before_fields = m(&row, "fields").clone();
                let fields = self.card_fields(c, org, &col(&row, "object_type"), fields, Some(&before_fields), None)?;
                let mut merged = before_fields.as_object().cloned().unwrap_or_default();
                for (k, v) in &fields {
                    merged.insert(k.clone(), v.clone());
                }
                self.validate(&self.definition(c, org, &col(&row, "object_type"))?, &Value::Object(merged))?;
                let proposal = uuid4();
                let patch = json!({"fields": fields, "narrative": narrative, "author_kind": caller.kind(),
                                   "session": caller.session, "created_at": now_iso()});
                c.exec(
                    &format!("INSERT INTO crm_change_proposals ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')", s::CHANGE_PROPOSALS),
                    &[&org, &proposal, &col(&row, "id"), &Int(expected_revision), &actor, &patch, &evidence, &reason],
                )?;
                return Ok(json!({"status": "proposed", "proposal_id": proposal}));
            }
            if policy.flag("review_required") && !policy.admin() {
                return Err(CrmError::forbidden("This caller must submit a proposal"));
            }
            self.edit(c, org, &actor, &policy, record_id, expected_revision, fields, narrative, reason, evidence)
        })
    }

    pub fn history(&self, org: &str, caller: &Caller, record_id: &str) -> R<Value> {
        self.connect(|c| {
            let policy = self.policy(c, org, caller, true)?;
            let row = self.row(c, org, record_id)?;
            let view = self.view(&policy, &row)?;
            let mut result = Vec::new();
            for rev in c.maps(&format!("SELECT {} FROM crm_revisions WHERE org_id = $1 AND record_id = $2 ORDER BY revision DESC LIMIT 100", s::REVISIONS), &[&org, &record_id])? {
                let before = match m(&rev, "before") {
                    Value::Object(b) if !b.is_empty() => Value::Object(self.visible(&policy, b)?),
                    _ => Value::Null,
                };
                let after = match m(&rev, "after") {
                    Value::Object(a) => Value::Object(self.visible(&policy, a)?),
                    _ => return Err(CrmError::internal("a revision without an after snapshot")),
                };
                result.push(json!({"revision": m(&rev, "revision"), "created_at": m(&rev, "created_at"), "before": before, "after": after,
                    "reason": if view.full { m(&rev, "reason").clone() } else { Value::Null },
                    "evidence": if view.full { m(&rev, "evidence").clone() } else { json!([]) }}));
            }
            let out = json!({"revisions": result});
            Ok(if caller.cross_org { cross_org_answer("history", out) } else { out })
        })
    }

    pub fn review(&self, org: &str, caller: &Caller, proposal_id: &str, accept: bool) -> R<Value> {
        let actor = caller.subject.clone();
        self.begin(|c| {
            let policy = self.policy(c, org, caller, true)?;
            if caller.delegated {
                return Err(CrmError::refused(confirm_refusal()));
            }
            let p = c.map(&format!("SELECT {} FROM crm_change_proposals WHERE org_id = $1 AND id = $2 FOR UPDATE", s::CHANGE_PROPOSALS), &[&org, &proposal_id])?;
            let Some(p) = p else { return Err(CrmError::not_found("Proposal not found")) };
            if col(&p, "status") != "pending" {
                return Err(CrmError::conflict("Proposal already reviewed"));
            }
            let status = if accept { "accepted" } else { "rejected" };
            if m(&p, "record_id").is_null() || self.is_card(c, org, &col(&p, "record_id"))? {
                let Some(cards) = self.cards() else { return Err(CrmError::not_found("Proposal not found")) };
                let result = cards.review(c, org, caller, &policy, &p, accept)?;
                c.exec("UPDATE crm_change_proposals SET status = $1 WHERE org_id = $2 AND id = $3", &[&status, &org, &proposal_id])?;
                return Ok(result);
            }
            if !policy.admin() && !policy.flag("reviewer") {
                return Err(CrmError::forbidden("Review not permitted"));
            }
            let row = self.row(c, org, &col(&p, "record_id"))?;
            self.rights(&policy, &row, "write")?;
            let mut result = json!({"status": "rejected", "proposal_id": proposal_id});
            if accept {
                let patch = m(&p, "patch");
                let pf = patch.get("fields").and_then(Value::as_object).cloned().ok_or_else(|| CrmError::internal("KeyError: 'fields'"))?;
                let narrative = g(patch, "narrative").as_str().map(str::to_owned);
                result = self.edit(c, org, &actor, &policy, &col(&p, "record_id"), m(&p, "base_revision").as_i64().unwrap_or(0), &pf,
                                   narrative.as_deref(), &col(&p, "reason"), m(&p, "evidence"))?;
            }
            c.exec("UPDATE crm_change_proposals SET status = $1 WHERE org_id = $2 AND id = $3", &[&status, &org, &proposal_id])?;
            Ok(result)
        })
    }

    pub fn is_card(&self, c: &mut Tx, org: &str, record_id: &str) -> R<bool> {
        let kind = c.scalar("SELECT object_type FROM crm_records WHERE org_id = $1 AND id = $2", &[&org, &record_id])?;
        match kind.filter(truthy) {
            Some(k) => Ok(truthy(g(&self.definition(c, org, &crate::val::s(&k))?, "x-card"))),
            None => Ok(false),
        }
    }

    pub fn card_fields(&self, c: &mut Tx, org: &str, object_type: &str, fields: &Obj, before: Option<&Value>, actor: Option<&str>) -> R<Obj> {
        let Some(cards) = self.cards() else { return Ok(fields.clone()) };
        if !truthy(g(&self.definition(c, org, object_type)?, "x-card")) {
            return Ok(fields.clone());
        }
        cards.normalise_fields(object_type, fields, before, actor)
    }

    pub fn merged_ids(&self, c: &mut Tx, org: &str, record_id: &str) -> R<Vec<String>> {
        let mut ids = vec![record_id.to_owned()];
        let mut frontier = vec![record_id.to_owned()];
        for _ in 0..8 {
            if frontier.is_empty() {
                break;
            }
            frontier = c.column("SELECT id FROM crm_records WHERE org_id = $1 AND merged_into = ANY($2)", &[&org, &frontier])?.iter().map(crate::val::s).collect();
            ids.extend(frontier.iter().cloned());
        }
        Ok(ids)
    }

    pub fn bindings_of(&self, c: &mut Tx, org: &str, workspace: &str) -> R<Vec<String>> {
        let mut out: Vec<String> = c.column("SELECT record_id FROM crm_workspace_bindings WHERE org_id = $1 AND workspace = $2", &[&org, &workspace])?.iter().map(crate::val::s).collect();
        out.sort();
        Ok(out)
    }

    pub fn bindings(&self, c: &mut Tx, org: &str, record_id: &str) -> R<Vec<String>> {
        let mut out: Vec<String> = c.column("SELECT workspace FROM crm_workspace_bindings WHERE org_id = $1 AND record_id = $2", &[&org, &record_id])?.iter().map(crate::val::s).collect();
        out.sort();
        Ok(out)
    }

    pub fn mentioned_in(&self, c: &mut Tx, org: &str, policy: &Policy, row: &Row) -> R<Value> {
        let caller = &policy.caller;
        let ids = self.merged_ids(c, org, &col(row, "id"))?;
        let mut q = Sql::new("SELECT workspace, page FROM crm_page_references WHERE org_id = ");
        let a = q.p(org.to_owned());
        let b = q.p(ids);
        q.push(&format!("{a} AND record_id = ANY({b})"));
        if !(policy.admin() && !caller.delegated) {
            let mut visible: BTreeSet<String> = caller.workspaces.iter().cloned().collect();
            if !caller.delegated {
                for w in c.column("SELECT workspace FROM crm_workspace_rosters WHERE org_id = $1 AND subject = $2 AND role = 'owner'", &[&org, &caller.subject])? {
                    visible.insert(crate::val::s(&w));
                }
            }
            if visible.is_empty() {
                return Ok(json!([]));
            }
            let v = q.p(visible.into_iter().collect::<Vec<_>>());
            q.push(&format!(" AND workspace = ANY({v})"));
        }
        q.push(" ORDER BY workspace, page");
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for r in q.tuples(c)? {
            let key = (crate::val::s(&r[0]), crate::val::s(&r[1]));
            if seen.insert(key.clone()) {
                out.push(json!({"workspace": key.0, "page": key.1}));
            }
        }
        Ok(Value::Array(out))
    }

    pub fn org_policy(&self, c: &mut Tx, org: &str) -> R<Option<Value>> {
        Ok(c.scalar("SELECT default_policy FROM crm_orgs WHERE org_id = $1", &[&org])?.filter(|v| !v.is_null()))
    }

    /// Decision 3, as D35 reads it: resolve the signed-in account to its Person.
    pub fn ensure_account(&self, org: &str, caller: &Caller) -> R<Option<String>> {
        if caller.internal || caller.subject.is_empty() {
            return Ok(None);
        }
        let email = if caller.email_verified { caller.email.clone() } else { String::new() };
        let p = crate::persons::Persons { store: self };
        self.engine_begin(|c| {
            if !email.is_empty() {
                if let Some(held) = p.holder(c, org, &email)? {
                    if p.linked(c, org, &held)?.contains(&caller.subject) {
                        p.prove(c, org, &held, &caller.subject, &email)?;
                        let mut seen = Map::new();
                        seen.insert(caller.subject.clone(), email.clone().into());
                        p.offer(c, org, &held, Some(&seen))?;
                        return Ok(Some(col(&held, "id")));
                    }
                }
                if let Some(matched) = p.bound(c, org, &email)? {
                    let attached = c.scalar("SELECT id FROM crm_records WHERE org_id = $1 AND account_id = $2", &[&org, &caller.subject])?;
                    if p.linked(c, org, &matched)?.is_empty() && attached.is_none() {
                        let before = matched.clone();
                        let mut after = before.clone();
                        let rev = m(&before, "revision").as_i64().unwrap_or(0) + 1;
                        after.insert("account_id".into(), caller.subject.clone().into());
                        after.insert("revision".into(), rev.into());
                        c.exec("UPDATE crm_records SET account_id = $1, revision = $2 WHERE org_id = $3 AND id = $4", &[&caller.subject, &Int(rev), &org, &col(&matched, "id")])?;
                        self.revision(c, org, &caller.subject, Some(&before), &after, "Account attached on sign-in (verified email)", &json!([]), None)?;
                        p.prove(c, org, &after, &caller.subject, &email)?;
                        return Ok(Some(col(&matched, "id")));
                    }
                    p.link(c, org, &matched, &caller.subject, &email)?;
                    return Ok(Some(col(&matched, "id")));
                }
            }
            if let Some(found) = p.resolve(c, org, &caller.subject, "")? {
                p.prove(c, org, &found, &caller.subject, &email)?;
                return Ok(Some(col(&found, "id")));
            }
            if c.scalar("SELECT name FROM crm_object_definitions WHERE org_id = $1 AND name = 'Person'", &[&org])?.is_none() {
                return Ok(None);
            }
            c.exec("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", &[&format!("crm-account-{}", caller.subject)])?;
            if let Some(found) = c.scalar("SELECT id FROM crm_records WHERE org_id = $1 AND account_id = $2", &[&org, &caller.subject])?.filter(truthy) {
                return Ok(Some(crate::val::s(&found)));
            }
            let record_id = uuid5_url(&dumps(&json!(["crm-account", org, caller.subject])));
            let mut fields = Map::new();
            fields.insert("Name".into(), (if caller.email.is_empty() { caller.subject.clone() } else { caller.email.clone() }).into());
            if !email.is_empty() {
                fields.insert("Email".into(), email.clone().into());
            }
            let mut row = Map::new();
            for (k, v) in [("org_id", json!(org)), ("id", json!(record_id)), ("object_type", json!("Person")), ("owner_id", json!(caller.subject)),
                           ("revision", json!(1)), ("fields", Value::Object(fields.clone())), ("narrative", json!("")), ("quarantined", json!(false)),
                           ("deleted", json!(false)), ("account_id", json!(caller.subject)), ("merged_into", Value::Null)] {
                row.insert(k.into(), v);
            }
            c.exec(
                &format!("INSERT INTO crm_records ({}) VALUES ($1, $2, 'Person', $3, 1, $4, '', false, false, $5, NULL)", s::RECORDS),
                &[&org, &record_id, &caller.subject, &Value::Object(fields), &caller.subject],
            )?;
            p.prove(c, org, &row, &caller.subject, &email)?;
            self.revision(c, org, &caller.subject, None, &row, "Person created on sign-in", &json!([]), None)?;
            Ok(Some(record_id))
        })
    }

    pub fn add_match_ids(&self, c: &mut Tx, org: &str, record_id: &str, identifiers: &[Value]) -> R<()> {
        for raw in identifiers {
            let identifier = normalise_match(raw)?;
            let held = c.scalar("SELECT record_id FROM crm_match_ids WHERE org_id = $1 AND identifier = $2", &[&org, &identifier])?;
            if held.as_ref().and_then(Value::as_str) == Some(record_id) {
                continue;
            }
            if held.is_some_and(|h| truthy(&h)) {
                return Err(CrmError::conflict("Identifier already belongs to another record; search for it or merge"));
            }
            let proof = if identifier.starts_with("email:") { Some(s::PROOF_RECORD) } else { None };
            c.exec(&format!("INSERT INTO crm_match_ids ({}) VALUES ($1, $2, $3, $4)", s::MATCH_IDS), &[&org, &identifier, &record_id, &proof])?;
        }
        Ok(())
    }

    pub fn merge(&self, org: &str, caller: &Caller, record_id: &str, into: &str, reason: &str) -> R<Value> {
        let actor = caller.subject.clone();
        if crate::val::strip(reason).is_empty() {
            return Err(CrmError::crm("A merge requires a reason"));
        }
        self.begin(|c| {
            let policy = self.policy(c, org, caller, true)?;
            if caller.delegated {
                return Err(CrmError::refused(confirm_refusal()));
            }
            let loser = self.row(c, org, record_id)?;
            let winner = self.row(c, org, into)?;
            if col(&loser, "id") == col(&winner, "id") {
                return Err(CrmError::crm("A record cannot merge into itself"));
            }
            if col(&loser, "object_type") != col(&winner, "object_type") {
                return Err(CrmError::crm("Only records of one type merge"));
            }
            for row in [&loser, &winner] {
                if !self.rights(&policy, row, "write")?.iter().any(|f| f == "*") {
                    return Err(CrmError::forbidden("Merge needs write access to every field of both records"));
                }
            }
            let (lid, wid) = (col(&loser, "id"), col(&winner, "id"));
            let linked = c.first("SELECT identifier FROM crm_match_ids WHERE org_id = $1 AND record_id = $2 AND identifier LIKE 'account:%' LIMIT 1", &[&org, &lid])?;
            if truthy(m(&loser, "account_id")) || linked.is_some() {
                return Err(CrmError::conflict("This record is a person's sign-in: it joins another person only on their own merge card. Merge the duplicate into this record instead"));
            }
            let rev = m(&loser, "revision").as_i64().unwrap_or(0);
            let mut after = loser.clone();
            after.insert("merged_into".into(), wid.clone().into());
            after.insert("revision".into(), json!(rev + 1));
            c.exec("UPDATE crm_records SET merged_into = $1, revision = $2 WHERE org_id = $3 AND id = $4 AND revision = $5", &[&wid, &Int(rev + 1), &org, &lid, &Int(rev)])?;
            c.exec("UPDATE crm_match_ids SET record_id = $1, proof = NULL WHERE org_id = $2 AND record_id = $3", &[&wid, &org, &lid])?;
            let have: BTreeSet<String> = self.bindings(c, org, &wid)?.into_iter().collect();
            for workspace in self.bindings(c, org, &lid)? {
                if !have.contains(&workspace) {
                    c.exec(&format!("INSERT INTO crm_workspace_bindings ({}) VALUES ($1, $2, $3, $4, $5)", s::WORKSPACE_BINDINGS), &[&org, &workspace, &wid, &actor, &now_iso()])?;
                }
            }
            c.exec("DELETE FROM crm_workspace_bindings WHERE org_id = $1 AND record_id = $2", &[&org, &lid])?;
            self.revision(c, org, &actor, Some(&loser), &after, reason, &json!([{"merged_into": wid}]), None)?;
            Ok(json!({"status": "merged", "record_id": lid, "merged_into": wid}))
        })
    }

    pub fn profile_link(&self, org: &str, caller: &Caller, record_id: &str, handle: &str, linked: bool) -> R<Value> {
        self.begin(|c| {
            let policy = self.policy(c, org, caller, true)?;
            let row = self.row(c, org, record_id)?;
            self.rights(&policy, &row, "write")?;
            if caller.unwatched() {
                return Err(CrmError::refused(refusal()));
            }
            let id = col(&row, "id");
            let old = c.scalar("SELECT target_id FROM crm_relationships WHERE org_id = $1 AND record_id = $2 AND kind = 'links_profile' AND target_domain = 'profile'", &[&org, &id])?;
            c.exec("DELETE FROM crm_relationships WHERE org_id = $1 AND record_id = $2 AND kind = 'links_profile' AND target_domain = 'profile'", &[&org, &id])?;
            if linked {
                c.exec(&format!("INSERT INTO crm_relationships ({}) VALUES ($1, $2, $3, 'links_profile', 'profile', $4)", s::RELATIONSHIPS), &[&org, &uuid4(), &id, &handle])?;
            }
            Ok(json!({"record_id": id, "handle": if linked { json!(handle) } else { Value::Null }, "previous": old.unwrap_or(Value::Null)}))
        })
    }

    pub fn profile_link_of(&self, org: &str, caller: &Caller, record_id: &str) -> R<(String, Option<String>)> {
        self.connect(|c| {
            let policy = self.policy(c, org, caller, true)?;
            let row = self.row(c, org, record_id)?;
            self.rights(&policy, &row, "read")?;
            let id = col(&row, "id");
            let handle = c.scalar("SELECT target_id FROM crm_relationships WHERE org_id = $1 AND record_id = $2 AND kind = 'links_profile' AND target_domain = 'profile'", &[&org, &id])?;
            Ok((id, handle.and_then(|h| h.as_str().map(str::to_owned))))
        })
    }

    pub fn bind(&self, org: &str, caller: &Caller, workspace: &str, record_id: &str, bound: bool) -> R<Value> {
        let actor = caller.subject.clone();
        let workspace = check_workspace(workspace)?;
        self.begin(|c| {
            let policy = self.policy(c, org, caller, true)?;
            if !policy.admin() {
                return Err(CrmError::forbidden("CRM administrator rights required to bind a workspace"));
            }
            if caller.unwatched() {
                return Err(CrmError::refused(refusal()));
            }
            let row = self.row(c, org, record_id)?;
            let id = col(&row, "id");
            let exists = c.scalar("SELECT workspace FROM crm_workspace_bindings WHERE org_id = $1 AND workspace = $2 AND record_id = $3", &[&org, &workspace, &id])?;
            if bound && exists.is_none() {
                c.exec(&format!("INSERT INTO crm_workspace_bindings ({}) VALUES ($1, $2, $3, $4, $5)", s::WORKSPACE_BINDINGS), &[&org, &workspace, &id, &actor, &now_iso()])?;
            } else if !bound && exists.is_some() {
                c.exec("DELETE FROM crm_workspace_bindings WHERE org_id = $1 AND workspace = $2 AND record_id = $3", &[&org, &workspace, &id])?;
            }
            let bound_to = self.bindings(c, org, &id)?;
            Ok(json!({"status": if bound { "bound" } else { "unbound" }, "workspace": workspace, "record_id": id, "bound_to": bound_to}))
        })
    }

    pub fn apply_workspace_snapshot(&self, org: &str, workspace: &str, commit: &str, committed_at: &str, references: &[Value], members: Option<&[Value]>) -> R<Value> {
        let workspace = check_workspace(workspace)?;
        let mut refs: BTreeSet<(String, String)> = BTreeSet::new();
        for r in references {
            let page = crate::val::strip(&or_str(g(r, "page"))).to_owned();
            let rec = if truthy(g(r, "record")) { g(r, "record") } else { g(r, "record_id") };
            let record = crate::val::strip(&or_str(rec)).to_owned();
            if page.is_empty() || page.chars().count() > 500 || record.is_empty() || record.chars().count() > 100 {
                return Err(CrmError::crm("A reference names a page and a record"));
            }
            refs.insert((page, record));
        }
        let stamp = committed_at.to_owned();
        self.begin(|c| {
            let head = c.tuples("SELECT \"commit\", updated_at FROM crm_workspace_heads WHERE org_id = $1 AND workspace = $2", &[&org, &workspace])?.into_iter().next();
            if let Some(h) = &head {
                let updated = crate::val::s(&h[1]);
                if !stamp.is_empty() && !updated.is_empty() && stamp < updated {
                    return Ok(json!({"status": "stale", "workspace": workspace, "commit": h[0]}));
                }
            }
            c.exec("DELETE FROM crm_page_references WHERE org_id = $1 AND workspace = $2", &[&org, &workspace])?;
            for (page, record) in &refs {
                c.exec(&format!("INSERT INTO crm_page_references ({}) VALUES ($1, $2, $3, $4)", s::PAGE_REFERENCES), &[&org, &workspace, page, record])?;
            }
            let mut seen: Vec<String> = Vec::new();
            if let Some(members) = members {
                c.exec("DELETE FROM crm_workspace_rosters WHERE org_id = $1 AND workspace = $2", &[&org, &workspace])?;
                for mm in members {
                    let subject = crate::val::strip(&or_str(g(mm, "subject"))).to_owned();
                    let role = crate::val::lower(crate::val::strip(&or_str(g(mm, "role"))));
                    if subject.is_empty() || seen.contains(&subject) || !["owner", "contributor", "viewer"].contains(&role.as_str()) {
                        continue;
                    }
                    seen.push(subject.clone());
                    c.exec(&format!("INSERT INTO crm_workspace_rosters ({}) VALUES ($1, $2, $3, $4)", s::WORKSPACE_ROSTERS), &[&org, &workspace, &subject, &role])?;
                }
            }
            if head.is_some() {
                c.exec("UPDATE crm_workspace_heads SET \"commit\" = $1, updated_at = $2 WHERE org_id = $3 AND workspace = $4", &[&commit, &stamp, &org, &workspace])?;
            } else {
                c.exec(&format!("INSERT INTO crm_workspace_heads ({}) VALUES ($1, $2, $3, $4)", s::WORKSPACE_HEADS), &[&org, &workspace, &commit, &stamp])?;
            }
            Ok(json!({"status": "applied", "workspace": workspace, "references": refs.len(),
                      "members": if members.is_none() { Value::Null } else { json!(seen.len()) }}))
        })
    }

    /// Erase an individual's personal CRM through the migrations path's function.
    pub fn erase_org(&self, org: &str) -> R<Value> {
        if !crate::orgs::is_personal_org(org) {
            return Err(CrmError::crm("Only an individual account's own CRM (p-<id>) can be erased"));
        }
        let out = self.engine_begin(|c| Ok(c.scalar("SELECT crm_erase_personal_org($1)", &[&org])?.unwrap_or(Value::Null)))?;
        let out = match out {
            Value::String(t) => vexa_native_kit::pyjson_decode::loads(&t).map_err(|_| CrmError::internal("erase answered text that is not JSON"))?,
            other => other,
        };
        if let Some(left) = out.get("left").and_then(Value::as_object) {
            if left.values().any(truthy) {
                let mut parts: Vec<(String, String)> = left.iter().filter(|(_, n)| truthy(n)).map(|(t, n)| (t.clone(), crate::val::pystr(n))).collect();
                parts.sort();
                eprintln!("WARNING:crm.store:crm erase {org}: append-only rows left in place pending a decision: {}",
                          parts.iter().map(|(t, n)| format!("{t}={n}")).collect::<Vec<_>>().join(", "));
            }
        }
        Ok(out)
    }
}
