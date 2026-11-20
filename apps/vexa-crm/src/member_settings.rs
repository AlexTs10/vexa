//! Workspace settings: one person's settings for one workspace, on the CRM \`member_of\` relation.
//!
//! Pinned, hidden from home, muted, the room order, a level override and the collapsed sections
//! (\`crm_member_settings\`). Per-person state about a workspace lives on the CRM relation, crm-api is
//! its only writer, and the rows live in the person's own boundary's CRM.
//!
//! - **The person is the caller's subject**, never an argument: a read answers only the caller's own
//!   rows, a write changes only the caller's own row.
//! - **A shared turn reads none of them**: other people read its answer, so a read there is refused
//!   with \`person_only\` like a write.
//! - **Who writes** is decided as the desk decides it (\`desk::may_arrange\`).
//! - **Settings carry no access.** A slug is checked for shape only; a row grants nothing.
//! - **A set is partial**: the keys given merge onto what is there, or onto the defaults. An unknown
//!   key, or one bad value, refuses the whole set (422).

use std::sync::Arc;

use serde_json::{json, Map, Value};
use vexa_native_kit::pg::Int;

use crate::caller::Caller;
use crate::desk::{id_ok, invalid, may_arrange, refusal, slug_ok};
use crate::err::{CrmError, Detail, R};
use crate::schema as s;
use crate::store::Store;
use crate::val::{m, truthy, Obj};

pub const NOTIFY: [&str; 3] = ["all", "mentions", "none"];
pub const ROOM_ORDER_MAX: usize = 100;
pub const COLLAPSED_MAX: usize = 20;
pub const LEVELS: (i64, i64) = (1, 5);

/// What a slug with no row reads as. Never returned for a slug the person has not set.
pub fn defaults() -> Obj {
    json!({"pinned": false, "hidden": false, "muted": false, "room_order": [], "level": null, "collapsed": [], "updated_at": null})
        .as_object()
        .cloned()
        .unwrap()
}

/// The \`notify\` column is filled with this on a new row; nothing writes or answers it: the
/// notification level per workspace lives in the person's identity notification policy.
pub const NOTIFY_RETIRED_FILL: &str = "all";
pub const NOTIFY_MOVED: &str = "settings.notify moved to the identity notification policy: Settings → Notifications \
(PUT /user/notifications with rooms {\"ws:<slug>\": \"all\" | \"mentions\" | \"none\"})";
/// The keys a set may name; \`updated_at\` is the server's.
pub const KEYS: [&str; 6] = ["pinned", "hidden", "muted", "room_order", "level", "collapsed"];

pub fn person_only_body() -> Value {
    refusal(
        "person_only",
        "Only the person, or you in a turn they typed in their own one-person chat, may change their \
         workspace settings. Tell them in one line how to do it themselves; do not retry it another way.",
        &[],
    )
}

/// PersonOnly(): 403 with the \`person_only\` refusal (a DeskRefused).
pub fn person_only() -> CrmError {
    CrmError::new("PersonOnly", 403, Detail::Body(person_only_body()))
}

pub fn check_slug(workspace: &str) -> R<String> {
    if !slug_ok(workspace) || workspace.contains("..") {
        return Err(invalid("workspace: not a workspace slug"));
    }
    Ok(workspace.to_owned())
}

fn flag(value: &Value, key: &str) -> R<Value> {
    if !value.is_boolean() {
        return Err(invalid(format!("settings.{key} must be true or false")));
    }
    Ok(value.clone())
}

fn list(value: &Value, key: &str, cap: usize) -> R<Value> {
    let items = match value {
        Value::Array(a) if a.len() <= cap => a,
        _ => return Err(invalid(format!("settings.{key} must be a list of at most {cap} ids"))),
    };
    let mut out: Vec<Value> = Vec::new();
    for (n, item) in items.iter().enumerate() {
        if !item.as_str().is_some_and(id_ok) {
            return Err(invalid(format!("settings.{key}[{n}]: not an id")));
        }
        if !out.contains(item) {
            out.push(item.clone());
        }
    }
    Ok(Value::Array(out))
}

/// The validated partial: only known keys, each a valid value. Empty is refused.
pub fn check_settings(settings: &Value) -> R<Obj> {
    let given = match settings {
        Value::Object(o) if !o.is_empty() => o,
        _ => return Err(invalid(format!("settings must name at least one of {}", KEYS.join(", ")))),
    };
    if given.contains_key("notify") {
        return Err(invalid(NOTIFY_MOVED));
    }
    let mut unknown: Vec<&String> = given.keys().filter(|k| !KEYS.contains(&k.as_str())).collect();
    unknown.sort();
    if let Some(k) = unknown.first() {
        return Err(invalid(format!("settings: unknown key {k}; one of {}", KEYS.join(", "))));
    }
    let mut out = Map::new();
    for (key, value) in given {
        let v = match key.as_str() {
            "pinned" | "hidden" | "muted" => flag(value, key)?,
            "level" => {
                let ok = match value {
                    Value::Null => true,
                    Value::Number(n) if n.is_i64() || n.is_u64() => n.as_i64().is_some_and(|v| LEVELS.0 <= v && v <= LEVELS.1),
                    _ => false,
                };
                if !ok {
                    return Err(invalid(format!("settings.level must be a whole number {}..{}, or null", LEVELS.0, LEVELS.1)));
                }
                value.clone()
            }
            "room_order" => list(value, key, ROOM_ORDER_MAX)?,
            _ => list(value, key, COLLAPSED_MAX)?,
        };
        out.insert(key.clone(), v);
    }
    Ok(out)
}

fn view(row: &Obj) -> Obj {
    let arr = |k: &str| match m(row, k) {
        Value::Array(a) => Value::Array(a.clone()),
        _ => Value::Array(Vec::new()),
    };
    let mut o = Map::new();
    o.insert("pinned".into(), truthy(m(row, "pinned")).into());
    o.insert("hidden".into(), truthy(m(row, "hidden")).into());
    o.insert("muted".into(), truthy(m(row, "muted")).into());
    o.insert("room_order".into(), arr("room_order"));
    o.insert("level".into(), m(row, "level").clone());
    o.insert("collapsed".into(), arr("collapsed"));
    o.insert("updated_at".into(), m(row, "updated_at").clone());
    o
}

pub struct MemberSettings {
    pub store: Arc<Store>,
    /// datetime.now(timezone.utc).isoformat().
    pub clock: Box<dyn Fn() -> String + Send + Sync>,
}

impl MemberSettings {
    pub fn new(store: Arc<Store>) -> Self {
        MemberSettings { store, clock: Box::new(crate::val::now_iso) }
    }

    fn person(&self, caller: &Caller) -> R<String> {
        if caller.internal || caller.subject.is_empty() {
            return Err(person_only());
        }
        Ok(caller.subject.clone())
    }

    pub fn read(&self, org: &str, caller: &Caller) -> R<Value> {
        let person = self.person(caller)?;
        if caller.shared {
            // other people read a shared turn: none of this is theirs
            return Err(person_only());
        }
        let rows = self.store.connect(|c| {
            Ok(c.maps(
                &format!("SELECT {} FROM crm_member_settings WHERE org_id = $1 AND person = $2 ORDER BY workspace", s::MEMBER_SETTINGS),
                &[&org, &person],
            )?)
        })?;
        let mut out = Map::new();
        for r in &rows {
            out.insert(crate::val::pystr(m(r, "workspace")), Value::Object(view(r)));
        }
        Ok(json!({"workspaces": out}))
    }

    pub fn set(&self, org: &str, caller: &Caller, workspace: &str, settings: &Value) -> R<Value> {
        let workspace = check_slug(workspace)?;
        let patch = check_settings(settings)?;
        if !may_arrange(caller) {
            return Err(person_only());
        }
        let person = caller.subject.as_str();
        for attempt in 0..2 {
            let done = self.store.engine_begin(|c| {
                let row = c.map(
                    &format!("SELECT {} FROM crm_member_settings WHERE org_id = $1 AND person = $2 AND workspace = $3", s::MEMBER_SETTINGS),
                    &[&org, &person, &workspace],
                )?;
                let mut merged = row.as_ref().map(view).unwrap_or_else(defaults);
                for (k, v) in &patch {
                    merged.insert(k.clone(), v.clone());
                }
                merged.insert("updated_at".into(), (self.clock)().into());
                let b = |k: &str| merged[k].as_bool().unwrap_or(false);
                let level: Option<Int> = merged["level"].as_i64().map(Int);
                let updated = crate::val::pystr(&merged["updated_at"]);
                if row.is_none() {
                    c.exec(
                        "INSERT INTO crm_member_settings (org_id, person, workspace, notify, pinned, hidden, muted, room_order, level, collapsed, updated_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                        &[&org, &person, &workspace, &NOTIFY_RETIRED_FILL, &b("pinned"), &b("hidden"), &b("muted"), &merged["room_order"], &level, &merged["collapsed"], &updated],
                    )?;
                } else {
                    c.exec(
                        "UPDATE crm_member_settings SET pinned = $4, hidden = $5, muted = $6, room_order = $7, level = $8, collapsed = $9, updated_at = $10 \
                         WHERE org_id = $1 AND person = $2 AND workspace = $3",
                        &[&org, &person, &workspace, &b("pinned"), &b("hidden"), &b("muted"), &merged["room_order"], &level, &merged["collapsed"], &updated],
                    )?;
                }
                Ok(merged)
            });
            match done {
                Ok(merged) => return Ok(json!({"workspace": workspace, "settings": merged})),
                // a concurrent first write won: read it and merge again, once
                Err(e) if e.is_integrity() && attempt == 0 => continue,
                Err(e) => return Err(e),
            }
        }
        Err(CrmError::internal("AssertionError: unreachable"))
    }
}
