//! What a page's \`{{crm …}}\` block shows ONE viewer.
//!
//! A workspace page holds a placeholder (\`{{crm company="OeNB"}}\`, \`{{crm people company=OeNB}}\`,
//! \`{{crm deals stage=negotiation}}\`, \`{{crm timeline person="Marvin Hinz" limit=5}}\`). The page's
//! server renderer asks this, with the VIEWER's own key, and draws what comes back. Nothing from the
//! CRM is ever written into the workspace.
//!
//! Per field, the answer says whether the workspace may see it too (\`shared\`). The workspace side is
//! the SAME rule a room reads by (\`Store::view\` for a shared caller over the workspace): one
//! ceiling, two readers.
//!
//! Three things this never answers, so nothing leaks through layout:
//! * a record the viewer cannot read: it is absent, exactly as if it did not exist;
//! * a total, a count of matches or a "next page" marker: the rows are the answer;
//! * an error that differs between "hidden" and "nothing there": both are an empty \`rows\`.
//!
//! Person only: a shared (room) caller is refused.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};
use vexa_native_kit::pg::Tx;

use crate::caller::Caller;
use crate::err::{CrmError, Detail, R};
use crate::schema as s;
use crate::store::{Policy, Row, Store};
use crate::val::{casefold, g, lower, m, or_str, py_eq, pystr, strip, truthy, Obj};

pub const VIEWS: [&str; 5] = ["company", "person", "people", "deals", "timeline"];
pub const ROWS_MAX: i64 = 25;
pub const TITLE_FIELDS: [&str; 3] = ["Name", "Title", "Subject"];

/// BlockRefused(message): a shared caller asked for a personal render.
pub fn block_refused(msg: &str) -> CrmError {
    CrmError::new("BlockRefused", 400, Detail::Text(msg.to_owned()))
}

/// The errors a record the viewer cannot read raises (NotFound, SharedRefused, Forbidden).
fn unreadable(e: &CrmError) -> bool {
    e.isa("NotFound") || e.isa("Forbidden")
}

fn title(fields: &Value, kind: &str) -> String {
    for k in TITLE_FIELDS {
        if truthy(g(fields, k)) {
            return pystr(g(fields, k));
        }
    }
    let full = ["FirstName", "LastName"].iter().map(|k| or_str(g(fields, k))).collect::<Vec<_>>().join(" ");
    let full = strip(&full);
    if full.is_empty() {
        kind.to_owned()
    } else {
        full.to_owned()
    }
}

/// The fields the WORKSPACE may see on this record: the room ceiling for \`workspace\`.
fn workspace_fields(store: &Store, c: &mut Tx, org: &str, viewer: &Caller, workspace: &str, row: &Row) -> R<BTreeSet<String>> {
    if workspace.is_empty() {
        return Ok(BTreeSet::new());
    }
    let room = Caller {
        subject: viewer.subject.clone(),
        workspaces: vec![workspace.to_owned()],
        writable: Some(Vec::new()),
        shared: true,
        delegated: true,
        regime: "human".into(),
        org: viewer.org.clone(),
        ..Default::default()
    };
    let view = match store.policy(c, org, &room, true).and_then(|p| store.view(&p, row)) {
        Ok(v) => v,
        Err(e) if unreadable(&e) => return Ok(BTreeSet::new()),
        Err(e) => return Err(e),
    };
    Ok(crate::val::keys(&view.filter(m(row, "fields"))).into_iter().collect())
}

/// v not in (None, '', [], {}).
fn shown(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(t) => !t.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

fn field_rows(values: &Obj, shared: &BTreeSet<String>) -> Value {
    let mut items: Vec<(&String, &Value)> = values.iter().collect();
    items.sort_by(|a, b| a.0.cmp(b.0));
    Value::Array(
        items
            .into_iter()
            .filter(|(_, v)| shown(v))
            .map(|(k, v)| json!({"name": k, "value": v, "shared": shared.contains(k)}))
            .collect(),
    )
}

fn row_out(store: &Store, c: &mut Tx, org: &str, viewer: &Caller, policy: &Policy, workspace: &str, row: &Row) -> R<Value> {
    let vis = store.visible(policy, row)?;
    let shared = workspace_fields(store, c, org, viewer, workspace, row)?;
    let fields = vis.get("fields").and_then(Value::as_object).cloned().unwrap_or_default();
    let kind = pystr(m(row, "object_type"));
    Ok(json!({"id": m(row, "id"), "type": m(row, "object_type"), "title": title(&Value::Object(fields.clone()), &kind),
        "fields": field_rows(&fields, &shared), "href": format!("/crm?record={}", pystr(m(row, "id")))}))
}

fn records(c: &mut Tx, org: &str, kind: &str) -> R<Vec<Row>> {
    Ok(c.maps(
        &format!("SELECT {} FROM crm_records WHERE org_id = $1 AND object_type = $2 AND deleted = false AND merged_into IS NULL ORDER BY id", s::RECORDS),
        &[&org, &kind],
    )?)
}

/// Records of \`kind\` whose Name is \`name\` (case-insensitive), in id order.
fn find(c: &mut Tx, org: &str, kind: &str, name: &Value) -> R<Vec<Row>> {
    let want = casefold(strip(&or_str(name)));
    if want.is_empty() {
        return Ok(Vec::new());
    }
    let empty = Value::Object(Map::new());
    Ok(records(c, org, kind)?
        .into_iter()
        .filter(|r| {
            let f = m(r, "fields");
            casefold(&title(if truthy(f) { f } else { &empty }, kind)) == want
        })
        .collect())
}

/// \`args.get(k) or ''\` as text.
fn arg(args: &Obj, k: &str) -> Value {
    m(args, k).clone()
}

fn first_truthy(vals: &[Value]) -> Value {
    vals.iter().find(|v| truthy(v)).cloned().unwrap_or(Value::String(String::new()))
}

/// int(str(limit)) when it is all digits, else ROWS_MAX; then clamped to 1..ROWS_MAX.
fn limit_of(args: &Obj) -> i64 {
    let raw = or_str(m(args, "limit"));
    let n = if !raw.is_empty() && raw.chars().all(|c| c.is_ascii_digit()) {
        let digits = raw.trim_start_matches('0');
        if digits.len() > 18 { ROWS_MAX } else { digits.parse::<i64>().unwrap_or(0) }
    } else {
        ROWS_MAX
    };
    n.clamp(1, ROWS_MAX)
}

fn empty_rows(view: &str) -> Value {
    json!({"view": view, "rows": []})
}

/// {view, rows} for one \`{{crm …}}\` block, for this viewer.
pub fn read_block(store: &Store, org: &str, viewer: &Caller, workspace: &str, view: &str, args: &Obj) -> R<Value> {
    if viewer.shared {
        return Err(block_refused("A page block is rendered for one person; a room reads with crm_read."));
    }
    let view = lower(strip(view));
    if !VIEWS.contains(&view.as_str()) {
        return Ok(empty_rows(&view));
    }
    let limit = limit_of(args);
    store.connect(|c| {
        let policy = match store.policy(c, org, viewer, true) {
            Ok(p) => p,
            Err(e) if e.isa("Forbidden") => return Ok(empty_rows(&view)),
            Err(e) => return Err(e),
        };
        let mut readable: Vec<Value> = Vec::new();
        let add = |c: &mut Tx, readable: &mut Vec<Value>, row: &Row| -> R<()> {
            match row_out(store, c, org, viewer, &policy, workspace, row) {
                Ok(v) => readable.push(v),
                // not this viewer's: absent, exactly like nothing
                Err(e) if unreadable(&e) => {}
                Err(e) => return Err(e),
            }
            Ok(())
        };
        if view == "company" || view == "person" {
            let kind = if view == "company" { "Company" } else { "Person" };
            let name = first_truthy(&[arg(args, &view), arg(args, "name")]);
            for row in find(c, org, kind, &name)? {
                add(c, &mut readable, &row)?;
                if !readable.is_empty() {
                    break;
                }
            }
        } else if view == "people" || view == "deals" {
            let kind = if view == "people" { "Person" } else { "Deal" };
            let company = strip(&or_str(m(args, "company"))).to_owned();
            let mut company_ids: BTreeSet<String> = BTreeSet::new();
            if !company.is_empty() {
                for row in find(c, org, "Company", &Value::String(company.clone()))? {
                    match store.view(&policy, &row) {
                        Ok(_) => {
                            company_ids.insert(pystr(m(&row, "id")));
                        }
                        Err(e) if unreadable(&e) => continue,
                        Err(e) => return Err(e),
                    }
                }
                if company_ids.is_empty() {
                    return Ok(empty_rows(&view));
                }
            }
            let stage = casefold(strip(&or_str(m(args, "stage"))));
            for row in records(c, org, kind)? {
                let f = m(&row, "fields");
                if !company_ids.is_empty() {
                    let co = g(f, "Company");
                    if co.is_array() || co.is_object() {
                        return Err(CrmError::internal("TypeError: unhashable type"));
                    }
                    if !co.as_str().is_some_and(|x| company_ids.contains(x)) {
                        continue;
                    }
                }
                if !stage.is_empty() && casefold(&or_str(g(f, "Stage"))) != stage {
                    continue;
                }
                let before = readable.len();
                add(c, &mut readable, &row)?;
                if !stage.is_empty() && readable.len() > before {
                    // a filter on a field the viewer cannot read would say which records hold it
                    let has_stage = readable.last().and_then(|r| r["fields"].as_array()).is_some_and(|fs| fs.iter().any(|x| x["name"] == "Stage"));
                    if !has_stage {
                        readable.pop();
                    }
                }
                if readable.len() as i64 >= limit {
                    break;
                }
            }
        } else {
            let who = first_truthy(&[arg(args, "person"), arg(args, "company")]);
            let kind = if truthy(m(args, "person")) { "Person" } else { "Company" };
            for row in find(c, org, kind, &who)? {
                match store.view(&policy, &row) {
                    Ok(_) => {}
                    Err(e) if unreadable(&e) => continue,
                    Err(e) => return Err(e),
                }
                let id = pystr(m(&row, "id"));
                let hist = store.history(org, viewer, &id)?;
                let shared = workspace_fields(store, c, org, viewer, workspace, &row)?;
                let revs = g(&hist, "revisions").as_array().cloned().unwrap_or_default();
                for rev in revs.iter().take(limit as usize) {
                    let fields_of = |k: &str| -> Obj {
                        let side = g(rev, k);
                        let f = if truthy(side) { g(side, "fields") } else { &Value::Null };
                        f.as_object().cloned().unwrap_or_default()
                    };
                    let after = fields_of("after");
                    let before = fields_of("before");
                    let changed: Obj = after.into_iter().filter(|(k, v)| !py_eq(m(&before, k), v)).collect();
                    readable.push(json!({"id": format!("{id}@{}", pystr(g(rev, "revision"))), "type": "Revision",
                        "title": or_str(g(rev, "created_at")), "fields": field_rows(&changed, &shared),
                        "href": format!("/crm?record={id}")}));
                }
                break;
            }
        }
        readable.truncate(limit as usize);
        Ok(json!({"view": view, "rows": readable}))
    })
}
