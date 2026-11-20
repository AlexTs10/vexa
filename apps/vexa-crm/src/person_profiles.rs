//! A profile is a CLAIMED CRM Person record (PRD 0.13.4 D35, founder addition).
//!
//! **Claim.** A signed-in person claims the Person record that the address identity verified for
//! them BINDS (`Persons::binds`), in their home org's CRM. The claim is strictly one-to-one: a second
//! account of the same human joins the claimed Person through the merge card. It happens on its own
//! at sign-in (`auto_claim`) when that record is unclaimed; the record's `Email` field and an identifier a
//! CRM merge carried never make a claim. A claim moves nothing from the org to the person.
//!
//! **Fields split by owner.** `PROFILE_FIELDS` are the person's, edited only by the person who claimed
//! the record, from their own signed-in session. Everything else on the record is the org's.
//!
//! **Visibility.** Profile fields follow the directory rule (agent-api applies it before calling
//! `directory`). The public page is off until the person switches it on, and shows only the fields they
//! marked public; no profile answer reads `crm_records.fields`.
//!
//! **Unclaim** keeps the record and the profile values; `claimed_by` is cleared and the public page goes off.
//!
//! **Social links** are stored as links (https, on the network's own domain). Nothing is fetched.
//! `IMPORTERS` is the seam for an import the person starts; it is empty.

use std::sync::OnceLock;

use serde_json::{json, Map, Value};
use vexa_native_kit::pg::Tx;
use vexa_native_kit::pyjson::py_str_repr;

use crate::caller::Caller;
use crate::err::{CrmError, R};
use crate::persons::{person_error, person_error_status, person_not_found, person_refused, Persons};
use crate::schema as s;
use crate::store::{col, py_in, Store};
use crate::val::{g, lower, m, now_iso, or_str, pystr, strings, strip, truthy, Obj};

/// field → (kind, max length). `links` and `contact` are objects of their own.
pub const PROFILE_FIELDS: [(&str, &str, usize); 9] = [
    ("display_name", "text", 120), ("photo", "url", 500), ("headline", "text", 160),
    ("company", "text", 120), ("bio", "text", 1000), ("location", "text", 120),
    ("timezone", "tz", 64), ("links", "links", 0), ("contact", "contact", 0),
];
/// link → the hosts it may be on (None: any).
pub const LINK_HOSTS: [(&str, Option<&[&str]>); 4] =
    [("linkedin", Some(&["linkedin.com"])), ("github", Some(&["github.com"])), ("x", Some(&["x.com", "twitter.com"])), ("website", None)];
pub const CONTACT_CHANNELS: [&str; 3] = ["email", "chat", "call"];
/// identity's retired profile field → this profile's field
pub const LEGACY_MAP: [(&str, &str); 5] = [("name", "display_name"), ("photo", "photo"), ("role", "headline"), ("company", "company"), ("bio", "bio")];

fn field(name: &str) -> Option<(&'static str, usize)> {
    PROFILE_FIELDS.iter().find(|(n, _, _)| *n == name).map(|(_, k, l)| (*k, *l))
}

pub fn is_profile_field(name: &str) -> bool {
    field(name).is_some()
}

fn tz_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(?:[A-Za-z_]+(?:/[A-Za-z0-9_+\-]+){0,2}|UTC)$").unwrap())
}

/// _CTRL.sub(' ', text): control characters other than tab and newline become spaces.
fn ctrl_to_space(text: &str) -> String {
    text.chars().map(|c| if matches!(c, '\x00'..='\x08' | '\x0b'..='\x1f' | '\x7f') { ' ' } else { c }).collect()
}

/// value in (None, '', {}, [])
fn is_blank(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(t) => t.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// urllib.parse.urlparse(text): (scheme, hostname). Err for the netlocs Python refuses
/// (ValueError: an unbalanced or invalid bracketed host).
pub fn urlparse_host(text: &str) -> R<(String, Option<String>)> {
    let bad = || CrmError::internal("ValueError: Invalid IPv6 URL");
    let mut url: String = text.trim_start_matches(|c: char| c <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let mut scheme = String::new();
    if let Some(i) = url.find(':') {
        let head = &url[..i];
        let first = head.chars().next();
        if i > 0 && first.is_some_and(|c| c.is_ascii_alphabetic()) && head.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
            scheme = head.to_ascii_lowercase();
            url = url[i + 1..].to_owned();
        }
    }
    if !url.starts_with("//") {
        return Ok((scheme, None));
    }
    let rest = &url[2..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let netloc = &rest[..end];
    if netloc.contains('[') != netloc.contains(']') {
        return Err(bad());
    }
    let hostport = netloc.rsplit_once('@').map(|(_, h)| h).unwrap_or(netloc);
    let host;
    if let Some((before, bracketed)) = hostport.split_once('[') {
        if netloc.contains(']') {
            if !before.is_empty() {
                return Err(bad());
            }
            let (h, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return Err(bad());
            }
            check_bracketed_host(h)?;
        }
        host = bracketed.split_once(']').map(|(h, _)| h).unwrap_or(bracketed).to_owned();
    } else {
        host = hostport.split_once(':').map(|(h, _)| h).unwrap_or(hostport).to_owned();
    }
    if host.is_empty() {
        return Ok((scheme, None));
    }
    let host = match host.split_once('%') {
        Some((h, zone)) => format!("{}%{}", lower(h), zone),
        None => lower(&host),
    };
    Ok((scheme, Some(host)))
}

fn check_bracketed_host(h: &str) -> R<()> {
    let bad = || CrmError::internal("ValueError: Invalid IPv6 URL");
    if let Some(rest) = h.strip_prefix('v') {
        let ok = rest.split_once('.').is_some_and(|(hex, tail)| !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) && !tail.is_empty() && !tail.contains('\n'));
        return if ok { Ok(()) } else { Err(bad()) };
    }
    let addr = h.split_once('%').map(|(a, _)| a).unwrap_or(h);
    if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        Ok(())
    } else if addr.parse::<std::net::Ipv4Addr>().is_ok() {
        Err(CrmError::internal("ValueError: An IPv4 address cannot be in brackets"))
    } else {
        Err(bad())
    }
}

fn https(value: &Value, hosts: Option<&[&str]>) -> R<String> {
    let v = strip(&or_str(value)).to_owned();
    let (scheme, host) = urlparse_host(&v)?;
    let host = match host {
        Some(h) if scheme == "https" && v.chars().count() <= 500 => h,
        _ => return Err(person_error("A link is an https address")),
    };
    if let Some(hosts) = hosts.filter(|h| !h.is_empty()) {
        if !hosts.iter().any(|h| host == *h || host.ends_with(&format!(".{h}"))) {
            return Err(person_error(format!("That link is not on {}", hosts[0])));
        }
    }
    Ok(v)
}

/// The person's profile fields, validated; an unknown field is refused, an empty one removed.
pub fn clean(fields: &Value) -> R<Obj> {
    let Some(fields) = fields.as_object() else { return Err(person_error("Profile fields are an object")) };
    let mut out = Map::new();
    for (name, value) in fields {
        let Some((kind, limit)) = field(name) else {
            return Err(person_error(format!("{} is not a profile field", py_str_repr(name))));
        };
        if is_blank(value) {
            continue;
        }
        match kind {
            "text" => {
                let v = strip(&ctrl_to_space(&pystr(value))).to_owned();
                if v.chars().count() > limit {
                    return Err(person_error(format!("{name} is at most {limit} characters")));
                }
                out.insert(name.clone(), Value::String(v));
            }
            "url" => {
                out.insert(name.clone(), Value::String(https(value, None)?));
            }
            "tz" => {
                let v = strip(&pystr(value)).to_owned();
                if !tz_re().is_match(&v) || v.chars().count() > limit {
                    return Err(person_error("A time zone is like Europe/Vienna"));
                }
                out.insert(name.clone(), Value::String(v));
            }
            "links" => {
                let Some(value) = value.as_object() else { return Err(person_error("links is an object")) };
                let mut links = Map::new();
                for (k, v) in value {
                    let Some((_, hosts)) = LINK_HOSTS.iter().find(|(n, _)| n == k) else {
                        return Err(person_error(format!("{} is not a link this profile keeps", py_str_repr(k))));
                    };
                    if truthy(v) {
                        links.insert(k.clone(), Value::String(https(v, *hosts)?));
                    }
                }
                if !links.is_empty() {
                    out.insert(name.clone(), Value::Object(links));
                }
            }
            _ => {
                let Some(value) = value.as_object().filter(|o| o.keys().all(|k| k == "prefer" || k == "note")) else {
                    return Err(person_error("contact is {prefer, note}"));
                };
                let mut cc = Map::new();
                let prefer = m(value, "prefer");
                if truthy(prefer) {
                    if !prefer.as_str().is_some_and(|p| CONTACT_CHANNELS.contains(&p)) {
                        return Err(person_error("prefer is email, chat or call"));
                    }
                    cc.insert("prefer".into(), prefer.clone());
                }
                let note = m(value, "note");
                if truthy(note) {
                    let note = strip(&ctrl_to_space(&pystr(note))).to_owned();
                    if note.chars().count() > 200 {
                        return Err(person_error("The contact note is at most 200 characters"));
                    }
                    cc.insert("note".into(), Value::String(note));
                }
                if !cc.is_empty() {
                    out.insert(name.clone(), Value::Object(cc));
                }
            }
        }
    }
    Ok(out)
}

fn one(name: &str, value: &Value) -> Value {
    let mut o = Map::new();
    o.insert(name.to_owned(), value.clone());
    Value::Object(o)
}

/// (fields, public_fields) out of identity's retired profile: the person's own entries, each kept
/// only if it passes this profile's rules; its links sorted onto LinkedIn, GitHub, X or website.
pub fn from_legacy(legacy: &Value) -> R<(Obj, Vec<String>)> {
    let mut fields = Map::new();
    let mut public: Vec<String> = Vec::new();
    let entries = g(legacy, "fields");
    let entries = if truthy(entries) { entries.as_object().cloned().unwrap_or_default() } else { Map::new() };
    for (old, f) in &entries {
        let (value, is_public) = match f {
            Value::Object(o) => (m(o, "value").clone(), truthy(m(o, "public"))),
            other => (other.clone(), false),
        };
        if let Some((_, new)) = LEGACY_MAP.iter().find(|(o, _)| o == old).filter(|_| truthy(&value)) {
            match clean(&one(new, &value)) {
                Ok(got) => fields.extend(got),
                Err(e) if e.isa("PersonError") => continue,
                Err(e) => return Err(e),
            }
            if is_public && fields.contains_key(*new) {
                public.push(new.to_string());
            }
        } else if old == "links" && truthy(&value) {
            let mut links = Map::new();
            let urls: Vec<Value> = match &value { Value::Array(a) => a.clone(), other => vec![other.clone()] };
            for url in urls {
                let host = lower(&urlparse_host(&pystr(&url))?.1.unwrap_or_default());
                let key = LINK_HOSTS
                    .iter()
                    .find(|(_, hosts)| hosts.is_some_and(|hs| hs.iter().any(|h| host == *h || host.ends_with(&format!(".{h}")))))
                    .map(|(k, _)| *k)
                    .unwrap_or("website");
                if !links.contains_key(key) {
                    match clean(&one("links", &one(key, &url))) {
                        Ok(got) => match got.get("links") {
                            Some(Value::Object(l)) => links.extend(l.clone()),
                            _ => continue, // KeyError: nothing kept
                        },
                        Err(e) if e.isa("PersonError") => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
            if !links.is_empty() {
                fields.insert("links".into(), Value::Object(links));
                if is_public {
                    public.push("links".into());
                }
            }
        }
    }
    public.sort();
    public.dedup();
    Ok((fields, public))
}

/// secrets.token_urlsafe(16)
fn token_urlsafe() -> String {
    vexa_native_kit::b64::url_nopad(&vexa_native_kit::ids::random_bytes(16))
}

/// The claimed-record profile, over the Store's pool and tables.
pub struct Profiles<'a> {
    pub store: &'a Store,
    pub persons: Persons<'a>,
}

impl<'a> Profiles<'a> {
    pub fn new(store: &'a Store) -> Self {
        Profiles { store, persons: Persons::new(store) }
    }

    /// identity's retired profile of `subject`; None when no client is set or there is none.
    fn legacy(&self, subject: &str) -> Option<Option<Value>> {
        self.store.legacy.get().map(|client| client.legacy(subject))
    }

    /// After a claim: move the person's entries from identity's retired profile into this one, if
    /// this one is still empty. The public page stays OFF, but the old handle is kept so the old link
    /// resolves at `/p/<handle>` once they switch it on.
    pub fn carry_legacy(&self, org: &str, subject: &str, record_id: &str) -> R<bool> {
        let Some(legacy) = self.legacy(subject).filter(|_| !record_id.is_empty()) else { return Ok(false) };
        let Some(legacy) = legacy.filter(truthy) else { return Ok(false) };
        let (fields, public) = from_legacy(&legacy)?;
        let mut handle = Some(or_str(g(&legacy, "handle"))).filter(|h| crate::profiles::is_handle(h));
        self.store.engine_begin(|c| {
            let Some(row) = self.by_record(c, org, record_id)? else { return Ok(false) };
            if m(&row, "claimed_by").as_str() != Some(subject) || truthy(m(&row, "fields")) {
                return Ok(false);
            }
            if let Some(h) = &handle {
                if !c.tuples("SELECT record_id FROM crm_profiles WHERE handle = $1", &[h])?.is_empty() {
                    handle = None;
                }
            }
            c.exec(
                "UPDATE crm_profiles SET fields = $1, public_fields = $2, handle = $3, published = false, updated_at = $4 WHERE org_id = $5 AND record_id = $6",
                &[&Value::Object(fields.clone()), &crate::val::str_list(public.clone()), &handle.as_deref(), &now_iso(), &org, &record_id],
            )?;
            Ok(true)
        })
    }

    // ── reading rows ─────────────────────────────────────────────────────────────────────────
    fn by_record(&self, c: &mut Tx, org: &str, record_id: &str) -> R<Option<Obj>> {
        Ok(c.map(&format!("SELECT {} FROM crm_profiles WHERE org_id = $1 AND record_id = $2", s::PROFILES), &[&org, &record_id])?)
    }

    fn claimed_by(&self, c: &mut Tx, org: &str, subject: &str) -> R<Option<Obj>> {
        Ok(c.map(&format!("SELECT {} FROM crm_profiles WHERE org_id = $1 AND claimed_by = $2", s::PROFILES), &[&org, &subject])?)
    }

    /// Person records `subject` may claim with the verified address `email`: the one record that address
    /// binds a sign-in to (`Persons::bound`), when no account holds it or `subject` is one of its accounts.
    pub fn candidates(&self, c: &mut Tx, org: &str, email: &str, subject: &str) -> R<Vec<Obj>> {
        let Some(row) = self.persons.bound(c, org, email)? else { return Ok(Vec::new()) };
        let accounts = self.persons.linked(c, org, &row)?;
        if !accounts.is_empty() && !accounts.iter().any(|a| a == subject) {
            return Ok(Vec::new());
        }
        Ok(vec![row])
    }

    /// The claim any account of this human already holds: this account's own, or the claim on the
    /// Person this account resolves to. `email` is a proven address or "".
    fn human_claim(&self, c: &mut Tx, org: &str, subject: &str, email: &str) -> R<Option<Obj>> {
        if let Some(mine) = self.claimed_by(c, org, subject)? {
            return Ok(Some(mine));
        }
        if let Some(person) = self.persons.resolve(c, org, subject, email)? {
            if let Some(row) = self.by_record(c, org, &col(&person, "id"))? {
                if truthy(m(&row, "claimed_by")) {
                    return Ok(Some(row));
                }
            }
        }
        Ok(None)
    }

    // ── claim ────────────────────────────────────────────────────────────────────────────────
    fn write_claim(&self, c: &mut Tx, org: &str, record: &Obj, subject: &str, email: &str) -> R<()> {
        let now = now_iso();
        let rid = col(record, "id");
        if self.by_record(c, org, &rid)?.is_none() {
            c.exec(
                &format!("INSERT INTO crm_profiles ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", s::PROFILES),
                &[&org, &rid, &subject, &None::<&str>, &json!({}), &json!([]), &false, &None::<&str>, &now, &now],
            )?;
        } else {
            c.exec(
                "UPDATE crm_profiles SET claimed_by = $1, unclaimed_by = $2, claimed_at = $3, updated_at = $4 WHERE org_id = $5 AND record_id = $6",
                &[&subject, &None::<&str>, &now, &now, &org, &rid],
            )?;
        }
        // the account is attached to the record it claimed, so it resolves there however it signs in
        let mut record = record.clone();
        if !truthy(m(&record, "account_id"))
            && c.scalar("SELECT id FROM crm_records WHERE org_id = $1 AND account_id = $2", &[&org, &subject])?.is_none()
        {
            c.exec("UPDATE crm_records SET account_id = $1 WHERE org_id = $2 AND id = $3", &[&subject, &org, &rid])?;
            record.insert("account_id".into(), Value::String(subject.to_owned()));
        }
        if self.persons.linked(c, org, &record)?.iter().any(|a| a == subject) {
            self.persons.prove(c, org, &record, subject, email)?; // the identity path: a proven address
        }
        Ok(())
    }

    /// On sign-in: claim the one record matching the verified address, if exactly one does, it is
    /// unclaimed, this account did not unclaim it, and no account of this human holds a claim.
    pub fn auto_claim(&self, c: &mut Tx, org: &str, caller: &Caller) -> R<Option<String>> {
        if caller.delegated || caller.internal || caller.subject.is_empty() || caller.email.is_empty() || !caller.email_verified {
            return Ok(None);
        }
        if self.human_claim(c, org, &caller.subject, &caller.email)?.is_some() {
            return Ok(None);
        }
        let found = self.candidates(c, org, &caller.email, &caller.subject)?;
        if found.len() != 1 {
            return Ok(None);
        }
        let rid = col(&found[0], "id");
        if let Some(row) = self.by_record(c, org, &rid)? {
            if truthy(m(&row, "claimed_by")) || m(&row, "unclaimed_by").as_str() == Some(caller.subject.as_str()) {
                return Ok(None);
            }
        }
        self.write_claim(c, org, &found[0], &caller.subject, &caller.email)?;
        Ok(Some(rid))
    }

    /// The claim at sign-in, as the person dependency runs it: the one record matching the verified
    /// address is claimed, and identity's retired profile moves into it (once, while it is empty). A
    /// claim is never an error of the request: every failure is dropped.
    pub fn sign_in(&self, org: &str, caller: &Caller) {
        if let Ok(Some(claimed)) = self.store.engine_begin(|c| self.auto_claim(c, org, caller)) {
            let _ = self.carry_legacy(org, &caller.subject, &claimed);
        }
    }

    /// The person's own claim (the claim card): the one match, or the one they pick among several.
    pub fn claim(&self, org: &str, caller: &Caller, record_id: Option<&str>) -> R<Value> {
        let caller = self.persons.person(caller)?;
        if caller.email.is_empty() || !caller.email_verified {
            return Err(person_error_status("A claim needs an address a sign-in verified", 403));
        }
        let record_id = record_id.filter(|r| !r.is_empty());
        self.store.engine_begin(|c| {
            if let Some(held) = self.human_claim(c, org, &caller.subject, &caller.email)? {
                if m(&held, "claimed_by").as_str() == Some(caller.subject.as_str()) && record_id.is_none_or(|r| m(&held, "record_id").as_str() == Some(r)) {
                    return Ok(json!({"status": "claimed", "record_id": m(&held, "record_id")}));
                }
                return Err(person_error_status("You already have a profile; a second address joins it through the merge card", 409));
            }
            let mut found = self.candidates(c, org, &caller.email, &caller.subject)?;
            if let Some(r) = record_id {
                found.retain(|row| col(row, "id") == r);
                if found.is_empty() {
                    return Err(person_not_found("No record matching your verified address has that id"));
                }
            }
            if found.is_empty() {
                return Err(person_not_found("No record matches your verified address"));
            }
            if found.len() > 1 {
                return Ok(json!({"status": "choose", "candidates": found.iter().map(candidate).collect::<Vec<_>>()}));
            }
            let rid = col(&found[0], "id");
            if let Some(row) = self.by_record(c, org, &rid)? {
                if truthy(m(&row, "claimed_by")) {
                    return Err(person_error_status("Someone else has claimed that record", 409));
                }
            }
            self.write_claim(c, org, &found[0], &caller.subject, &caller.email)?;
            Ok(json!({"status": "claimed", "record_id": m(&found[0], "id")}))
        })
    }

    /// After the person's own claim: identity's retired profile moves in; the claim stands without it.
    pub fn claimed(&self, org: &str, subject: &str, result: Value) -> Value {
        if g(&result, "status").as_str() == Some("claimed") {
            let _ = self.carry_legacy(org, subject, &pystr(g(&result, "record_id")));
        }
        result
    }

    pub fn unclaim(&self, org: &str, caller: &Caller) -> R<Value> {
        let caller = self.persons.person(caller)?;
        self.store.engine_begin(|c| {
            let Some(row) = self.claimed_by(c, org, &caller.subject)? else {
                return Err(person_not_found("You have not claimed a record"));
            };
            c.exec(
                "UPDATE crm_profiles SET claimed_by = $1, unclaimed_by = $2, published = false, handle = $3, updated_at = $4 WHERE org_id = $5 AND record_id = $6",
                &[&None::<&str>, &caller.subject, &None::<&str>, &now_iso(), &org, &col(&row, "record_id")],
            )?;
            Ok(json!({"status": "unclaimed", "record_id": m(&row, "record_id")}))
        })
    }

    // ── the person's own read and edit ───────────────────────────────────────────────────────
    pub fn mine(&self, org: &str, caller: &Caller) -> R<Value> {
        let caller = self.persons.person(caller)?;
        self.store.engine_begin(|c| {
            let Some(row) = self.claimed_by(c, org, &caller.subject)? else {
                if let Some(held) = self.human_claim(c, org, &caller.subject, &caller.proven_email())? {
                    return Ok(json!({"claimed": true, "via_merge": true, "record_id": m(&held, "record_id"),
                        "fields": dict(m(&held, "fields")), "public_fields": list(m(&held, "public_fields")),
                        "published": truthy(m(&held, "published")), "handle": null, "candidates": []}));
                }
                let found = if caller.email_verified { self.candidates(c, org, &caller.email, &caller.subject)? } else { Vec::new() };
                let shown: Vec<Value> = if found.len() > 1 { found.iter().map(candidate).collect() } else { Vec::new() };
                return Ok(json!({"claimed": false, "record_id": null, "fields": {}, "public_fields": [], "published": false,
                    "handle": null, "candidates": shown}));
            };
            let published = truthy(m(&row, "published"));
            Ok(json!({"claimed": true, "record_id": m(&row, "record_id"), "fields": dict(m(&row, "fields")),
                "public_fields": list(m(&row, "public_fields")), "published": published,
                "handle": if published { m(&row, "handle").clone() } else { Value::Null }, "candidates": []}))
        })
    }

    /// Profile fields are the claimant's alone. Unclaimed (`record_id`), they are the org's, and whoever
    /// may write every field of that record edits them.
    pub fn edit(&self, org: &str, caller: &Caller, fields: &Value, record_id: Option<&str>) -> R<Value> {
        let caller = self.persons.person(caller)?;
        let values = clean(fields)?;
        let record_id = record_id.filter(|r| !r.is_empty());
        self.store.engine_begin(|c| {
            let row = if let Some(rid) = record_id {
                let Some(row) = self.by_record(c, org, rid)? else { return Err(person_not_found("No profile on that record")) };
                let claimant = m(&row, "claimed_by");
                if truthy(claimant) && claimant.as_str() != Some(caller.subject.as_str()) {
                    return Err(person_refused(Some(json!({"status": "refused", "reason": "profile_is_the_persons",
                        "instruction": "Only the person who claimed this record edits its profile."}))));
                }
                if !truthy(claimant) {
                    let policy = self.store.policy(c, org, caller, true)?;
                    let record = self.store.row(c, org, &col(&row, "record_id"))?;
                    if !self.store.rights(&policy, &record, "write")?.iter().any(|f| f == "*") {
                        return Err(person_refused(Some(json!({"status": "refused", "reason": "write_access_required",
                            "instruction": "Editing this unclaimed profile needs write access to the record."}))));
                    }
                }
                row
            } else {
                let Some(row) = self.claimed_by(c, org, &caller.subject)? else { return Err(person_not_found("Claim your record first")) };
                row
            };
            let mut merged = dict(m(&row, "fields"));
            for (k, v) in &values {
                merged.insert(k.clone(), v.clone());
            }
            if let Some(given) = fields.as_object() {
                for (k, v) in given {
                    if is_blank(v) {
                        merged.shift_remove(k);
                    }
                }
            }
            let public: Vec<String> = strings(&list(m(&row, "public_fields"))).into_iter().filter(|f| merged.contains_key(f)).collect();
            c.exec(
                "UPDATE crm_profiles SET fields = $1, public_fields = $2, updated_at = $3 WHERE org_id = $4 AND record_id = $5",
                &[&Value::Object(merged.clone()), &crate::val::str_list(public), &now_iso(), &org, &col(&row, "record_id")],
            )?;
            Ok(json!({"status": "saved", "fields": merged}))
        })
    }

    /// The public page: off by default, on only by the person, showing only the fields they mark.
    pub fn publish(&self, org: &str, caller: &Caller, on: bool, public_fields: Option<&[String]>) -> R<Value> {
        let caller = self.persons.person(caller)?;
        self.store.engine_begin(|c| {
            let Some(row) = self.claimed_by(c, org, &caller.subject)? else { return Err(person_not_found("Claim your record first")) };
            let mut public = list(m(&row, "public_fields"));
            if let Some(given) = public_fields {
                if let Some(bad) = given.iter().find(|f| !is_profile_field(f)) {
                    return Err(person_error(format!("{} is not a profile field", py_str_repr(bad))));
                }
                let mut set: Vec<String> = given.to_vec();
                set.sort();
                set.dedup();
                public = crate::val::str_list(set);
            }
            let mut handle = m(&row, "handle").clone();
            if on && !truthy(&handle) {
                handle = Value::String(token_urlsafe());
            }
            let stored = if on { handle.clone() } else { m(&row, "handle").clone() };
            c.exec(
                "UPDATE crm_profiles SET published = $1, public_fields = $2, handle = $3, updated_at = $4 WHERE org_id = $5 AND record_id = $6",
                &[&on, &public, &stored.as_str(), &now_iso(), &org, &col(&row, "record_id")],
            )?;
            Ok(json!({"published": on, "handle": if on { handle } else { Value::Null }, "public_fields": public}))
        })
    }

    /// An importer the PERSON starts (`IMPORTERS`); none ships, so every source is refused.
    pub fn import_profile(&self, org: &str, caller: &Caller, source: &str) -> R<Value> {
        let _ = (org, source);
        self.persons.person(caller)?;
        Err(person_error("Importing a profile is not available yet; add the fields yourself"))
    }

    /// The person's own act on their profile (POST /person/profile): read, edit, claim (with the
    /// retired profile carried in), unclaim, publish, import. `record_id` "" is none.
    #[allow(clippy::too_many_arguments)]
    pub fn act(&self, org: &str, caller: &Caller, action: &str, fields: &Value, record_id: &str, public: bool, public_fields: Option<&[String]>, source: &str) -> R<Value> {
        let rid = Some(record_id).filter(|r| !r.is_empty());
        match action {
            "read" => self.mine(org, caller),
            "edit" => self.edit(org, caller, fields, rid),
            "claim" => Ok(self.claimed(org, &caller.subject, self.claim(org, caller, rid)?)),
            "unclaim" => self.unclaim(org, caller),
            "publish" => self.publish(org, caller, public, public_fields),
            "import" => self.import_profile(org, caller, source),
            other => Err(CrmError::internal(format!("KeyError: {}", py_str_repr(other)))),
        }
    }

    // ── for the platform ─────────────────────────────────────────────────────────────────────
    /// `accounts`: `[{subject, email, email_verified}]`, the people agent-api's directory rule already let
    /// the viewer see. Each one's profile fields (their claimed record's, also for a second login), or
    /// None. The address finds the Person only when `email_verified` vouches for it.
    pub fn directory(&self, org: &str, accounts: &[Value]) -> R<Obj> {
        self.store.connect(|c| {
            let mut out = Map::new();
            for a in accounts.iter().take(500) {
                let subject = strip(&or_str(g(a, "subject"))).to_owned();
                if subject.is_empty() {
                    continue;
                }
                let email = if g(a, "email_verified") == &Value::Bool(true) { or_str(g(a, "email")) } else { String::new() };
                let row = self.human_claim(c, org, &subject, &email)?;
                out.insert(subject, row.map(|r| Value::Object(dict(m(&r, "fields")))).unwrap_or(Value::Null));
            }
            Ok(out)
        })
    }

    /// The public page: the fields the person marked public, while it is switched on; else None.
    pub fn public(&self, handle: &str) -> R<Option<Value>> {
        if !crate::profiles::is_handle(handle) {
            return Ok(None);
        }
        let row = self.store.connect(|c| Ok(c.map(&format!("SELECT {} FROM crm_profiles WHERE handle = $1", s::PROFILES), &[&handle])?))?;
        let Some(row) = row.filter(|r| truthy(m(r, "published")) && truthy(m(r, "claimed_by"))) else { return Ok(None) };
        let marked = list(m(&row, "public_fields"));
        let fields: Obj = dict(m(&row, "fields")).into_iter().filter(|(k, _)| py_in(k, &marked)).collect();
        Ok(Some(json!({"handle": handle, "fields": fields})))
    }
}

/// How the org names the record, and nothing else from it (no notes, no history).
fn candidate(row: &Obj) -> Value {
    json!({"record_id": m(row, "id"), "name": or_str(g(m(row, "fields"), "Name"))})
}

fn dict(v: &Value) -> Obj {
    v.as_object().cloned().unwrap_or_default()
}

/// list(value or [])
fn list(v: &Value) -> Value {
    if truthy(v) { v.clone() } else { json!([]) }
}
