//! One person, many addresses (PRD 0.13.4 D35; decision I10; ADR-0047 d3).
//!
//! There is no persons table: the human is the CRM's Person record, and its match identifiers say
//! which addresses are theirs. An account resolves to its Person by the address identity verified
//! for it (`email:<address>`), and only when no Person holds that address by the record its account is
//! attached to (`account_id`). Only identity binds an address to an account (`crm_match_ids.proof`,
//! `binds`). One Person may answer for several accounts: its attached account plus one `account:<id>`
//! identifier per further account. Grants go only to CONFIRMED accounts (`confirmed`). Merging is the
//! person's act, never automatic: a merge card (a `crm_change_proposals` row with status
//! `merge_offered`) is confirmed from every linked account's own session; declining splits the Person.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};
use vexa_native_kit::pg::{Int, Tx};

use crate::caller::{confirm_refusal, Caller};
use crate::err::{CrmError, Detail, R};
use crate::schema as s;
use crate::schema::{PROOF_RECORD, PROOF_SIGNIN};
use crate::store::{col, py_in, Store};
use crate::val::{dumps, g, lower, m, now_iso, or_str, py_eq, pystr, strings, strip, truthy, uuid4, uuid5_url, Obj};

pub const ACCOUNT: &str = "account:";
pub const EMAIL: &str = "email:";
pub const MERGE_KIND: &str = "person_merge";
pub const OFFERED: &str = "merge_offered";
pub const CONFIRMED: &str = "merge_confirmed";
pub const DECLINED: &str = "merge_declined";
pub const MERGE_STATUSES: [&str; 3] = [OFFERED, CONFIRMED, DECLINED];
pub const SYSTEM: &str = "system:person-resolution";
pub const MAX_ACCOUNTS: usize = 500;
const MERGE_REASON: &str = "One person, many addresses (D35): the person confirms which accounts are theirs";

/// PersonError(message): 400.
pub fn person_error(msg: impl Into<String>) -> CrmError {
    CrmError::new("PersonError", 400, Detail::Text(msg.into()))
}

/// PersonError(message) with its status set (403, 409).
pub fn person_error_status(msg: impl Into<String>, status: u16) -> CrmError {
    CrmError::new("PersonError", status, Detail::Text(msg.into()))
}

/// PersonRefused(body): 403 with the body (the confirmation refusal when None).
pub fn person_refused(body: Option<Value>) -> CrmError {
    CrmError::new("PersonRefused", 403, Detail::Body(body.unwrap_or_else(confirm_refusal)))
}

/// PersonNotFound(message): 404.
pub fn person_not_found(msg: impl Into<String>) -> CrmError {
    CrmError::new("PersonNotFound", 404, Detail::Text(msg.into()))
}

/// `v•••@example.org`: enough for the person to recognise their own address on a card, not enough
/// to read someone else's off it.
pub fn mask(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) if !domain.is_empty() => {
            let first: String = local.chars().take(1).collect();
            format!("{first}•••@{domain}")
        }
        _ => "•••".to_owned(),
    }
}

/// str(email or '').strip().lower()
fn norm(email: &str) -> String {
    lower(strip(email))
}

/// dict(value or {})
fn dict(v: &Value) -> Obj {
    v.as_object().cloned().unwrap_or_default()
}

fn list(v: &Value) -> Value {
    if truthy(v) { v.clone() } else { json!([]) }
}

fn sorted_set<I: IntoIterator<Item = String>>(items: I) -> Vec<String> {
    items.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

/// The card's patch, as Python reads `card['patch'] or {}`.
fn patch_of(card: &Obj) -> Obj {
    dict(m(card, "patch"))
}

/// Resolution, linking and the merge card, over the Store's pool and tables.
pub struct Persons<'a> {
    pub store: &'a Store,
}

impl<'a> Persons<'a> {
    pub fn new(store: &'a Store) -> Self {
        Persons { store }
    }

    // ── resolution ───────────────────────────────────────────────────────────────────────────
    /// The live Person a record id answers to (merged records answer their survivor), or None.
    pub fn follow(&self, c: &mut Tx, org: &str, record_id: &str) -> R<Option<Obj>> {
        let mut id = record_id.to_owned();
        for _ in 0..8 {
            let row = c.map(&format!("SELECT {} FROM crm_records WHERE org_id = $1 AND id = $2", s::RECORDS), &[&org, &id])?;
            let Some(row) = row else { return Ok(None) };
            if truthy(m(&row, "merged_into")) {
                id = pystr(m(&row, "merged_into"));
                continue;
            }
            if truthy(m(&row, "deleted")) || m(&row, "object_type").as_str() != Some("Person") {
                return Ok(None);
            }
            return Ok(Some(row));
        }
        Ok(None)
    }

    fn held(&self, c: &mut Tx, org: &str, identifier: &str) -> R<Option<String>> {
        Ok(c.scalar("SELECT record_id FROM crm_match_ids WHERE org_id = $1 AND identifier = $2", &[&org, &identifier])?.map(|v| pystr(&v)))
    }

    fn identifier(&self, c: &mut Tx, org: &str, identifier: &str) -> R<Option<(String, Value)>> {
        let rows = c.tuples("SELECT record_id, proof FROM crm_match_ids WHERE org_id = $1 AND identifier = $2", &[&org, &identifier])?;
        Ok(rows.into_iter().next().map(|r| (pystr(&r[0]), r[1].clone())))
    }

    /// The live record holding `email:<address>`, whether or not it binds a sign-in.
    pub fn holder(&self, c: &mut Tx, org: &str, email: &str) -> R<Option<Obj>> {
        match self.identifier(c, org, &format!("{EMAIL}{}", norm(email)))? {
            Some((rid, _)) => self.follow(c, org, &rid),
            None => Ok(None),
        }
    }

    /// Does an `email:` identifier with `proof` on Person `row` bind a sign-in to it? Only when identity
    /// proved the address for an account the record answers to, or when the identifier came with the
    /// record at its creation and no account holds the record yet.
    pub fn binds(&self, c: &mut Tx, org: &str, row: &Obj, proof: &Value) -> R<bool> {
        let accounts = self.linked(c, org, row)?;
        let proof = or_str(proof);
        if proof == PROOF_RECORD {
            return Ok(accounts.is_empty());
        }
        Ok(proof.strip_prefix(PROOF_SIGNIN).is_some_and(|who| accounts.iter().any(|a| a == who)))
    }

    /// The Person a PROVEN address binds a sign-in to (`binds`), or None.
    pub fn bound(&self, c: &mut Tx, org: &str, email: &str) -> R<Option<Obj>> {
        let email = norm(email);
        if email.is_empty() {
            return Ok(None);
        }
        let Some((rid, proof)) = self.identifier(c, org, &format!("{EMAIL}{email}"))? else { return Ok(None) };
        match self.follow(c, org, &rid)? {
            Some(row) if self.binds(c, org, &row, &proof)? => Ok(Some(row)),
            _ => Ok(None),
        }
    }

    /// THE IDENTITY PATH: identity proved `email` for account `subject`, whose Person is `row`. The
    /// address's identifier is that Person's from now on, proven for that account, wherever a CRM
    /// writer had put it.
    pub fn prove(&self, c: &mut Tx, org: &str, row: &Obj, subject: &str, email: &str) -> R<()> {
        let email = norm(email);
        if email.is_empty() {
            return Ok(());
        }
        let identifier = format!("{EMAIL}{email}");
        let proof = format!("{PROOF_SIGNIN}{subject}");
        let id = col(row, "id");
        match self.identifier(c, org, &identifier)? {
            None => {
                c.exec(
                    "INSERT INTO crm_match_ids (org_id, identifier, record_id, proof) VALUES ($1, $2, $3, $4)",
                    &[&org, &identifier, &id, &proof],
                )?;
            }
            Some((rid, got)) => {
                if rid == id && or_str(&got).starts_with(PROOF_SIGNIN) && self.binds(c, org, row, &got)? {
                    return Ok(());
                }
                if rid != id || got.as_str() != Some(proof.as_str()) {
                    c.exec(
                        "UPDATE crm_match_ids SET record_id = $1, proof = $2 WHERE org_id = $3 AND identifier = $4",
                        &[&id, &proof, &org, &identifier],
                    )?;
                }
            }
        }
        Ok(())
    }

    /// The Person an account answers to: by `email` first (I10) where that address binds a sign-in
    /// (`bound`), then by an `account:` link, then by the record the account is attached to. `email` is
    /// an address a sign-in PROVED, or "".
    pub fn resolve(&self, c: &mut Tx, org: &str, subject: &str, email: &str) -> R<Option<Obj>> {
        if let Some(row) = self.bound(c, org, email)? {
            return Ok(Some(row));
        }
        if subject.is_empty() {
            return Ok(None);
        }
        if let Some(held) = self.held(c, org, &format!("{ACCOUNT}{subject}"))?.filter(|h| !h.is_empty()) {
            if let Some(row) = self.follow(c, org, &held)? {
                return Ok(Some(row));
            }
        }
        let attached = c.scalar("SELECT id FROM crm_records WHERE org_id = $1 AND account_id = $2", &[&org, &subject])?;
        match attached.filter(truthy) {
            Some(a) => self.follow(c, org, &pystr(&a)),
            None => Ok(None),
        }
    }

    /// Every account linked to this Person: the attached one, then the `account:` links.
    pub fn linked(&self, c: &mut Tx, org: &str, row: &Obj) -> R<Vec<String>> {
        let mut out: Vec<String> = if truthy(m(row, "account_id")) { vec![pystr(m(row, "account_id"))] } else { Vec::new() };
        let like = format!("{ACCOUNT}%");
        for v in c.column(
            "SELECT identifier FROM crm_match_ids WHERE org_id = $1 AND record_id = $2 AND identifier LIKE $3",
            &[&org, &col(row, "id"), &like],
        )? {
            let identifier = pystr(&v);
            let who = identifier.get(ACCOUNT.len()..).unwrap_or("").to_owned();
            if !who.is_empty() && !out.contains(&who) {
                out.push(who);
            }
        }
        Ok(out)
    }

    /// The accounts a grant to `subject` may reach: `subject` and every account the person confirmed
    /// together with it on a merge card, each from its own session. An unconfirmed link reaches nothing.
    pub fn confirmed(&self, c: &mut Tx, org: &str, row: &Obj, subject: &str) -> R<Vec<String>> {
        let mut out = vec![subject.to_owned()];
        for card in self.cards(c, org, &col(row, "id"), &[CONFIRMED])? {
            let accounts = list(g(m(&card, "patch"), "accounts"));
            if py_in(subject, &accounts) {
                for who in strings(&accounts) {
                    if !out.contains(&who) {
                        out.push(who);
                    }
                }
            }
        }
        Ok(out)
    }

    /// The Person's own addresses: those identity proved for an account it answers to.
    pub fn addresses(&self, c: &mut Tx, org: &str, record_id: &str) -> R<Vec<String>> {
        let Some(row) = self.follow(c, org, record_id)? else { return Ok(Vec::new()) };
        let accounts: BTreeSet<String> = self.linked(c, org, &row)?.into_iter().collect();
        let like = format!("{EMAIL}%");
        let mut out = Vec::new();
        for r in c.tuples(
            "SELECT identifier, proof FROM crm_match_ids WHERE org_id = $1 AND record_id = $2 AND identifier LIKE $3",
            &[&org, &col(&row, "id"), &like],
        )? {
            let proof = or_str(&r[1]);
            if proof.strip_prefix(PROOF_SIGNIN).is_some_and(|who| accounts.contains(who)) {
                out.push(pystr(&r[0]).get(EMAIL.len()..).unwrap_or("").to_owned());
            }
        }
        out.sort();
        Ok(out)
    }

    /// The merge cards on a record with one of `statuses`, oldest first.
    pub fn cards(&self, c: &mut Tx, org: &str, record_id: &str, statuses: &[&str]) -> R<Vec<Obj>> {
        let statuses: Vec<String> = statuses.iter().map(|x| x.to_string()).collect();
        let rows = c.maps(
            &format!("SELECT {} FROM crm_change_proposals WHERE org_id = $1 AND record_id = $2 AND status = ANY($3)", s::CHANGE_PROPOSALS),
            &[&org, &record_id, &statuses],
        )?;
        Ok(by_created(rows))
    }

    /// The addresses the person may choose as primary on this card: every address of every Person on
    /// it, and the address each account signed in with.
    pub fn options(&self, c: &mut Tx, org: &str, card: &Obj) -> R<Vec<String>> {
        let patch = patch_of(card);
        let mut out: BTreeSet<String> = dict(m(&patch, "addresses")).values().filter(|a| truthy(a)).map(pystr).collect();
        let records = m(&patch, "records");
        let records: Vec<String> = if truthy(records) { strings(records) } else { vec![pystr(m(card, "record_id"))] };
        for record_id in records {
            if let Some(row) = self.follow(c, org, &record_id)? {
                out.extend(self.addresses(c, org, &col(&row, "id"))?);
            }
        }
        Ok(out.into_iter().collect())
    }

    /// The option key of an address on a card: stable while the list grows, meaningless elsewhere.
    pub fn option(card_id: &str, address: &str) -> String {
        let d = vexa_native_kit::sha256::digest(format!("{card_id}\n{address}").as_bytes());
        vexa_native_kit::sha256::hex(&d)[..12].to_owned()
    }

    fn chosen(&self, c: &mut Tx, org: &str, card: &Obj, option: &str) -> R<String> {
        let id = col(card, "id");
        for address in self.options(c, org, card)? {
            if Self::option(&id, &address) == option {
                return Ok(address);
            }
        }
        Err(person_error("Choose the primary address from the card"))
    }

    /// Open merge cards that name this account, oldest first.
    fn waiting_for(&self, c: &mut Tx, org: &str, subject: &str) -> R<Vec<Obj>> {
        let rows = c.maps(
            &format!("SELECT {} FROM crm_change_proposals WHERE org_id = $1 AND status = $2", s::CHANGE_PROPOSALS),
            &[&org, &OFFERED],
        )?;
        let rows = rows.into_iter().filter(|r| py_in(subject, &list(g(m(r, "patch"), "accounts")))).collect();
        Ok(by_created(rows))
    }

    /// Where invites and nudges go: the address chosen on the last confirmed merge card, else the
    /// record's `Email` when it is one of the Person's addresses, else `fallback`.
    pub fn primary(&self, c: &mut Tx, org: &str, row: &Obj, fallback: &str) -> R<Option<String>> {
        let mine: BTreeSet<String> = self.addresses(c, org, &col(row, "id"))?.into_iter().collect();
        for card in self.cards(c, org, &col(row, "id"), &[CONFIRMED])?.iter().rev() {
            let chosen = or_str(g(m(card, "patch"), "primary"));
            if !chosen.is_empty() && mine.contains(&chosen) {
                return Ok(Some(chosen));
            }
        }
        let email = lower(strip(&or_str(g(m(row, "fields"), "Email"))));
        if !email.is_empty() && mine.contains(&email) {
            return Ok(Some(email));
        }
        let f = norm(fallback);
        Ok(if f.is_empty() { None } else { Some(f) })
    }

    // ── linking (sign-in) ────────────────────────────────────────────────────────────────────
    /// Record that `subject` resolved to this Person, and offer the merge card if it is now one of
    /// several accounts the person has not confirmed together.
    pub fn link(&self, c: &mut Tx, org: &str, row: &Obj, subject: &str, email: &str) -> R<()> {
        let id = col(row, "id");
        if m(row, "account_id").as_str() != Some(subject) {
            let identifier = format!("{ACCOUNT}{subject}");
            match self.held(c, org, &identifier)? {
                None => {
                    c.exec("INSERT INTO crm_match_ids (org_id, identifier, record_id) VALUES ($1, $2, $3)", &[&org, &identifier, &id])?;
                }
                Some(h) if h != id => {
                    // the verified address decides (I10): the link follows the address to this Person
                    c.exec("UPDATE crm_match_ids SET record_id = $1 WHERE org_id = $2 AND identifier = $3", &[&id, &org, &identifier])?;
                }
                _ => {}
            }
        }
        self.prove(c, org, row, subject, email)?;
        let mut seen = Map::new();
        seen.insert(subject.to_owned(), Value::String(norm(email)));
        self.offer(c, org, row, Some(&seen))?;
        Ok(())
    }

    /// The open merge card for this Person, created or refreshed; None when there is nothing for the
    /// person to confirm (one account, or every linked account already confirmed together).
    pub fn offer(&self, c: &mut Tx, org: &str, row: &Obj, seen: Option<&Obj>) -> R<Option<Obj>> {
        let mut accounts = self.linked(c, org, row)?;
        accounts.sort();
        let seen: Obj = seen.map(|o| o.iter().filter(|(_, v)| truthy(v)).map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
        let cards = self.cards(c, org, &col(row, "id"), &MERGE_STATUSES)?;
        if let Some(open) = cards.iter().filter(|k| m(k, "status").as_str() == Some(OFFERED)).last() {
            let mut card = open.clone();
            let mut patch = patch_of(&card);
            let mut changed = false;
            let have = strings(&list(m(&patch, "accounts")));
            let union = sorted_set(have.iter().cloned().chain(accounts.iter().cloned()));
            let mut have_sorted = have.clone();
            have_sorted.sort();
            if union != have_sorted {
                patch.insert("accounts".into(), crate::val::str_list(union));
                changed = true;
            }
            let mut addresses = dict(m(&patch, "addresses"));
            for (who, address) in &seen {
                let Some(on_card) = patch.get("accounts") else {
                    return Err(CrmError::internal("KeyError: 'accounts'"));
                };
                if py_in(who, on_card) && !addresses.get(who).is_some_and(|a| py_eq(a, address)) {
                    addresses.insert(who.clone(), address.clone());
                    changed = true;
                }
            }
            if changed {
                patch.insert("addresses".into(), Value::Object(addresses));
                let pv = Value::Object(patch);
                c.exec("UPDATE crm_change_proposals SET patch = $1 WHERE org_id = $2 AND id = $3", &[&pv, &org, &col(&card, "id")])?;
                card.insert("patch".into(), pv);
            }
            return Ok(Some(card));
        }
        if accounts.len() < 2 {
            return Ok(None);
        }
        for card in &cards {
            if m(card, "status").as_str() == Some(CONFIRMED) {
                let on: BTreeSet<String> = strings(&list(g(m(card, "patch"), "accounts"))).into_iter().collect();
                if accounts.iter().all(|a| on.contains(a)) {
                    return Ok(None);
                }
            }
        }
        let records = vec![m(row, "id").clone()];
        Ok(Some(self.insert(c, org, row, &accounts, &seen, records, SYSTEM)?))
    }

    fn insert(&self, c: &mut Tx, org: &str, row: &Obj, accounts: &[String], addresses: &Obj, records: Vec<Value>, author: &str) -> R<Obj> {
        let addresses: Obj = addresses.iter().filter(|(k, v)| accounts.contains(k) && truthy(v)).map(|(k, v)| (k.clone(), v.clone())).collect();
        let patch = json!({"kind": MERGE_KIND, "fields": {}, "narrative": null, "accounts": sorted_set(accounts.iter().cloned()),
            "addresses": addresses, "records": records, "confirmed": {}, "primary": null, "created_at": now_iso()});
        let card = json!({"org_id": org, "id": uuid4(), "record_id": m(row, "id").clone(), "base_revision": m(row, "revision").clone(),
            "author_id": author, "patch": patch, "evidence": [], "reason": MERGE_REASON, "status": OFFERED});
        let card = dict(&card);
        let evidence = json!([]);
        c.exec(
            &format!("INSERT INTO crm_change_proposals ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", s::CHANGE_PROPOSALS),
            &[&org, &col(&card, "id"), &col(&card, "record_id"), &Int(m(&card, "base_revision").as_i64().unwrap_or(0)), &author,
              m(&card, "patch"), &evidence, &MERGE_REASON, &OFFERED],
        )?;
        Ok(card)
    }

    // ── the person's own view and acts ───────────────────────────────────────────────────────
    /// An agent never confirms who a person is, and never reads their addresses for them.
    pub fn person<'c>(&self, caller: &'c Caller) -> R<&'c Caller> {
        if caller.delegated || caller.internal || caller.subject.is_empty() {
            return Err(person_refused(None));
        }
        Ok(caller)
    }

    fn card_view(&self, c: &mut Tx, org: &str, card: &Obj, caller: &Caller) -> R<Value> {
        let patch = patch_of(card);
        let accounts = strings(&list(m(&patch, "accounts")));
        let addresses = dict(m(&patch, "addresses"));
        let own = match addresses.get(&caller.subject) {
            Some(a) if truthy(a) => a.clone(),
            _ => Value::String(caller.email.clone()),
        };
        let options = self.options(c, org, card)?;
        let confirmed = dict(m(&patch, "confirmed"));
        let id = col(card, "id");
        let shown: Vec<Value> = options
            .iter()
            .map(|a| {
                let yours = py_eq(&Value::String(a.clone()), &own);
                json!({"option": Self::option(&id, a), "address": if yours { a.clone() } else { mask(a) }, "yours": yours})
            })
            .collect();
        let primary = match m(&patch, "primary") {
            Value::String(p) if options.contains(p) => Value::String(Self::option(&id, p)),
            _ => Value::Null,
        };
        Ok(json!({"id": m(card, "id"), "status": m(card, "status"), "accounts": accounts.len(),
            "confirmed_by_you": confirmed.contains_key(&caller.subject),
            "waiting_on": accounts.iter().filter(|a| !confirmed.contains_key(*a)).count(),
            "addresses": shown, "primary": primary}))
    }

    /// The signed-in person's own Person: how many accounts answer for it, their addresses (theirs in
    /// full), the primary, and the merge card waiting for them, if any.
    pub fn me(&self, org: &str, caller: &Caller) -> R<Value> {
        let caller = self.person(caller)?;
        self.store.engine_begin(|c| {
            let proven = caller.proven_email();
            let Some(row) = self.resolve(c, org, &caller.subject, &proven)? else {
                let addresses = if caller.email.is_empty() { json!([]) } else { json!([caller.email]) };
                let primary = if caller.email.is_empty() { Value::Null } else { Value::String(caller.email.clone()) };
                return Ok(json!({"person": null, "accounts": 1, "addresses": addresses, "primary": primary, "merge": null}));
            };
            let mut seen = Map::new();
            seen.insert(caller.subject.clone(), Value::String(proven.clone()));
            self.offer(c, org, &row, Some(&seen))?;
            let mut accounts = self.linked(c, org, &row)?;
            if !accounts.contains(&caller.subject) {
                accounts.push(caller.subject.clone());
            }
            let mine = self.addresses(c, org, &col(&row, "id"))?;
            let primary = self.primary(c, org, &row, &proven)?;
            let pending = self.waiting_for(c, org, &caller.subject)?;
            let merge = match pending.last() {
                Some(card) => self.card_view(c, org, card, caller)?,
                None => Value::Null,
            };
            let addresses: Vec<String> = mine.iter().map(|a| if *a == caller.email { a.clone() } else { mask(a) }).collect();
            let primary = match primary {
                Some(p) if p == caller.email => Value::String(p),
                Some(p) => Value::String(mask(&p)),
                None => Value::Null,
            };
            Ok(json!({"person": m(&row, "id"), "accounts": accounts.len(), "addresses": addresses, "primary": primary, "merge": merge}))
        })
    }

    fn open_card(&self, c: &mut Tx, org: &str, caller: &Caller, card_id: &str) -> R<Obj> {
        let card = c.map(
            &format!("SELECT {} FROM crm_change_proposals WHERE org_id = $1 AND id = $2 FOR UPDATE", s::CHANGE_PROPOSALS),
            &[&org, &card_id],
        )?;
        match card {
            Some(card)
                if g(m(&card, "patch"), "kind").as_str() == Some(MERGE_KIND)
                    && py_in(&caller.subject, &list(g(m(&card, "patch"), "accounts"))) =>
            {
                Ok(card)
            }
            // not yours (or not a merge card): the answer an unknown id gets
            _ => Err(person_not_found("No merge card for you with that id")),
        }
    }

    /// This account confirms the card. The merge applies once every account on it has confirmed;
    /// `primary` (an option from the card) is the person's choice of address.
    pub fn confirm(&self, org: &str, caller: &Caller, card_id: &str, primary: Option<&str>) -> R<Value> {
        let caller = self.person(caller)?;
        self.store.engine_begin(|c| {
            let mut card = self.open_card(c, org, caller, card_id)?;
            if m(&card, "status").as_str() != Some(OFFERED) {
                return Err(person_error("This merge card was already decided"));
            }
            let mut patch = patch_of(&card);
            if let Some(p) = primary.filter(|p| !p.is_empty()) {
                patch.insert("primary".into(), Value::String(self.chosen(c, org, &card, p)?));
            }
            let mut confirmed = dict(m(&patch, "confirmed"));
            confirmed.insert(caller.subject.clone(), Value::String(now_iso()));
            patch.insert("confirmed".into(), Value::Object(confirmed.clone()));
            let mut addresses = dict(m(&patch, "addresses"));
            let proven = caller.proven_email();
            if !proven.is_empty() {
                addresses.insert(caller.subject.clone(), Value::String(proven.clone()));
            }
            patch.insert("addresses".into(), Value::Object(addresses));
            let done = strings(&list(m(&patch, "accounts"))).iter().all(|a| confirmed.contains_key(a));
            let mut status = OFFERED;
            if done {
                status = CONFIRMED;
                if !truthy(m(&patch, "primary")) {
                    let mut with = card.clone();
                    with.insert("patch".into(), Value::Object(patch.clone()));
                    let options = self.options(c, org, &with)?;
                    let p = if !proven.is_empty() { Value::String(proven.clone()) } else { options.first().map(|o| Value::String(o.clone())).unwrap_or(Value::Null) };
                    patch.insert("primary".into(), p);
                }
                self.apply(c, org, &card, &patch, &caller.subject)?;
            }
            let pv = Value::Object(patch);
            c.exec("UPDATE crm_change_proposals SET patch = $1, status = $2 WHERE org_id = $3 AND id = $4", &[&pv, &status, &org, &col(&card, "id")])?;
            card.insert("patch".into(), pv);
            card.insert("status".into(), Value::String(status.into()));
            Ok(json!({"status": if done { "merged" } else { "confirmed" }, "merge": self.card_view(c, org, &card, caller)?}))
        })
    }

    /// "These are not all me": the card closes and the Person keeps only its own account. Every other
    /// account goes back to a record of its own, so grants to this Person stop reaching it.
    pub fn decline(&self, org: &str, caller: &Caller, card_id: &str) -> R<Value> {
        let caller = self.person(caller)?;
        self.store.engine_begin(|c| {
            let card = self.open_card(c, org, caller, card_id)?;
            if m(&card, "status").as_str() != Some(OFFERED) {
                return Err(person_error("This merge card was already decided"));
            }
            let patch = patch_of(&card);
            let row = self.follow(c, org, &pystr(m(&card, "record_id")))?;
            let mut split = 0;
            if let Some(row) = row {
                let records = m(&patch, "records");
                let n = match records { Value::Array(a) => a.len(), _ => 0 };
                if n <= 1 {
                    let keep = if truthy(m(&row, "account_id")) { pystr(m(&row, "account_id")) } else { caller.subject.clone() };
                    let addresses = dict(m(&patch, "addresses"));
                    for who in self.linked(c, org, &row)? {
                        if who != keep {
                            let address = addresses.get(&who).map(or_str).unwrap_or_default();
                            self.detach(c, org, &row, &who, &address, &caller.subject)?;
                            split += 1;
                        }
                    }
                }
            }
            c.exec("UPDATE crm_change_proposals SET status = $1 WHERE org_id = $2 AND id = $3", &[&DECLINED, &org, &col(&card, "id")])?;
            Ok(json!({"status": "declined", "split": split}))
        })
    }

    /// Change the primary address later, on the person's last confirmed card.
    pub fn set_primary(&self, org: &str, caller: &Caller, option: &str) -> R<Value> {
        let caller = self.person(caller)?;
        self.store.engine_begin(|c| {
            let row = self.resolve(c, org, &caller.subject, &caller.proven_email())?;
            let cards = match &row { Some(r) => self.cards(c, org, &col(r, "id"), &[CONFIRMED])?, None => Vec::new() };
            let Some(card) = cards.last().filter(|k| py_in(&caller.subject, &list(g(m(k, "patch"), "accounts")))) else {
                return Err(person_error("Confirm your accounts first; the primary address is chosen on the merge card"));
            };
            let mut patch = patch_of(card);
            patch.insert("primary".into(), Value::String(self.chosen(c, org, card, option)?));
            c.exec("UPDATE crm_change_proposals SET patch = $1 WHERE org_id = $2 AND id = $3", &[&Value::Object(patch), &org, &col(card, "id")])?;
            Ok(json!({"status": "primary_set"}))
        })
    }

    /// The person says another address is theirs too. A card opens between their Person and the
    /// Person that address resolves to; it completes only when that address's account confirms. The
    /// answer is the same whether or not the address has an account here.
    pub fn offer_for_address(&self, org: &str, caller: &Caller, address: &str) -> R<Value> {
        let caller = self.person(caller)?;
        let address = norm(address);
        if !address.contains('@') || address.chars().count() > 300 {
            return Err(person_error("An address is name@domain"));
        }
        let answer = json!({"status": "offered", "instruction": "Sign in with that address and confirm the card there."});
        self.store.engine_begin(|c| {
            let proven = caller.proven_email();
            let mine = self.resolve(c, org, &caller.subject, &proven)?;
            let other = self.resolve(c, org, "", &address)?;
            let (Some(mine), Some(other)) = (mine, other) else { return Ok(answer.clone()) };
            if py_eq(m(&other, "id"), m(&mine, "id")) {
                return Ok(answer.clone());
            }
            let theirs = self.linked(c, org, &other)?;
            if theirs.is_empty() {
                return Ok(answer.clone()); // an address nobody signs in with: nothing to confirm from
            }
            let accounts = sorted_set(self.linked(c, org, &mine)?.into_iter().chain([caller.subject.clone()]).chain(theirs));
            for card in self.cards(c, org, &col(&mine, "id"), &[OFFERED])? {
                let on: BTreeSet<String> = strings(&list(g(m(&card, "patch"), "accounts"))).into_iter().collect();
                if accounts.iter().all(|a| on.contains(a)) {
                    return Ok(answer.clone());
                }
            }
            let mut seen = Map::new();
            seen.insert(caller.subject.clone(), Value::String(proven.clone()));
            let card = self.insert(c, org, &mine, &accounts, &seen, vec![m(&mine, "id").clone(), m(&other, "id").clone()], &caller.subject)?;
            let mut patch = patch_of(&card);
            let mut confirmed = Map::new();
            confirmed.insert(caller.subject.clone(), Value::String(now_iso()));
            patch.insert("confirmed".into(), Value::Object(confirmed));
            c.exec("UPDATE crm_change_proposals SET patch = $1 WHERE org_id = $2 AND id = $3", &[&Value::Object(patch), &org, &col(&card, "id")])?;
            Ok(answer.clone())
        })
    }

    // ── applying and undoing ─────────────────────────────────────────────────────────────────
    /// Every account confirmed: the other Persons on the card merge into this one (their identifiers,
    /// attached accounts and bindings move to it; their ids answer it from now on).
    fn apply(&self, c: &mut Tx, org: &str, card: &Obj, patch: &Obj, actor: &str) -> R<()> {
        let Some(winner) = self.follow(c, org, &pystr(m(card, "record_id")))? else {
            return Err(person_not_found("The person on this card no longer exists"));
        };
        let wid = col(&winner, "id");
        let records = strings(&list(m(patch, "records")));
        for other_id in records.iter().skip(1) {
            let Some(loser) = self.follow(c, org, other_id)? else { continue };
            let lid = col(&loser, "id");
            if lid == wid {
                continue;
            }
            let revision = m(&loser, "revision").as_i64().unwrap_or(0) + 1;
            let mut after = loser.clone();
            after.insert("merged_into".into(), Value::String(wid.clone()));
            after.insert("revision".into(), revision.into());
            after.insert("account_id".into(), Value::Null);
            c.exec(
                "UPDATE crm_records SET merged_into = $1, revision = $2, account_id = $3 WHERE org_id = $4 AND id = $5",
                &[&wid, &Int(revision), &None::<&str>, &org, &lid],
            )?;
            c.exec("UPDATE crm_match_ids SET record_id = $1 WHERE org_id = $2 AND record_id = $3", &[&wid, &org, &lid])?;
            let la = m(&loser, "account_id");
            if truthy(la) && !py_eq(la, m(&winner, "account_id")) {
                let identifier = format!("{ACCOUNT}{}", pystr(la));
                if self.held(c, org, &identifier)?.is_none() {
                    c.exec("INSERT INTO crm_match_ids (org_id, identifier, record_id) VALUES ($1, $2, $3)", &[&org, &identifier, &wid])?;
                }
            }
            let have: BTreeSet<String> = c
                .column("SELECT workspace FROM crm_workspace_bindings WHERE org_id = $1 AND record_id = $2", &[&org, &wid])?
                .iter()
                .map(pystr)
                .collect();
            for w in c.column("SELECT workspace FROM crm_workspace_bindings WHERE org_id = $1 AND record_id = $2", &[&org, &lid])? {
                let workspace = pystr(&w);
                if !have.contains(&workspace) {
                    c.exec(
                        &format!("INSERT INTO crm_workspace_bindings ({}) VALUES ($1, $2, $3, $4, $5)", s::WORKSPACE_BINDINGS),
                        &[&org, &workspace, &wid, &actor, &now_iso()],
                    )?;
                }
            }
            c.exec("DELETE FROM crm_workspace_bindings WHERE org_id = $1 AND record_id = $2", &[&org, &lid])?;
            // one profile per human: the merged-away record's claim ends; the survivor's stands
            c.exec(
                "UPDATE crm_profiles SET claimed_by = $1, published = false, handle = $2, updated_at = $3 WHERE org_id = $4 AND record_id = $5",
                &[&None::<&str>, &None::<&str>, &now_iso(), &org, &lid],
            )?;
            let evidence = json!([{"merged_into": wid, "card": m(card, "id")}]);
            self.store.revision(c, org, actor, Some(&loser), &after, MERGE_REASON, &evidence, None)?;
        }
        Ok(())
    }

    /// Give account `who` a Person of its own again, with its address.
    fn detach(&self, c: &mut Tx, org: &str, row: &Obj, who: &str, address: &str, actor: &str) -> R<()> {
        let own = c.scalar("SELECT id FROM crm_records WHERE org_id = $1 AND account_id = $2", &[&org, &who])?.filter(truthy);
        let target = match own {
            Some(o) => self.follow(c, org, &pystr(&o))?,
            None => None,
        };
        let target_id = match target {
            Some(t) => col(&t, "id"),
            None => {
                let record_id = uuid5_url(&dumps(&json!(["crm-account", org, who])));
                let existing = c.scalar("SELECT id FROM crm_records WHERE org_id = $1 AND id = $2", &[&org, &record_id])?;
                if existing.is_none() {
                    let mut fields = Map::new();
                    fields.insert("Name".into(), Value::String(if address.is_empty() { who.to_owned() } else { address.to_owned() }));
                    if !address.is_empty() {
                        fields.insert("Email".into(), Value::String(address.to_owned()));
                    }
                    let new = dict(&json!({"org_id": org, "id": record_id, "object_type": "Person", "owner_id": who, "revision": 1,
                        "fields": fields, "narrative": "", "quarantined": false, "deleted": false, "account_id": who, "merged_into": null}));
                    c.exec(
                        &format!("INSERT INTO crm_records ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)", s::RECORDS),
                        &[&org, &record_id, &"Person", &who, &Int(1), m(&new, "fields"), &"", &false, &false, &who, &None::<&str>],
                    )?;
                    self.store.revision(c, org, actor, None, &new, "Split from a person on their own merge card (D35)", &json!([]), None)?;
                }
                record_id
            }
        };
        let rid = col(row, "id");
        let mut identifiers = vec![format!("{ACCOUNT}{who}")];
        if !address.is_empty() {
            identifiers.push(format!("{EMAIL}{address}"));
        }
        for identifier in identifiers {
            if self.held(c, org, &identifier)?.as_deref() == Some(rid.as_str()) {
                // the address goes with the account it was proven for (`prove`)
                if identifier.starts_with(EMAIL) {
                    let proof = format!("{PROOF_SIGNIN}{who}");
                    c.exec(
                        "UPDATE crm_match_ids SET record_id = $1, proof = $2 WHERE org_id = $3 AND identifier = $4",
                        &[&target_id, &proof, &org, &identifier],
                    )?;
                } else {
                    c.exec("UPDATE crm_match_ids SET record_id = $1 WHERE org_id = $2 AND identifier = $3", &[&target_id, &org, &identifier])?;
                }
            }
        }
        Ok(())
    }

    // ── for the platform (agent-api through /internal/persons, crm's own card membership) ────
    /// `accounts`: `[{subject, email, email_verified}]`. For each, the Person it resolves to and every
    /// account linked to that Person (accounts given together that resolve to one Person count once),
    /// and the primary address. Accounts with no Person answer as a Person of one.
    pub fn group(&self, org: &str, accounts: &[Value]) -> R<Obj> {
        self.store.connect(|c| {
            let mut out = Map::new();
            for a in accounts.iter().take(MAX_ACCOUNTS) {
                let subject = strip(&or_str(g(a, "subject"))).to_owned();
                let email = lower(strip(&or_str(g(a, "email"))));
                if subject.is_empty() {
                    continue;
                }
                // an address finds a Person only when the producer vouches a sign-in proved it
                let proven = if g(a, "email_verified") == &Value::Bool(true) { email.clone() } else { String::new() };
                let Some(row) = self.resolve(c, org, &subject, &proven)? else {
                    let primary = if email.is_empty() { Value::Null } else { Value::String(email.clone()) };
                    out.insert(subject.clone(), json!({"person": null, "accounts": [subject], "confirmed": [subject],
                        "primary": primary, "merged": false}));
                    continue;
                };
                let mut linked = self.linked(c, org, &row)?;
                if !linked.contains(&subject) {
                    linked.push(subject.clone());
                }
                let mut merged = false;
                for k in self.cards(c, org, &col(&row, "id"), &[CONFIRMED])? {
                    let on: BTreeSet<String> = strings(&list(g(m(&k, "patch"), "accounts"))).into_iter().collect();
                    if linked.iter().all(|a| on.contains(a)) {
                        merged = true;
                        break;
                    }
                }
                let confirmed = self.confirmed(c, org, &row, &subject)?;
                let primary = self.primary(c, org, &row, &email)?;
                out.insert(subject.clone(), json!({"person": m(&row, "id"), "accounts": linked, "confirmed": confirmed,
                    "primary": primary, "merged": merged}));
            }
            // accounts given together that resolve to one Person: each answers the union
            let mut by_person: Vec<(Value, Vec<String>)> = Vec::new();
            for (subject, v) in &out {
                let person = g(v, "person");
                if truthy(person) {
                    match by_person.iter_mut().find(|(p, _)| py_eq(p, person)) {
                        Some((_, subjects)) => subjects.push(subject.clone()),
                        None => by_person.push((person.clone(), vec![subject.clone()])),
                    }
                }
            }
            for (_, subjects) in by_person {
                let mut union: Vec<String> = Vec::new();
                for subject in &subjects {
                    for who in strings(g(&out[subject], "accounts")) {
                        if !union.contains(&who) {
                            union.push(who);
                        }
                    }
                }
                for subject in &subjects {
                    if let Some(Value::Object(o)) = out.get_mut(subject) {
                        o.insert("accounts".into(), crate::val::str_list(union.clone()));
                    }
                }
            }
            Ok(out)
        })
    }

    /// The accounts a grant to `subject` reaches: `subject` and the accounts the person CONFIRMED
    /// together with it (`confirmed`); never an unconfirmed link.
    pub fn linked_accounts(&self, c: &mut Tx, org: &str, subject: &str) -> R<Vec<String>> {
        match self.resolve(c, org, subject, "")? {
            None => Ok(vec![subject.to_owned()]),
            Some(row) => self.confirmed(c, org, &row, subject),
        }
    }
}

/// sorted(rows that are merge cards, key=str(patch.created_at or '')).
fn by_created(rows: Vec<Obj>) -> Vec<Obj> {
    let mut out: Vec<Obj> = rows.into_iter().filter(|r| g(m(r, "patch"), "kind").as_str() == Some(MERGE_KIND)).collect();
    out.sort_by_cached_key(|r| or_str(g(m(r, "patch"), "created_at")));
    out
}
