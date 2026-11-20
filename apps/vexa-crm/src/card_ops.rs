//! Cards on the CRM: one shared registry record per card, never a copy (card_ops.py).

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use regex::Regex;
use serde_json::{json, Map, Value};
use vexa_native_kit::pg::Tx;

use crate::caller::Caller;
use crate::card_templates as tpl;
use crate::err::{CrmError, R};
use crate::policies::{front_matter, Policies, DEFAULTS as LIMIT_DEFAULTS};
use crate::store::{col, Policy, Row, Store};
use crate::val::{g, m, pystr, truthy, Obj};

pub const DEFAULT_TYPE: &str = "Card";
pub const LIST_MAX: i64 = 50;
pub const TITLE_MAX: usize = 200;
pub const REASON_MAX: usize = 500;
/// The fields a person or a proposal may set on a card. State moves only by `transition`.
pub const EDITABLE: [&str; 16] = ["Title", "About", "Next", "Waiting", "Summary", "Due", "Progress", "Checklist", "Parent", "Face",
    "Kind", "NextActor", "Requester", "NextCheckAt", "Chain", "Origin"];
/// Written only by a gate decision (D12), never by an edit or a proposal.
pub const GATE_ONLY: [&str; 5] = ["Handoff", "HandoffSince", "Answer", "Evidence", "Receipt"];
/// Days a card that has not moved shows as stalled (`card_stalled_days` tunes it).
pub const STALLED_AFTER_DAYS: i64 = 14;
/// Minutes a decision nonce lives.
pub const NONCE_TTL_MINUTES: i64 = 15;
/// Hours after its last move an open card of a kind is checked again (`card_check_hours`).
pub const CHECK_AFTER_HOURS: i64 = 24;
/// "Due soon" in the inbox counts.
pub const DUE_SOON_DAYS: i64 = 3;

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).unwrap())
}
static PERSON_RE: OnceLock<Regex> = OnceLock::new();
static ORIGIN_RE: OnceLock<Regex> = OnceLock::new();
static REF_RE: OnceLock<Regex> = OnceLock::new();
static ID_RE: OnceLock<Regex> = OnceLock::new();
static SLUG_RE: OnceLock<Regex> = OnceLock::new();
static CONTROL_RE: OnceLock<Regex> = OnceLock::new();
static STATE_RE: OnceLock<Regex> = OnceLock::new();
pub fn person_re() -> &'static Regex { re(&PERSON_RE, r"\A[A-Za-z0-9_][A-Za-z0-9_.:@\-]{0,127}\z") }
pub fn origin_re() -> &'static Regex {
    re(&ORIGIN_RE, r"\A(session:[A-Za-z0-9._:\-]{1,128}|meeting:[A-Za-z0-9._:\-]{1,128}|message:[A-Za-z0-9._:\-]{1,128}/[A-Za-z0-9._:\-]{1,128})\z")
}
pub fn ref_re() -> &'static Regex { re(&REF_RE, r"\A[a-z]+:[^\x00-\x1f\x7f]{1,290}\z") }
pub fn id_re() -> &'static Regex { re(&ID_RE, r"\A[A-Za-z0-9_][A-Za-z0-9_.:\-]{0,127}\z") }
pub fn slug_re() -> &'static Regex { re(&SLUG_RE, r"\A[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}\z") }
fn control_re() -> &'static Regex { re(&CONTROL_RE, r"[\x00-\x1f\x7f\\]") }
fn state_re() -> &'static Regex { re(&STATE_RE, r"\A[^\x00-\x1f\x7f|>]{1,60}\z") }

/// {'status': 'refused', 'reason': .., 'instruction': .., **extra}.
pub fn refusal(reason: &str, instruction: &str, extra: Obj) -> Value {
    let mut o = Map::new();
    o.insert("status".into(), "refused".into());
    o.insert("reason".into(), reason.into());
    o.insert("instruction".into(), instruction.into());
    o.extend(extra);
    Value::Object(o)
}

pub fn propose_card() -> Value {
    refusal("propose_instead", "You may not make or change a card yourself. Call card_propose (a new card) or card_update_propose (a change or a stage move) with a one-line reason; a person accepts it. Do not retry it another way.", Map::new())
}
pub fn session_required() -> Value {
    refusal("session_required", "A decision on a card is made by the person at their own terminal, signed in — never with an API key or an agent's token. Tell them it is waiting on them and give the card's link.", Map::new())
}
pub fn members_person_only() -> Value {
    refusal("person_confirmation_required", "Only a person adds or removes a card's members, or accepts being added. Tell them, and give the card's link; do not retry it another way.", Map::new())
}
pub fn pending_full(n: i64) -> Value {
    refusal("proposals_pending_max", &format!("{n} card proposals from this person already wait for an answer. Do not add another; mention the waiting ones instead."), Map::new())
}
pub fn daily_full(n: i64) -> Value {
    refusal("proposals_daily_max", &format!("This session has made its {n} card proposals for today. Stop proposing."), Map::new())
}

/// A card type's stages in order, then its side states.
#[derive(Debug, Clone, PartialEq)]
pub struct Lifecycle {
    pub stages: Vec<String>,
    pub side: Vec<String>,
}

impl Lifecycle {
    pub fn default_lifecycle() -> Self {
        Lifecycle { stages: vec!["To do".into(), "Doing".into(), "Done".into()], side: vec!["Dropped".into()] }
    }
    pub fn to_json(&self) -> Value {
        json!({"stages": self.stages, "side": self.side})
    }
}

/// `Stage > Stage > Stage | Side | Side` — at least two stages; anything else is the default.
pub fn parse_lifecycle(value: Option<&str>) -> Lifecycle {
    let text = crate::val::strip(value.unwrap_or(""));
    if text.is_empty() {
        return Lifecycle::default_lifecycle();
    }
    let (main, rest) = match text.find('|') { Some(i) => (&text[..i], &text[i + 1..]), None => (&text[..], "") };
    let stages: Vec<String> = main.split('>').map(|x| crate::val::strip(x).to_owned()).filter(|x| !x.is_empty()).collect();
    let side: Vec<String> = if rest.is_empty() { Vec::new() } else { rest.split('|').map(|x| crate::val::strip(x).to_owned()).filter(|x| !x.is_empty()).collect() };
    let names: Vec<String> = stages.iter().chain(side.iter()).cloned().collect();
    let folded: std::collections::BTreeSet<String> = names.iter().map(|n| crate::val::casefold(n)).collect();
    if stages.len() < 2 || folded.len() != names.len() || !names.iter().all(|n| state_re().is_match(n)) || names.len() > 12 {
        return Lifecycle::default_lifecycle();
    }
    Lifecycle { stages, side }
}

const ABOUT_ERR: &str = "About is a reference: page:<workspace>/<path>, chat:<id>, workspace:<slug>, meeting:<id> or crm:<record id>";

/// `page:<workspace>/<path>` · `chat:<id>` · `workspace:<slug>` · `meeting:<id>` · `crm:<id>`.
pub fn check_about(r: &Value) -> R<Value> {
    let Some(r) = r.as_str() else { return Err(CrmError::crm(ABOUT_ERR)) };
    if !r.contains(':') || r.chars().count() > 600 {
        return Err(CrmError::crm(ABOUT_ERR));
    }
    let (kind, rest) = r.split_once(':').unwrap();
    let ok = json!({"kind": kind, "ref": r});
    if ["chat", "meeting", "crm"].contains(&kind) && id_re().is_match(rest) {
        return Ok(ok);
    }
    if kind == "workspace" && slug_re().is_match(rest) && !rest.contains("..") {
        return Ok(ok);
    }
    if kind == "page" {
        let (slug, path) = rest.split_once('/').unwrap_or((rest, ""));
        if slug_re().is_match(slug) && !slug.contains("..") && !path.is_empty() && path.chars().count() <= 500
            && !control_re().is_match(path) && path.split('/').all(|p| !["", ".", ".."].contains(&p)) {
            return Ok(ok);
        }
    }
    Err(CrmError::crm(ABOUT_ERR))
}

thread_local! {
    /// Set while a gate decision writes (`decide`): the only writer of a kind card's stage and of
    /// the gate-only fields.
    static GATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` as a gate write (`decide`).
pub fn as_gate<T>(f: impl FnOnce() -> T) -> T {
    let was = GATE.with(|g| g.replace(true));
    let out = f();
    GATE.with(|g| g.set(was));
    out
}

fn days_from_civil(y: i64, mo: i64, d: i64) -> i64 {
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Seconds since the epoch of `YYYY-MM-DD` at midnight UTC, or None when it is not a date.
fn date_epoch(text: &str) -> Option<f64> {
    let b = text.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, mo, d) = (text[..4].parse::<i64>().ok()?, text[5..7].parse::<i64>().ok()?, text[8..].parse::<i64>().ok()?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo) || y < 1 || d < 1 || d > dim[(mo - 1) as usize] {
        return None;
    }
    Some((days_from_civil(y, mo, d) * 86400) as f64)
}

/// type(v).__name__ of a JSON value.
fn py_type(v: &Value) -> &'static str {
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

/// datetime.fromisoformat(str(iso).replace('Z', '+00:00')) as epoch seconds (naive is UTC).
fn iso_epoch(text: &str) -> Option<f64> {
    let t = text.replace('Z', "+00:00");
    if t.len() < 10 || !t.is_char_boundary(10) {
        return None;
    }
    let mut secs = date_epoch(&t[..10])?;
    let rest = &t[10..];
    if rest.is_empty() {
        return Some(secs);
    }
    let rest = &rest[1..];
    let (clock, off) = match rest.find(['+', '-']) { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "") };
    let (hms, frac) = clock.split_once('.').unwrap_or((clock, ""));
    let p: Vec<&str> = hms.split(':').collect();
    let num = |s: &str| s.parse::<i64>().ok().filter(|_| s.len() == 2);
    let h = num(p.first()?)?;
    let mi = p.get(1).map(|x| num(x)).unwrap_or(Some(0))?;
    let se = p.get(2).map(|x| num(x)).unwrap_or(Some(0))?;
    secs += (h * 3600 + mi * 60 + se) as f64;
    if !frac.is_empty() {
        secs += format!("0.{frac}").parse::<f64>().ok()?;
    }
    if !off.is_empty() {
        let sign = if off.starts_with('-') { -1.0 } else { 1.0 };
        let o: Vec<&str> = off[1..].split(':').collect();
        let oh = o.first()?.parse::<i64>().ok()?;
        let om = o.get(1).map(|x| x.parse::<i64>().ok()).unwrap_or(Some(0))?;
        secs -= sign * (oh * 3600 + om * 60) as f64;
    }
    Some(secs)
}

/// SHA-256 of `data` as lower-case hex (hashlib.sha256(..).hexdigest()).
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    let mut h: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

/// secrets.token_urlsafe(n): n random bytes, URL-safe base64 without padding.
pub fn token_urlsafe(n: usize) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let b = vexa_native_kit::ids::random_bytes(n);
    let mut out = String::new();
    for ch in b.chunks(3) {
        let v = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        for i in 0..(ch.len() + 1) {
            out.push(A[((v >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// The value with every object's keys sorted (json.dumps sort_keys=True).
fn sorted_keys(v: &Value) -> Value {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            Value::Object(keys.into_iter().map(|k| (k.clone(), sorted_keys(&o[k]))).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted_keys).collect()),
        other => other.clone(),
    }
}

fn clip(value: &Value, n: usize) -> String {
    crate::card_face::plain(value, n)
}

/// set(caller.writable if caller.writable is not None else caller.workspaces).
fn writable(caller: &Caller) -> std::collections::BTreeSet<String> {
    caller.writable.as_ref().unwrap_or(&caller.workspaces).iter().cloned().collect()
}

/// The record id of a `card:<id>` desk ref.
pub fn card_id(r: &str) -> String {
    r.strip_prefix("card:").map(str::to_owned).unwrap_or_default()
}

/// `_global/POLICIES.md` as text through the desk's policy door, kept 30 seconds.
pub struct PolicyText {
    pub policies: Option<Arc<Policies>>,
    pub ttl_s: f64,
    state: Mutex<(Option<Instant>, Option<String>)>,
}

impl PolicyText {
    pub fn new(policies: Option<Arc<Policies>>) -> Self {
        PolicyText { policies, ttl_s: 30.0, state: Mutex::new((None, None)) }
    }
    /// The text, or None when there is no door or it does not answer (the defaults then apply).
    pub fn call(&self) -> Option<String> {
        let mut st = self.state.lock().unwrap();
        if st.0.is_none_or(|at| at.elapsed().as_secs_f64() >= self.ttl_s) {
            st.1 = self.policies.as_ref().and_then(|p| p.fetch());
            st.0 = Some(Instant::now());
        }
        st.1.clone()
    }
}

pub struct Cards {
    pub store: Arc<Store>,
    pub policy_text: Option<PolicyText>,
    pub limits_source: Option<Arc<Policies>>,
}

#[allow(clippy::too_many_arguments)]
impl Cards {
    pub fn new(store: Arc<Store>, policy_text: Option<PolicyText>, limits: Option<Arc<Policies>>) -> Self {
        Cards { store, policy_text, limits_source: limits }
    }

    fn attrs(&self) -> Map<String, Value> {
        let Some(pt) = &self.policy_text else { return Map::new() };
        front_matter(&pt.call().unwrap_or_default()).into_iter().map(|(k, v)| (k, Value::String(v))).collect()
    }

    /// The stages a card moves through: its KIND's seeded template (D11) when it has one, else its
    /// type's `lifecycles.<type>` line.
    pub fn lifecycle(&self, object_type: &str, kind: &Value) -> Lifecycle {
        if let Some(t) = self.template(kind) {
            return Lifecycle { stages: t.stages.clone(), side: t.side.clone() };
        }
        let attrs = self.attrs();
        let line = attrs.get(&format!("lifecycles.{}", crate::val::lower(object_type))).filter(|v| truthy(v))
            .or_else(|| attrs.get("lifecycles.card"));
        parse_lifecycle(line.and_then(Value::as_str))
    }

    /// A card kind's lifecycle template, with the org's renamed stages if `_global/POLICIES.md`
    /// restates them (`card_templates.<kind>`); None for no kind.
    pub fn template(&self, kind: &Value) -> Option<tpl::Template> {
        let kind = kind.as_str().filter(|k| !k.is_empty())?;
        if !tpl::KINDS.contains(&kind) {
            return None;
        }
        let attrs = self.attrs();
        let line = attrs.get(&format!("card_templates.{kind}")).filter(|v| truthy(v)).cloned()
            .or_else(|| attrs.get(&format!("card_templates.{}", tpl::kind_template(kind).unwrap_or(""))).cloned());
        let over = line.filter(|v| truthy(v)).map(|v| parse_lifecycle(v.as_str()));
        tpl::template_for(kind, over.as_ref().map(|l| (&l.stages[..], &l.side[..])))
    }

    /// Hours between checks of an open card (`card_check_hours`, 1..720).
    pub fn check_after_hours(&self) -> i64 {
        let raw = self.attrs().get("card_check_hours").map(pystr).unwrap_or_default();
        let v = crate::val::strip(&raw);
        match v.parse::<i64>() { Ok(h) if v.chars().all(|c| c.is_ascii_digit()) && (1..=720).contains(&h) => h, _ => CHECK_AFTER_HOURS }
    }

    /// D14/N-7: whether a card's sender sees that its next actor has seen it (default off).
    pub fn seen_visible_to_sender(&self) -> bool {
        crate::val::lower(&crate::val::strip(&self.attrs().get("card_seen_visible_to_sender").map(pystr).unwrap_or_default())) == "true"
    }

    /// Days without a move before a card shows as stalled (`card_stalled_days`, 1..3650).
    pub fn stalled_after_days(&self) -> i64 {
        let raw = self.attrs().get("card_stalled_days").map(pystr).unwrap_or_default();
        let v = crate::val::strip(&raw);
        match v.parse::<i64>() { Ok(d) if v.chars().all(|c| c.is_ascii_digit()) && (1..=3650).contains(&d) => d, _ => STALLED_AFTER_DAYS }
    }

    /// The desk's limits (`policies.rs`), narrow-only; the defaults if the source fails.
    pub fn limits(&self) -> Map<String, Value> {
        let mut out: Map<String, Value> = LIMIT_DEFAULTS.iter().map(|(k, v)| (k.to_string(), Value::from(*v))).collect();
        let Some(src) = &self.limits_source else { return out };
        let got = src.limits();
        for (key, default) in LIMIT_DEFAULTS {
            if let Some(v) = got.get(key).and_then(Value::as_i64) {
                if got[key].is_i64() && (0..=default).contains(&v) {
                    out.insert(key.to_string(), Value::from(v));
                }
            }
        }
        out
    }

    /// The next check of an open card: its due date when that is sooner, else the check interval.
    pub fn next_check(&self, due: &Value, now: Option<f64>) -> String {
        let now = now.unwrap_or_else(vexa_native_kit::ids::now);
        let mut at = now + (self.check_after_hours() * 3600) as f64;
        if let Some(due) = due.as_str() {
            let b = due.as_bytes();
            if b.len() >= 10 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && b[5..7].iter().all(u8::is_ascii_digit)
                && b[7] == b'-' && b[8..10].iter().all(u8::is_ascii_digit) {
                if let Some(d) = date_epoch(&due[..10]) {
                    if now < d && d < at {
                        at = d;
                    }
                }
            }
        }
        vexa_native_kit::ids::utc_isoformat(at)
    }

    /// The one-line text of a revision: what moved, in the fields this viewer reads.
    pub fn describe(&self, before: &Value, after: &Value, readable: &std::collections::BTreeSet<String>) -> String {
        let can = |name: &str| readable.contains("*") || readable.contains(name);
        if before.is_null() {
            return "Made the card".into();
        }
        let empty = Map::new();
        let b = g(before, "fields").as_object().filter(|o| !o.is_empty()).unwrap_or(&empty);
        let a = g(after, "fields").as_object().filter(|o| !o.is_empty()).unwrap_or(&empty);
        let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
        let null = Value::Null;
        let changed: Vec<&String> = keys.into_iter().filter(|k| !crate::val::py_eq(a.get(*k).unwrap_or(&null), b.get(*k).unwrap_or(&null))).collect();
        let has = |k: &str| changed.iter().any(|c| c.as_str() == k);
        let av = |k: &str| a.get(k).unwrap_or(&null);
        if has("State") && can("State") {
            return format!("Moved to {}", clip(av("State"), 60));
        }
        if has("Next") && can("Next") && truthy(av("Next")) {
            return format!("Next: {}", clip(av("Next"), 80));
        }
        if has("Waiting") && can("Waiting") && truthy(av("Waiting")) {
            return format!("Waiting on {}", clip(av("Waiting"), 80));
        }
        if has("Title") && can("Title") {
            return format!("Renamed to {}", clip(av("Title"), 80));
        }
        if !crate::val::py_eq(g(before, "merged_into"), g(after, "merged_into")) {
            return "Merged".into();
        }
        let visible: Vec<&String> = changed.iter().copied().filter(|k| can(k)).collect();
        if visible.len() == 1 && visible[0] == "Face" {
            return "Changed the face".into();
        }
        if !visible.is_empty() {
            return format!("Updated {}", visible.iter().take(3).map(|k| crate::val::lower(k)).collect::<Vec<_>>().join(", "));
        }
        "Updated the card".into()
    }

    /// A revision as a movement: who moved it (an accepted proposal's author), and what.
    pub fn movement(&self, rev: &Obj, readable: &std::collections::BTreeSet<String>) -> Value {
        let mut by = m(rev, "actor_id").clone();
        let mut kind = "person";
        if let Some(items) = m(rev, "evidence").as_array() {
            for item in items {
                if item.is_object() && truthy(g(item, "proposal")) {
                    by = Value::String(if truthy(g(item, "author")) { pystr(g(item, "author")) } else { pystr(&by) });
                    kind = if crate::val::or_str(g(item, "author_kind")).starts_with("agent") { "agent" } else { "person" };
                }
            }
        }
        json!({"by": by, "kind": kind, "what": self.describe(m(rev, "before"), m(rev, "after"), readable), "at": m(rev, "created_at")})
    }

    /// The card's decision records, newest first (D13): each revision a gate decision wrote.
    fn decisions(&self, c: &mut Tx, org: &str, record_id: &str) -> R<Vec<Value>> {
        let rows = c.maps("SELECT revision, decision, actor_id, created_at, credential_class FROM crm_revisions WHERE org_id = $1 AND record_id = $2 AND decision != '' ORDER BY revision DESC LIMIT 50", &[&org, &record_id])?;
        Ok(rows.iter().map(|r| json!({"revision": m(r, "revision"), "action": m(r, "decision"), "by": m(r, "actor_id"), "at": m(r, "created_at"), "credential_class": m(r, "credential_class")})).collect())
    }

    fn seen_at(&self, c: &mut Tx, org: &str, person: &str, record_id: &str) -> R<Value> {
        if person.is_empty() {
            return Ok(Value::Null);
        }
        let row = c.map("SELECT seen_at FROM crm_card_seen WHERE org_id = $1 AND person = $2 AND record_id = $3", &[&org, &person, &record_id])?;
        Ok(row.map(|r| m(&r, "seen_at").clone()).unwrap_or(Value::Null))
    }

    /// One card as this viewer may read it (`CardView`). A room with people from outside the org
    /// reads only its public fields; its movement, activity, members and boards are blank.
    pub fn view(&self, c: &mut Tx, org: &str, policy: &Policy, row: &Row, activity: bool) -> R<Value> {
        let store = &self.store;
        let caller = &policy.caller;
        let cross_org = caller.cross_org;
        let visible = store.visible(policy, row)?;
        let mut readable = store.view(policy, row)?.readable();
        if cross_org {
            readable = crate::store::public_fields(policy, &col(row, "object_type"));
        }
        let empty = Map::new();
        let f: &Obj = visible.get("fields").and_then(Value::as_object).unwrap_or(&empty);
        let fv = |k: &str| f.get(k).cloned().unwrap_or(Value::Null);
        let raw: Obj = m(row, "fields").as_object().cloned().unwrap_or_default();
        let raw_kind = raw.get("Kind").cloned().unwrap_or(Value::Null);
        let kind = if raw_kind.as_str().is_some_and(|k| tpl::KINDS.contains(&k)) { raw_kind } else { Value::Null };
        let template = self.template(&kind);
        let object_type = col(row, "object_type");
        let life = self.lifecycle(&object_type, &kind);
        let can_write = match store.rights(policy, row, "write") {
            Ok(r) => !r.is_empty() && !caller.delegated,
            Err(e) if e.isa("NotFound") => false,
            Err(e) => return Err(e),
        };
        let id = col(row, "id");
        let mut bindings = store.bindings(c, org, &id)?;
        if !policy.admin() || caller.delegated {
            bindings.retain(|w| caller.workspaces.contains(w));
        }
        if cross_org {
            bindings.clear();
        }
        let mut parent = Value::Null;
        if truthy(&fv("Parent")) {
            match self.card_row(c, org, &pystr(&fv("Parent"))) {
                Ok(prow) => {
                    let pv = store.visible(policy, &prow);
                    match pv {
                        Ok(pv) => {
                            let t = g(&pv["fields"], "Title");
                            parent = json!({"id": m(&prow, "id"), "title": if truthy(t) { t.clone() } else { "A card".into() }});
                        }
                        Err(e) if e.isa("NotFound") => {}
                        Err(e) => return Err(e),
                    }
                }
                Err(e) if e.isa("NotFound") => {}
                Err(e) => return Err(e),
            }
        }
        let mut items: Vec<Value> = Vec::new();
        let kids = c.maps("SELECT record_id FROM crm_relationships WHERE org_id = $1 AND target_domain = 'crm' AND target_id = $2 AND kind = 'Parent'", &[&org, &id])?;
        for k in kids {
            let child_id = col(&k, "record_id");
            let got = self.card_row(c, org, &child_id).and_then(|crow| store.visible(policy, &crow).map(|v| (crow, v)));
            let (crow, cv) = match got {
                Ok(x) => x,
                Err(e) if e.isa("NotFound") => continue,
                Err(e) => return Err(e),
            };
            let cf = cv.get("fields").cloned().unwrap_or(Value::Null);
            let clife = self.lifecycle(&col(&crow, "object_type"), &Value::Null);
            let t = g(&cf, "Title");
            let st = g(&cf, "State");
            items.push(json!({"id": m(&crow, "id"), "title": if truthy(t) { t.clone() } else { "A card".into() },
                "state": if truthy(st) { st.clone() } else { "".into() },
                "done": st.as_str() == clife.stages.last().map(String::as_str)}));
        }
        items.sort_by(|a, b| {
            let ka = (a["done"].as_bool().unwrap_or(false), crate::val::casefold(&pystr(&a["title"])));
            let kb = (b["done"].as_bool().unwrap_or(false), crate::val::casefold(&pystr(&b["title"])));
            ka.cmp(&kb)
        });
        let revs: Vec<Obj> = if cross_org { Vec::new() } else {
            c.maps(&format!("SELECT {} FROM crm_revisions WHERE org_id = $1 AND record_id = $2 ORDER BY revision DESC LIMIT {}", crate::schema::REVISIONS, if activity { 50 } else { 1 }), &[&org, &id])?
        };
        let movement = revs.first().map(|r| self.movement(r, &readable)).unwrap_or(Value::Null);
        let state = fv("State");
        let finished = state.as_str() == life.stages.last().map(String::as_str) || state.as_str().is_some_and(|st| life.side.iter().any(|x| x == st));
        let stalled = truthy(&movement) && !finished && {
            let at = iso_epoch(&pystr(&movement["at"])).ok_or_else(|| CrmError::internal(format!("ValueError: Invalid isoformat string: '{}'", pystr(&movement["at"]))))?;
            vexa_native_kit::ids::now() - at > (self.stalled_after_days() * 86400) as f64
        };
        let seen = c.map("SELECT seen_at FROM crm_card_seen WHERE org_id = $1 AND person = $2 AND record_id = $3", &[&org, &caller.subject, &id])?;
        let new = seen.is_none() && col(row, "owner_id") != caller.subject;
        let mut about = Value::Null;
        if truthy(&fv("About")) {
            about = check_about(&fv("About")).unwrap_or(Value::Null);
        }
        let face_source = if readable.contains("*") || readable.contains("Face") { fv("Face") } else { Value::Null };
        let def = store.definition(c, org, &object_type)?;
        let mut formats = Map::new();
        if let Some(props) = g(&def, "properties").as_object() {
            for (k, v) in props {
                if v.is_object() && truthy(g(v, "x-format")) {
                    formats.insert(k.clone(), g(v, "x-format").clone());
                }
            }
        }
        let done = items.iter().filter(|i| i["done"] == Value::Bool(true)).count();
        let total = items.len();
        let members = if cross_org { Vec::new() } else { self.members_of(c, org, &id)? };
        let title = fv("Title");
        let mut out = json!({
            "id": m(row, "id"), "ref": format!("card:{id}"), "type": m(row, "object_type"), "revision": m(row, "revision"),
            "title": if truthy(&title) { title } else { "A card".into() }, "about": about, "state": state,
            "states": life.stages, "side_states": life.side,
            "next": fv("Next"), "waiting": fv("Waiting"), "summary": fv("Summary"),
            "due": fv("Due"), "progress": fv("Progress"),
            "workspaces": bindings, "parent": parent,
            "children": {"done": done, "total": total, "items": items.into_iter().take(20).collect::<Vec<_>>()},
            "members": members,
            "face": crate::card_face::resolve(&face_source, f, &readable, &formats),
            "movement": movement, "stalled": stalled, "new": new,
            "can": {"edit": can_write, "transition": can_write, "review": can_write, "members": can_write},
            "href": crate::val::record_href(&id),
        });
        let co = self.coordination(c, org, row, &raw, &kind, template.as_ref(), caller, cross_org, &state)?;
        let o = out.as_object_mut().unwrap();
        for (k, v) in co {
            o.insert(k, v);
        }
        if activity {
            o.insert("activity".into(), Value::Array(revs.iter().map(|r| self.movement(r, &readable)).collect()));
        }
        Ok(out)
    }

    /// The lifecycle coordination fields and the viewer's own position on the card, read whoever
    /// may read the card; a room with people from outside the org reads none of them.
    fn coordination(&self, c: &mut Tx, org: &str, row: &Row, raw: &Obj, kind: &Value, template: Option<&tpl::Template>, caller: &Caller, cross_org: bool, state: &Value) -> R<Obj> {
        if cross_org {
            let b = json!({"kind": kind, "next_actor": null, "requester": null, "next_check_at": null,
                "chain": {"blocks": [], "blocked_by": []}, "origin": null, "open": true,
                "handoff": {"phase": null, "since": null}, "gates": [], "decisions": [], "last_decision": null,
                "viewer": {"role": "watcher", "seen": false, "actions": []}});
            return Ok(b.as_object().cloned().unwrap());
        }
        let or_none = |k: &str| raw.get(k).filter(|v| truthy(v)).cloned().unwrap_or(Value::Null);
        let me = if caller.delegated || caller.internal { String::new() } else { caller.subject.clone() };
        let next_actor = or_none("NextActor");
        let requester = match raw.get("Requester").filter(|v| truthy(v)) {
            Some(v) => v.clone(),
            None => if template.is_some() { m(row, "owner_id").clone() } else { Value::Null },
        };
        let id = col(row, "id");
        let decisions = self.decisions(c, org, &id)?;
        let empty = Map::new();
        let chain = raw.get("Chain").and_then(Value::as_object).unwrap_or(&empty);
        let list_of = |v: Option<&Value>| -> Value {
            match v.filter(|v| truthy(v)) {
                Some(Value::Array(a)) => Value::Array(a.clone()),
                Some(Value::String(s)) => Value::Array(s.chars().map(|c| Value::String(c.to_string())).collect()),
                Some(Value::Object(o)) => Value::Array(o.keys().map(|k| Value::String(k.clone())).collect()),
                _ => json!([]),
            }
        };
        let last = decisions.first().map(|d| json!({"action": d["action"], "by": d["by"], "at": d["at"]})).unwrap_or(Value::Null);
        let mut out = json!({
            "kind": kind, "next_actor": next_actor, "requester": requester,
            "next_check_at": or_none("NextCheckAt"),
            "chain": {"blocks": list_of(chain.get("blocks")), "blocked_by": list_of(chain.get("blocked_by"))},
            "origin": or_none("Origin"),
            "handoff": {"phase": or_none("Handoff"), "since": or_none("HandoffSince")},
            "decisions": decisions,
            "last_decision": last,
        }).as_object().cloned().unwrap();
        let is_member = |s: &Self, c: &mut Tx| -> R<bool> {
            Ok(!me.is_empty() && s.members_of(c, org, &id)?.iter().any(|x| x["subject"].as_str() == Some(me.as_str())))
        };
        let Some(template) = template else {
            out.insert("open".into(), true.into());
            out.insert("gates".into(), json!([]));
            let role = if is_member(self, c)? { "member" } else { "watcher" };
            let seen = truthy(&self.seen_at(c, org, &me, &id)?);
            out.insert("viewer".into(), json!({"role": role, "seen": seen, "actions": []}));
            return Ok(out);
        };
        out.insert("open".into(), tpl::is_open(template, state).into());
        out.insert("gates".into(), Value::Array(tpl::gate_strip(template, state, &out["decisions"].as_array().cloned().unwrap_or_default())));
        let role = if !me.is_empty() && next_actor.as_str() == Some(me.as_str()) { "next_actor" }
            else if !me.is_empty() && requester.as_str() == Some(me.as_str()) { "requester" }
            else if is_member(self, c)? { "member" } else { "watcher" };
        let seen_at = self.seen_at(c, org, &me, &id)?;
        let since = raw.get("HandoffSince").filter(|v| truthy(v)).map(pystr).unwrap_or_default();
        let seen = truthy(&seen_at) && (since.is_empty() || pystr(&seen_at) >= since);
        let actions = tpl::actions_for(template, state, raw.get("Handoff").unwrap_or(&Value::Null), &me, &next_actor);
        out.insert("viewer".into(), json!({"role": role, "seen": seen, "actions": actions}));
        if role == "next_actor" || (role == "requester" && self.seen_visible_to_sender()) {
            let na = if next_actor.is_null() { String::new() } else { pystr(&next_actor) };
            let na_seen = self.seen_at(c, org, &na, &id)?;
            let s = truthy(&na_seen) && (since.is_empty() || pystr(&na_seen) >= since);
            if let Some(h) = out.get_mut("handoff").and_then(Value::as_object_mut) {
                h.insert("seen".into(), s.into());
            }
        }
        Ok(out)
    }

    /// D13: decisions and the seen relation take the terminal's session credential — never an API
    /// key, never a delegation token, never the internal tier.
    pub fn require_session(caller: &Caller) -> R<()> {
        if caller.delegated || caller.internal || caller.subject.is_empty() || caller.credential_class != "session" {
            return Err(CrmError::refused(session_required()));
        }
        Ok(())
    }

    /// The card as its signer saw it, canonically: what the decision binds to.
    pub fn canonical(view: &Value) -> Value {
        let keep = ["id", "revision", "type", "kind", "title", "state", "next_actor", "requester", "due", "summary",
            "next", "waiting", "about", "face", "chain"];
        Value::Object(keep.iter().map(|k| (k.to_string(), g(view, k).clone())).collect())
    }

    pub fn content_hash(view: &Value) -> String {
        let blob = crate::val::dumps_compact(&sorted_keys(&Self::canonical(view)));
        sha256_hex(blob.as_bytes())
    }

    fn locked(view: &Value) -> Vec<Value> {
        g(view, "face").as_array().map(|a| a.iter().filter(|b| g(b, "type").as_str() == Some("locked"))
            .map(|b| if truthy(g(b, "label")) { g(b, "label").clone() } else { "a field".into() }).collect()).unwrap_or_default()
    }

    /// Write a gate's patch as one revision. The template authorised it, so field write rights are
    /// not consulted; the schema and the lifecycle still are.
    fn apply(&self, c: &mut Tx, org: &str, actor: &str, row: &Row, patch: &Obj, reason: &str, evidence: &Value, decision: &Value) -> R<()> {
        let store = &self.store;
        let object_type = col(row, "object_type");
        let fields = self.normalise_fields(&object_type, patch, Some(m(row, "fields")), None)?;
        let mut merged = m(row, "fields").as_object().cloned().unwrap_or_default();
        for (k, v) in fields {
            merged.insert(k, v);
        }
        let rev = m(row, "revision").as_i64().unwrap_or(0);
        let mut after = row.clone();
        after.insert("fields".into(), Value::Object(merged));
        after.insert("revision".into(), Value::from(rev + 1));
        store.validate(&store.definition(c, org, &object_type)?, &after["fields"])?;
        let changed = c.exec("UPDATE crm_records SET fields = $1, revision = $2 WHERE org_id = $3 AND id = $4 AND revision = $5",
            &[&after["fields"], &vexa_native_kit::pg::Int(rev + 1), &org, &col(row, "id"), &vexa_native_kit::pg::Int(rev)])?;
        if changed != 1 {
            return Err(CrmError::conflict("The card changed since you read it; read it again"));
        }
        store.sync_relationships(c, &after)?;
        store.revision(c, org, actor, Some(row), &after, reason, evidence, Some(decision))
    }

    fn ensure_member(&self, c: &mut Tx, org: &str, record_id: &str, subject: &str, by: &str) -> R<()> {
        let have = c.map("SELECT status FROM crm_card_members WHERE org_id = $1 AND record_id = $2 AND subject = $3", &[&org, &record_id, &subject])?;
        if have.is_none() {
            c.exec("INSERT INTO crm_card_members (org_id, record_id, subject, status, added_by, added_at) VALUES ($1, $2, $3, 'member', $4, $5)",
                &[&org, &record_id, &subject, &by, &crate::val::now_iso()])?;
        }
        Ok(())
    }

    fn new_fields(&self, title: &Value, about: Option<&str>, parent: Option<&str>, fields: &Obj, face: Option<&Value>) -> R<Obj> {
        let mut out: Obj = fields.iter().filter(|(k, _)| EDITABLE.contains(&k.as_str()) && !["Title", "About", "Parent", "Face"].contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut unknown: Vec<&String> = fields.keys().filter(|k| !EDITABLE.contains(&k.as_str())).collect();
        if !unknown.is_empty() {
            unknown.sort();
            return Err(CrmError::crm(format!("A card does not take {}", unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))));
        }
        let title = clip(title, TITLE_MAX);
        if title.is_empty() {
            return Err(CrmError::crm("A card needs a title"));
        }
        out.insert("Title".into(), title.into());
        if let Some(about) = about.filter(|a| !a.is_empty()) {
            check_about(&Value::from(about))?;
            out.insert("About".into(), about.into());
        }
        if let Some(parent) = parent.filter(|p| !p.is_empty()) {
            out.insert("Parent".into(), parent.into());
        }
        if let Some(face) = face.filter(|f| !f.is_null()) {
            out.insert("Face".into(), face.clone());
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(&self, c: &mut Tx, org: &str, owner: &str, object_type: &str, fields: &Obj, narrative: Option<&str>, reason: &str, evidence: &Value, workspace: Option<&str>, members: &[String]) -> R<String> {
        let store = &self.store;
        let definition = self.definition_of(c, org, object_type)?;
        let fields = self.normalise_fields(object_type, fields, None, None)?;
        let fv = Value::Object(fields.clone());
        store.validate(&definition, &fv)?;
        let record_id = crate::val::uuid4();
        let narrative = narrative.unwrap_or("");
        let row: Obj = json!({"org_id": org, "id": record_id, "object_type": object_type, "owner_id": owner, "revision": 1,
            "fields": fv, "narrative": narrative, "quarantined": false, "deleted": false}).as_object().cloned().unwrap();
        c.exec("INSERT INTO crm_records (org_id, id, object_type, owner_id, revision, fields, narrative, quarantined, deleted) VALUES ($1, $2, $3, $4, 1, $5, $6, false, false)",
            &[&org, &record_id, &object_type, &owner, &row["fields"], &narrative])?;
        store.sync_relationships(c, &row)?;
        let now = crate::val::now_iso();
        let mut subjects: Vec<String> = members.to_vec();
        if truthy(fields.get("Kind").unwrap_or(&Value::Null)) {
            for k in ["NextActor", "Requester"] {
                if let Some(p) = fields.get(k).filter(|p| truthy(p)) {
                    subjects.push(pystr(p));
                }
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for subject in subjects {
            if !seen.insert(subject.clone()) {
                continue;
            }
            c.exec("INSERT INTO crm_card_members (org_id, record_id, subject, status, added_by, added_at) VALUES ($1, $2, $3, 'member', $4, $5)",
                &[&org, &record_id, &subject, &owner, &now])?;
        }
        if let Some(ws) = workspace.filter(|w| !w.is_empty()) {
            c.exec("INSERT INTO crm_workspace_bindings (org_id, workspace, record_id, created_by, created_at) VALUES ($1, $2, $3, $4, $5)",
                &[&org, &ws, &record_id, &owner, &now])?;
        }
        store.audit_names(&record_id);
        store.revision(c, org, owner, None, &row, reason, evidence, None)?;
        Ok(record_id)
    }

    fn check_parent(&self, c: &mut Tx, org: &str, policy: &Policy, parent: &Value) -> R<()> {
        if truthy(parent) {
            let got = self.card_row(c, org, &pystr(parent)).and_then(|r| self.store.visible(policy, &r));
            if let Err(e) = got {
                if e.isa("NotFound") || e.isa("SharedRefused") {
                    return Err(CrmError::not_found("Parent card not found"));
                }
                return Err(e);
            }
        }
        Ok(())
    }

    fn patch(fields: &Obj, face: Option<&Value>, transition: Option<&str>) -> R<Obj> {
        let mut fields = fields.clone();
        let mut transition: Value = transition.filter(|t| !t.is_empty()).map(Value::from).unwrap_or(Value::Null);
        if fields.contains_key("State") && !truthy(&transition) {
            transition = fields.shift_remove("State").unwrap();
        }
        let mut unknown: Vec<&String> = fields.keys().filter(|k| !EDITABLE.contains(&k.as_str())).collect();
        if !unknown.is_empty() {
            unknown.sort();
            return Err(CrmError::crm(format!("A card does not take {}", unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))));
        }
        if let Some(t) = fields.get("Title").cloned() {
            let t = clip(&t, TITLE_MAX);
            if t.is_empty() {
                return Err(CrmError::crm("A card needs a title"));
            }
            fields.insert("Title".into(), t.into());
        }
        if let Some(face) = face.filter(|f| !f.is_null()) {
            fields.insert("Face".into(), face.clone());
        }
        if truthy(&transition) {
            fields.insert("State".into(), transition);
        }
        if fields.is_empty() {
            return Err(CrmError::crm("Nothing to change"));
        }
        Ok(fields)
    }

    fn pending(&self, c: &mut Tx, org: &str, ttl_days: i64) -> R<Vec<Obj>> {
        let now = vexa_native_kit::ids::now();
        let rows = c.maps(&format!("SELECT {} FROM crm_change_proposals WHERE org_id = $1 AND status = 'pending'", crate::schema::CHANGE_PROPOSALS), &[&org])?;
        let mut out = Vec::new();
        for row in rows {
            if !m(&row, "record_id").is_null() && !self.store.is_card(c, org, &col(&row, "record_id"))? {
                continue;
            }
            let at = g(m(&row, "patch"), "created_at");
            if truthy(at) {
                let t = iso_epoch(&pystr(at)).ok_or_else(|| CrmError::internal(format!("ValueError: Invalid isoformat string: '{}'", pystr(at))))?;
                if now - t >= (ttl_days * 86400) as f64 {
                    continue;
                }
            }
            out.push(row);
        }
        Ok(out)
    }

    fn caps(&self, c: &mut Tx, org: &str, caller: &Caller) -> R<()> {
        let limits = self.limits();
        let lim = |k: &str| limits.get(k).and_then(Value::as_i64).unwrap_or(0);
        let pending = self.pending(c, org, self.ttl_days(Some(&limits)))?;
        let mine: Vec<&Obj> = pending.iter().filter(|p| m(p, "author_id").as_str() == Some(caller.subject.as_str())).collect();
        if mine.len() as i64 >= lim("card_proposals_pending_max") {
            return Err(CrmError::refused(pending_full(lim("card_proposals_pending_max"))));
        }
        if caller.delegated {
            let day = mine.iter().filter(|p| g(m(p, "patch"), "session").as_str() == Some(caller.session.as_str())).count();
            if day as i64 >= lim("card_proposals_per_agent_per_day") {
                return Err(CrmError::refused(daily_full(lim("card_proposals_per_agent_per_day"))));
            }
        }
        Ok(())
    }

    fn reason(reason: &Value) -> R<String> {
        let reason = clip(reason, REASON_MAX);
        if reason.is_empty() {
            return Err(CrmError::crm("A proposal needs a one-line reason the person reads"));
        }
        Ok(reason)
    }

    fn offered_today(&self, c: &mut Tx, org: &str, caller: &Caller) -> R<i64> {
        let since = vexa_native_kit::ids::utc_isoformat(vexa_native_kit::ids::now() - 86400.0);
        let rows = c.maps("SELECT evidence FROM crm_revisions WHERE org_id = $1 AND revision = 1 AND actor_id = $2 AND created_at > $3", &[&org, &caller.subject, &since])?;
        let mut n = 0;
        for r in rows {
            if m(&r, "evidence").as_array().is_some_and(|a| a.iter().any(|e| e.is_object() && g(e, "proposal").as_str() == Some("offer")
                && g(e, "session").as_str() == Some(caller.session.as_str()))) {
                n += 1;
            }
        }
        Ok(n)
    }

    /// D11/R10: an agent's card OF A KIND is made in its first stage and OFFERED to its next actor —
    /// the card itself is the proposal. Capped per session per day like proposals.
    #[allow(clippy::too_many_arguments)]
    fn offer(&self, org: &str, caller: &Caller, title: &Value, workspace: Option<&str>, about: Option<&str>, type_: &str, parent: Option<&str>, fields: &Obj, face: Option<&Value>, reason: &str) -> R<Value> {
        self.store.begin(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let mut ws = workspace.filter(|w| !w.is_empty()).map(str::to_owned);
            if let Some(w) = &ws {
                let w = crate::store::check_workspace(w)?;
                if !caller.workspaces.contains(&w) {
                    return Err(CrmError::forbidden("Propose a card only into a workspace you work in"));
                }
                ws = Some(w);
            }
            self.check_parent(c, org, &policy, &parent.map(Value::from).unwrap_or(Value::Null))?;
            let limits = self.limits();
            let day = limits.get("card_proposals_per_agent_per_day").and_then(Value::as_i64).unwrap_or(0);
            if caller.delegated && self.offered_today(c, org, caller)? >= day {
                return Err(CrmError::refused(daily_full(day)));
            }
            let mut data = self.new_fields(title, about, parent, fields, face)?;
            let on_behalf = match caller.extra.get("on_behalf_of") { Some(v) if truthy(v) => crate::val::strip(&pystr(v)).to_owned(), _ => String::new() };
            data.entry("Requester").or_insert_with(|| Value::String(if on_behalf.is_empty() { caller.subject.clone() } else { on_behalf }));
            let trail = json!([{"proposal": "offer", "author": caller.subject, "author_kind": caller.kind(), "session": caller.session}]);
            let kind = if type_.is_empty() { DEFAULT_TYPE } else { type_ };
            let record_id = self.insert(c, org, &caller.subject, kind, &data, None, reason, &trail, ws.as_deref(), &[])?;
            let policy = self.store.policy(c, org, caller, true)?;
            let got = self.card_row(c, org, &record_id).and_then(|row| self.view(c, org, &policy, &row, false));
            match got {
                Ok(v) => Ok(json!({"status": "offered", "card": v})),
                Err(e) if e.isa("NotFound") || e.isa("SharedRefused") => Ok(json!({"status": "offered", "card": null, "record_id": record_id})),
                Err(e) => Err(e),
            }
        })
    }

    fn may_review_create(policy: &Policy, caller: &Caller, p: &Obj) -> bool {
        let ws = g(g(m(p, "patch"), "create"), "workspace");
        if truthy(ws) {
            return ws.as_str().is_some_and(|w| writable(caller).contains(w)) || policy.admin();
        }
        m(p, "author_id").as_str() == Some(caller.subject.as_str())
    }

    fn proposal_view(&self, c: &mut Tx, org: &str, policy: &Policy, p: &Obj) -> R<Value> {
        let patch = m(p, "patch");
        let create = g(patch, "create");
        let author_kind = match patch.get("author_kind") { Some(v) => v.clone(), None => "person".into() };
        let mut base = json!({"id": m(p, "id"), "reason": m(p, "reason"), "author_kind": author_kind,
            "author": m(p, "author_id"), "at": g(patch, "created_at")}).as_object().cloned().unwrap();
        if truthy(create) {
            let f = g(create, "fields").as_object().cloned().unwrap_or_default();
            let t = f.get("Title").filter(|t| truthy(t)).cloned().unwrap_or("A card".into());
            base.insert("kind".into(), "create".into());
            base.insert("card".into(), Value::Null);
            base.insert("title".into(), t);
            base.insert("workspace".into(), g(create, "workspace").clone());
            base.insert("fields".into(), Value::Object(f.into_iter().filter(|(k, _)| k != "Face").collect()));
            return Ok(Value::Object(base));
        }
        let row = self.card_row(c, org, &col(p, "record_id"))?;
        let readable = self.store.rights(policy, &row, "read")?;
        let vt = g(&self.store.visible(policy, &row)?["fields"], "Title").clone();
        let title = if truthy(&vt) { vt } else { "A card".into() };
        let fields: Obj = g(patch, "fields").as_object().cloned().unwrap_or_default().into_iter()
            .filter(|(k, _)| (readable.iter().any(|r| r == "*") || readable.contains(k)) && k != "Face").collect();
        base.insert("kind".into(), "change".into());
        base.insert("card".into(), json!({"id": m(&row, "id"), "title": title}));
        base.insert("title".into(), title);
        base.insert("workspace".into(), Value::Null);
        base.insert("fields".into(), Value::Object(fields));
        Ok(Value::Object(base))
    }

    /// Pending card proposals this person may answer, newest first; none to a room with people
    /// from outside the org.
    fn reviewable(&self, c: &mut Tx, org: &str, caller: &Caller, policy: &Policy, workspace: Option<&str>) -> R<Vec<Value>> {
        if caller.internal || caller.cross_org {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let ttl = self.ttl_days(None);
        for p in self.pending(c, org, ttl)? {
            let got = (|| -> R<Option<Value>> {
                if m(&p, "record_id").is_null() {
                    if !Self::may_review_create(policy, caller, &p) {
                        return Ok(None);
                    }
                    if let Some(w) = workspace.filter(|w| !w.is_empty()) {
                        if g(g(m(&p, "patch"), "create"), "workspace").as_str() != Some(w) {
                            return Ok(None);
                        }
                    }
                } else {
                    let row = self.card_row(c, org, &col(&p, "record_id"))?;
                    self.store.rights(policy, &row, "write")?;
                    if let Some(w) = workspace.filter(|w| !w.is_empty()) {
                        if !self.store.bindings(c, org, &col(&row, "id"))?.iter().any(|b| b == w) {
                            return Ok(None);
                        }
                    }
                }
                Ok(Some(self.proposal_view(c, org, policy, &p)?))
            })();
            match got {
                Ok(Some(v)) => out.push(v),
                Ok(None) => {}
                Err(e) if e.isa("NotFound") || e.isa("SharedRefused") => {}
                Err(e) => return Err(e),
            }
        }
        out.sort_by(|a, b| {
            let k = |x: &Value| if truthy(&x["at"]) { pystr(&x["at"]) } else { String::new() };
            k(b).cmp(&k(a))
        });
        Ok(out)
    }

    fn views(&self, c: &mut Tx, org: &str, policy: &Policy, ids: &[String]) -> R<Vec<Value>> {
        let mut out = Vec::new();
        for id in ids {
            match self.card_row(c, org, id).and_then(|row| self.view(c, org, policy, &row, false)) {
                Ok(v) => out.push(v),
                Err(e) if e.isa("NotFound") || e.isa("SharedRefused") => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// An open card whose next actor is this person. THE predicate every count uses.
    pub fn waits_on(view: &Value, me: &str) -> bool {
        !me.is_empty() && view.get("open").map(truthy).unwrap_or(true) && g(view, "next_actor").as_str() == Some(me)
    }

    pub fn counts(&self, views: &[Value], me: &str) -> Value {
        let soon = vexa_native_kit::ids::utc_isoformat(vexa_native_kit::ids::now() + (DUE_SOON_DAYS * 86400) as f64)[..10].to_owned();
        let open = |v: &Value| v.get("open").map(truthy).unwrap_or(true);
        let is_me = |x: &Value| x.as_str() == Some(me);
        let due_soon = |v: &Value| truthy(g(v, "due")) && open(v) && pystr(g(v, "due")).chars().take(10).collect::<String>() <= soon
            && (is_me(g(v, "next_actor")) || is_me(g(v, "requester")));
        json!({"waiting_on_me": views.iter().filter(|v| Self::waits_on(v, me)).count(),
            "due_soon": views.iter().filter(|v| !me.is_empty() && due_soon(v)).count(),
            "i_wait_on": views.iter().filter(|v| !me.is_empty() && open(v) && truthy(g(v, "kind")) && is_me(g(v, "requester"))
                && !(g(v, "next_actor").is_null() || is_me(g(v, "next_actor")))).count()})
    }

    fn ttl_days(&self, limits: Option<&Map<String, Value>>) -> i64 {
        let own;
        let l = match limits { Some(l) => l, None => { own = self.limits(); &own } };
        l.get("card_proposal_ttl_days").and_then(Value::as_i64).unwrap_or(7)
    }

    fn definition_of(&self, c: &mut Tx, org: &str, object_type: &str) -> R<Value> {
        let d = self.store.definition(c, org, object_type)?;
        if !truthy(g(&d, "x-card")) {
            return Err(CrmError::crm("Not a card type"));
        }
        Ok(d)
    }

    fn card_row(&self, c: &mut Tx, org: &str, record_id: &str) -> R<Row> {
        let row = self.store.row(c, org, record_id)?;
        if !truthy(g(&self.store.definition(c, org, &col(&row, "object_type"))?, "x-card")) {
            return Err(CrmError::not_found("Card not found"));
        }
        Ok(row)
    }

    fn members_of(&self, c: &mut Tx, org: &str, record_id: &str) -> R<Vec<Value>> {
        let rows = c.maps("SELECT subject, status FROM crm_card_members WHERE org_id = $1 AND record_id = $2 ORDER BY added_at, subject", &[&org, &record_id])?;
        Ok(rows.into_iter().map(|r| json!({"subject": m(&r, "subject"), "status": m(&r, "status")})).collect())
    }
    /// A card's fields as every write path stores them. `actor` is the person whose write is being
    /// APPLIED (an edit, the reviewer accepting a proposal, the person making the record); None while
    /// a proposal is only filed, and on the paths of this type that set the requester themselves.
    pub fn normalise_fields(&self, object_type: &str, fields: &Obj, before: Option<&Value>, actor: Option<&str>) -> R<Obj> {
        let mut fields = fields.clone();
        let empty = Map::new();
        let prior: &Obj = before.and_then(Value::as_object).unwrap_or(&empty);
        let gate_write = GATE.with(|g| g.get());
        if let Some(face) = fields.get("Face") {
            let clean = crate::card_face::sanitize(face);
            fields.insert("Face".into(), Value::Array(clean));
        }
        if truthy(fields.get("About").unwrap_or(&Value::Null)) {
            check_about(&fields["About"])?;
        }
        if !gate_write && GATE_ONLY.iter().any(|k| fields.contains_key(*k)) {
            return Err(CrmError::crm("A card's handoff, answer, evidence and receipt change only through its gates (decide)"));
        }
        let kind = fields.get("Kind").or_else(|| prior.get("Kind")).cloned().unwrap_or(Value::Null);
        if truthy(prior.get("Kind").unwrap_or(&Value::Null)) && fields.contains_key("Kind")
            && !crate::val::py_eq(&fields["Kind"], &prior["Kind"]) {
            return Err(CrmError::crm("A card's kind does not change; make a new card"));
        }
        if !kind.is_null() && !kind.as_str().is_some_and(|k| tpl::KINDS.contains(&k)) {
            return Err(CrmError::crm(format!("Kind is one of {}", tpl::KINDS.join(", "))));
        }
        let template = self.template(&kind);
        let life = self.lifecycle(object_type, &kind);
        let states: Vec<String> = life.stages.iter().chain(life.side.iter()).cloned().collect();
        if let Some(state) = fields.get("State") {
            if !state.as_str().is_some_and(|st| states.iter().any(|x| x == st)) {
                return Err(CrmError::crm(format!("\"{}\" is not a stage of this card type; its stages are {}", clip(state, 60), states.join(", "))));
            }
            if template.is_some() && before.is_some() && !gate_write
                && !crate::val::py_eq(state, prior.get("State").unwrap_or(&Value::Null)) {
                return Err(CrmError::crm("A card of this kind moves only through its gates (decide), by the person whose move it is"));
            }
        } else if before.is_none() {
            fields.insert("State".into(), Value::String(life.stages[0].clone()));
        }
        for key in ["NextActor", "Requester"] {
            if let Some(v) = fields.get(key).filter(|v| !v.is_null()) {
                let value = crate::val::strip(&pystr(v)).to_owned();
                if !person_re().is_match(&value) {
                    return Err(CrmError::crm(format!("{key} is a person id")));
                }
                fields.insert(key.into(), Value::String(value));
            }
        }
        if let Some(o) = fields.get("Origin").filter(|v| !v.is_null()) {
            if !origin_re().is_match(&pystr(o)) {
                return Err(CrmError::crm("Origin is session:<id>, meeting:<id> or message:<session>/<message id>"));
            }
        }
        if let Some(chain) = fields.get("Chain") {
            let empty_chain = Map::new();
            let chain = chain.as_object().unwrap_or(&empty_chain);
            let mut out = Map::new();
            for k in ["blocks", "blocked_by"] {
                let items: Vec<String> = match chain.get(k) {
                    Some(v) if truthy(v) => match v {
                        Value::Array(a) => a.iter().map(pystr).collect(),
                        Value::String(s) => s.chars().map(|c| c.to_string()).collect(),
                        Value::Object(o) => o.keys().cloned().collect(),
                        _ => return Err(CrmError::internal(format!("TypeError: '{}' object is not iterable", py_type(v)))),
                    },
                    _ => Vec::new(),
                };
                let kept: Vec<Value> = items.into_iter().filter(|x| id_re().is_match(x)).take(20).map(Value::String).collect();
                out.insert(k.into(), Value::Array(kept));
            }
            fields.insert("Chain".into(), Value::Object(out));
        }
        if let Some(template) = &template {
            let mut merged = prior.clone();
            for (k, v) in &fields {
                merged.insert(k.clone(), v.clone());
            }
            if before.is_none() {
                if !truthy(merged.get("NextActor").unwrap_or(&Value::Null)) {
                    return Err(CrmError::crm("A card of a kind names its next actor (NextActor: a person id)"));
                }
                if let Some(actor) = actor {
                    Self::made_by(&mut fields, actor)?;
                }
                fields.entry("Handoff").or_insert_with(|| "offered".into());
                fields.entry("HandoffSince").or_insert_with(|| Value::String(crate::val::now_iso()));
            } else if !gate_write {
                if let Some(actor) = actor {
                    Self::may_reassign(prior, &fields, actor)?;
                }
                if fields.contains_key("NextActor") && !crate::val::py_eq(&fields["NextActor"], prior.get("NextActor").unwrap_or(&Value::Null)) {
                    fields.insert("Handoff".into(), "offered".into());
                    fields.insert("HandoffSince".into(), Value::String(crate::val::now_iso()));
                }
            }
            let ms = merged.get("State").filter(|v| truthy(v)).or_else(|| fields.get("State")).cloned().unwrap_or(Value::Null);
            if tpl::is_open(template, &ms) && !truthy(merged.get("NextCheckAt").unwrap_or(&Value::Null)) {
                let at = self.next_check(merged.get("Due").unwrap_or(&Value::Null), None);
                fields.insert("NextCheckAt".into(), Value::String(at));
            }
        }
        Ok(fields)
    }

    /// A card of a kind made through the generic record create waits on the person who makes it.
    fn made_by(fields: &mut Obj, actor: &str) -> R<()> {
        match fields.get("Requester") {
            None | Some(Value::Null) => {
                fields.insert("Requester".into(), Value::String(actor.to_owned()));
            }
            Some(r) if !crate::val::py_eq(r, &Value::String(actor.to_owned())) => {
                return Err(CrmError::forbidden("A card of a kind waits on the person who makes it; Requester is you"));
            }
            _ => {}
        }
        Ok(())
    }

    /// WHOSE MOVE IT IS IS NOT A FIELD ANY WRITER SETS (D12): the requester is fixed when the card is
    /// made; the next actor changes by an edit only when the person waiting or the current next actor
    /// hands it on, to someone else.
    fn may_reassign(prior: &Obj, fields: &Obj, actor: &str) -> R<()> {
        let null = Value::Null;
        if fields.contains_key("Requester") && !crate::val::py_eq(&fields["Requester"], prior.get("Requester").unwrap_or(&null)) {
            return Err(CrmError::forbidden("A card's requester does not change; make a new card"));
        }
        if !fields.contains_key("NextActor") || crate::val::py_eq(&fields["NextActor"], prior.get("NextActor").unwrap_or(&null)) {
            return Ok(());
        }
        let or_empty = |v: Option<&Value>| -> String { match v { Some(v) if truthy(v) => pystr(v), _ => String::new() } };
        let allowed: Vec<String> = [or_empty(prior.get("Requester")), or_empty(prior.get("NextActor"))].into_iter().filter(|x| !x.is_empty()).collect();
        if !allowed.iter().any(|a| a == actor) {
            return Err(CrmError::forbidden("Only the person waiting on this card, or its next actor, hands it to someone else"));
        }
        if or_empty(fields.get("NextActor")) == actor {
            return Err(CrmError::forbidden("A card is handed to you by someone else; you do not make yourself its next actor"));
        }
        Ok(())
    }
    /// `store.review` for a card proposal, inside its transaction. The caller is a person.
    pub fn review(&self, c: &mut Tx, org: &str, caller: &Caller, policy: &Policy, proposal: &Obj, accept: bool) -> R<Value> {
        let p = proposal;
        let patch = m(p, "patch");
        let at = g(patch, "created_at");
        if truthy(at) {
            let t = iso_epoch(&pystr(at)).ok_or_else(|| CrmError::internal(format!("ValueError: Invalid isoformat string: '{}'", pystr(at))))?;
            if vexa_native_kit::ids::now() - t >= (self.ttl_days(None) * 86400) as f64 {
                return Err(CrmError::not_found("Proposal expired"));
            }
        }
        let author_kind = match patch.get("author_kind") { Some(v) => v.clone(), None => "person".into() };
        let trail = json!([{"proposal": m(p, "id"), "author": m(p, "author_id"), "author_kind": author_kind}]);
        let pid = m(p, "id").clone();
        if m(p, "record_id").is_null() {
            if !Self::may_review_create(policy, caller, p) {
                return Err(CrmError::forbidden("Review not permitted"));
            }
            if !accept {
                return Ok(json!({"status": "rejected", "proposal_id": pid}));
            }
            let spec = patch.get("create").ok_or_else(|| CrmError::internal("KeyError: 'create'"))?;
            let ws = g(spec, "workspace");
            if truthy(ws) {
                crate::store::check_workspace(&pystr(ws))?;
            }
            let fields = g(spec, "fields").as_object().cloned().unwrap_or_default();
            let author = col(p, "author_id");
            let wsv = if truthy(ws) { Some(pystr(ws)) } else { None };
            let record_id = self.insert(c, org, &author, &pystr(g(spec, "object_type")), &fields, None, &pystr(m(p, "reason")), &trail,
                wsv.as_deref(), &[author.clone(), caller.subject.clone()])?;
            return Ok(json!({"status": "saved", "record_id": record_id, "revision": 1, "proposal_id": pid}));
        }
        let row = self.store.row(c, org, &col(p, "record_id"))?;
        self.store.rights(policy, &row, "write")?;
        if !accept {
            return Ok(json!({"status": "rejected", "proposal_id": pid}));
        }
        let crow = self.card_row(c, org, &col(&row, "id"))?;
        let locked = Self::locked(&self.view(c, org, policy, &crow, false)?);
        if !locked.is_empty() {
            let names: Vec<String> = locked.iter().take(3).map(pystr).collect();
            return Err(CrmError::forbidden(format!("You cannot sign a card with a field hidden from you: {}", names.join(", "))));
        }
        let mut evidence: Vec<Value> = m(p, "evidence").as_array().cloned().unwrap_or_default();
        evidence.extend(trail.as_array().cloned().unwrap_or_default());
        let fields = g(patch, "fields").as_object().cloned().unwrap_or_default();
        let narrative = g(patch, "narrative").as_str().map(str::to_owned);
        let out = self.store.edit(c, org, &caller.subject, policy, &col(p, "record_id"), m(p, "base_revision").as_i64().unwrap_or(0),
            &fields, narrative.as_deref(), &pystr(m(p, "reason")), &Value::Array(evidence))?;
        let mut o = out.as_object().cloned().unwrap_or_default();
        o.insert("proposal_id".into(), pid);
        Ok(Value::Object(o))
    }
    /// Whether this caller may read this card now (the desk's `place` check).
    pub fn readable(&self, c: &mut Tx, org: &str, caller: &Caller, record_id: &str) -> R<bool> {
        let got = (|| -> R<()> {
            let policy = self.store.policy(c, org, caller, true)?;
            let row = self.card_row(c, org, record_id)?;
            self.store.visible(&policy, &row)?;
            Ok(())
        })();
        match got {
            Ok(()) => Ok(true),
            Err(e) if e.isa("NotFound") || e.isa("Forbidden") || e.isa("SharedRefused") => Ok(false),
            Err(e) => Err(e),
        }
    }
    /// The desk's card part: cards I am a member of or placed (minus member cards I took off), cards
    /// I was invited to, and proposals I may answer.
    pub fn desk(&self, org: &str, caller: &Caller, placements: &[Value], layout: &Value) -> R<Obj> {
        let hidden: std::collections::BTreeSet<String> = g(layout, "hidden_cards").as_array().map(|a| a.iter().map(pystr).collect()).unwrap_or_default();
        let placed: Vec<String> = placements.iter().filter(|p| pystr(g(p, "ref")).starts_with("card:") && !g(p, "ref").is_null())
            .map(|p| card_id(&pystr(g(p, "ref")))).collect();
        self.store.connect(|c| {
            let policy = match self.store.policy(c, org, caller, true) {
                Ok(p) => p,
                Err(e) if e.isa("Forbidden") => {
                    return Ok(json!({"cards": [], "card_invites": [], "card_proposals": []}).as_object().cloned().unwrap());
                }
                Err(e) => return Err(e),
            };
            let mut joined: Vec<String> = policy.members.iter().filter(|(k, v)| v.as_str() == "member" && !hidden.contains(&format!("card:{k}"))).map(|(k, _)| k.clone()).collect();
            joined.sort();
            let mut invited: Vec<String> = policy.members.iter().filter(|(_, v)| v.as_str() == "invited").map(|(k, _)| k.clone()).collect();
            invited.sort();
            let mut ids: Vec<String> = Vec::new();
            for id in placed.iter().chain(joined.iter()) {
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
            let mut views = self.views(c, org, &policy, &ids)?;
            let order: Vec<String> = g(g(layout, "order"), "cards").as_array().map(|a| a.iter().map(|r| card_id(&pystr(r))).collect()).unwrap_or_default();
            let mut rank: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for (n, i) in order.iter().enumerate() {
                rank.insert(i.clone(), n);
            }
            let at = |v: &Value| { let a = g(&v["movement"], "at"); if truthy(a) { pystr(a) } else { String::new() } };
            views.sort_by(|a, b| at(b).cmp(&at(a)));
            let n = rank.len();
            views.sort_by_key(|v| *rank.get(&pystr(&v["id"])).unwrap_or(&n));
            let invites = self.views(c, org, &policy, &invited)?;
            let proposals = self.reviewable(c, org, caller, &policy, None)?;
            Ok(json!({"cards": views, "card_invites": invites, "card_proposals": proposals}).as_object().cloned().unwrap())
        })
    }
    /// One card with its activity. Reading never marks it seen (D14, P21): only `seen` does.
    pub fn read(&self, org: &str, caller: &Caller, card: &str) -> R<Value> {
        self.store.connect(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let row = self.card_row(c, org, card)?;
            self.view(c, org, &policy, &row, true)
        })
    }
    pub fn list(&self, org: &str, caller: &Caller, workspace: Option<&str>, about: Option<&str>, state: Option<&str>, mine: bool, limit: i64) -> R<Value> {
        let limit = (if limit == 0 { LIST_MAX } else { limit }).clamp(1, LIST_MAX) as usize;
        self.store.connect(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let members: std::collections::BTreeSet<String> = policy.members.iter().filter(|(_, v)| v.as_str() == "member").map(|(k, _)| k.clone()).collect();
            let mut ws: Option<String> = None;
            let ids: std::collections::BTreeSet<String> = if let Some(w) = workspace.filter(|w| !w.is_empty()) {
                let w = crate::store::check_workspace(w)?;
                let out = if caller.workspaces.contains(&w) || (policy.admin() && !caller.delegated) { self.store.bindings_of(c, org, &w)?.into_iter().collect() } else { Default::default() };
                ws = Some(w);
                out
            } else if mine {
                members
            } else {
                members.into_iter().chain(policy.bound.keys().cloned()).collect()
            };
            let ids: Vec<String> = ids.into_iter().collect();
            let mut views = self.views(c, org, &policy, &ids)?;
            if let Some(a) = about.filter(|a| !a.is_empty()) {
                views.retain(|v| truthy(&v["about"]) && v["about"]["ref"].as_str() == Some(a));
            }
            if let Some(st) = state.filter(|s| !s.is_empty()) {
                views.retain(|v| v["state"].as_str() == Some(st));
            }
            let at = |v: &Value| { let a = g(&v["movement"], "at"); if truthy(a) { pystr(a) } else { String::new() } };
            views.sort_by(|a, b| at(b).cmp(&at(a)));
            let me = if caller.delegated { String::new() } else { caller.subject.clone() };
            let proposals = self.reviewable(c, org, caller, &policy, ws.as_deref())?;
            let counts = self.counts(&views, &me);
            Ok(json!({"cards": views.into_iter().take(limit).collect::<Vec<_>>(), "proposals": proposals, "counts": counts}))
        })
    }

    /// The person's Inbox: open cards waiting on them, soonest check first, with the counts.
    pub fn inbox(&self, org: &str, caller: &Caller) -> R<Value> {
        if caller.delegated || caller.internal || caller.subject.is_empty() {
            return Err(CrmError::refused(members_person_only()));
        }
        self.store.connect(|c| {
            let policy = match self.store.policy(c, org, caller, true) {
                Ok(p) => p,
                Err(e) if e.isa("Forbidden") => return Ok(json!({"items": [], "counts": {"waiting_on_me": 0, "due_soon": 0, "i_wait_on": 0}})),
                Err(e) => return Err(e),
            };
            let ids: Vec<String> = policy.members.iter().filter(|(_, v)| v.as_str() == "member" || v.as_str() == "invited").map(|(k, _)| k.clone()).collect();
            let views = self.views(c, org, &policy, &ids)?;
            let mut items: Vec<Value> = views.iter().filter(|v| Self::waits_on(v, &caller.subject)).cloned().collect();
            let key = |v: &Value| {
                let s = |k: &str| if truthy(g(v, k)) { pystr(g(v, k)) } else { "9999".into() };
                (s("next_check_at"), s("due"), crate::val::casefold(&pystr(&v["title"])))
            };
            items.sort_by_key(key);
            Ok(json!({"items": items.into_iter().take(LIST_MAX as usize).collect::<Vec<_>>(), "counts": self.counts(&views, &caller.subject)}))
        })
    }
    /// D14: the person's terminal rendered this card in view. The ONE writer of `crm_card_seen`.
    pub fn seen(&self, org: &str, caller: &Caller, card: &str) -> R<Value> {
        Self::require_session(caller)?;
        self.store.begin(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let row = self.card_row(c, org, card)?;
            self.store.visible(&policy, &row)?;
            let now = crate::val::now_iso();
            let id = col(&row, "id");
            let had = c.map("SELECT seen_at FROM crm_card_seen WHERE org_id = $1 AND person = $2 AND record_id = $3", &[&org, &caller.subject, &id])?;
            if had.is_none() {
                c.exec("INSERT INTO crm_card_seen (org_id, person, record_id, seen_at) VALUES ($1, $2, $3, $4)", &[&org, &caller.subject, &id, &now])?;
            } else {
                c.exec("UPDATE crm_card_seen SET seen_at = $4 WHERE org_id = $1 AND person = $2 AND record_id = $3", &[&org, &caller.subject, &id, &now])?;
            }
            Ok(json!({"card": id, "seen_at": now}))
        })
    }
    /// A server nonce bound to this person, this card at this revision, and the content hash of the
    /// face they are shown now. Spent by exactly one decision.
    pub fn nonce(&self, org: &str, caller: &Caller, card: &str) -> R<Value> {
        Self::require_session(caller)?;
        self.store.begin(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let row = self.card_row(c, org, card)?;
            let view = self.view(c, org, &policy, &row, false)?;
            let now = vexa_native_kit::ids::now();
            let value = token_urlsafe(24);
            let digest = Self::content_hash(&view);
            let id = col(&row, "id");
            let rev = m(&row, "revision").as_i64().unwrap_or(0);
            let created = vexa_native_kit::ids::utc_isoformat(now);
            let expires = vexa_native_kit::ids::utc_isoformat(now + (NONCE_TTL_MINUTES * 60) as f64);
            c.exec("INSERT INTO crm_card_nonces (org_id, nonce, record_id, person, revision, content_hash, created_at, expires_at, used_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL)",
                &[&org, &value, &id, &caller.subject, &vexa_native_kit::pg::Int(rev), &digest, &created, &expires])?;
            Ok(json!({"card": id, "nonce": value, "content_hash": digest, "revision": m(&row, "revision"),
                "expires_at": expires, "actions": view["viewer"]["actions"]}))
        })
    }
    /// A gate decision (D12) as a decision record (D13): one append-only revision carrying the action,
    /// `credential_class=session`, the nonce and the content hash. The authority is the template, so
    /// field write rights do not apply.
    pub fn decide(&self, org: &str, caller: &Caller, card: &str, action: &str, nonce: &str, content_hash: &str, evidence: Option<&Value>, receipt: Option<&str>, answer: Option<&str>, reason: Option<&str>) -> R<Value> {
        Self::require_session(caller)?;
        let action = action.to_owned();
        self.store.begin(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let row = self.card_row(c, org, card)?;
            let raw: Obj = m(&row, "fields").as_object().cloned().unwrap_or_default();
            let Some(template) = self.template(raw.get("Kind").unwrap_or(&Value::Null)) else {
                return Err(CrmError::crm("This card has no lifecycle template; it moves with update, not decide"));
            };
            let view = self.view(c, org, &policy, &row, false)?;
            if !view["viewer"]["actions"].as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some(action.as_str()))) {
                return Err(CrmError::forbidden("This decision is not yours to make on this card now"));
            }
            let locked = Self::locked(&view);
            if !locked.is_empty() {
                let names: Vec<String> = locked.iter().take(3).map(pystr).collect();
                return Err(CrmError::forbidden(format!("You cannot sign a card with a field hidden from you: {}", names.join(", "))));
            }
            let got = c.map(&format!("SELECT {} FROM crm_card_nonces WHERE org_id = $1 AND nonce = $2 FOR UPDATE", crate::schema::CARD_NONCES), &[&org, &nonce])?;
            let now = vexa_native_kit::ids::now();
            let live = match &got {
                None => false,
                Some(n) => {
                    let exp = pystr(m(n, "expires_at"));
                    let at = iso_epoch(&exp).ok_or_else(|| CrmError::internal(format!("ValueError: Invalid isoformat string: '{exp}'")))?;
                    m(n, "person").as_str() == Some(caller.subject.as_str()) && col(n, "record_id") == col(&row, "id")
                        && m(n, "used_at").is_null() && at > now
                }
            };
            if !live {
                return Err(CrmError::conflict("This decision is not bound to a live pending item; read the card again"));
            }
            let got = got.unwrap();
            if !crate::val::py_eq(m(&got, "revision"), m(&row, "revision")) {
                return Err(CrmError::conflict("The card changed since you read it; read it again"));
            }
            let digest = Self::content_hash(&view);
            if !(content_hash == digest && m(&got, "content_hash").as_str() == Some(digest.as_str())) {
                return Err(CrmError::conflict("The card you saw is not the card now; read it again"));
            }
            let stamp = vexa_native_kit::ids::utc_isoformat(now);
            let spent = c.exec("UPDATE crm_card_nonces SET used_at = $3 WHERE org_id = $1 AND nonce = $2 AND used_at IS NULL", &[&org, &col(&got, "nonce"), &stamp])?;
            if spent != 1 {
                return Err(CrmError::conflict("This decision was already made"));
            }
            let gate = template.gate(&action).cloned().ok_or_else(|| CrmError::internal(format!("KeyError: '{action}'")))?;
            let mut patch = Map::new();
            if gate.needs == Some("evidence") {
                let items: Vec<Value> = match evidence { Some(Value::Array(a)) => a.clone(), Some(v) => vec![v.clone()], None => vec![Value::Null] };
                let refs: Vec<String> = items.iter().filter(|e| !crate::val::strip(&crate::val::or_str(e)).is_empty())
                    .map(|e| crate::val::strip(&pystr(e)).to_owned()).collect();
                if refs.is_empty() || !refs.iter().all(|r| ref_re().is_match(r)) {
                    return Err(CrmError::crm("Delivering cites evidence: one or more references (page:…, meeting:…, crm:…)"));
                }
                patch.insert("Evidence".into(), json!(refs.into_iter().take(10).collect::<Vec<_>>()));
            }
            if gate.needs == Some("receipt") {
                match receipt.filter(|r| !r.is_empty() && ref_re().is_match(r)) {
                    Some(r) => { patch.insert("Receipt".into(), r.into()); }
                    None => return Err(CrmError::crm("Executed needs the effect receipt reference")),
                }
            }
            if gate.needs == Some("answer") {
                let text = clip(&answer.map(Value::from).unwrap_or(Value::Null), 500);
                if text.is_empty() {
                    return Err(CrmError::crm("An answer is needed"));
                }
                patch.insert("Answer".into(), text.into());
            }
            if let Some(to) = gate.to.as_ref().filter(|t| !t.is_empty()) {
                patch.insert("State".into(), to.clone().into());
            }
            let then = gate.then;
            if then == tpl::REQUESTER {
                patch.insert("NextActor".into(), view["requester"].clone());
                patch.insert("Handoff".into(), "offered".into());
                patch.insert("HandoffSince".into(), stamp.clone().into());
            } else if then == tpl::NOBODY {
                patch.insert("NextActor".into(), Value::Null);
                patch.insert("Handoff".into(), Value::Null);
                patch.insert("HandoffSince".into(), stamp.clone().into());
                patch.insert("NextCheckAt".into(), Value::Null);
            } else {
                patch.insert("Handoff".into(), "acknowledged".into());
                patch.insert("HandoffSince".into(), stamp.clone().into());
            }
            if then != tpl::NOBODY {
                let at = self.next_check(raw.get("Due").unwrap_or(&Value::Null), Some(now));
                patch.insert("NextCheckAt".into(), at.into());
            }
            let words = tpl::done_word(&action).ok_or_else(|| CrmError::internal(format!("KeyError: '{action}'")))?;
            let record = json!({"decision": action, "credential_class": "session", "nonce": m(&got, "nonce"), "content_hash": digest});
            let trail = match reason.filter(|r| !r.is_empty()) {
                Some(r) => json!([{"decision": action, "reason": clip(&Value::from(r), REASON_MAX)}]),
                None => json!([]),
            };
            as_gate(|| self.apply(c, org, &caller.subject, &row, &patch, words, &trail, &record))?;
            if truthy(patch.get("NextActor").unwrap_or(&Value::Null)) {
                let na = pystr(&patch["NextActor"]);
                self.ensure_member(c, org, &col(&row, "id"), &na, &caller.subject)?;
            }
            let policy = self.store.policy(c, org, caller, true)?;
            let frow = self.card_row(c, org, &col(&row, "id"))?;
            let fresh = self.view(c, org, &policy, &frow, true)?;
            let rev = fresh["revision"].clone();
            Ok(json!({"status": "saved", "card": fresh,
                "decision": {"action": action, "by": caller.subject, "at": stamp, "revision": rev,
                    "credential_class": "session", "content_hash": digest}}))
        })
    }
    pub fn create(&self, org: &str, caller: &Caller, title: &str, workspace: Option<&str>, about: Option<&str>, type_: &str, parent: Option<&str>, fields: &Obj, face: Option<&Value>, narrative: Option<&str>) -> R<Value> {
        if caller.delegated || caller.internal || caller.subject.is_empty() {
            return Err(CrmError::refused(propose_card()));
        }
        self.store.begin(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let mut ws = workspace.filter(|w| !w.is_empty()).map(str::to_owned);
            if let Some(w) = &ws {
                let w = crate::store::check_workspace(w)?;
                if !writable(caller).contains(&w) && !policy.admin() {
                    return Err(CrmError::forbidden("A card goes on the board of a workspace you can write"));
                }
                ws = Some(w);
            }
            let pv = parent.map(Value::from).unwrap_or(Value::Null);
            self.check_parent(c, org, &policy, &pv)?;
            let mut data = self.new_fields(&Value::from(title), about, parent, fields, face)?;
            if truthy(data.get("Kind").unwrap_or(&Value::Null)) {
                data.entry("Requester").or_insert_with(|| Value::String(caller.subject.clone()));
            }
            let kind = if type_.is_empty() { DEFAULT_TYPE } else { type_ };
            let record_id = self.insert(c, org, &caller.subject, kind, &data, narrative, "Made the card", &json!([]), ws.as_deref(), &[caller.subject.clone()])?;
            let policy = self.store.policy(c, org, caller, true)?;
            let row = self.card_row(c, org, &record_id)?;
            Ok(json!({"status": "saved", "card": self.view(c, org, &policy, &row, false)?}))
        })
    }
    pub fn update(&self, org: &str, caller: &Caller, card: &str, expected_revision: i64, fields: &Obj, face: Option<&Value>, transition: Option<&str>) -> R<Value> {
        if caller.delegated || caller.internal || caller.subject.is_empty() {
            return Err(CrmError::refused(propose_card()));
        }
        let patch = Self::patch(fields, face, transition)?;
        self.store.begin(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let row = self.card_row(c, org, card)?;
            if let Some(p) = patch.get("Parent") {
                self.check_parent(c, org, &policy, p)?;
            }
            let reason = match transition.filter(|t| !t.is_empty()) { Some(t) => format!("Moved to {t}"), None => "Updated the card".into() };
            let id = col(&row, "id");
            self.store.edit(c, org, &caller.subject, &policy, &id, expected_revision, &patch, None, &reason, &json!([]))?;
            let row = self.card_row(c, org, &id)?;
            Ok(json!({"status": "saved", "card": self.view(c, org, &policy, &row, false)?}))
        })
    }
    /// Add or remove a card's member (a person: every account linked to them); leaving is one
    /// account's own.
    pub fn members(&self, org: &str, caller: &Caller, card: &str, subject: &str, add: bool) -> R<Value> {
        if caller.delegated || caller.internal || caller.subject.is_empty() {
            return Err(CrmError::refused(members_person_only()));
        }
        let subject = crate::val::strip(subject).to_owned();
        if subject.is_empty() || subject.chars().count() > 128 || control_re().is_match(&subject) {
            return Err(CrmError::crm("A member is a person id"));
        }
        self.store.begin(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let row = self.card_row(c, org, card)?;
            self.store.visible(&policy, &row)?;
            let leaving = !add && subject == caller.subject;
            if !leaving {
                self.store.rights(&policy, &row, "write")?;
            }
            let who = if leaving { vec![subject.clone()] } else { crate::persons::Persons::new(&self.store).linked_accounts(c, org, &subject)? };
            let id = col(&row, "id");
            for one in who {
                let have = c.map("SELECT status FROM crm_card_members WHERE org_id = $1 AND record_id = $2 AND subject = $3", &[&org, &id, &one])?;
                if add && have.is_none() && (one == subject || one != caller.subject) {
                    c.exec("INSERT INTO crm_card_members (org_id, record_id, subject, status, added_by, added_at) VALUES ($1, $2, $3, 'invited', $4, $5)",
                        &[&org, &id, &one, &caller.subject, &crate::val::now_iso()])?;
                } else if !add && have.is_some() {
                    c.exec("DELETE FROM crm_card_members WHERE org_id = $1 AND record_id = $2 AND subject = $3", &[&org, &id, &one])?;
                }
            }
            Ok(json!({"members": self.members_of(c, org, &id)?}))
        })
    }

    /// Accept or decline being on a card.
    pub fn membership(&self, org: &str, caller: &Caller, card: &str, accept: bool) -> R<Value> {
        if caller.delegated || caller.internal || caller.subject.is_empty() {
            return Err(CrmError::refused(members_person_only()));
        }
        self.store.begin(|c| {
            let have = c.map("SELECT status FROM crm_card_members WHERE org_id = $1 AND record_id = $2 AND subject = $3", &[&org, &card, &caller.subject])?;
            let Some(have) = have else { return Err(CrmError::not_found("You are not on this card")) };
            if accept {
                c.exec("UPDATE crm_card_members SET status = 'member' WHERE org_id = $1 AND record_id = $2 AND subject = $3", &[&org, &card, &caller.subject])?;
                return Ok(json!({"status": "member"}));
            }
            c.exec("DELETE FROM crm_card_members WHERE org_id = $1 AND record_id = $2 AND subject = $3", &[&org, &card, &caller.subject])?;
            Ok(json!({"status": if m(&have, "status").as_str() == Some("invited") { "declined" } else { "left" }}))
        })
    }
    pub fn propose(&self, org: &str, caller: &Caller, title: &str, workspace: Option<&str>, about: Option<&str>, type_: &str, parent: Option<&str>, fields: &Obj, face: Option<&Value>, reason: &str) -> R<Value> {
        if caller.internal || caller.subject.is_empty() {
            return Err(CrmError::refused(propose_card()));
        }
        let reason = Self::reason(&Value::from(reason))?;
        if truthy(fields.get("Kind").unwrap_or(&Value::Null)) {
            return self.offer(org, caller, &Value::from(title), workspace, about, type_, parent, fields, face, &reason);
        }
        self.store.begin(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let mut ws = workspace.filter(|w| !w.is_empty()).map(str::to_owned);
            if let Some(w) = &ws {
                let w = crate::store::check_workspace(w)?;
                if !caller.workspaces.contains(&w) {
                    return Err(CrmError::forbidden("Propose a card only into a workspace you work in"));
                }
                ws = Some(w);
            }
            self.check_parent(c, org, &policy, &parent.map(Value::from).unwrap_or(Value::Null))?;
            let object_type = if type_.is_empty() { DEFAULT_TYPE } else { type_ };
            let definition = self.definition_of(c, org, object_type)?;
            let nf = self.new_fields(&Value::from(title), about, parent, fields, face)?;
            let data = Value::Object(self.normalise_fields(object_type, &nf, None, None)?);
            self.store.validate(&definition, &data)?;
            self.caps(c, org, caller)?;
            let pid = crate::val::uuid4();
            let patch = json!({"create": {"object_type": object_type, "fields": data, "workspace": ws,
                    "parent": parent.filter(|p| !p.is_empty())},
                "fields": data, "narrative": null, "author_kind": caller.kind(), "session": caller.session,
                "created_at": crate::val::now_iso()});
            c.exec("INSERT INTO crm_change_proposals (org_id, id, record_id, base_revision, author_id, patch, evidence, reason, status) VALUES ($1, $2, NULL, 0, $3, $4, $5, $6, 'pending')",
                &[&org, &pid, &caller.subject, &patch, &json!([]), &reason])?;
            Ok(json!({"status": "proposed", "proposal_id": pid}))
        })
    }
    pub fn update_propose(&self, org: &str, caller: &Caller, card: &str, expected_revision: i64, fields: &Obj, face: Option<&Value>, transition: Option<&str>, reason: &str) -> R<Value> {
        if caller.internal || caller.subject.is_empty() {
            return Err(CrmError::refused(propose_card()));
        }
        let reason = Self::reason(&Value::from(reason))?;
        let patch = Self::patch(fields, face, transition)?;
        self.store.begin(|c| {
            let policy = self.store.policy(c, org, caller, true)?;
            let row = self.card_row(c, org, card)?;
            self.store.visible(&policy, &row)?;
            if m(&row, "revision").as_i64() != Some(expected_revision) {
                return Err(CrmError::conflict("Card changed; read it again"));
            }
            let allowed = self.store.rights(&policy, &row, "read")?;
            if !allowed.iter().any(|a| a == "*") && patch.keys().any(|k| !allowed.contains(k)) {
                return Err(CrmError::forbidden("Cannot propose changes to fields you cannot read"));
            }
            let object_type = col(&row, "object_type");
            let patch = self.normalise_fields(&object_type, &patch, Some(m(&row, "fields")), None)?;
            let mut merged = m(&row, "fields").as_object().cloned().unwrap_or_default();
            for (k, v) in &patch {
                merged.insert(k.clone(), v.clone());
            }
            let def = self.definition_of(c, org, &object_type)?;
            self.store.validate(&def, &Value::Object(merged))?;
            self.caps(c, org, caller)?;
            let pid = crate::val::uuid4();
            let body = json!({"fields": patch, "narrative": null, "author_kind": caller.kind(), "session": caller.session,
                "created_at": crate::val::now_iso()});
            c.exec("INSERT INTO crm_change_proposals (org_id, id, record_id, base_revision, author_id, patch, evidence, reason, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')",
                &[&org, &pid, &col(&row, "id"), &vexa_native_kit::pg::Int(expected_revision), &caller.subject, &body, &json!([]), &reason])?;
            Ok(json!({"status": "proposed", "proposal_id": pid}))
        })
    }
    /// Offer several cards of a kind from one origin, idempotently: a card with the same origin,
    /// title and next actor already offered by this caller is returned, not made again.
    pub fn offer_many(&self, org: &str, caller: &Caller, workspace: Option<&str>, origin: &str, specs: &[Value], reason: &str) -> R<Value> {
        let mut have: Vec<(Value, Value, Value)> = Vec::new();
        self.store.connect(|c| {
            for r in c.maps("SELECT id, fields FROM crm_records WHERE org_id = $1 AND owner_id = $2 AND deleted = false", &[&org, &caller.subject])? {
                let f = m(&r, "fields");
                if g(f, "Origin").as_str() == Some(origin) && truthy(g(f, "Kind")) {
                    have.push((g(f, "Title").clone(), g(f, "NextActor").clone(), m(&r, "id").clone()));
                }
            }
            Ok(())
        })?;
        let mut out = Vec::new();
        for spec in specs {
            let mut fields: Obj = g(spec, "fields").as_object().cloned().unwrap_or_default();
            fields.insert("Origin".into(), origin.into());
            let title = Value::String(clip(g(spec, "title"), TITLE_MAX));
            let na = fields.get("NextActor").cloned().unwrap_or(Value::Null);
            let found = have.iter().rev().find(|(t, n, _)| crate::val::py_eq(t, &title) && crate::val::py_eq(n, &na)).map(|x| x.2.clone());
            let kind = fields.get("Kind").cloned().unwrap_or(Value::Null);
            if let Some(rid) = found {
                out.push(json!({"id": rid, "title": title, "kind": kind, "existing": true}));
                continue;
            }
            let why = if truthy(g(spec, "reason")) { g(spec, "reason").clone() } else { Value::from(reason) };
            let why = Self::reason(&why)?;
            let about = g(spec, "about").as_str().filter(|a| !a.is_empty());
            let res = self.offer(org, caller, &title, workspace, about, DEFAULT_TYPE, None, &fields, None, &why)?;
            let rid = match g(&res, "card") { v if truthy(v) && truthy(g(v, "id")) => g(v, "id").clone(), _ => g(&res, "record_id").clone() };
            have.push((title.clone(), na, rid.clone()));
            out.push(json!({"id": rid, "title": title, "kind": kind, "existing": false}));
        }
        Ok(json!({"cards": out}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_ops_helpers() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(token_urlsafe(24).len(), 32);
        assert_eq!(parse_lifecycle(Some("A > B | X")), Lifecycle { stages: vec!["A".into(), "B".into()], side: vec!["X".into()] });
        assert_eq!(parse_lifecycle(Some("A > a")), Lifecycle::default_lifecycle());
        assert_eq!(parse_lifecycle(None), Lifecycle::default_lifecycle());
        assert!(check_about(&json!("page:ws/a/b")).is_ok());
        assert!(check_about(&json!("page:ws/a/../b")).is_err());
        assert!(check_about(&json!("crm:abc")).is_ok());
        assert!(check_about(&json!(5)).is_err());
        assert_eq!(iso_epoch("1970-01-02T00:00:00+00:00"), Some(86400.0));
        assert_eq!(iso_epoch("1970-01-01T01:00:00+01:00"), Some(0.0));
    }
}
