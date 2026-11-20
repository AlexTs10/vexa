//! subject-ticket.v1, the door's side: read a ticket a producer signed, and mint the gateway's own.
//!
//!     token = "st1." + b64u(claims) + "." + b64u(Ed25519_sign(key, "st1." + b64u(claims)))

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use vexa_native_kit::b64;
use vexa_native_kit::pyjson::{py_str, Dumps};

pub const VERSION: &str = "st1";
pub const TYPE: &str = "subject-ticket.v1";
pub const HEADER: &str = "x-vexa-subject-ticket";
const MAX_SKEW_SEC: i64 = 60;
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_TICKETS_PER_CALL: usize = 16;

pub const TRANSCRIPT_READ: &str = "transcript.read";
pub const BOT_DISPATCH: &str = "bot.dispatch";
pub const CHAT_AUTONOMOUS: &str = "chat.autonomous";
pub const DESK_WRITE: &str = "desk.write";
pub const ROOM_BILLS_TO: &str = "room.bills_to";
pub const ROUTINE_TURN: &str = "routine.turn";
pub const PEER_CLASSES: [&str; 1] = [DESK_WRITE];

pub const MEETINGS: &str = "meetings";
pub const AGENT: &str = "agent";
pub const MAIL: &str = "mail";
pub const GATEWAY: &str = "gateway";
pub const EVENT: &str = "event";
pub const GRANT: &str = "grant";
const DAY: i64 = 86400;

pub fn issuer_classes(iss: &str) -> &'static [&'static str] {
    match iss {
        MEETINGS => &[TRANSCRIPT_READ, CHAT_AUTONOMOUS, DESK_WRITE, ROOM_BILLS_TO],
        AGENT => &[ROUTINE_TURN, BOT_DISPATCH],
        MAIL => &[BOT_DISPATCH, TRANSCRIPT_READ, CHAT_AUTONOMOUS, DESK_WRITE],
        GATEWAY => &[DESK_WRITE, ROUTINE_TURN, BOT_DISPATCH],
        _ => &[],
    }
}

pub fn max_lifetime(iss: &str, kind: &str) -> Option<i64> {
    Some(match (iss, kind) {
        (MEETINGS, EVENT) => 3 * DAY,
        (AGENT, EVENT) => DAY,
        (AGENT, GRANT) => 400 * DAY,
        (MAIL, EVENT) => 60 * DAY,
        (GATEWAY, EVENT) => 600,
        (GATEWAY, GRANT) => 400 * DAY,
        _ => return None,
    })
}

pub type Checks = HashMap<String, VerifyingKey>;

pub fn native_of(platform: &Value, native: &Value) -> String {
    let s = |v: &Value| if vexa_native_kit::pyjson::truthy(Some(v)) { py_str(v).trim().to_owned() } else { String::new() };
    let (p, n) = (s(platform), s(native));
    if p.is_empty() || n.is_empty() { String::new() } else { format!("{p}/{n}") }
}

/// The tickets in one header value, at most 16.
pub fn split(value: Option<&str>) -> Vec<String> {
    value.unwrap_or("").split(',').map(str::trim).filter(|t| !t.is_empty()).take(MAX_TICKETS_PER_CALL).map(str::to_owned).collect()
}

fn issuer_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

fn int(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// The claims of a ticket one of `checks` verifies, or the one-word reason it does not hold.
pub fn read(token: &str, checks: &Checks, now: i64) -> Result<Map<String, Value>, &'static str> {
    let token = token.trim();
    if token.is_empty() || token.chars().count() > MAX_TOKEN_BYTES {
        return Err("malformed");
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != VERSION {
        return Err("malformed");
    }
    let payload = b64::url_decode_canonical(parts[1]).ok_or("malformed")?;
    let sig = b64::url_decode_canonical(parts[2]).ok_or("malformed")?;
    let claims = match serde_json::from_slice::<Value>(&payload) {
        Ok(Value::Object(m)) => m,
        Ok(_) => return Err("malformed"),
        Err(_) => return Err("malformed"),
    };
    if claims.get("v").and_then(Value::as_str) != Some(TYPE) {
        return Err("malformed");
    }
    let iss = match claims.get("iss") {
        Some(Value::String(s)) if issuer_name(s) && checks.contains_key(s) => s.clone(),
        _ => return Err("unknown_issuer"),
    };
    let signed = format!("{}.{}", parts[0], parts[1]);
    let ok = <[u8; 64]>::try_from(sig.as_slice())
        .map(|s| checks[&iss].verify(signed.as_bytes(), &Signature::from_bytes(&s)).is_ok())
        .unwrap_or(false);
    if !ok {
        return Err("bad_signature");
    }
    let (iat, exp) = match (int(claims.get("iat")), int(claims.get("exp"))) {
        (Some(i), Some(e)) if e > i => (i, e),
        _ => return Err("malformed"),
    };
    let kind = claims.get("kind").and_then(Value::as_str).unwrap_or("\u{0}");
    let Some(cap) = max_lifetime(&iss, kind) else { return Err("issuer_not_allowed") };
    if exp - iat > cap {
        return Err("lifetime_too_long");
    }
    match claims.get("cls") {
        Some(Value::Array(a)) if !a.is_empty() && a.iter().all(|c| c.as_str().is_some_and(|c| issuer_classes(&iss).contains(&c))) => {}
        _ => return Err("issuer_not_allowed"),
    }
    let (Some(Value::String(sub)), Some(Value::String(_))) = (claims.get("sub"), claims.get("jti")) else { return Err("malformed") };
    let addr = claims.get("addr").filter(|v| vexa_native_kit::pyjson::truthy(Some(v))).map(py_str).unwrap_or_default();
    if sub.trim().is_empty() && addr.trim().is_empty() {
        return Err("malformed");
    }
    if iat > now + MAX_SKEW_SEC {
        return Err("not_yet_valid");
    }
    if now >= exp {
        return Err("expired");
    }
    Ok(claims)
}

/// A gateway ticket for `sub`: `classes` sorted, alive `ttl` seconds.
pub fn mint(key: &SigningKey, kind: &str, sub: &str, classes: &[&str], evt: &str, ttl: i64, now: i64) -> String {
    let mut cls: Vec<&str> = classes.to_vec();
    cls.sort_unstable();
    cls.dedup();
    let jti = vexa_native_kit::sha256::hex(&vexa_native_kit::ids::random_bytes(12));
    let claims = json!({"v": TYPE, "iss": GATEWAY, "kind": kind, "sub": sub, "cls": cls, "evt": evt,
        "iat": now, "exp": now + ttl, "jti": jti});
    let body = format!("{VERSION}.{}", b64::url_nopad(Dumps::COMPACT.sorted().text(&claims).as_bytes()));
    let sig = key.sign(body.as_bytes());
    format!("{body}.{}", b64::url_nopad(&sig.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mints_reads_and_refuses() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut checks = Checks::new();
        checks.insert(GATEWAY.into(), key.verifying_key());
        let t = mint(&key, EVENT, "42", &[ROUTINE_TURN, DESK_WRITE, BOT_DISPATCH], "validate", 600, 1000);
        let c = read(&t, &checks, 1001).unwrap();
        assert_eq!(c["cls"], json!(["bot.dispatch", "desk.write", "routine.turn"]));
        assert_eq!(c["exp"], json!(1600));
        assert_eq!(read(&t, &checks, 1600), Err("expired"));
        assert_eq!(read(&t, &Checks::new(), 1001), Err("unknown_issuer"));
        let mut bad = t.clone();
        bad.pop();
        assert!(read(&bad, &checks, 1001).is_err());
        assert_eq!(split(Some(" a, ,b ")), vec!["a", "b"]);
        assert_eq!(native_of(&json!("zoom"), &json!(123)), "zoom/123");
    }
}
