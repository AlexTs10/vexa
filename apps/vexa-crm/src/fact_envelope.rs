//! event.v2 — the SEALED FACT ENVELOPE: who a fact reaches, computed by its producer.
//!
//! A fact posted to flows carries `refs` (references, never bodies). The producer computes the
//! audience (the next actor, the card's members, the workspace principal) and seals it; flows admits
//! a person's flow by subject ∪ audience. The envelope has enumerated keys only — a content field is
//! refused, so a fat fact cannot be sealed:
//!
//! - `v` 2 · `producer` · `object` · `owner` · `visibility` ("members" | "workspace" | "owner")
//! - `audience`: up to 200 short strings (person ids, `ws:<slug>` for a workspace principal)
//! - `lifecycle` (cards only, optional): kind, state, next_actor, next_check_at, handoff
//! - `exp`: unix seconds, set by `seal` to now + `SEAL_TTL_S`
//! - `sig`: hex Ed25519 signature (128 hex digits) over
//!   `canonical({"envelope": <envelope without sig>, "fact": <fact>})`
//!
//! The seal covers the whole fact (`event_type`, `source_event_id`, every `refs` key), so a sealed
//! audience cannot be lifted onto another event, record or subject. This module never touches key
//! material: `seal` takes the producer's signer (`fact_keys`).

use serde_json::{Map, Value};
use vexa_native_kit::pyjson::Dumps;

use crate::fact_keys::Signer;

pub const VERSION: i64 = 2;
/// The signature scheme every seal uses.
pub const ALG: &str = "ed25519";
/// How long a seal is good for. A producer seals at delivery, so this covers transit, not a queue.
pub const SEAL_TTL_S: i64 = 300;
/// The clock difference between a producer and flows that verification tolerates on `exp`.
pub const CLOCK_SKEW_S: i64 = 60;
pub const VISIBILITIES: [&str; 3] = ["members", "workspace", "owner"];
/// The only card fields a fact may carry.
pub const LIFECYCLE_KEYS: [&str; 5] = ["kind", "state", "next_actor", "next_check_at", "handoff"];
/// The only keys an envelope may have.
pub const ENVELOPE_KEYS: [&str; 9] = ["v", "producer", "object", "owner", "visibility", "audience", "lifecycle", "exp", "sig"];
pub const REQUIRED_KEYS: [&str; 6] = ["v", "producer", "object", "owner", "visibility", "audience"];
/// The keys of the fact a seal is bound to.
pub const FACT_KEYS: [&str; 3] = ["event_type", "source_event_id", "refs"];
pub const MAX_AUDIENCE: usize = 200;
pub const MAX_STR: usize = 200;
/// The prefix of a workspace principal in `audience`. It never matches a person.
pub const WORKSPACE_PREFIX: &str = "ws:";

/// Why a seal failed: a ValueError (a producer bug, named) or another exception (TypeError,
/// AttributeError) the Python module lets through.
#[derive(Debug, Clone, PartialEq)]
pub enum SealError {
    Value(String),
    Other(String),
}

/// The fact a seal is bound to: the event's type, its producer-side id and its refs as posted.
pub fn fact(event_type: &Value, source_event_id: &Value, refs: &Value) -> Value {
    let mut f = Map::new();
    f.insert("event_type".into(), event_type.clone());
    f.insert("source_event_id".into(), source_event_id.clone());
    f.insert("refs".into(), refs.clone());
    Value::Object(f)
}

/// The bytes a seal covers: sorted keys, compact separators, UTF-8.
pub fn canonical(env: &Value) -> Vec<u8> {
    Dumps::COMPACT.ascii(false).sorted().text(env).into_bytes()
}

/// What the producer signs: the envelope without its seal, bound to the fact it rides on.
pub fn message(body: &Value, the_fact: &Value) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("envelope".into(), body.clone());
    m.insert("fact".into(), the_fact.clone());
    canonical(&Value::Object(m))
}

fn short(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        let n = s.chars().count();
        0 < n && n <= MAX_STR
    })
}

fn keys_within(o: &Map<String, Value>, allowed: &[&str]) -> bool {
    o.keys().all(|k| allowed.contains(&k.as_str()))
}

/// Shape only — the seal and the expiry are checked separately. Err: the TypeError Python raises
/// for an unhashable `visibility`.
fn well_formed(env: &Value) -> Result<bool, SealError> {
    let Some(o) = env.as_object() else { return Ok(false) };
    if !REQUIRED_KEYS.iter().all(|k| o.contains_key(*k)) || !keys_within(o, &ENVELOPE_KEYS) {
        return Ok(false);
    }
    let v = &o["v"];
    if v.is_boolean() || !crate::val::py_eq(v, &Value::from(VERSION)) {
        return Ok(false);
    }
    if !(short(&o["producer"]) && short(&o["object"]) && short(&o["owner"])) {
        return Ok(false);
    }
    match &o["visibility"] {
        Value::Array(_) | Value::Object(_) => return Err(SealError::Other("TypeError: unhashable type".into())),
        Value::String(s) if VISIBILITIES.contains(&s.as_str()) => {}
        _ => return Ok(false),
    }
    let Some(audience) = o["audience"].as_array() else { return Ok(false) };
    if audience.len() > MAX_AUDIENCE || !audience.iter().all(short) {
        return Ok(false);
    }
    if let Some(life) = o.get("lifecycle") {
        let Some(life) = life.as_object() else { return Ok(false) };
        if !keys_within(life, &LIFECYCLE_KEYS) || !life.values().all(short) {
            return Ok(false);
        }
    }
    if let Some(exp) = o.get("exp") {
        if !(exp.is_i64() || exp.is_u64()) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn well_formed_fact(f: &Value) -> bool {
    let Some(o) = f.as_object() else { return false };
    o.len() == FACT_KEYS.len() && FACT_KEYS.iter().all(|k| o.contains_key(*k))
        && short(&o["event_type"]) && short(&o["source_event_id"]) && o["refs"].is_object()
}

/// The envelope without its seal, with null lifecycle values dropped: absent and null are one
/// answer, and a seal must not depend on which was sent.
fn body(env: &Value) -> Result<Map<String, Value>, SealError> {
    let Some(o) = env.as_object() else {
        return Err(SealError::Other("AttributeError: the envelope has no items".into()));
    };
    let mut body: Map<String, Value> = o.iter().filter(|(k, _)| *k != "sig").map(|(k, v)| (k.clone(), v.clone())).collect();
    if let Some(Value::Object(life)) = body.get("lifecycle") {
        let kept: Map<String, Value> = life.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect();
        body.insert("lifecycle".into(), Value::Object(kept));
    }
    Ok(body)
}

/// int(time.time() if now is None else now).
fn now_s(now: Option<f64>) -> i64 {
    let t = now.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0));
    t.trunc() as i64
}

/// The envelope with `exp` (now + `SEAL_TTL_S`) and `sig` added: `sign` is the producer's own
/// signer applied to `message(envelope, the_fact)`. Err(Value) on an envelope that would not verify
/// (wrong version, an extra key, an unenumerated lifecycle field, an over-long audience, an `exp` of
/// its own), on a malformed fact, or with no signer — a producer bug fails at the producer, loudly.
pub fn seal(env: &Value, sign: Option<&Signer>, the_fact: &Value, now: Option<f64>) -> Result<Value, SealError> {
    let Some(sign) = sign else {
        return Err(SealError::Value("fact envelope: no seal key (the producer has no signer)".into()));
    };
    if !well_formed_fact(the_fact) {
        return Err(SealError::Value("fact envelope: the fact must be event_type, source_event_id and refs".into()));
    }
    if env.as_object().is_some_and(|o| o.contains_key("exp")) {
        return Err(SealError::Value("fact envelope: `exp` is set by the seal, never by the producer".into()));
    }
    let mut b = body(env)?;
    b.insert("exp".into(), Value::from(now_s(now) + SEAL_TTL_S));
    let b = Value::Object(b);
    if !well_formed(&b)? {
        return Err(SealError::Value("fact envelope: not an event.v2 envelope (enumerated keys and short strings only)".into()));
    }
    let sig = sign.sign(&message(&b, the_fact));
    let hex: String = sig.iter().map(|x| format!("{x:02x}")).collect();
    let Value::Object(mut out) = b else { unreachable!("the body is an object") };
    out.insert("sig".into(), Value::String(hex));
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `crm.fact_envelope.seal` in Python over this key, envelope, fact and time (now=1700000000.9).
    const VECTOR: &str = r##"{"pem": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n-----END PRIVATE KEY-----\n", "env": {"v": 2, "producer": "crm", "object": "card", "owner": "42", "visibility": "members", "audience": ["42", "ws:\u00e9-team", "7"], "lifecycle": {"kind": "ask", "state": "Open", "next_actor": "7", "next_check_at": null, "handoff": "offered"}, "sig": "zz"}, "refs": {"uid": "42", "record_id": "r-1", "revision": 3, "org": "one", "score": 1.5, "note": "\u65e5\u2028x\"q\\\u0001\ud83d\ude00"}, "sealed": {"v": 2, "producer": "crm", "object": "card", "owner": "42", "visibility": "members", "audience": ["42", "ws:\u00e9-team", "7"], "lifecycle": {"kind": "ask", "state": "Open", "next_actor": "7", "handoff": "offered"}, "exp": 1700000300, "sig": "372fbb25e2169b6eb365a303337fd36287aaf6ba1f8a95e09eed000567b7e6e50fb36cd7c97a86b09fe26f1188e49d6873826c6b2127a909f9a1a2354a3bfa0d"}, "message": "{\"envelope\":{\"audience\":[\"42\",\"ws:\u00e9-team\",\"7\"],\"exp\":1700000300,\"lifecycle\":{\"handoff\":\"offered\",\"kind\":\"ask\",\"next_actor\":\"7\",\"state\":\"Open\"},\"object\":\"card\",\"owner\":\"42\",\"producer\":\"crm\",\"v\":2,\"visibility\":\"members\"},\"fact\":{\"event_type\":\"crm.record.changed\",\"refs\":{\"note\":\"\u65e5\u2028x\\\"q\\\\\\u0001\ud83d\ude00\",\"org\":\"one\",\"record_id\":\"r-1\",\"revision\":3,\"score\":1.5,\"uid\":\"42\"},\"source_event_id\":\"ev-1\"}}"}"##;

    fn signer(pem: &str) -> Signer {
        crate::fact_keys::load_signer(pem.as_bytes()).unwrap()
    }

    #[test]
    fn seal_equals_python_vector() {
        let v: Value = serde_json::from_str(VECTOR).unwrap();
        let s = signer(v["pem"].as_str().unwrap());
        let f = fact(&json!("crm.record.changed"), &json!("ev-1"), &v["refs"]);
        let sealed = seal(&v["env"], Some(&s), &f, Some(1700000000.9)).unwrap();
        // the posted envelope: same keys, same order, same values
        assert_eq!(Dumps::DEFAULT.text(&sealed), Dumps::DEFAULT.text(&v["sealed"]));
        let mut body = sealed.as_object().unwrap().clone();
        body.remove("sig");
        assert_eq!(message(&Value::Object(body), &f), v["message"].as_str().unwrap().as_bytes());
    }

    #[test]
    fn refusals_name_the_producer_bug() {
        let v: Value = serde_json::from_str(VECTOR).unwrap();
        let s = signer(v["pem"].as_str().unwrap());
        let f = fact(&json!("e"), &json!("id"), &json!({}));
        let env = json!({"v": 2, "producer": "crm", "object": "card", "owner": "1", "visibility": "owner", "audience": []});
        let value = |m: &str| Err(SealError::Value(m.into()));
        assert_eq!(seal(&env, None, &f, None), value("fact envelope: no seal key (the producer has no signer)"));
        assert_eq!(seal(&env, Some(&s), &json!({"event_type": "e"}), None), value("fact envelope: the fact must be event_type, source_event_id and refs"));
        let mut with_exp = env.clone();
        with_exp["exp"] = json!(1);
        assert_eq!(seal(&with_exp, Some(&s), &f, None), value("fact envelope: `exp` is set by the seal, never by the producer"));
        let bad = "fact envelope: not an event.v2 envelope (enumerated keys and short strings only)";
        for (k, val) in [("v", json!(3)), ("v", json!(true)), ("title", json!("x")), ("audience", json!([""])), ("lifecycle", json!({"title": "x"})), ("visibility", json!("all"))] {
            let mut e = env.clone();
            e[k] = val;
            assert_eq!(seal(&e, Some(&s), &f, None), value(bad), "{k}");
        }
        let mut e = env.clone();
        e["visibility"] = json!(["owner"]);
        assert!(matches!(seal(&e, Some(&s), &f, None), Err(SealError::Other(_))));
        assert!(matches!(seal(&json!([1]), Some(&s), &f, None), Err(SealError::Other(_))));
        let mut e = env.clone();
        e["v"] = json!(2.0);
        assert!(seal(&e, Some(&s), &f, Some(10.0)).unwrap()["exp"] == json!(310));
    }
}
