//! credential-broker.v1 assertion: the X-Vexa-Assertion verifier (and a signer
//! for tests), wire-identical to the contract's canonical assertion.py.
//!
//!     X-Vexa-Assertion: <base64url(claims JSON), unpadded>.<hex HMAC-SHA256(role key, encoded part)>
//!
//! The claims bind role, actor, session, time, a single-use nonce, the method,
//! the exact path with its query, and the SHA-256 of the exact body bytes.

use serde_json::Value;

use crate::util;

pub const HEADER: &str = "x-vexa-assertion";
pub const ROLES: [&str; 6] = ["agent", "human", "git", "bots", "sensors", "signals"];
pub const METHODS: [&str; 2] = ["GET", "POST"];
pub const MAX_AGE_S: f64 = 30.0;
pub const MAX_SKEW_S: f64 = 5.0;
pub const NONCE_TTL_S: f64 = MAX_AGE_S + MAX_SKEW_S + 25.0;
pub const MIN_KEY_BYTES: usize = 32;
const FIELDS: [&str; 8] = ["role", "actor", "session", "at", "nonce", "method", "path", "body"];
const TEXT_LIMIT: usize = 160;
const PATH_LIMIT: usize = 16384;

/// The fixture keys the contract's signing vectors are made with.
pub const PUBLISHED_KEYS: [&[u8]; 6] = [
    b"fixture-agent-key-not-a-deployment-secret-0001",
    b"fixture-human-key-not-a-deployment-secret-0001",
    b"fixture-git-key-not-a-deployment-secret-000001",
    b"fixture-bots-key-not-a-deployment-secret-00001",
    b"fixture-sensors-key-not-a-deployment-secret-01",
    b"fixture-signals-key-not-a-deployment-secret-01",
];

#[derive(Debug, PartialEq)]
pub enum KeyError {
    Unavailable,
    Published,
}

/// The verified claims of one request.
#[derive(Debug, Clone)]
pub struct Claims {
    pub role: String,
    pub actor: String,
    pub session: String,
}

fn strip(bytes: &[u8]) -> &[u8] {
    let ws = |c: &u8| c.is_ascii_whitespace() || *c == 0x0b || *c == 0x0c;
    let start = bytes.iter().position(|c| !ws(c)).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|c| !ws(c)).map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Read one role key file; refuse a short or a published key.
pub fn load_key(path: &str) -> Result<Vec<u8>, KeyError> {
    if path.is_empty() {
        return Err(KeyError::Unavailable);
    }
    let raw = std::fs::read(path).map_err(|_| KeyError::Unavailable)?;
    let key = strip(&raw).to_vec();
    if key.len() < MIN_KEY_BYTES {
        return Err(KeyError::Unavailable);
    }
    if PUBLISHED_KEYS.contains(&key.as_slice()) {
        return Err(KeyError::Published);
    }
    Ok(key)
}

pub fn body_digest(body: &[u8]) -> String {
    util::sha256_hex(body)
}

fn signature(key: &[u8], encoded: &str) -> String {
    util::hmac_hex(key, encoded.as_bytes())
}

/// The header value for one request.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn sign(key: &[u8], role: &str, actor: &str, session: &str, method: &str, path: &str, body: &[u8], at: i64, nonce: &str) -> String {
    let mut claims = serde_json::Map::new();
    claims.insert("role".into(), role.into());
    claims.insert("actor".into(), actor.into());
    claims.insert("session".into(), session.into());
    claims.insert("at".into(), at.into());
    claims.insert("nonce".into(), nonce.into());
    claims.insert("method".into(), method.into());
    claims.insert("path".into(), path.into());
    claims.insert("body".into(), body_digest(body).into());
    let raw = crate::util::py_dumps(&Value::Object(claims)).replace(", ", ",").replace(": ", ":");
    let encoded = util::b64url_nopad(raw.as_bytes());
    let sig = signature(key, &encoded);
    format!("{encoded}.{sig}")
}

/// Why an assertion was refused (a typed log kind; never a value).
pub type Refusal = &'static str;

/// The verified claims, or the refusal kind. key_for(role) is None when the
/// role is not configured here; remember(nonce, expires) is false for a nonce
/// already seen.
pub fn verify(
    header: &str,
    key_for: &dyn Fn(&str) -> Option<Vec<u8>>,
    method: &str,
    path: &str,
    body: &[u8],
    now: f64,
    remember: &dyn Fn(&str, f64) -> bool,
) -> Result<Claims, Refusal> {
    let parts: Vec<&str> = header.split('.').collect();
    if parts.len() != 2 {
        return Err("malformed");
    }
    let (encoded, sig) = (parts[0], parts[1]);
    let raw = util::b64url_decode_lenient(encoded).ok_or("malformed")?;
    let claims: Value = serde_json::from_slice(&raw).map_err(|_| "malformed")?;
    let obj = claims.as_object().ok_or("malformed")?;
    if obj.len() != FIELDS.len() || !FIELDS.iter().all(|f| obj.contains_key(*f)) {
        return Err("malformed");
    }
    let role = match &obj["role"] {
        Value::String(r) if ROLES.contains(&r.as_str()) => r.clone(),
        _ => return Err("role"),
    };
    let key = key_for(&role).ok_or("role")?;
    if !util::ct_eq(signature(&key, encoded).as_bytes(), sig.as_bytes()) {
        return Err("signature");
    }
    let text_ok = |k: &str| matches!(&obj[k], Value::String(s) if (1..=TEXT_LIMIT).contains(&s.chars().count()));
    let claim_method = obj["method"].as_str().filter(|m| METHODS.contains(m));
    let claim_path = obj["path"].as_str().filter(|p| p.starts_with("/api/") && p.chars().count() <= PATH_LIMIT);
    let at = match &obj["at"] {
        Value::Number(n) if n.is_i64() || n.is_u64() => n.as_f64().unwrap_or(f64::NAN),
        _ => return Err("malformed"),
    };
    if claim_method.is_none() || claim_path.is_none() || !obj["body"].is_string() || !["actor", "session", "nonce"].iter().all(|k| text_ok(k)) {
        return Err("malformed");
    }
    if !(now - MAX_AGE_S <= at && at <= now + MAX_SKEW_S) {
        return Err("expired");
    }
    if claim_method != Some(method) || claim_path != Some(path) || obj["body"].as_str() != Some(body_digest(body).as_str()) {
        return Err("binding");
    }
    let nonce = obj["nonce"].as_str().unwrap_or_default().to_owned();
    if !remember(&nonce, now + NONCE_TTL_S) {
        return Err("replay");
    }
    Ok(Claims {
        role,
        actor: obj["actor"].as_str().unwrap_or_default().to_owned(),
        session: obj["session"].as_str().unwrap_or_default().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn contract() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/agent/contracts/credential-broker.v1/golden")
    }

    /// Every SignedAssertionVector golden re-derives and verifies.
    #[test]
    fn reproduces_the_contract_signing_vectors() {
        let mut checked = 0;
        for entry in std::fs::read_dir(contract()).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.starts_with("SignedAssertionVector.") {
                continue;
            }
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let key = v["key"].as_str().unwrap().as_bytes();
            let c = &v["claims"];
            let body = v["request_body"].as_str().unwrap_or("").as_bytes();
            let header = sign(
                key,
                c["role"].as_str().unwrap(),
                c["actor"].as_str().unwrap(),
                c["session"].as_str().unwrap(),
                c["method"].as_str().unwrap(),
                c["path"].as_str().unwrap(),
                body,
                c["at"].as_i64().unwrap(),
                c["nonce"].as_str().unwrap(),
            );
            assert_eq!(header, v["header"].as_str().unwrap(), "{name}");
            let at = c["at"].as_f64().unwrap();
            let ok = verify(&header, &|_| Some(key.to_vec()), c["method"].as_str().unwrap(), c["path"].as_str().unwrap(), body, at, &|_, _| true);
            assert!(ok.is_ok(), "{name}");
            checked += 1;
        }
        assert!(checked >= 5, "found {checked} vectors");
    }

    #[test]
    fn refuses_each_kind() {
        let key = b"k".repeat(40);
        let h = sign(&key, "agent", "1", "s", "GET", "/api/connections", b"", 1000, "n1");
        let kf = |_: &str| Some(b"k".repeat(40));
        let yes = |_: &str, _: f64| true;
        assert_eq!(verify(&h, &kf, "GET", "/api/connections", b"", 1000.0, &yes).unwrap().actor, "1");
        assert_eq!(verify(&h, &kf, "GET", "/api/connections", b"", 1031.0, &yes).unwrap_err(), "expired");
        assert_eq!(verify(&h, &kf, "GET", "/api/connections", b"", 994.0, &yes).unwrap_err(), "expired");
        assert_eq!(verify(&h, &kf, "POST", "/api/connections", b"", 1000.0, &yes).unwrap_err(), "binding");
        assert_eq!(verify(&h, &kf, "GET", "/api/connections", b"x", 1000.0, &yes).unwrap_err(), "binding");
        assert_eq!(verify(&h, &kf, "GET", "/api/connections", b"", 1000.0, &|_, _| false).unwrap_err(), "replay");
        assert_eq!(verify(&h, &|_| None, "GET", "/api/connections", b"", 1000.0, &yes).unwrap_err(), "role");
        assert_eq!(verify(&h, &|_| Some(b"x".repeat(40)), "GET", "/api/connections", b"", 1000.0, &yes).unwrap_err(), "signature");
        assert_eq!(verify("a.b.c", &kf, "GET", "/api/connections", b"", 1000.0, &yes).unwrap_err(), "malformed");
        let outside = sign(&key, "agent", "1", "s", "GET", "/health", b"", 1000, "n1");
        assert_eq!(verify(&outside, &kf, "GET", "/health", b"", 1000.0, &yes).unwrap_err(), "malformed");
    }
}
