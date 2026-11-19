//! gateway-identity.v1 verification: the gateway's Ed25519 signature over the
//! person a request acts for. The broker holds the PUBLIC key only.
//!
//!     token = "v1." + b64u(claims) + "." + b64u(Ed25519_sign(private_key, "v1." + b64u(claims)))

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

use crate::util;

pub const HEADER: &str = "x-vexa-identity";
pub const TYPE: &str = "vexa-identity";
pub const MAX_TTL_SEC: i64 = 300;
pub const MAX_SKEW_SEC: i64 = 30;

/// The SubjectPublicKeyInfo prefix of an Ed25519 public key (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// The public halves of RFC 8032 section 7.1 TEST 1 and TEST 2.
const PUBLISHED: [(&str, &str); 2] = [
    ("RFC 8032 section 7.1 TEST 1", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    ("RFC 8032 section 7.1 TEST 2", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
];

/// The answer a service gives a worker whose turn other people read.
pub fn shared_refusal() -> Value {
    serde_json::json!({
        "status": "refused",
        "reason": "shared_conversation",
        "instruction": "Other people read this conversation, so its answer may use only what every one of them can read. Say you cannot use it here, and offer to answer in the person's private chat; do not retry it another way.",
    })
}

/// A configuration fault with the identity key (a message without key material).
#[derive(Debug, PartialEq)]
pub struct KeyUnavailable(pub String);

fn pem_block(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = start + text[start..].find(&end)?;
    let body: String = text[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    util::b64decode_strict(&body)
}

/// A verifier's key from SubjectPublicKeyInfo PEM; a private key, another key
/// type or a published test key is refused.
pub fn load_verify_key(pem: &[u8]) -> Result<VerifyingKey, KeyUnavailable> {
    let text = String::from_utf8_lossy(pem);
    if text.contains("PRIVATE KEY") {
        return Err(KeyUnavailable("a verifier holds the identity PUBLIC key only; this is a private key".into()));
    }
    let der = pem_block(&text, "PUBLIC KEY").ok_or_else(|| KeyUnavailable("the identity verification key is not a PEM public key".into()))?;
    if der.len() != 44 || der[..12] != SPKI_PREFIX {
        return Err(KeyUnavailable("the identity verification key is not an Ed25519 key".into()));
    }
    let raw: [u8; 32] = der[12..].try_into().map_err(|_| KeyUnavailable("the identity verification key is not an Ed25519 key".into()))?;
    VerifyingKey::from_bytes(&raw).map_err(|_| KeyUnavailable("the identity verification key is not a PEM public key".into()))
}

pub fn read_verify_key(path: &str) -> Result<VerifyingKey, KeyUnavailable> {
    if path.is_empty() {
        return Err(KeyUnavailable("no identity key file is configured".into()));
    }
    let data = std::fs::read(path).map_err(|_| KeyUnavailable("the identity key file is unreadable".into()))?;
    let key = load_verify_key(&data)?;
    let hex = util::hex(key.as_bytes());
    if let Some((name, _)) = PUBLISHED.iter().find(|(_, h)| *h == hex) {
        return Err(KeyUnavailable(format!(
            "the identity key is {name}, a published test key anybody can sign with; generate this deployment's own pair"
        )));
    }
    Ok(key)
}

/// The claims of a token the gateway signed, or the refusal reason.
pub fn verify(key: &VerifyingKey, token: &str, now: i64) -> Result<serde_json::Map<String, Value>, &'static str> {
    let token = token.trim();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return Err("malformed");
    }
    let payload = util::b64url_decode_canonical(parts[1]).ok_or("malformed")?;
    let sig = util::b64url_decode_canonical(parts[2]).ok_or("malformed")?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "bad_signature")?;
    let signed = format!("{}.{}", parts[0], parts[1]);
    key.verify_strict_or_plain(signed.as_bytes(), &Signature::from_bytes(&sig)).map_err(|_| "bad_signature")?;
    let claims: Value = serde_json::from_slice(&payload).map_err(|_| "malformed")?;
    let claims = match claims {
        Value::Object(map) if map.get("typ").and_then(Value::as_str) == Some(TYPE) => map,
        _ => return Err("malformed"),
    };
    let int = |k: &str| claims.get(k).and_then(|v| if v.is_i64() || v.is_u64() { v.as_i64() } else { None });
    let (iat, exp) = match (int("iat"), int("exp")) {
        (Some(i), Some(e)) if e > i => (i, e),
        _ => return Err("malformed"),
    };
    if exp - iat > MAX_TTL_SEC {
        return Err("lifetime_too_long");
    }
    if iat > now + MAX_SKEW_SEC {
        return Err("not_yet_valid");
    }
    if now >= exp + MAX_SKEW_SEC {
        return Err("expired");
    }
    match claims.get("sub") {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(claims),
        _ => Err("malformed"),
    }
}

trait PlainVerify {
    fn verify_strict_or_plain(&self, msg: &[u8], sig: &Signature) -> Result<(), ed25519_dalek::SignatureError>;
}

impl PlainVerify for VerifyingKey {
    /// RFC 8032 verification with a canonical S, as OpenSSL performs it.
    fn verify_strict_or_plain(&self, msg: &[u8], sig: &Signature) -> Result<(), ed25519_dalek::SignatureError> {
        use ed25519_dalek::Verifier;
        self.verify(msg, sig)
    }
}

/// The agent session a verified identity names (delegation.unit), or "".
pub fn signed_session(claims: &serde_json::Map<String, Value>) -> String {
    match claims.get("delegation").and_then(|d| d.get("unit")) {
        Some(Value::String(u)) => u.trim().to_owned(),
        _ => String::new(),
    }
}

/// A delegated identity whose regime is not human (fail closed on any other shape).
pub fn unwatched(claims: &serde_json::Map<String, Value>) -> bool {
    let Some(dlg) = claims.get("delegation") else { return false };
    match dlg {
        Value::Object(d) => {
            let regime = match d.get("regime") {
                Some(v) if util::truthy(Some(v)) => util::py_str(v),
                _ => String::new(),
            };
            regime.trim().to_lowercase() != "human"
        }
        _ => true,
    }
}

/// A delegated identity whose turn other people read (delegation.shared is true).
pub fn shared(claims: &serde_json::Map<String, Value>) -> bool {
    matches!(claims.get("delegation"), Some(Value::Object(d)) if d.get("shared") == Some(&Value::Bool(true)))
}

/// frozenset(str(w) for w in claims.get("workspaces") or ()).
pub fn memberships(claims: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut out: Vec<String> = match claims.get("workspaces") {
        Some(v) if !util::truthy(Some(v)) => vec![],
        Some(Value::Array(items)) => items.iter().map(util::py_str).collect(),
        Some(Value::String(s)) => s.chars().map(String::from).collect(),
        Some(Value::Object(o)) => o.keys().cloned().collect(),
        _ => vec![],
    };
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::path::Path;

    fn golden(name: &str) -> Value {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/gateway/contracts/gateway-identity.v1/golden");
        serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap()
    }

    #[test]
    fn verifies_the_contract_vectors_and_refuses_the_refused_ones() {
        for name in ["vector-human.json", "vector-delegated.json", "vector-session.json"] {
            let v = golden(name);
            let key = load_verify_key(v["public_key"].as_str().unwrap().as_bytes()).unwrap();
            let claims = verify(&key, v["token"].as_str().unwrap(), v["now"].as_i64().unwrap()).unwrap();
            for (k, want) in v["claims"].as_object().unwrap() {
                assert_eq!(&claims[k], want, "{name} {k}");
            }
        }
        let mut refused = 0;
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/gateway/contracts/gateway-identity.v1/golden");
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().to_string();
            if !name.starts_with("refused-") {
                continue;
            }
            let v = golden(&name);
            let key = load_verify_key(v["public_key"].as_str().unwrap().as_bytes()).unwrap();
            let got = verify(&key, v["token"].as_str().unwrap(), v["now"].as_i64().unwrap());
            assert_eq!(got.err(), Some(v["reason"].as_str().unwrap()), "{name}");
            refused += 1;
        }
        assert!(refused >= 6);
    }

    #[test]
    fn a_published_or_private_key_is_refused() {
        let dir = std::env::temp_dir().join(format!("vcb-id-{}", util::uuid_hex()));
        std::fs::create_dir_all(&dir).unwrap();
        let published = golden("vector-human.json")["public_key"].as_str().unwrap().to_owned();
        std::fs::write(dir.join("pub.pem"), &published).unwrap();
        assert!(read_verify_key(dir.join("pub.pem").to_str().unwrap()).unwrap_err().0.contains("TEST 1"));
        std::fs::write(dir.join("priv.pem"), "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n").unwrap();
        assert!(read_verify_key(dir.join("priv.pem").to_str().unwrap()).is_err());
        assert!(read_verify_key("").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reads_the_delegation_claims() {
        let c = |v: Value| v.as_object().unwrap().clone();
        assert!(!unwatched(&c(serde_json::json!({"sub": "1"}))));
        assert!(unwatched(&c(serde_json::json!({"delegation": {"regime": "autonomous"}}))));
        assert!(!unwatched(&c(serde_json::json!({"delegation": {"regime": " Human "}}))));
        assert!(unwatched(&c(serde_json::json!({"delegation": "x"}))));
        assert!(shared(&c(serde_json::json!({"delegation": {"shared": true}}))));
        assert!(!shared(&c(serde_json::json!({"delegation": {"shared": 1}}))));
        assert_eq!(signed_session(&c(serde_json::json!({"delegation": {"unit": " u1 "}}))), "u1");
        assert_eq!(memberships(&c(serde_json::json!({"workspaces": ["b", "a", 3]}))), vec!["3", "a", "b"]);
    }
}
