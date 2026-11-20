//! gateway-identity.v1: the identity this edge resolved, signed with its Ed25519 private key, and
//! the plain `x-user-*` headers that stand for it.
//!
//!     token = "v1." + b64u(claims) + "." + b64u(Ed25519_sign(private_key, "v1." + b64u(claims)))

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use vexa_native_kit::b64;
use vexa_native_kit::pyjson::{py_dumps, py_str, truthy, Dumps};

pub const HEADER: &str = "x-vexa-identity";
pub const TYPE: &str = "vexa-identity";
pub const DEFAULT_TTL_SEC: i64 = 60;
pub const MAX_TTL_SEC: i64 = 300;
pub const MAX_SKEW_SEC: i64 = 30;
pub const UNATTENDED_GRANTS: [&str; 3] = ["bot.request", "bot.stop", "flow.retire_self"];
const CREDENTIAL_CLASSES: [&str; 3] = ["session", "key", "delegation"];

const CLAIM_HEADERS: [(&str, &str); 10] = [
    ("sub", "x-user-id"),
    ("email", "x-user-email"),
    ("scopes", "x-user-scopes"),
    ("limits", "x-user-limits"),
    ("workspaces", "x-user-workspaces"),
    ("writable_workspaces", "x-user-writable-workspaces"),
    ("webhook_url", "x-user-webhook-url"),
    ("webhook_secret", "x-user-webhook-secret"),
    ("webhook_events", "x-user-webhook-events"),
    ("credential_class", "x-user-credential-class"),
];

/// The SubjectPublicKeyInfo prefix of an Ed25519 public key (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
/// The PKCS#8 v1 prefix of an Ed25519 private key, as OpenSSL writes it.
const PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// The public halves of the RFC 8032 section 7.1 TEST 1 and TEST 2 keys.
const PUBLISHED: [(&str, &str); 2] = [
    ("RFC 8032 section 7.1 TEST 1", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    ("RFC 8032 section 7.1 TEST 2", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
];

/// The answer every service gives a worker whose turn other people read.
pub fn shared_refusal() -> Value {
    json!({
        "status": "refused",
        "reason": "shared_conversation",
        "instruction": "Other people read this conversation, so its answer may use only what every one of them can read. Say you cannot use it here, and offer to answer in the person's private chat; do not retry it another way.",
    })
}

fn pem_block(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = start + text[start..].find(&end)?;
    let body: String = text[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    b64::decode_strict(&body)
}

fn pem(label: &str, der: &[u8]) -> String {
    let text = b64::encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// The seed of a PKCS#8 Ed25519 private key (v1, or v2 with its public key).
fn pkcs8_seed(der: &[u8]) -> Result<[u8; 32], &'static str> {
    if der.len() >= 48 && der[..16] == PKCS8_PREFIX {
        return der[16..48].try_into().map_err(|_| "the identity signing key is not an Ed25519 key");
    }
    // OneAsymmetricKey (v2): SEQUENCE { INTEGER 1, SEQUENCE { OID }, OCTET STRING { OCTET STRING seed }, [1] pub }
    if der.len() > 16 && der[0] == 0x30 {
        let body = if der[1] & 0x80 == 0 { &der[2..] } else { &der[2 + (der[1] & 0x7f) as usize..] };
        if body.len() > 16 && body[..3] == [0x02, 0x01, 0x01] && body[3..5] == [0x30, 0x05] {
            if body[5..10] != ED25519_OID {
                return Err("the identity signing key is not an Ed25519 key");
            }
            if body[10..14] == [0x04, 0x22, 0x04, 0x20] && body.len() >= 46 {
                return body[14..46].try_into().map_err(|_| "the identity signing key is not an Ed25519 key");
            }
        }
        if der.windows(5).any(|w| w == ED25519_OID) {
            return Err("the identity signing key is not an unencrypted PEM private key");
        }
        return Err("the identity signing key is not an Ed25519 key");
    }
    Err("the identity signing key is not an unencrypted PEM private key")
}

pub fn load_signing_key(pem_bytes: &[u8]) -> Result<SigningKey, String> {
    let text = String::from_utf8_lossy(pem_bytes);
    let der = pem_block(&text, "PRIVATE KEY")
        .ok_or_else(|| "the identity signing key is not an unencrypted PEM private key".to_owned())?;
    Ok(SigningKey::from_bytes(&pkcs8_seed(&der)?))
}

pub fn private_key_pem(key: &SigningKey) -> String {
    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&key.to_bytes());
    pem("PRIVATE KEY", &der)
}

pub fn public_key_pem(key: &VerifyingKey) -> String {
    let mut der = SPKI_PREFIX.to_vec();
    der.extend_from_slice(key.as_bytes());
    pem("PUBLIC KEY", &der)
}

/// The signing key a deployment configured; a published test key is refused.
pub fn read_signing_key(path: &str) -> Result<SigningKey, String> {
    if path.is_empty() {
        return Err("no identity key file is configured".into());
    }
    let data = std::fs::read(path).map_err(|_| "the identity key file is unreadable".to_owned())?;
    let key = load_signing_key(&data)?;
    let hex = vexa_native_kit::sha256::hex(key.verifying_key().as_bytes());
    if let Some((name, _)) = PUBLISHED.iter().find(|(_, h)| *h == hex) {
        return Err(format!("the identity key is {name}, a published test key anybody can sign with; generate this deployment's own pair"));
    }
    Ok(key)
}

/// A verifier's key from SubjectPublicKeyInfo PEM; a private key and a published test key are refused.
pub fn read_verify_key(path: &str) -> Result<VerifyingKey, String> {
    let data = std::fs::read(path).map_err(|_| "the identity key file is unreadable".to_owned())?;
    let text = String::from_utf8_lossy(&data);
    if text.contains("PRIVATE KEY") {
        return Err("a verifier holds the identity PUBLIC key only; this is a private key".into());
    }
    let der = pem_block(&text, "PUBLIC KEY").ok_or_else(|| "the identity verification key is not a PEM public key".to_owned())?;
    if der.len() != 44 || der[..12] != SPKI_PREFIX {
        return Err("the identity verification key is not an Ed25519 key".into());
    }
    let raw: [u8; 32] = der[12..].try_into().map_err(|_| "the identity verification key is not an Ed25519 key".to_owned())?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| "the identity verification key is not a PEM public key".to_owned())?;
    let hex = vexa_native_kit::sha256::hex(key.as_bytes());
    if let Some((name, _)) = PUBLISHED.iter().find(|(_, h)| *h == hex) {
        return Err(format!("the identity key is {name}, a published test key anybody can sign with; generate this deployment's own pair"));
    }
    Ok(key)
}

/// `identity_token.py keygen SIGNING PUBLIC`: keep (or make) the signing key, rewrite its public half.
pub fn keygen(signing: &str, public: &str) -> Result<bool, String> {
    let write = |path: &str, data: &str, mode: u32| -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let p = std::path::Path::new(path);
        if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    };
    let generated = !std::path::Path::new(signing).exists();
    let key = if generated {
        let seed: [u8; 32] = vexa_native_kit::ids::random_bytes(32).try_into().map_err(|_| "no random source".to_owned())?;
        let key = SigningKey::from_bytes(&seed);
        write(signing, &private_key_pem(&key), 0o600)?;
        key
    } else {
        read_signing_key(signing)?
    };
    write(public, &public_key_pem(&key.verifying_key()), 0o644)?;
    Ok(generated)
}

fn list_of_str(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(items) => items.iter().map(|x| Value::String(py_str(x))).collect(),
        Value::Object(m) => m.keys().map(|k| Value::String(k.clone())).collect(),
        Value::String(s) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        _ => Vec::new(),
    }
}

fn is_int(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Number(n)) if n.is_i64() || n.is_u64())
}

/// The claims for a `/internal/validate` answer.
pub fn claims_from_validation(user: &Value) -> Map<String, Value> {
    let get = |k: &str| user.get(k);
    let mut c = Map::new();
    c.insert("sub".into(), Value::String(get("user_id").map(py_str).unwrap_or_else(|| "None".into())));
    if truthy(get("email")) {
        c.insert("email".into(), Value::String(py_str(&user["email"])));
    }
    c.insert("scopes".into(), Value::Array(get("scopes").filter(|v| truthy(Some(v))).map(list_of_str).unwrap_or_default()));
    match get("max_concurrent") {
        None => {
            c.insert("limits".into(), json!(3));
        }
        Some(v) if is_int(Some(v)) => {
            c.insert("limits".into(), v.clone());
        }
        _ => {}
    }
    if truthy(get("workspaces")) {
        c.insert("workspaces".into(), Value::Array(list_of_str(&user["workspaces"])));
    }
    if truthy(get("writable_workspaces")) {
        c.insert("writable_workspaces".into(), Value::Array(list_of_str(&user["writable_workspaces"])));
    }
    if truthy(get("webhook_url")) {
        c.insert("webhook_url".into(), Value::String(py_str(&user["webhook_url"])));
        if truthy(get("webhook_secret")) {
            c.insert("webhook_secret".into(), Value::String(py_str(&user["webhook_secret"])));
        }
        if truthy(get("webhook_events")) {
            c.insert("webhook_events".into(), user["webhook_events"].clone());
        }
    }
    if let Some(Value::String(cc)) = get("credential_class") {
        if CREDENTIAL_CLASSES.contains(&cc.as_str()) {
            c.insert("credential_class".into(), Value::String(cc.clone()));
        }
    }
    if let Some(Value::Object(dlg)) = get("delegation") {
        let dget = |k: &str| dlg.get(k);
        let mut d = Map::new();
        d.insert("regime".into(), Value::String(dget("regime").filter(|v| truthy(Some(v))).map(py_str).unwrap_or_default()));
        let ws = match dget("workspaces") {
            Some(Value::String(s)) if s == "*" => Value::String("*".into()),
            Some(v) if truthy(Some(v)) => Value::Array(list_of_str(v)),
            _ => Value::Array(vec![]),
        };
        d.insert("workspaces".into(), ws);
        for k in ["target", "unit"] {
            if truthy(dget(k)) {
                d.insert(k.into(), Value::String(py_str(&dlg[k])));
            }
        }
        if dget("shared") == Some(&Value::Bool(true)) {
            d.insert("shared".into(), Value::Bool(true));
        }
        if dget("principal_kind").and_then(Value::as_str) == Some("workspace") {
            d.insert("principal_kind".into(), "workspace".into());
            for k in ["principal_workspace", "on_behalf_of"] {
                if truthy(dget(k)) {
                    d.insert(k.into(), Value::String(py_str(&dlg[k])));
                }
            }
            if is_int(dget("bills_to")) {
                d.insert("bills_to".into(), dlg["bills_to"].clone());
            }
        }
        let flow = dget("flow").filter(|v| truthy(Some(v))).map(py_str).unwrap_or_default();
        if let (Some(Value::Array(grants)), false) = (dget("grants"), flow.trim().is_empty()) {
            let mut kept: Vec<String> = grants.iter().map(py_str).filter(|g| UNATTENDED_GRANTS.contains(&g.as_str())).collect();
            kept.sort();
            kept.dedup();
            if !kept.is_empty() {
                d.insert("grants".into(), json!(kept));
                d.insert("flow".into(), Value::String(flow.trim().to_owned()));
            }
        }
        c.insert("delegation".into(), Value::Object(d));
    }
    c
}

pub fn sign(key: &SigningKey, claims: &Map<String, Value>, now: i64) -> String {
    let mut payload = claims.clone();
    payload.insert("typ".into(), TYPE.into());
    payload.insert("iat".into(), json!(now));
    payload.insert("exp".into(), json!(now + DEFAULT_TTL_SEC));
    let text = Dumps::COMPACT.sorted().text(&Value::Object(payload));
    let body = format!("v1.{}", b64::url_nopad(text.as_bytes()));
    let sig = key.sign(body.as_bytes());
    format!("{body}.{}", b64::url_nopad(&sig.to_bytes()))
}

pub fn now() -> i64 {
    vexa_native_kit::ids::now().floor() as i64
}

/// The claims of a token this edge signed, or the refusal reason.
pub fn verify(key: &VerifyingKey, token: &str, now: i64) -> Result<Map<String, Value>, &'static str> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return Err("malformed");
    }
    let payload = b64::url_decode_canonical(parts[1]).ok_or("malformed")?;
    let sig = b64::url_decode_canonical(parts[2]).ok_or("malformed")?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "bad_signature")?;
    let signed = format!("{}.{}", parts[0], parts[1]);
    key.verify(signed.as_bytes(), &Signature::from_bytes(&sig)).map_err(|_| "bad_signature")?;
    let claims = match serde_json::from_slice::<Value>(&payload) {
        Ok(Value::Object(map)) if map.get("typ").and_then(Value::as_str) == Some(TYPE) => map,
        _ => return Err("malformed"),
    };
    let int = |k: &str| claims.get(k).and_then(|v| if v.is_i64() { v.as_i64() } else { None });
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

fn join(v: &Value) -> String {
    match v {
        Value::Array(items) => items.iter().map(py_str).collect::<Vec<_>>().join(","),
        other => py_str(other),
    }
}

fn empty(v: &Value) -> bool {
    matches!(v, Value::Null) || v.as_str() == Some("") || v.as_array().is_some_and(|a| a.is_empty())
}

/// The plain `x-user-*` headers a set of claims stands for.
pub fn headers_from_claims(claims: &Map<String, Value>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (claim, header) in CLAIM_HEADERS {
        let Some(value) = claims.get(claim).filter(|v| !empty(v)) else { continue };
        let text = match claim {
            "scopes" | "workspaces" | "writable_workspaces" => join(value),
            "webhook_events" => match value {
                Value::String(s) => s.clone(),
                other => py_dumps(other),
            },
            _ => py_str(value),
        };
        out.push((header.into(), text));
    }
    if let Some(Value::Object(d)) = claims.get("delegation") {
        let t = |k: &str| truthy(d.get(k));
        if t("regime") {
            out.push(("x-user-regime".into(), py_str(&d["regime"])));
        }
        match d.get("workspaces") {
            Some(Value::String(s)) if s == "*" => out.push(("x-user-delegation-workspaces".into(), "*".into())),
            Some(v @ Value::Array(_)) => out.push(("x-user-delegation-workspaces".into(), join(v))),
            _ => {}
        }
        if t("target") {
            out.push(("x-user-delegation-target".into(), py_str(&d["target"])));
        }
        if t("unit") {
            out.push(("x-user-delegation-unit".into(), py_str(&d["unit"])));
        }
        if d.get("shared") == Some(&Value::Bool(true)) {
            out.push(("x-user-delegation-shared".into(), "1".into()));
        }
        for (k, h) in [("principal_kind", "x-user-principal-kind"), ("principal_workspace", "x-user-principal-workspace"), ("on_behalf_of", "x-user-delegation-on-behalf-of")] {
            if t(k) {
                out.push((h.into(), py_str(&d[k])));
            }
        }
        if let Some(b) = d.get("bills_to").filter(|v| !matches!(v, Value::Null) && v.as_str() != Some("")) {
            out.push(("x-user-bills-to".into(), py_str(b)));
        }
        if t("grants") && t("flow") {
            out.push(("x-user-delegation-grants".into(), join(&d["grants"])));
            out.push(("x-user-delegation-flow".into(), py_str(&d["flow"])));
        }
    }
    out
}

/// What a forward carries for a resolved user: the plain headers, and the token when this edge
/// holds a key.
pub fn identity_headers(key: Option<&SigningKey>, user: &Value) -> Vec<(String, String)> {
    let claims = claims_from_validation(user);
    let mut out = headers_from_claims(&claims);
    if let Some(k) = key {
        out.push((HEADER.into(), sign(k, &claims, now())));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test1() -> SigningKey {
        let seed: [u8; 32] = (0..32)
            .map(|i| u8::from_str_radix(&"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn signs_verifies_and_round_trips_pem() {
        let key = test1();
        let pem = private_key_pem(&key);
        assert_eq!(load_signing_key(pem.as_bytes()).unwrap().to_bytes(), key.to_bytes());
        assert_eq!(public_key_pem(&key.verifying_key()), "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n");
        let user = json!({"user_id": 7, "scopes": ["bot", "tx"], "email": "u@example.com"});
        let claims = claims_from_validation(&user);
        assert_eq!(serde_json::to_string(&claims).unwrap(), r#"{"sub":"7","email":"u@example.com","scopes":["bot","tx"],"limits":3}"#);
        let token = sign(&key, &claims, 1000);
        let back = verify(&key.verifying_key(), &token, 1010).unwrap();
        assert_eq!(back["sub"], "7");
        assert_eq!(verify(&key.verifying_key(), &token, 1090), Err("expired"));
        let h = headers_from_claims(&claims);
        assert_eq!(h[0], ("x-user-id".into(), "7".into()));
        assert_eq!(h[2], ("x-user-scopes".into(), "bot,tx".into()));
        assert_eq!(h[3], ("x-user-limits".into(), "3".into()));
    }

    #[test]
    fn delegation_claims() {
        let user = json!({"user_id": 7, "scopes": ["bot"], "max_concurrent": true, "delegation": {
            "regime": "human", "workspaces": "*", "unit": "agent-x-chat-1", "shared": true,
            "principal_kind": "workspace", "principal_workspace": "w1", "bills_to": 9,
            "grants": ["bot.stop", "x", "bot.request", "bot.stop"], "flow": " f "}});
        let c = claims_from_validation(&user);
        assert!(!c.contains_key("limits"));
        assert_eq!(serde_json::to_string(&c["delegation"]).unwrap(),
            r#"{"regime":"human","workspaces":"*","unit":"agent-x-chat-1","shared":true,"principal_kind":"workspace","principal_workspace":"w1","bills_to":9,"grants":["bot.request","bot.stop"],"flow":"f"}"#);
    }
}
