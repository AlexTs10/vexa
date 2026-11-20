//! event.v2 — the producer's Ed25519 key: the one place a fact seal touches key material.
//!
//! The producer holds its OWN private key, a PKCS#8 PEM Ed25519 key in a file only it mounts
//! (`openssl genpkey -algorithm ed25519`); `signer_from_file` reads it, and without it nothing
//! seals. flows-api holds only the public halves (`load_check` reads one). Keys are minted by the
//! `fact_keys keygen` one-shot of the deploy surfaces; this module only reads them. It reads no
//! environment: each service declares the one key it holds.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use vexa_native_kit::b64;

/// The Ed25519 algorithm identifier, OID 1.3.101.112.
const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// `sign(message) -> 64-byte signature` for a PKCS#8 PEM Ed25519 private key.
#[derive(Clone)]
pub struct Signer(pub SigningKey);

impl Signer {
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

/// `check(message, signature) -> bool` for a PEM Ed25519 public key.
#[derive(Clone)]
pub struct Check(pub VerifyingKey);

impl Check {
    pub fn check(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(sig) = <[u8; 64]>::try_from(signature) else { return false };
        self.0.verify(message, &Signature::from_bytes(&sig)).is_ok()
    }
}

/// The first PEM block of `pem`: its label and its DER bytes.
fn pem_block(pem: &[u8]) -> Option<(String, Vec<u8>)> {
    let text = std::str::from_utf8(pem).ok()?;
    let start = text.find("-----BEGIN ")?;
    let rest = &text[start + 11..];
    let label_end = rest.find("-----")?;
    let label = &rest[..label_end];
    let body = &rest[label_end + 5..];
    let end = body.find(&format!("-----END {label}-----"))?;
    let b64text: String = body[..end].chars().filter(|c| !c.is_ascii_whitespace()).collect();
    Some((label.to_owned(), b64::decode_strict(&b64text)?))
}

/// One DER element at the start of `der`: its tag, its content and what follows it.
fn der(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        if len < 0x80 || rest[0] == 0 {
            return None;
        }
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// The 32-byte seed of a PKCS#8 (v1 or v2) Ed25519 PrivateKeyInfo.
fn pkcs8_seed(info: &[u8]) -> Option<[u8; 32]> {
    let (tag, body, tail) = der(info)?;
    if tag != 0x30 || !tail.is_empty() {
        return None;
    }
    let (tag, version, rest) = der(body)?;
    if tag != 0x02 || !(version == [0] || version == [1]) {
        return None;
    }
    let (tag, alg, rest) = der(rest)?;
    if tag != 0x30 || alg != ED25519_OID {
        return None;
    }
    let (tag, key, mut rest) = der(rest)?;
    if tag != 0x04 {
        return None;
    }
    let (tag, seed, after) = der(key)?;
    if tag != 0x04 || !after.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let (tag, _, after) = der(rest)?;
        if tag != 0xa0 && tag != 0x81 && tag != 0xa1 {
            return None;
        }
        rest = after;
    }
    seed.try_into().ok()
}

/// The signer of a PKCS#8 PEM Ed25519 private key. Err for anything else (another algorithm, an
/// encrypted or malformed key), named and never echoed: the PEM is a secret.
pub fn load_signer(pem: &[u8]) -> Result<Signer, String> {
    let Some((label, der)) = pem_block(pem) else {
        return Err("fact seal key: not a PEM private key".into());
    };
    if !label.ends_with("PRIVATE KEY") {
        return Err("fact seal key: not a PEM private key".into());
    }
    match (label.as_str(), pkcs8_seed(&der)) {
        ("PRIVATE KEY", Some(seed)) => Ok(Signer(SigningKey::from_bytes(&seed))),
        _ => Err("fact seal key: not an Ed25519 key".into()),
    }
}

/// The check of a SubjectPublicKeyInfo PEM Ed25519 public key. Err for anything else.
pub fn load_check(pem: &[u8]) -> Result<Check, String> {
    let parsed = pem_block(pem).filter(|(label, _)| label == "PUBLIC KEY");
    let Some((_, der_bytes)) = parsed else {
        return Err("fact verify key: not a PEM public key".into());
    };
    let key = der(&der_bytes)
        .filter(|(tag, _, tail)| *tag == 0x30 && tail.is_empty())
        .and_then(|(_, body, _)| {
            let (tag, alg, rest) = der(body)?;
            let (btag, bits, tail) = der(rest)?;
            (tag == 0x30 && alg == ED25519_OID && btag == 0x03 && tail.is_empty() && bits.len() == 33 && bits[0] == 0)
                .then(|| <[u8; 32]>::try_from(&bits[1..]).ok())?
        })
        .and_then(|k| VerifyingKey::from_bytes(&k).ok());
    key.map(Check).ok_or_else(|| "fact verify key: not an Ed25519 key".into())
}

/// The producer's signer from the PEM file at `path`, else None (no path, unreadable, or not an
/// Ed25519 private key — the producer's preflight names which).
pub fn signer_from_file(path: Option<&str>) -> Option<Signer> {
    let path = crate::val::strip(path.unwrap_or(""));
    if path.is_empty() {
        return None;
    }
    load_signer(&std::fs::read(path).ok()?).ok()
}

/// The SubjectPublicKeyInfo DER of a signer's public half.
pub fn public_der(signer: &Signer) -> Vec<u8> {
    let mut out = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    out.extend_from_slice(signer.0.verifying_key().as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Ed25519PrivateKey.from_private_bytes(bytes(range(32)))` as cryptography writes it.
    pub const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n-----END PRIVATE KEY-----\n";

    #[test]
    fn reads_pkcs8_v1() {
        let s = load_signer(PEM.as_bytes()).unwrap();
        let seed: Vec<u8> = (0u8..32).collect();
        assert_eq!(s.0.to_bytes().to_vec(), seed);
    }

    #[test]
    fn reads_pkcs8_v2_with_public_key() {
        let s = load_signer(PEM.as_bytes()).unwrap();
        let mut der = vec![0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        der.extend(0u8..32);
        der.extend([0x81, 0x21, 0x00]);
        der.extend_from_slice(s.0.verifying_key().as_bytes());
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", b64::encode(&der));
        assert!(load_signer(pem.as_bytes()).is_ok());
    }

    #[test]
    fn refuses_other_keys() {
        assert_eq!(load_signer(b"nope").err().unwrap(), "fact seal key: not a PEM private key");
        let pem = PEM.replace("PRIVATE KEY", "ENCRYPTED PRIVATE KEY");
        assert!(load_signer(pem.as_bytes()).is_err());
        // an X25519 key (OID 1.3.101.110)
        let x = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n-----END PRIVATE KEY-----\n";
        assert_eq!(load_signer(x.as_bytes()).err().unwrap(), "fact seal key: not an Ed25519 key");
        assert!(signer_from_file(None).is_none());
        assert!(signer_from_file(Some("  ")).is_none());
        assert!(signer_from_file(Some("/nonexistent/key.pem")).is_none());
    }

    #[test]
    fn check_verifies_own_signature() {
        let s = load_signer(PEM.as_bytes()).unwrap();
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", b64::encode(&public_der(&s)));
        let c = load_check(pem.as_bytes()).unwrap();
        let sig = s.sign(b"m");
        assert!(c.check(b"m", &sig));
        assert!(!c.check(b"n", &sig));
    }
}
