//! Base64 the way Python's `base64` module writes and reads it.

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(STD[(n >> 18) as usize & 63] as char);
        out.push(STD[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { STD[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { STD[n as usize & 63] as char } else { '=' });
    }
    out
}

/// base64.urlsafe_b64encode(data).rstrip(b"=")
pub fn url_nopad(data: &[u8]) -> String {
    encode(data).replace('+', "-").replace('/', "_").trim_end_matches('=').to_owned()
}

fn sextet(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn sextets(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for chunk in body.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= sextet(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Standard base64 with every character in the alphabet and correct padding
/// (base64.b64decode(validate=True)).
pub fn decode_strict(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let pad = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - pad];
    if body.iter().any(|&c| sextet(c).is_none()) {
        return None;
    }
    sextets(body)
}

/// Strict, canonical base64url without padding: the alphabet only, and the one spelling of what it
/// decodes to (gateway-identity.v1 `_unb64u`).
pub fn url_decode_canonical(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return None;
    }
    let mapped: Vec<u8> = text.bytes().map(|c| match c { b'-' => b'+', b'_' => b'/', c => c }).collect();
    let raw = sextets(&mapped)?;
    (url_nopad(&raw) == text).then_some(raw)
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trips_and_refuses_non_canonical() {
        assert_eq!(super::encode(b"ab"), "YWI=");
        assert_eq!(super::url_nopad(&[0xfb, 0xff]), "-_8");
        assert_eq!(super::url_decode_canonical("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(super::url_decode_canonical("-_9"), None);
        assert_eq!(super::decode_strict("YWI="), Some(b"ab".to_vec()));
    }
}
