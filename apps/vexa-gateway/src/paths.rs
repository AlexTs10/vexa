//! What a caller's path parameters and catch-all tails may become on a downstream hop: one opaque
//! percent-encoded segment each, or a 400.

pub const INVALID: &str = "{\"detail\": \"invalid path parameter\"}";

/// One path parameter as one opaque segment; Err for a control character.
pub fn path_segment(value: &str) -> Result<String, ()> {
    if value.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(());
    }
    let seg = vexa_native_kit::client::quote(value);
    if !seg.is_empty() && seg.bytes().all(|b| b == b'.') {
        return Ok(seg.replace('.', "%2E"));
    }
    Ok(seg)
}

/// An encoded `/` or `\` anywhere in the raw path.
pub fn encoded_separator(raw_path: &str) -> bool {
    let l = raw_path.to_ascii_lowercase();
    l.contains("%2f") || l.contains("%5c")
}

pub fn forwarded_param(value: &str, raw_path: &str) -> Result<String, ()> {
    if encoded_separator(raw_path) || value == "." || value == ".." {
        return Err(());
    }
    path_segment(value)
}

pub fn tail_path(path: &str, raw_path: &str) -> Result<String, ()> {
    if encoded_separator(raw_path) {
        return Err(());
    }
    let mut out = Vec::new();
    for seg in path.split('/') {
        if seg == "." || seg == ".." {
            return Err(());
        }
        out.push(path_segment(seg)?);
    }
    Ok(out.join("/"))
}

/// The path httpx sends for a URL: its `normalize_path` (a `.` segment dropped, a `..` segment
/// popping the one before it).
pub fn remove_dot_segments(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if !parts.iter().any(|s| *s == "." || *s == "..") {
        return path.to_owned();
    }
    let mut out: Vec<&str> = Vec::new();
    for s in parts {
        match s {
            "." => {}
            ".." => {
                if !out.is_empty() && out != [""] {
                    out.pop();
                }
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_and_dots() {
        assert_eq!(path_segment("a b/?#").unwrap(), "a%20b%2F%3F%23");
        assert_eq!(path_segment("..").unwrap(), "%2E%2E");
        assert!(path_segment("a\nb").is_err());
        assert!(tail_path("a/../b", "/x").is_err());
        assert!(forwarded_param("x", "/agent/a%2Fb").is_err());
        assert_eq!(remove_dot_segments("/user/directory/profiles/.."), "/user/directory");
        assert_eq!(remove_dot_segments("/b/../c"), "/c");
        assert_eq!(remove_dot_segments("/x/./y"), "/x/y");
    }
}
