//! Canonical CRM links in Markdown descriptions. Code examples are not graph edges.

use std::collections::BTreeSet;

use regex::Regex;

/// str.splitlines(): every line boundary Python knows.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = text.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(c, '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if brk {
            out.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' {
                if let Some((_, '\n')) = it.peek() {
                    it.next();
                    end += 1;
                }
            }
            start = end;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// re.sub(r'(`+).*?\1', '', text, flags=re.S), with the regex's backtracking.
fn strip_code_spans(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut kept = 0;
    while i < b.len() {
        if b[i] != b'`' {
            i += 1;
            continue;
        }
        let mut run = 0;
        while i + run < b.len() && b[i + run] == b'`' {
            run += 1;
        }
        let mut matched = None;
        for n in (1..=run).rev() {
            let needle = "`".repeat(n);
            if let Some(off) = text[i + n..].find(&needle) {
                matched = Some(i + n + off + n);
                break;
            }
        }
        match matched {
            Some(end) => {
                out.push_str(&text[kept..i]);
                i = end;
                kept = end;
            }
            None => i += 1,
        }
    }
    out.push_str(&text[kept..]);
    out
}

fn unquote_plus(s: &str) -> String {
    let s = s.replace('+', " ");
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(v) = hex {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn crm_references(markdown: &str) -> Vec<String> {
    let marker_re = Regex::new(r"^ {0,3}(`{3,}|~{3,})").unwrap();
    let mut prose = Vec::new();
    let mut fence: Option<String> = None;
    for line in splitlines(markdown) {
        let marker = marker_re.captures(line).map(|c| c[1].to_owned());
        if let Some(f) = &fence {
            if let Some(mk) = &marker {
                if mk.as_bytes()[0] == f.as_bytes()[0] && mk.len() >= f.len() {
                    fence = None;
                }
            }
            continue;
        }
        if let Some(mk) = marker {
            fence = Some(mk);
            continue;
        }
        prose.push(line);
    }
    let prose = strip_code_spans(&prose.join("\n"));
    let link = Regex::new(r"\[[^\]\n]*\]\((/crm\?[^\s)]+)\)").unwrap();
    let mut found = BTreeSet::new();
    let mut at = 0;
    while let Some(c) = link.captures_at(&prose, at) {
        let whole = c.get(0).unwrap();
        let before = prose[..whole.start()].chars().next_back();
        if matches!(before, Some('!') | Some('\\')) {
            at = whole.start() + 1;
            continue;
        }
        at = whole.end();
        let href = &c[1];
        let rest = &href["/crm?".len()..];
        let query = rest.split('#').next().unwrap_or("");
        for part in query.split('&') {
            let Some((k, v)) = part.split_once('=') else { continue };
            if unquote_plus(k) != "record" {
                continue;
            }
            let v = unquote_plus(v);
            if v.is_empty() {
                continue;
            }
            if let Some(u) = crate::val::parse_uuid(&v) {
                found.insert(u);
            }
        }
    }
    found.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_outside_code_only() {
        let id = "12345678-1234-5678-1234-567812345678";
        let md = format!("see [a](/crm?record={id})\n`[b](/crm?record=22345678-1234-5678-1234-567812345678)`\n```\n[c](/crm?record=32345678-1234-5678-1234-567812345678)\n```\n![i](/crm?record=42345678-1234-5678-1234-567812345678)");
        assert_eq!(crm_references(&md), vec![id.to_owned()]);
    }
}
