//! routes.v1: the edge assembles its route table from the manifests of the domains it fronts, and
//! refuses to boot on a manifest (or a combination) it cannot read one way.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::Value;
use vexa_native_kit::pyjson::py_repr;

pub const CATCH_ALL: &str = "{path:path}";
const SCOPES: [&str; 3] = ["bot", "tx", "browser"];
const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
const EDGE_DOMAIN: &str = "gateway";

pub type Key = (String, String);

#[derive(Default, Debug)]
pub struct Assembly {
    pub scopes: HashMap<Key, BTreeSet<String>>,
    pub unscoped: HashSet<Key>,
    pub domains: BTreeMap<String, usize>,
    pub owner_of: BTreeMap<Key, String>,
    pub delegation: HashSet<Key>,
    pub mcp_reentry: HashSet<Key>,
    pub stream: HashSet<Key>,
    pub shared_allow: HashSet<Key>,
    pub forwards: HashMap<String, (String, String)>,
    pub upstream: HashMap<Key, String>,
}

pub fn manifest_path(root: &Path, domain: &str) -> Option<PathBuf> {
    let rel = match domain {
        "gateway" => "core/gateway/services/gateway/routes.v1.json",
        "meetings" => "core/meetings/routes.v1.json",
        "identity" => "core/identity/routes.v1.json",
        "mcp" => "core/gateway/services/mcp/routes.v1.json",
        "agent" => "core/agent/routes.v1.json",
        "crm" => "core/crm/routes.v1.json",
        _ => return None,
    };
    Some(root.join(rel))
}

fn read(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| format!("{} is missing — a deployed domain must declare its routes", path.display()))?;
    let doc: Value = serde_json::from_str(&text).map_err(|e| format!("{} is not readable JSON: {e}", path.display()))?;
    if doc.get("contract").and_then(Value::as_str) != Some("routes.v1") {
        return Err(format!("{} declares contract {}, not 'routes.v1'", path.display(), py_repr(doc.get("contract").unwrap_or(&Value::Null))));
    }
    if !vexa_native_kit::pyjson::truthy(doc.get("domain")) {
        return Err(format!("{} names no domain", path.display()));
    }
    Ok(doc)
}

/// One whole path segment that is a parameter: `{name}`.
fn param_segment(s: &str) -> Option<&str> {
    let name = s.strip_prefix('{')?.strip_suffix('}')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    ((first.is_ascii_alphabetic() || first == '_') && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')).then_some(name)
}

/// The whole-segment `{name}` parameters of a row template, in order.
pub fn params_of(path: &str) -> Vec<String> {
    path.split('/').filter_map(param_segment).map(str::to_owned).collect()
}

fn segments_ok<'a>(segments: impl Iterator<Item = &'a str>, allow_empty: bool) -> bool {
    let mut names = Vec::new();
    for s in segments {
        if s.is_empty() && !allow_empty {
            return false;
        }
        if s.contains('{') || s.contains('}') {
            match param_segment(s) {
                Some(n) if !names.contains(&n) => names.push(n),
                _ => return false,
            }
        }
    }
    true
}

fn forwardable(tail: &str) -> bool {
    !tail.is_empty() && (tail == CATCH_ALL || segments_ok(tail.split('/'), true))
}

fn template(v: &Value) -> bool {
    match v.as_str() {
        Some(s) if s.starts_with('/') && s != "/" => segments_ok(s.split('/').skip(1), false),
        _ => false,
    }
}

fn prefix(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    (s.starts_with('/') && s.ends_with('/') && !s.contains('{')).then(|| s.to_owned())
}

fn flag(domain: &str, row: &Value, name: &str) -> Result<bool, String> {
    match row.get(name) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(other) => Err(format!(
            "{domain}: {} {} — {name} must be true or false (got {})",
            row.get("method").map(vexa_native_kit::pyjson::py_str).unwrap_or("None".into()),
            row.get("path").map(vexa_native_kit::pyjson::py_str).unwrap_or("None".into()),
            py_repr(other)
        )),
    }
}

pub fn assemble(docs: &[Value]) -> Result<Assembly, String> {
    let mut out = Assembly::default();
    for doc in docs {
        let domain = vexa_native_kit::pyjson::py_str(&doc["domain"]);
        let empty = Vec::new();
        let rows = doc.get("routes").and_then(Value::as_array).unwrap_or(&empty);
        let forward = match doc.get("forward") {
            None | Some(Value::Null) => None,
            Some(raw) => {
                let edge = prefix(raw.get("edge_prefix"));
                let up = prefix(raw.get("upstream_prefix"));
                match (edge, up) {
                    (Some(e), Some(u)) => Some((e, u)),
                    _ => {
                        return Err(format!(
                            "{domain}: forward must be {{\"edge_prefix\": \"/x/\", \"upstream_prefix\": \"/y/\"}} — two absolute prefixes that end at a segment (got {})",
                            py_repr(raw)
                        ))
                    }
                }
            }
        };
        if let Some(f) = &forward {
            out.forwards.insert(domain.clone(), f.clone());
        }
        for row in rows {
            let method = row.get("method").map(vexa_native_kit::pyjson::py_str).unwrap_or_default().to_uppercase();
            let path = row.get("path").map(vexa_native_kit::pyjson::py_str).unwrap_or_default();
            if !METHODS.contains(&method.as_str()) {
                return Err(format!("{domain}: '{method}' is not an HTTP method ({path})"));
            }
            if !path.starts_with('/') {
                return Err(format!("{domain}: '{path}' is not a route template"));
            }
            let scopes: BTreeSet<String> = row
                .get("scopes")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(vexa_native_kit::pyjson::py_str).collect())
                .unwrap_or_default();
            let unknown: Vec<&String> = scopes.iter().filter(|s| !SCOPES.contains(&s.as_str())).collect();
            if !unknown.is_empty() {
                return Err(format!("{domain}: {method} {path} names scope(s) {unknown:?} outside the vocabulary ['bot', 'browser', 'tx']"));
            }
            let key = (method.clone(), path.clone());
            if let Some(owner) = out.owner_of.get(&key) {
                return Err(format!("{method} {path} is declared by both '{owner}' and '{domain}' — one route, one owner; the edge composes and cannot arbitrate"));
            }
            out.owner_of.insert(key.clone(), domain.clone());
            if scopes.is_empty() {
                out.unscoped.insert(key.clone());
            } else {
                out.scopes.insert(key.clone(), scopes.clone());
            }
            let delegation = flag(&domain, row, "delegation")?;
            if delegation {
                if scopes.is_empty() {
                    return Err(format!("{domain}: {method} {path} is unscoped and cannot admit a delegation"));
                }
                out.delegation.insert(key.clone());
            }
            if flag(&domain, row, "mcp_reentry")? {
                if delegation {
                    return Err(format!("{domain}: {method} {path} declares both delegation and mcp_reentry"));
                }
                if scopes.is_empty() && domain != EDGE_DOMAIN {
                    return Err(format!("{domain}: {method} {path} is unscoped and cannot admit the MCP's re-entry"));
                }
                if path.ends_with(CATCH_ALL) {
                    return Err(format!("{domain}: {method} {path} is a catch-all and cannot admit the MCP's re-entry"));
                }
                out.mcp_reentry.insert(key.clone());
            }
            if let Some(up) = row.get("upstream") {
                if let Some(f) = &forward {
                    return Err(format!("{domain}: {method} {path} declares an upstream, but the domain is forwarded wholesale — its forward ({} -> {}) is the one mapping", f.0, f.1));
                }
                if !template(up) {
                    return Err(format!("{domain}: {method} {path} — upstream must be a route template of literal segments and whole {{name}} parameters (got {})", py_repr(up)));
                }
                let up = up.as_str().unwrap_or_default().to_owned();
                let mine = params_of(&path);
                let mut extra: Vec<String> = params_of(&up).into_iter().filter(|p| !mine.contains(p)).collect();
                extra.sort();
                if !extra.is_empty() {
                    return Err(format!("{domain}: {method} {path} — upstream {up} names {extra:?}, which the row does not match"));
                }
                out.upstream.insert(key.clone(), up);
            }
            match row.get("shared") {
                None | Some(Value::Null) => {}
                Some(Value::String(s)) if s == "allow" => {
                    out.shared_allow.insert(key.clone());
                }
                Some(Value::String(s)) if s == "refuse" => {}
                Some(other) => return Err(format!("{domain}: {method} {path} — shared must be allow or refuse (got {})", py_repr(other))),
            }
            let stream = flag(&domain, row, "stream")?;
            if let Some((edge, _)) = &forward {
                let tail = path.strip_prefix(edge.as_str());
                if !tail.is_some_and(forwardable) {
                    return Err(format!("{domain}: {method} {path} is outside its forward ({edge}…)"));
                }
                if stream && tail == Some(CATCH_ALL) {
                    return Err(format!("{domain}: {method} {path} — only a literal row streams"));
                }
            } else if stream {
                return Err(format!("{domain}: {method} {path} — stream applies to a forwarded domain's literal rows only"));
            }
            if stream {
                out.stream.insert(key);
            }
        }
        out.domains.insert(domain, rows.len());
    }
    Ok(out)
}

/// Assemble the table from the manifests of the domains this deployment runs (sorted by name).
pub fn load(root: &Path, present: &BTreeSet<String>) -> Result<Assembly, String> {
    let mut docs = Vec::new();
    for d in present {
        let path = manifest_path(root, d).ok_or_else(|| format!("no routes.v1 manifest is known for domain(s) ['{d}']"))?;
        docs.push(read(&path)?);
    }
    assemble(&docs)
}

/// The checkout root: walked up from the binary (and the working directory) to the first directory
/// holding `core/gateway` and `core/meetings`; `VEXA_SOURCE_DIR` names it outright.
pub fn repo_root() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("VEXA_SOURCE_DIR") {
        if !dir.trim().is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let starts = [std::env::current_exe().ok(), std::env::current_dir().ok()];
    for start in starts.into_iter().flatten() {
        for p in start.ancestors() {
            if p.join("core/gateway").is_dir() && p.join("core/meetings").is_dir() {
                return Ok(p.to_path_buf());
            }
        }
    }
    Err("cannot find the repository root — the gateway must carry the routes.v1 manifests of the domains it fronts (set VEXA_SOURCE_DIR)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_the_checkout_and_refuses_duplicates() {
        let root = repo_root().unwrap();
        let present: BTreeSet<String> = ["gateway", "meetings", "identity", "mcp", "agent", "crm"].iter().map(|s| s.to_string()).collect();
        let a = load(&root, &present).unwrap();
        assert!(a.unscoped.contains(&("GET".into(), "/health".into())));
        assert_eq!(a.forwards["agent"], ("/agent/".into(), "/api/".into()));
        let doc = serde_json::json!({"contract": "routes.v1", "domain": "x", "routes": [{"method": "GET", "path": "/a", "scopes": ["bot"]}]});
        assert!(assemble(&[doc.clone(), doc]).unwrap_err().contains("declared by both"));
        assert_eq!(params_of("/a/{b}/c/{d}/{path:path}"), vec!["b", "d"]);
    }
}
