//! The runtime's config.v1 checks (ADR-0026), read from its declaration
//! (`core/runtime/src/runtime_kernel/config.v1.json`): the boot preflight,
//! the caller-token rules, and the capability rows of `/health`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use vexa_native_kit::json::{self, object, Value};

pub const TOKEN_ENV: &str = "RUNTIME_API_TOKEN";
/// A caller token shorter than this is refused at boot.
pub const MIN_TOKEN_BYTES: usize = 32;

const CONFIGURED: &str = "configured";
const NOT_CONFIGURED: &str = "not_configured";
const MISCONFIGURED: &str = "misconfigured";

pub struct Declaration {
    service: String,
    /// (key, class, capability, forbidden values, description)
    keys: Vec<(String, String, String, Vec<String>, String)>,
    /// (name, mode, probe)
    capabilities: Vec<(String, String, Option<Value>)>,
    probes: Mutex<BTreeMap<String, (Instant, Value)>>,
}

fn is_set(env: &BTreeMap<String, String>, key: &str) -> bool {
    env.get(key).is_some_and(|v| !v.trim().is_empty())
}

impl Declaration {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let decl = json::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let text_of = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let keys = decl
            .get("keys")
            .and_then(Value::as_array)
            .unwrap_or(&[])
            .iter()
            .map(|k| {
                let forbidden = k
                    .get("forbidden_values")
                    .and_then(Value::as_array)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect();
                (text_of(k, "key"), text_of(k, "class"), text_of(k, "capability"), forbidden, text_of(k, "description"))
            })
            .collect::<Vec<_>>();
        let capabilities = decl
            .get("capabilities")
            .and_then(Value::as_object)
            .unwrap_or(&[])
            .iter()
            .map(|(name, cap)| {
                let mode = cap.get("mode").and_then(Value::as_str).unwrap_or("all").to_owned();
                (name.clone(), mode, cap.get("probe").cloned())
            })
            .collect::<Vec<(String, String, Option<Value>)>>();
        for (key, class, capability, _, _) in &keys {
            if class == "capability" && !capabilities.iter().any(|(n, _, _)| n == capability) {
                return Err(format!("config.v1 declaration is inconsistent: key {key:?} names undeclared capability {capability:?}"));
            }
        }
        Ok(Self { service: text_of(&decl, "service"), keys, capabilities, probes: Mutex::new(BTreeMap::new()) })
    }

    /// Refuse to boot on a missing required-explicit key or a key holding a
    /// published placeholder (the Python `preflight`).
    pub fn preflight(&self, env: &BTreeMap<String, String>) -> Result<(), String> {
        let missing: Vec<String> = self
            .keys
            .iter()
            .filter(|(key, class, ..)| class == "required-explicit" && !is_set(env, key))
            .map(|(key, .., description)| format!("{key} ({description})"))
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "{} is misconfigured and refuses to boot — required environment variable(s) not set: {}.",
                self.service,
                missing.join("; ")
            ));
        }
        let placeheld: Vec<&str> = self
            .keys
            .iter()
            .filter(|(key, _, _, forbidden, _)| {
                let value = env.get(key).map(|v| v.trim()).unwrap_or("");
                !forbidden.is_empty() && forbidden.iter().any(|f| f == value)
            })
            .map(|(key, ..)| key.as_str())
            .collect();
        if !placeheld.is_empty() {
            return Err(format!(
                "{} is misconfigured and refuses to boot — {} still hold(s) a documented PLACEHOLDER value.",
                self.service,
                placeheld.join(", ")
            ));
        }
        Ok(())
    }

    /// The caller token, or why the runtime must not serve with it.
    pub fn caller_token(&self, env: &BTreeMap<String, String>) -> Result<String, String> {
        let token = env.get(TOKEN_ENV).map(|t| t.trim().to_owned()).unwrap_or_default();
        if token.is_empty() {
            return Err(format!("{TOKEN_ENV} is not set — the runtime refuses to serve its workload API without a caller credential."));
        }
        let published = self.keys.iter().any(|(key, _, _, forbidden, _)| key == TOKEN_ENV && forbidden.contains(&token));
        if published {
            return Err(format!("{TOKEN_ENV} holds a value published in the Vexa repository — generate a real one"));
        }
        if token.len() < MIN_TOKEN_BYTES {
            return Err(format!("{TOKEN_ENV} must be at least {MIN_TOKEN_BYTES} bytes"));
        }
        Ok(token)
    }

    fn states(&self, env: &BTreeMap<String, String>) -> Vec<(String, &'static str, Option<Value>)> {
        self.capabilities
            .iter()
            .map(|(name, mode, probe)| {
                let keys: Vec<&str> = self
                    .keys
                    .iter()
                    .filter(|(_, class, capability, ..)| class == "capability" && capability == name)
                    .map(|(key, ..)| key.as_str())
                    .collect();
                let present = keys.iter().filter(|k| is_set(env, k)).count();
                let state = if mode == "any" {
                    if present > 0 { CONFIGURED } else { NOT_CONFIGURED }
                } else if !keys.is_empty() && present == keys.len() {
                    CONFIGURED
                } else if present == 0 {
                    NOT_CONFIGURED
                } else {
                    MISCONFIGURED
                };
                (name.clone(), state, probe.clone())
            })
            .collect()
    }

    /// The `/health` capability rows: the tri-state per capability, and the
    /// probe verdict for a configured capability that declares one.
    pub fn capability_health(&self, env: &BTreeMap<String, String>) -> Value {
        let mut rows = Vec::new();
        for (name, state, probe) in self.states(env) {
            let mut row = object(vec![("state", state.into())]);
            if let (Some(spec), CONFIGURED) = (probe, state) {
                let result = self.cached_probe(&name, &spec, env);
                if result.get("ok").and_then(Value::as_bool) != Some(true) {
                    row.set("state", MISCONFIGURED.into());
                }
                row.set("probe", result);
            }
            rows.push((name, row));
        }
        Value::Object(rows)
    }

    fn cached_probe(&self, name: &str, spec: &Value, env: &BTreeMap<String, String>) -> Value {
        let ttl = Duration::from_secs_f64(spec.get("ttl_s").and_then(Value::as_f64).filter(|t| *t > 0.0).unwrap_or(60.0));
        let mut cache = self.probes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, result)) = cache.get(name) {
            if at.elapsed() < ttl {
                return result.clone();
            }
        }
        let result = match spec.get("kind").and_then(Value::as_str) {
            Some("file") => file_probe(spec.get("file").unwrap_or(&Value::Null), env),
            // The runtime declares only file probes; an HTTP probe is not run here.
            Some("http") => object(vec![("ok", true.into()), ("skipped", "the native runtime does not run HTTP probes".into())]),
            other => object(vec![("ok", false.into()), ("reason", format!("unknown probe kind {other:?}").into())]),
        };
        cache.insert(name.to_owned(), (Instant::now(), result.clone()));
        result
    }
}

/// A credentials file as this service sees it: a regular, readable, non-empty JSON file.
fn file_probe(spec: &Value, env: &BTreeMap<String, String>) -> Value {
    let key = spec.get("path_key").and_then(Value::as_str).unwrap_or("");
    let raw = env.get(key).map(|v| v.trim().to_owned()).unwrap_or_default();
    if raw.is_empty() {
        return object(vec![("ok", true.into()), ("skipped", format!("{key} unset — this credential path is not in use").into())]);
    }
    let mut paths = vec![raw];
    paths.extend(spec.get("fallback_paths").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|p| p.as_str().map(str::to_owned)));
    let mut tried = Vec::new();
    for path in paths {
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(_) => {
                tried.push(format!("{path}: not found"));
                continue;
            }
        };
        if !meta.is_file() {
            return object(vec![
                ("ok", false.into()),
                ("path", path.clone().into()),
                ("reason", format!("{path} is not a regular file — the host file behind {key} is absent").into()),
            ]);
        }
        let parsed = match std::fs::read_to_string(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return object(vec![
                    ("ok", true.into()),
                    ("path", path.clone().into()),
                    ("unverified", format!("{path}: permission denied to this service; not checked here").into()),
                ])
            }
            Err(_) => None,
            Ok(text) => json::parse(&text).ok(),
        };
        return match parsed {
            None => object(vec![("ok", false.into()), ("path", path.clone().into()), ("reason", format!("{path}: unreadable or not JSON").into())]),
            Some(v) if matches!(&v, Value::Null | Value::Bool(false)) || v.as_object().is_some_and(<[_]>::is_empty) || v.as_array().is_some_and(<[_]>::is_empty) || v.as_str() == Some("") => {
                object(vec![("ok", false.into()), ("path", path.clone().into()), ("reason", format!("{path}: empty credentials JSON").into())])
            }
            Some(_) => object(vec![("ok", true.into()), ("path", path.into())]),
        };
    }
    object(vec![("ok", false.into()), ("reason", tried.join("; ").into())])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration() -> Declaration {
        let dir = std::env::temp_dir().join(format!("vexa-preflight-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.v1.json");
        std::fs::write(
            &path,
            r#"{"service":"runtime","capabilities":{"scheduler":{"mode":"all"},"model":{"mode":"any","probe":{"kind":"file","file":{"path_key":"CRED"}}}},
               "keys":[{"key":"RUNTIME_API_TOKEN","class":"required-explicit","description":"the caller token","forbidden_values":["changeme-runtime-token-0123456789abcdef"]},
                       {"key":"REDIS_URL","class":"capability","capability":"scheduler"},
                       {"key":"CRED","class":"capability","capability":"model"}]}"#,
        )
        .unwrap();
        Declaration::load(&path).unwrap()
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn refuses_a_missing_or_placeholder_token() {
        let d = declaration();
        assert!(d.preflight(&env(&[])).unwrap_err().contains("RUNTIME_API_TOKEN (the caller token)"));
        assert!(d.preflight(&env(&[(TOKEN_ENV, "changeme-runtime-token-0123456789abcdef")])).unwrap_err().contains("PLACEHOLDER"));
        assert!(d.caller_token(&env(&[(TOKEN_ENV, "short")])).is_err());
        let good = "0123456789abcdef0123456789abcdef";
        assert!(d.preflight(&env(&[(TOKEN_ENV, good)])).is_ok());
        assert_eq!(d.caller_token(&env(&[(TOKEN_ENV, good)])).unwrap(), good);
    }

    #[test]
    fn reports_capability_rows() {
        let d = declaration();
        let rows = d.capability_health(&env(&[("REDIS_URL", "redis://x"), ("CRED", "/nonexistent/creds.json")]));
        assert_eq!(rows.get("scheduler").unwrap().get("state").unwrap().as_str(), Some("configured"));
        let model = rows.get("model").unwrap();
        assert_eq!(model.get("state").unwrap().as_str(), Some("misconfigured"));
        assert_eq!(model.get("probe").unwrap().get("ok").unwrap().as_bool(), Some(false));
        let none = d.capability_health(&env(&[]));
        assert_eq!(none.get("model").unwrap().get("state").unwrap().as_str(), Some("not_configured"));
        assert!(none.get("model").unwrap().get("probe").is_none());
    }
}
