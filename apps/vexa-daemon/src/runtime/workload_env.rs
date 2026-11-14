//! What a caller may say about a workload's environment and what only the
//! runtime decides (`runtime_kernel.workload_env` and the process backend's
//! child environment).

use std::collections::BTreeMap;

use vexa_native_kit::json::{self, Value};
use vexa_native_kit::sha256;

/// Spec env keys only the runtime may set. A caller-supplied value is dropped.
pub const RUNTIME_OWNED_PREFIXES: [&str; 2] = ["RUNTIME_K8S_", "VEXA_WORKSPACE_MOUNT_"];
pub const STORE_SOURCE_ENV: &str = "VEXA_WORKSPACE_MOUNT_SOURCE";
pub const STORE_TARGET_ENV: &str = "VEXA_WORKSPACE_MOUNT_TARGET";
pub const EXTRA_SOURCES_ENV: &str = "RUNTIME_EXTRA_MOUNT_SOURCES";
pub const DEFAULT_STORE_TARGET: &str = "/workspaces";
pub const MOUNTS_ENV: &str = "VEXA_MOUNTS";
pub const WORKSPACE_PATH_ENV: &str = "VEXA_WORKSPACE_PATH";

/// The deployment dials an agent worker receives from the runtime's own
/// environment (the agent profile's forward list). No model route and no
/// model credential is among them.
pub const WORKER_FORWARD_ENV: [&str; 16] = [
    "VEXA_MODEL_ALLOWLIST",
    "VEXA_MIDTURN_INJECT",
    "VEXA_AGENT_MAX_TOOL_CALLS",
    "VEXA_AGENT_MAX_TURN_SEC",
    "VEXA_AGENT_MAX_TOOL_CALLS_CHAT",
    "VEXA_AGENT_MAX_TOOL_CALLS_JOB",
    "VEXA_AGENT_MAX_TOOL_CALLS_ROOM",
    "VEXA_AGENT_MAX_TOOL_CALLS_FLOW",
    "VEXA_AGENT_JOB_MAX_TOOL_CALLS",
    "VEXA_AGENT_JOB_MAX_TURN_SEC",
    "VEXA_AGENT_CONTEXT_TOKENS",
    "VEXA_AGENT_STREAM",
    "VEXA_AGENT_MAX_OUTPUT_TOKENS",
    "VEXA_SEARCH_URL",
    "VEXA_SEARCH_DIALECT",
    "VEXA_SEARCH_API_KEY",
];

/// What a child process inherits from the runtime's environment besides its
/// profile's forward list: what any program needs to run on this host. Never
/// product configuration and never a service credential.
pub const PROCESS_PLUMBING_ENV: [&str; 31] = [
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TZ", "TMPDIR",
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE",
    "PLAYWRIGHT_BROWSERS_PATH", "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "PNPM_HOME", "NODE_ENV", "CI",
    "VEXA_HF_CACHE", "VEXA_IMAGE_VERSION",
    "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
];

/// A mount set the runtime does not serve (a 400 at the API).
#[derive(Debug)]
pub struct MountRefused(pub String);

/// `raw` as one file-name component: unchanged when it already is one
/// (`[a-zA-Z0-9][a-zA-Z0-9_.-]+`); otherwise each run of other characters
/// becomes `-` and a hash of `raw` is appended. Never holds `/` and never
/// starts with `.`.
pub fn name_component(raw: &str) -> String {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-');
    let mut chars = raw.chars();
    let valid = raw.chars().count() >= 2
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(allowed);
    if valid {
        return raw.to_owned();
    }
    let mut base = String::new();
    let mut in_run = false;
    for c in raw.chars() {
        if allowed(c) {
            base.push(c);
            in_run = false;
        } else if !in_run {
            base.push('-');
            in_run = true;
        }
    }
    let base = base.trim_matches(['-', '_', '.']);
    let digest = &sha256::hex(&sha256::digest(raw.as_bytes()))[..10];
    if base.is_empty() {
        format!("w-{digest}")
    } else {
        format!("{base}-{digest}")
    }
}

/// The runtime's own view of the workspace store.
#[derive(Debug, Clone, PartialEq)]
pub struct StoreConfig {
    pub source: String,
    pub target: String,
    pub extra_sources: Vec<String>,
}

fn normpath(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

/// `path` as a normalized absolute path; relative paths and `..` are refused.
fn clean_abs(path: &str, what: &str) -> Result<String, MountRefused> {
    if !path.starts_with('/') || path.split('/').any(|p| p == "..") {
        return Err(MountRefused(format!("{what} must be an absolute path without '..' segments")));
    }
    Ok(normpath(path))
}

impl StoreConfig {
    pub fn from_env(env: &BTreeMap<String, String>) -> Result<Self, MountRefused> {
        let get = |k: &str| env.get(k).map(|v| v.trim().to_owned()).unwrap_or_default();
        let target = get(STORE_TARGET_ENV);
        let target = clean_abs(if target.is_empty() { DEFAULT_STORE_TARGET } else { &target }, STORE_TARGET_ENV)?;
        let mut extra_sources = Vec::new();
        for p in get(EXTRA_SOURCES_ENV).split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let clean = clean_abs(p, EXTRA_SOURCES_ENV)?;
            if !extra_sources.contains(&clean) {
                extra_sources.push(clean);
            }
        }
        Ok(Self { source: get(STORE_SOURCE_ENV), target, extra_sources })
    }
}

fn strictly_under(path: &str, root: &str) -> bool {
    path != root && path.starts_with(&format!("{}/", root.trim_end_matches('/')))
}

fn python_repr(value: Option<&Value>) -> String {
    match value.and_then(Value::as_str) {
        Some(s) => format!("'{s}'"),
        None => "None".to_owned(),
    }
}

/// The spec's mount set: `VEXA_MOUNTS` must be a JSON array of objects that
/// each carry a non-empty string `path`. Absent means none.
pub fn declared_mounts(env: &BTreeMap<String, String>) -> Result<Vec<Value>, MountRefused> {
    let raw = match env.get(MOUNTS_ENV) {
        None => return Ok(Vec::new()),
        Some(raw) if raw.is_empty() => return Ok(Vec::new()),
        Some(raw) => raw,
    };
    let data = json::parse(raw).map_err(|_| MountRefused(format!("{MOUNTS_ENV} is not valid JSON")))?;
    let items = data.as_array().map(<[Value]>::to_vec).unwrap_or_default();
    let valid = data.as_array().is_some()
        && items.iter().all(|m| m.as_object().is_some() && m.get("path").and_then(Value::as_str).is_some_and(|p| !p.is_empty()));
    if !valid {
        return Err(MountRefused(format!("{MOUNTS_ENV} must be a JSON array of mount objects, each with a path")));
    }
    Ok(items)
}

/// Refuse any mount the runtime does not serve.
pub fn check_mounts(env: &BTreeMap<String, String>, store: &StoreConfig) -> Result<(), MountRefused> {
    for mount in declared_mounts(env)? {
        let path = clean_abs(mount.get("path").and_then(Value::as_str).unwrap_or(""), &format!("{MOUNTS_ENV} path"))?;
        if let Some(source) = mount.get("source").filter(|s| !matches!(s, Value::Null | Value::Bool(false)) && s.as_str() != Some("")) {
            let served = match source.as_str() {
                Some(s) => store.extra_sources.contains(&clean_abs(s, &format!("{MOUNTS_ENV} source"))?),
                None => false,
            };
            if !served {
                return Err(MountRefused(format!(
                    "{MOUNTS_ENV}: mount {} names a source this runtime does not serve",
                    python_repr(mount.get("slug"))
                )));
            }
        }
        if !strictly_under(&path, &store.target) {
            return Err(MountRefused(format!(
                "{MOUNTS_ENV}: mount {} is outside the workspace store",
                python_repr(mount.get("slug"))
            )));
        }
    }
    if let Some(cwd) = env.get(WORKSPACE_PATH_ENV).filter(|c| !c.is_empty()) {
        if !strictly_under(&clean_abs(cwd, WORKSPACE_PATH_ENV)?, &store.target) {
            return Err(MountRefused(format!("{WORKSPACE_PATH_ENV} is outside the workspace store")));
        }
    }
    Ok(())
}

/// The environment a backend receives for one workload.
pub fn workload_env(spec_env: &BTreeMap<String, String>, store: &StoreConfig) -> Result<BTreeMap<String, String>, MountRefused> {
    let mut env: BTreeMap<String, String> = spec_env
        .iter()
        .filter(|(k, _)| !RUNTIME_OWNED_PREFIXES.iter().any(|p| k.starts_with(p)))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    check_mounts(&env, store)?;
    let declares = |k: &str| env.get(k).is_some_and(|v| !v.is_empty());
    if declares(MOUNTS_ENV) || declares(WORKSPACE_PATH_ENV) {
        env.insert(STORE_TARGET_ENV.to_owned(), store.target.clone());
        if !store.source.is_empty() {
            env.insert(STORE_SOURCE_ENV.to_owned(), store.source.clone());
        }
    }
    Ok(env)
}

/// A child process's complete environment, built from scratch: host plumbing
/// from `parent`, the profile's `forward` keys the workload does not set, then
/// the workload's own `env`.
pub fn child_environment(env: &BTreeMap<String, String>, forward: &[&str], parent: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = PROCESS_PLUMBING_ENV
        .iter()
        .filter_map(|k| parent.get(*k).map(|v| (k.to_string(), v.clone())))
        .collect();
    for key in forward {
        if let Some(value) = parent.get(*key).filter(|v| !v.is_empty()) {
            if !env.contains_key(*key) {
                out.insert(key.to_string(), value.clone());
            }
        }
    }
    out.extend(env.iter().map(|(k, v)| (k.clone(), v.clone())));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn keeps_valid_names_and_hashes_others() {
        assert_eq!(name_component("mtg-1-abcdef12"), "mtg-1-abcdef12");
        let digest = |raw: &str| sha256::hex(&sha256::digest(raw.as_bytes()))[..10].to_owned();
        assert_eq!(name_component("chat/../x y"), format!("chat-..-x-y-{}", digest("chat/../x y")));
        assert_eq!(name_component(".hidden"), format!("hidden-{}", digest(".hidden")));
        assert_eq!(name_component("a"), format!("a-{}", &sha256::hex(&sha256::digest(b"a"))[..10]));
        assert!(name_component("///").starts_with("w-"));
    }

    #[test]
    fn refuses_mounts_outside_the_store() {
        let store = StoreConfig::from_env(&map(&[(STORE_TARGET_ENV, "/ws")])).unwrap();
        let inside = map(&[(MOUNTS_ENV, r#"[{"slug":"me","path":"/ws/me"}]"#)]);
        assert!(check_mounts(&inside, &store).is_ok());
        let outside = map(&[(MOUNTS_ENV, r#"[{"slug":"acme","path":"/etc/acme"}]"#)]);
        assert_eq!(
            check_mounts(&outside, &store).unwrap_err().0,
            "VEXA_MOUNTS: mount 'acme' is outside the workspace store"
        );
        let root = map(&[(MOUNTS_ENV, r#"[{"slug":"x","path":"/ws"}]"#)]);
        assert!(check_mounts(&root, &store).is_err());
        let dotdot = map(&[(MOUNTS_ENV, r#"[{"slug":"x","path":"/ws/../etc"}]"#)]);
        assert!(check_mounts(&dotdot, &store).is_err());
        let source = map(&[(MOUNTS_ENV, r#"[{"slug":"g","path":"/ws/g","source":"/srv/g"}]"#)]);
        assert!(check_mounts(&source, &store).is_err());
        let served = StoreConfig::from_env(&map(&[(STORE_TARGET_ENV, "/ws"), (EXTRA_SOURCES_ENV, "/srv/g")])).unwrap();
        assert!(check_mounts(&source, &served).is_ok());
        assert!(check_mounts(&map(&[(MOUNTS_ENV, "{}")]), &store).is_err());
        assert!(check_mounts(&map(&[(WORKSPACE_PATH_ENV, "/tmp")]), &store).is_err());
    }

    #[test]
    fn drops_runtime_owned_keys_and_adds_the_store() {
        let store = StoreConfig::from_env(&map(&[(STORE_TARGET_ENV, "/ws")])).unwrap();
        let env = workload_env(
            &map(&[("RUNTIME_K8S_X", "1"), (STORE_SOURCE_ENV, "/evil"), (WORKSPACE_PATH_ENV, "/ws/me"), ("A", "b")]),
            &store,
        )
        .unwrap();
        assert_eq!(env, map(&[(STORE_TARGET_ENV, "/ws"), (WORKSPACE_PATH_ENV, "/ws/me"), ("A", "b")]));
    }

    #[test]
    fn builds_the_child_environment_from_scratch() {
        let parent = map(&[("PATH", "/bin"), ("RUNTIME_API_TOKEN", "secret"), ("VEXA_AGENT_STREAM", "1"), ("VEXA_SEARCH_URL", "")]);
        let child = child_environment(&map(&[("X", "y")]), &WORKER_FORWARD_ENV, &parent);
        assert_eq!(child, map(&[("PATH", "/bin"), ("VEXA_AGENT_STREAM", "1"), ("X", "y")]));
        let set = child_environment(&map(&[("VEXA_AGENT_STREAM", "0")]), &WORKER_FORWARD_ENV, &parent);
        assert_eq!(set.get("VEXA_AGENT_STREAM").map(String::as_str), Some("0"));
    }
}
