//! Deployment configuration, read once from the environment (config.v1.json is
//! the declaration), and the config.v1 boot preflight.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;

use crate::{obs, store, util};

pub const ROLES: [&str; 6] = ["agent", "human", "git", "bots", "sensors", "signals"];

#[derive(Debug, Clone)]
pub struct Settings {
    pub state_dir: PathBuf,
    pub key_files: BTreeMap<String, String>,
    pub store: String,
    pub store_key_file: String,
    pub openbao_addr: String,
    pub openbao_token_file: String,
    pub openbao_mount: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub product_redirect: String,
    pub identity_public_key_file: String,
}

pub type Env = BTreeMap<String, String>;

pub fn process_env() -> Env {
    std::env::vars().collect()
}

fn get(env: &Env, key: &str, default: &str) -> String {
    match env.get(key).map(String::as_str) {
        Some(v) if !v.is_empty() => v.trim().to_owned(),
        _ => default.trim().to_owned(),
    }
}

/// config.v1: the declaration this service ships (the Python service's own file).
pub const DECLARATION: &str = include_str!("../../../core/agent/services/credential-broker/src/credential_broker/config.v1.json");

/// The config.v1 boot preflight: every missing required-explicit key, in one
/// refusal; a placeholder value refuses too; one line per capability.
pub fn preflight(env: &Env) -> Result<(), String> {
    let decl: Value = serde_json::from_str(DECLARATION).map_err(|e| format!("config.v1 declaration: {e}"))?;
    let service = util::text(&decl, "service").to_owned();
    let keys = decl["keys"].as_array().cloned().unwrap_or_default();
    let set = |k: &str| env.get(k).is_some_and(|v| !v.trim().is_empty());
    let missing: Vec<String> = keys
        .iter()
        .filter(|e| util::text(e, "class") == "required-explicit" && !set(util::text(e, "key")))
        .map(|e| format!("{} ({})", util::text(e, "key"), util::text(e, "description")))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "{service} is misconfigured and refuses to boot — required environment variable(s) not set: {}. Each is declared required-explicit in this service's config.v1 declaration (config.v1.json, gate:config-contract); set them and restart.",
            missing.join("; ")
        ));
    }
    let placeheld: Vec<&str> = keys
        .iter()
        .filter(|e| {
            let forbidden = e["forbidden_values"].as_array().cloned().unwrap_or_default();
            let value = env.get(util::text(e, "key")).map(|v| v.trim().to_owned()).unwrap_or_default();
            forbidden.iter().any(|f| f.as_str() == Some(value.as_str()))
        })
        .map(|e| util::text(e, "key"))
        .collect();
    if !placeheld.is_empty() {
        return Err(format!(
            "{service} is misconfigured and refuses to boot — {} still hold(s) a documented PLACEHOLDER value. That literal is published in this repository, so it is not a secret: anyone can present it. Generate a real value (`openssl rand -hex 32`), set it on every service that shares the tier, and restart. The forbidden literals are declared per key in this service's config.v1 declaration (config.v1.json, gate:config-contract).",
            placeheld.join(", ")
        ));
    }
    let caps = decl["capabilities"].as_object().cloned().unwrap_or_default();
    let mut names: Vec<&String> = caps.keys().collect();
    names.sort();
    for name in names {
        let members: Vec<&str> = keys.iter().filter(|e| util::text(e, "capability") == name.as_str() && util::text(e, "class") == "capability").map(|e| util::text(e, "key")).collect();
        let present = members.iter().filter(|k| set(k)).count();
        let any = util::text(&caps[name], "mode") == "any";
        let state = if any {
            if present > 0 { "configured" } else { "not_configured" }
        } else if !members.is_empty() && present == members.len() {
            "configured"
        } else if present == 0 {
            "not_configured"
        } else {
            "misconfigured"
        };
        obs::info("config_capability", serde_json::json!({"capability": name, "state": state}));
    }
    Ok(())
}

/// load(): refuse a configuration the broker cannot honour, naming each problem.
pub fn load(env: &Env) -> Result<Settings, String> {
    let mut key_files = BTreeMap::new();
    for role in ROLES {
        key_files.insert(role.to_owned(), get(env, &format!("VEXA_CONNECTIONS_{}_KEY_FILE", role.to_uppercase()), ""));
    }
    let s = Settings {
        state_dir: PathBuf::from(get(env, "VEXA_CONNECTIONS_STATE_DIR", "/state")),
        key_files,
        store: get(env, "VEXA_CONNECTIONS_STORE", "local"),
        store_key_file: get(env, "VEXA_CONNECTIONS_STORE_KEY_FILE", ""),
        openbao_addr: get(env, "VEXA_CONNECTIONS_OPENBAO_ADDR", ""),
        openbao_token_file: get(env, "VEXA_CONNECTIONS_OPENBAO_TOKEN_FILE", ""),
        openbao_mount: get(env, "VEXA_CONNECTIONS_OPENBAO_MOUNT", "connections"),
        google_client_id: get(env, "VEXA_CONNECTIONS_GOOGLE_CLIENT_ID", ""),
        google_client_secret: get(env, "VEXA_CONNECTIONS_GOOGLE_CLIENT_SECRET", ""),
        product_redirect: get(env, "VEXA_CONNECTIONS_PRODUCT_REDIRECT", ""),
        identity_public_key_file: get(env, "VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE", ""),
    };
    let mut problems = Vec::new();
    if s.identity_public_key_file.is_empty() {
        problems.push("VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE must name the gateway's identity public key (no agent-role call can be verified without it)".to_owned());
    }
    if s.store == "local" && s.store_key_file.is_empty() {
        problems.push("VEXA_CONNECTIONS_STORE=local needs VEXA_CONNECTIONS_STORE_KEY_FILE".to_owned());
    } else if s.store == "openbao" && (s.openbao_addr.is_empty() || s.openbao_token_file.is_empty()) {
        problems.push("VEXA_CONNECTIONS_STORE=openbao needs VEXA_CONNECTIONS_OPENBAO_ADDR and VEXA_CONNECTIONS_OPENBAO_TOKEN_FILE".to_owned());
    } else if s.store == "openbao" && !store::address_allowed(&s.openbao_addr) {
        problems.push("VEXA_CONNECTIONS_OPENBAO_ADDR must be https:// (plain http:// only to a loopback address on this host), with no credentials, query or fragment".to_owned());
    } else if s.store != "local" && s.store != "openbao" {
        problems.push("VEXA_CONNECTIONS_STORE must be `local` or `openbao`".to_owned());
    }
    if !s.product_redirect.is_empty() {
        let ok = util::urlsplit(&s.product_redirect).is_ok_and(|p| {
            p.scheme == "https" && !p.netloc.is_empty() && p.path == "/api/auth/callback/google" && p.query.is_empty() && p.fragment.is_empty() && p.username().is_none() && p.password().is_none()
        });
        if !ok {
            problems.push("VEXA_CONNECTIONS_PRODUCT_REDIRECT must be https://<terminal>/api/auth/callback/google".to_owned());
        }
    }
    if !problems.is_empty() {
        return Err(format!("credential-broker refuses to boot: {}", problems.join("; ")));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn refuses_what_the_python_settings_refuse() {
        let base = [("VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE", "/k"), ("VEXA_CONNECTIONS_STORE_KEY_FILE", "/s")];
        assert!(load(&env(&base)).is_ok());
        let e = load(&env(&[])).unwrap_err();
        assert!(e.contains("VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE") && e.contains("needs VEXA_CONNECTIONS_STORE_KEY_FILE"), "{e}");
        let mut bad = base.to_vec();
        bad.push(("VEXA_CONNECTIONS_STORE", "s3"));
        assert!(load(&env(&bad)).unwrap_err().contains("must be `local`"));
        let mut bao = base.to_vec();
        bao.extend([("VEXA_CONNECTIONS_STORE", "openbao"), ("VEXA_CONNECTIONS_OPENBAO_ADDR", "http://vault:8200"), ("VEXA_CONNECTIONS_OPENBAO_TOKEN_FILE", "/t")]);
        assert!(load(&env(&bao)).unwrap_err().contains("must be https://"));
        let mut redirect = base.to_vec();
        redirect.push(("VEXA_CONNECTIONS_PRODUCT_REDIRECT", "http://app/api/auth/callback/google"));
        assert!(load(&env(&redirect)).unwrap_err().contains("PRODUCT_REDIRECT"));
        redirect.pop();
        redirect.push(("VEXA_CONNECTIONS_PRODUCT_REDIRECT", "https://app.example/api/auth/callback/google"));
        assert!(load(&env(&redirect)).is_ok());
    }

    #[test]
    fn preflight_names_every_missing_required_key() {
        let e = preflight(&env(&[])).unwrap_err();
        for key in ["VEXA_CONNECTIONS_AGENT_KEY_FILE", "VEXA_CONNECTIONS_HUMAN_KEY_FILE", "VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE"] {
            assert!(e.contains(key), "{key}");
        }
        assert!(preflight(&env(&[("VEXA_CONNECTIONS_AGENT_KEY_FILE", "a"), ("VEXA_CONNECTIONS_HUMAN_KEY_FILE", "h"), ("VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE", "g")])).is_ok());
    }
}
