//! config.v1 preflight — the boot-time deployment-config validator over crm-api's declaration
//! (`config.v1.json`, embedded at build time).
//!
//! * **required-explicit** — unset/empty at boot refuses the boot with ONE message naming every
//!   missing key;
//! * **defaulted** — the documented code default applies; nothing to enforce at boot;
//! * **capability** — the key belongs to a named capability whose tri-state is computed from the
//!   env: `configured` / `not_configured` / `misconfigured` (mode=all: some-but-not-all keys set).
//!   The service runs either way.
//!
//! Any key may carry **forbidden_values** — the placeholder literals a stock deploy surface once
//! supplied; a boot whose env holds one is refused beside the missing-key refusal. crm declares no
//! live probes. Env-level state is computed at call time.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::{Map, Value};

pub type Env = HashMap<String, String>;

pub const CONFIGURED: &str = "configured";
pub const NOT_CONFIGURED: &str = "not_configured";
pub const MISCONFIGURED: &str = "misconfigured";

/// The declaration, as the service vendors it.
const DECLARATION: &str = include_str!("../../../core/crm/src/crm/config.v1.json");

/// The environment of this process.
pub fn process_env() -> Env {
    std::env::vars().collect()
}

/// This service's config.v1 declaration. Err (ConfigError) when a `capability`-classed key names
/// an undeclared capability.
pub fn load_declaration() -> Result<&'static Value, String> {
    static DECL: OnceLock<Value> = OnceLock::new();
    let decl = DECL.get_or_init(|| serde_json::from_str(DECLARATION).expect("config.v1.json is JSON"));
    let caps = decl.get("capabilities").and_then(Value::as_object);
    for entry in keys(decl) {
        if s(entry, "class") == "capability" && !caps.is_some_and(|c| c.contains_key(&s(entry, "capability"))) {
            return Err(format!(
                "config.v1 declaration for {} is inconsistent: key {} names undeclared capability {}",
                repr(decl.get("service")), repr(entry.get("key")), repr(entry.get("capability"))
            ));
        }
    }
    Ok(decl)
}

fn keys(decl: &Value) -> &[Value] {
    decl.get("keys").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_owned()
}

fn repr(v: Option<&Value>) -> String {
    vexa_native_kit::pyjson::py_repr(v.unwrap_or(&Value::Null))
}

/// (env.get(key) or "").strip()
pub fn env_value<'a>(env: &'a Env, key: &str) -> &'a str {
    crate::val::strip(env.get(key).map(String::as_str).unwrap_or(""))
}

/// Empty counts as unset: deploy surfaces default absent vars to "".
pub fn is_set(env: &Env, key: &str) -> bool {
    !env_value(env, key).is_empty()
}

/// The env-level tri-state of every declared capability, in declaration order.
pub fn capability_states(env: &Env) -> Result<Map<String, Value>, String> {
    let decl = load_declaration()?;
    let empty = Map::new();
    let caps = decl.get("capabilities").and_then(Value::as_object).unwrap_or(&empty);
    let mut states = Map::new();
    for (name, cap) in caps {
        let members: Vec<String> = keys(decl).iter()
            .filter(|e| s(e, "class") == "capability" && s(e, "capability") == *name)
            .map(|e| s(e, "key")).collect();
        let present = members.iter().filter(|k| is_set(env, k)).count();
        let mode = cap.get("mode").and_then(Value::as_str).filter(|m| !m.is_empty()).unwrap_or("all");
        let state = if mode == "any" {
            if present > 0 { CONFIGURED } else { NOT_CONFIGURED }
        } else if !members.is_empty() && present == members.len() {
            CONFIGURED
        } else if present == 0 {
            NOT_CONFIGURED
        } else {
            MISCONFIGURED
        };
        states.insert(name.clone(), state.into());
    }
    Ok(states)
}

/// One capability's env-level tri-state. An undeclared name is Err (ConfigError).
pub fn capability_state(name: &str, env: &Env) -> Result<String, String> {
    let states = capability_states(env)?;
    match states.get(name) {
        Some(v) => Ok(v.as_str().unwrap_or("").to_owned()),
        None => Err(format!("capability {} is not declared in {}'s config.v1",
                            vexa_native_kit::pyjson::py_str_repr(name), repr(load_declaration()?.get("service")))),
    }
}

/// The unset member keys behind a not_configured/misconfigured capability.
pub fn missing_capability_keys(name: &str, env: &Env) -> Result<Vec<String>, String> {
    let decl = load_declaration()?;
    Ok(keys(decl).iter()
        .filter(|e| s(e, "class") == "capability" && s(e, "capability") == name)
        .map(|e| s(e, "key"))
        .filter(|k| !is_set(env, k))
        .collect())
}

/// The /health rows: `{"state": ...}` per capability (crm declares no probes).
pub fn capability_health(env: &Env) -> Result<Map<String, Value>, String> {
    Ok(capability_states(env)?.into_iter().map(|(name, state)| {
        let mut row = Map::new();
        row.insert("state".into(), state);
        (name, Value::Object(row))
    }).collect())
}

/// Boot-time validation of the declaration against `env`. Err (ConfigError) naming every missing
/// required-explicit key, or every key on a documented placeholder; logs one line per capability.
/// Returns `{"service", "capabilities"}`.
pub fn preflight_env(env: &Env) -> Result<Value, String> {
    let decl = load_declaration()?;
    let service = decl.get("service").map(vexa_native_kit::pyjson::py_str).unwrap_or_else(|| "None".into());
    let missing: Vec<&Value> = keys(decl).iter()
        .filter(|e| s(e, "class") == "required-explicit" && !is_set(env, &s(e, "key")))
        .collect();
    if !missing.is_empty() {
        let detail = missing.iter().map(|e| format!("{} ({})", s(e, "key"), s(e, "description"))).collect::<Vec<_>>().join("; ");
        return Err(format!(
            "{service} is misconfigured and refuses to boot — required environment variable(s) not set: {detail}. \
             Each is declared required-explicit in this service's config.v1 declaration (config.v1.json, \
             gate:config-contract); set them and restart."
        ));
    }
    let placeheld: Vec<String> = keys(decl).iter()
        .filter(|e| {
            let forbidden = e.get("forbidden_values").and_then(Value::as_array).filter(|f| !f.is_empty());
            forbidden.is_some_and(|f| f.iter().any(|v| v.as_str() == Some(env_value(env, &s(e, "key")))))
        })
        .map(|e| s(e, "key"))
        .collect();
    if !placeheld.is_empty() {
        return Err(format!(
            "{service} is misconfigured and refuses to boot — {} still hold(s) a documented PLACEHOLDER value. \
             That literal is published in this repository, so it is not a secret: anyone can present it. \
             Generate a real value (`openssl rand -hex 32`), set it on every service that shares the tier, \
             and restart. The forbidden literals are declared per key in this service's config.v1 declaration \
             (config.v1.json, gate:config-contract).",
            placeheld.join(", ")
        ));
    }
    let rows = capability_health(env)?;
    let mut names: Vec<&String> = rows.keys().collect();
    names.sort_by(|a, b| a.chars().cmp(b.chars()));
    for name in names {
        let state = rows[name.as_str()]["state"].as_str().unwrap_or("");
        if state == MISCONFIGURED {
            eprintln!("WARNING:config.v1.preflight:config.v1 capability {name}: MISCONFIGURED — some-but-not-all keys set");
        } else {
            eprintln!("INFO:config.v1.preflight:config.v1 capability {name}: {state}");
        }
    }
    let mut out = Map::new();
    out.insert("service".into(), decl.get("service").cloned().unwrap_or(Value::Null));
    out.insert("capabilities".into(), Value::Object(rows));
    Ok(Value::Object(out))
}

/// The preflight crm-api runs before serving: on a refusal the ConfigError's last traceback line
/// goes to stderr and the process exits 1.
pub fn preflight() {
    if let Err(msg) = preflight_env(&process_env()) {
        eprintln!("Traceback (most recent call last):");
        eprintln!("crm.config_preflight.ConfigError: {msg}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    const FULL: &[(&str, &str)] = &[("CRM_DATABASE_URL", "postgresql+pg8000://u:p@h/d"), ("CRM_ORG_ID", "one"),
                                     ("ADMIN_API_URL", "http://admin"), ("INTERNAL_API_SECRET", "s3cr3t-real")];

    /// The Python module's answers for the same envs (crm.config_preflight.preflight).
    #[test]
    fn matches_python() {
        let expected: Value = serde_json::from_str(PY).unwrap();
        let got = |e: Env| match preflight_env(&e) { Ok(v) => v, Err(m) => Value::String(m) };
        assert_eq!(got(env(&[])), expected[0]);
        assert_eq!(got(env(&[("CRM_ORG_ID", " one "), ("INTERNAL_API_SECRET", "x")])), expected[1]);
        let mut e = env(FULL);
        e.insert("INTERNAL_API_SECRET".into(), " changeme ".into());
        e.insert("FLOWS_PUBLISH_KEY".into(), "secret".into());
        assert_eq!(got(e), expected[2]);
        assert_eq!(got(env(FULL)), expected[3]);
        let mut e = env(FULL);
        e.insert("VEXA_FACT_SEAL_KEY_FILE".into(), "/k".into());
        assert_eq!(got(e), expected[4]);
        assert_eq!(capability_state("nope", &env(&[])).unwrap_err(), expected[5]);
        assert_eq!(missing_capability_keys("fact_seal_key", &env(&[])).unwrap(), vec!["VEXA_FACT_SEAL_KEY_FILE".to_string()]);
    }

    const PY: &str = r##"["crm-api is misconfigured and refuses to boot \u2014 required environment variable(s) not set: CRM_DATABASE_URL (crm-api's own Postgres login (`postgresql+pg8000://<CRM_DB_USER>:<CRM_DB_PASSWORD>@host/db`), the role `python -m crm.migrate init` made: never a superuser, grants on the crm_* tables only. crm-api refuses any other driver, a superuser and any other schema version (`migrate.check`). The outbox (`python -m crm.outbox --watch`) and `crm.migrate check|migrate` log in with it too); CRM_ORG_ID (the one organisation this install's CRM serves (ADR-0047), never chosen by a caller. `crm.migrate init` creates it with its entity types; with `personal_crm` on, an individual is served from their org of one instead); ADMIN_API_URL (identity's internal door: every caller is resolved by `/internal/validate`, and with `personal_crm` on each person's home org by `GET /internal/users/{id}/org`. No host-port default: a deployment default names the service and lives in the deploy surface); INTERNAL_API_SECRET (the internal tier's secret: presented to identity on every caller resolution and to agent-api on the desk-limits read, and the credential crm-api's own /internal routes require. A published placeholder is refused outright (F95)). Each is declared required-explicit in this service's config.v1 declaration (config.v1.json, gate:config-contract); set them and restart.", "crm-api is misconfigured and refuses to boot \u2014 required environment variable(s) not set: CRM_DATABASE_URL (crm-api's own Postgres login (`postgresql+pg8000://<CRM_DB_USER>:<CRM_DB_PASSWORD>@host/db`), the role `python -m crm.migrate init` made: never a superuser, grants on the crm_* tables only. crm-api refuses any other driver, a superuser and any other schema version (`migrate.check`). The outbox (`python -m crm.outbox --watch`) and `crm.migrate check|migrate` log in with it too); ADMIN_API_URL (identity's internal door: every caller is resolved by `/internal/validate`, and with `personal_crm` on each person's home org by `GET /internal/users/{id}/org`. No host-port default: a deployment default names the service and lives in the deploy surface). Each is declared required-explicit in this service's config.v1 declaration (config.v1.json, gate:config-contract); set them and restart.", "crm-api is misconfigured and refuses to boot \u2014 INTERNAL_API_SECRET, FLOWS_PUBLISH_KEY still hold(s) a documented PLACEHOLDER value. That literal is published in this repository, so it is not a secret: anyone can present it. Generate a real value (`openssl rand -hex 32`), set it on every service that shares the tier, and restart. The forbidden literals are declared per key in this service's config.v1 declaration (config.v1.json, gate:config-contract).", {"service": "crm-api", "capabilities": {"fact_seal_key": {"state": "not_configured"}}}, {"service": "crm-api", "capabilities": {"fact_seal_key": {"state": "configured"}}}, "capability 'nope' is not declared in 'crm-api''s config.v1"]"##;
}
