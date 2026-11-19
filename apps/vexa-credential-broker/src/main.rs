//! credential-broker (credential-broker.v1) as a native process: the
//! Connections credential broker. Composition root: environment → preflight
//! → settings → store → broker → HTTP on 127.0.0.1.
//!
//!     vexa-credential-broker [serve] [--port N]
//!     vexa-credential-broker mail-secret put|delete <name>    (the value on stdin)
//!     vexa-credential-broker signals-key put|delete <name>    (the value on stdin)

mod assertion;
mod broker;
mod calendar;
mod config;
mod fail;
mod google;
mod identity;
mod lock;
mod metadata;
mod models;
mod net;
mod obs;
mod policy;
mod routes;
mod sensor_grants;
mod server;
mod service;
mod setup;
mod ssrf;
mod store;
mod tz;
mod util;

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use serde_json::json;

use crate::config::Settings;
use crate::store::{LocalEncryptedStore, OpenBaoStore, Store};

extern "C" {
    fn umask(mask: u32) -> u32;
}

fn build_store(settings: &Settings) -> Result<Box<dyn Store>, String> {
    if settings.store == "openbao" {
        return OpenBaoStore::new(&settings.openbao_addr, Path::new(&settings.openbao_token_file), &settings.openbao_mount)
            .map(|s| Box::new(s) as Box<dyn Store>)
            .map_err(|e| format!("credential-broker refuses to boot: the OpenBao store is unavailable ({})", e.0));
    }
    std::fs::create_dir_all(&settings.state_dir).map_err(|e| format!("state directory: {e}"))?;
    let key = store::load_store_key(&settings.store_key_file).map_err(|_| {
        "credential-broker refuses to boot: VEXA_CONNECTIONS_STORE_KEY_FILE must name a readable file holding 64 hex characters (`openssl rand -hex 32`)".to_owned()
    })?;
    LocalEncryptedStore::open(&settings.state_dir.join("secrets.sqlite"), &key)
        .map(|s| Box::new(s) as Box<dyn Store>)
        .map_err(|e| format!("credential-broker refuses to boot: the local store is unavailable ({})", e.0))
}

fn boot(env: &config::Env) -> Result<Broker, String> {
    config::preflight(env)?;
    let settings = config::load(env)?;
    identity::read_verify_key(&settings.identity_public_key_file).map_err(|e| format!("credential-broker refuses to boot: VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE — {}", e.0))?;
    for (role, path) in &settings.key_files {
        if let Err(assertion::KeyError::Published) = assertion::load_key(path) {
            return Err(format!(
                "credential-broker refuses to boot: VEXA_CONNECTIONS_{}_KEY_FILE — this key is a published fixture key from the credential-broker.v1 goldens; generate this deployment's own key (`openssl rand -hex 32`)",
                role.to_uppercase()
            ));
        }
    }
    let store = build_store(&settings)?;
    obs::info(
        "broker_started",
        json!({"store": store.name(), "git_store": !settings.key_files["git"].is_empty(), "bot_accounts": !settings.key_files["bots"].is_empty(), "google_oauth": !settings.google_client_id.is_empty() && !settings.product_redirect.is_empty()}),
    );
    Broker::new(settings, store)
}

use crate::broker::Broker;

/// The operator commands: store or remove a company secret, the value on stdin.
fn secret_command(kind: &str, args: &[String]) -> ExitCode {
    let (owner, what, absent) = if kind == "mail-secret" { ("mail", "mail credential", "value") } else { ("signals", "signal-model key", "key") };
    let usage = || {
        eprintln!("usage: vexa-credential-broker {kind} put|delete <name>  (lowercase name; the {absent} on stdin)");
        ExitCode::from(2)
    };
    if args.len() != 2 || !["put", "delete"].contains(&args[0].as_str()) || !models::is_service_name(&args[1]) {
        return usage();
    }
    let (action, name) = (&args[0], &args[1]);
    let env = config::process_env();
    let store = match config::load(&env).and_then(|s| build_store(&s)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let path = format!("service/{owner}/{name}");
    if action == "delete" {
        if store.delete(&path).is_err() {
            eprintln!("refused: the store is unavailable");
            return ExitCode::from(1);
        }
        println!("{what} '{name}' removed");
        return ExitCode::SUCCESS;
    }
    let mut value = String::new();
    let _ = std::io::stdin().read_to_string(&mut value);
    let value = value.trim();
    if value.is_empty() {
        eprintln!("refused: no {absent} on stdin");
        return ExitCode::from(2);
    }
    if store.put(&path, &json!({"value": value, "owner": owner}), None).is_err() {
        eprintln!("refused: the store is unavailable");
        return ExitCode::from(1);
    }
    println!("{what} '{name}' stored ({} characters)", value.chars().count());
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    // Files this process creates (metadata, the encrypted store, the PKCE key) are its own alone.
    unsafe { umask(0o077) };
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some(kind @ ("mail-secret" | "signals-key")) => return secret_command(kind, &args[1..]),
        Some("serve") | None => {}
        Some(a) if a.starts_with("--") => {}
        Some(other) => {
            eprintln!("unknown command {other:?}; use serve, mail-secret or signals-key");
            return ExitCode::from(2);
        }
    }
    let env = config::process_env();
    let mut port: u16 = env.get("VEXA_CREDENTIAL_BROKER_PORT").and_then(|p| p.trim().parse().ok()).unwrap_or(23110);
    if let Some(i) = args.iter().position(|a| a == "--port") {
        match args.get(i + 1).and_then(|p| p.parse().ok()) {
            Some(p) => port = p,
            None => {
                eprintln!("--port needs a number");
                return ExitCode::from(2);
            }
        }
    }
    let broker = match boot(&env) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = server::run(broker, port) {
        eprintln!("credential-broker cannot listen on 127.0.0.1:{port}: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
