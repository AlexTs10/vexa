//! vexa-gateway: the Vexa API gateway as one native process — the public edge (api.v1, ws.v1) on
//! `PORT`, and the service door (flows' only way to another domain) on
//! `VEXA_GATEWAY_SERVICE_DOOR_PORT` when `VEXA_FLOWS_SERVICE_KEY` names a flows tier.
//!
//!     vexa-gateway                      serve
//!     vexa-gateway keygen SIGNING PUBLIC   make (or keep) the identity key pair

mod door;
mod edge;
mod guard;
mod identity;
mod link;
mod manifest;
mod multiplex;
mod obs;
mod paths;
mod redis;
mod routes;
mod taint;
mod tickets;
mod ws;

use std::collections::{BTreeSet, HashMap};
use std::net::TcpListener;
use std::sync::Arc;

use serde_json::Value;

fn env(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_owned())
}

fn is_set(k: &str) -> bool {
    !std::env::var(k).unwrap_or_default().trim().is_empty()
}

/// config.v1: every required-explicit key set, no key on a published placeholder.
fn preflight(root: &std::path::Path) -> Result<(), String> {
    let path = root.join("core/gateway/services/gateway/src/gateway/config.v1.json");
    let decl: Value = serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let keys = decl["keys"].as_array().cloned().unwrap_or_default();
    let missing: Vec<String> = keys
        .iter()
        .filter(|e| e["class"] == "required-explicit" && !is_set(e["key"].as_str().unwrap_or("")))
        .map(|e| format!("{} ({})", e["key"].as_str().unwrap_or(""), e["description"].as_str().unwrap_or("")))
        .collect();
    if !missing.is_empty() {
        return Err(format!("gateway is misconfigured and refuses to boot — required environment variable(s) not set: {}. Each is declared required-explicit in this service's config.v1 declaration (config.v1.json, gate:config-contract); set them and restart.", missing.join("; ")));
    }
    let placeheld: Vec<&str> = keys
        .iter()
        .filter(|e| {
            let value = std::env::var(e["key"].as_str().unwrap_or("")).unwrap_or_default();
            e["forbidden_values"].as_array().is_some_and(|f| f.iter().any(|v| v.as_str() == Some(value.trim())))
        })
        .filter_map(|e| e["key"].as_str())
        .collect();
    if !placeheld.is_empty() {
        return Err(format!("gateway is misconfigured and refuses to boot — {} still hold(s) a documented PLACEHOLDER value. That literal is published in this repository, so it is not a secret: anyone can present it. Generate a real value (`openssl rand -hex 32`), set it on every service that shares the tier, and restart. The forbidden literals are declared per key in this service's config.v1 declaration (config.v1.json, gate:config-contract).", placeheld.join(", ")));
    }
    Ok(())
}

fn build() -> Result<(edge::Edge, Option<door::Door>), String> {
    let root = manifest::repo_root()?;
    preflight(&root)?;
    if is_set("VEXA_WS_SCOPE_MODE") {
        eprintln!("WARNING: VEXA_WS_SCOPE_MODE is not read since 0.13.4 (/ws takes any key holding bot or tx, as the REST routes do; meeting ownership, workspace and share decide what it streams; there is no setting); unset it. https://docs.vexa.ai/changes-0-13-4-auth");
        obs::ev("config_key_removed", "system", "warning", Some("boot"))
            .fields(serde_json::json!({"key": "VEXA_WS_SCOPE_MODE", "changed_in": "0.13.4", "docs": "https://docs.vexa.ai/changes-0-13-4-auth"}))
            .emit();
    }
    let key = identity::read_signing_key(&env("VEXA_GATEWAY_IDENTITY_SIGNING_KEY_FILE", ""))
        .map_err(|e| format!("gateway refuses to boot: VEXA_GATEWAY_IDENTITY_SIGNING_KEY_FILE — {e}"))?;
    let agent = env("AGENT_API_URL", "");
    let crm = env("CRM_API_URL", "");
    let mut present: BTreeSet<String> = ["gateway", "meetings", "identity", "mcp"].iter().map(|s| s.to_string()).collect();
    let mut forward_base = HashMap::new();
    let mut forwarded = Vec::new();
    if !agent.trim().is_empty() {
        present.insert("agent".into());
        forward_base.insert("agent".to_owned(), agent.clone());
        forwarded.push(("agent", agent.clone()));
    }
    if !crm.trim().is_empty() {
        present.insert("crm".into());
        forward_base.insert("crm".to_owned(), crm.clone());
        forwarded.push(("crm", crm.clone()));
    }
    let asm = manifest::load(&root, &present)?;
    for (d, _) in &forwarded {
        if !asm.forwards.contains_key(*d) {
            return Err(format!("{d} is fronted wholesale but its routes.v1.json declares no forward"));
        }
    }
    let routes = routes::http_routes(&asm, &forwarded);
    let mut missing = Vec::new();
    for r in &routes {
        for m in r.methods.iter().filter(|m| *m != "HEAD") {
            let k = (m.clone(), r.path.clone());
            if !asm.scopes.contains_key(&k) && !asm.unscoped.contains(&k) {
                missing.push(format!("{m} {}", r.path));
            }
        }
    }
    if !missing.is_empty() {
        return Err(format!("gateway routes with no scope declaration: {} — declare each in the OWNING DOMAIN's routes.v1.json (an identity-only route that needs no scope is declared there with an empty `scopes`). The edge composes the table from the domains it fronts and owns none of it; this build fronts {:?}.", missing.join(", "), present));
    }
    let redis_url = env("REDIS_URL", "redis://redis:6379/0");
    let redis_target = redis::parse_url(&redis_url)?;
    let door = if is_set("VEXA_FLOWS_SERVICE_KEY") { Some(door::Door::from_env(key.clone())?) } else { None };
    let edge = edge::Edge {
        routes,
        asm,
        admin_url: env("ADMIN_API_URL", "http://admin-api:8001"),
        meeting_url: env("MEETING_API_URL", "http://meeting-api:8080"),
        mcp_url: env("MCP_URL", "http://mcp:8010"),
        forward_base,
        vkey: Some(key.verifying_key()),
        key: Some(key),
        internal_secret: env("INTERNAL_API_SECRET", ""),
        limiter: guard::UserLimiter::from_env()?,
        agent_allow: guard::AgentAllow::from_env(),
        marker: taint::Marker::new(redis_target.clone()),
        guard: guard::Guard::from_env()?,
        redis: redis_target,
    };
    Ok((edge, door))
}

fn listen(host: &str, port: &str) -> Result<TcpListener, String> {
    let port: u16 = port.trim().parse().map_err(|_| format!("invalid port {port:?}"))?;
    TcpListener::bind((host, port)).map_err(|e| format!("cannot listen on {host}:{port}: {e}"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("keygen") {
        if args.len() != 4 {
            eprintln!("usage: vexa-gateway keygen <signing-key.pem> <public-key.pem>");
            std::process::exit(2);
        }
        match identity::keygen(&args[2], &args[3]) {
            Ok(generated) => {
                println!("identity keygen: {}; public key at {}", if generated { "generated a new signing key" } else { "kept the signing key" }, args[3]);
                return;
            }
            Err(e) => {
                eprintln!("identity keygen: {e}");
                std::process::exit(1);
            }
        }
    }
    let (edge, door) = match build() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let host = env("HOST", "0.0.0.0");
    let edge_listener = match listen(&host, &env("PORT", "8000")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if let Some(door) = door {
        let l = match listen(&host, &env("VEXA_GATEWAY_SERVICE_DOOR_PORT", "8002")) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };
        let door = Arc::new(door);
        let handler: Arc<dyn Fn(&mut vexa_native_kit::httpd::Exchange) + Send + Sync> = Arc::new(move |ex: &mut vexa_native_kit::httpd::Exchange| door.handle(ex));
        std::thread::spawn(move || vexa_native_kit::httpd::serve(l, handler));
    }
    let edge = Arc::new(edge);
    let handler: Arc<dyn Fn(&mut vexa_native_kit::httpd::Exchange) + Send + Sync> = Arc::new(move |ex: &mut vexa_native_kit::httpd::Exchange| edge.handle(ex));
    vexa_native_kit::httpd::serve(edge_listener, handler);
}
