//! vexa-mcp — the Vexa MCP edge (contract mcp.tools.v1, the streamable-HTTP MCP transport at /mcp)
//! as one native process. The Python service it replaces is core/gateway/services/mcp; PARITY.md
//! records what was compared and what was not.

mod assembly;
mod builtin;
mod edge;
mod link;
mod mcp;
mod net;
mod obs;
mod pyd;
mod pyjson_decode;
mod schema;
mod server;
mod tickets;
mod wire;

use std::net::TcpListener;
use std::sync::RwLock;

use serde_json::{json, Value};

use assembly::Env;
use edge::{App, Assembled, Builtin};

const SURFACE: &str = include_str!("surface.json");
const BOT_ACCOUNT_TOOLS: [&str; 3] = [
    "browser_session_open",
    "bot_accounts_list",
    "bot_account_verify",
];

fn closed(mut descriptor: Value) -> Value {
    if let Some(s) = descriptor
        .get_mut("inputSchema")
        .and_then(Value::as_object_mut)
    {
        if s.get("type").and_then(Value::as_str) == Some("object")
            && !s.contains_key("additionalProperties")
        {
            s.insert("additionalProperties".into(), false.into());
        }
    }
    descriptor
}

fn builtins(surface: &Value, bot_accounts: bool) -> Vec<Builtin> {
    surface["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| bot_accounts || !BOT_ACCOUNT_TOOLS.contains(&t["name"].as_str().unwrap_or("")))
        .map(|t| Builtin {
            name: t["name"].as_str().unwrap_or("").to_owned(),
            descriptor: closed(json!({"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]})),
            method: t["method"].as_str().unwrap_or("").to_owned(),
            path: t["path"].as_str().unwrap_or("").to_owned(),
            query: t["parameters"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| p["in"] == "query")
                .map(|p| (p["name"].as_str().unwrap_or("").to_owned(), p["required"] == true, p["schema"].clone()))
                .collect(),
            body: t.get("body").filter(|b| !b.is_null()).cloned(),
            body_required: t["body_required"] == true,
        })
        .collect()
}

/// re.sub(r"Signed-in bots:.*?\n\n", "", text, count=1, flags=re.S)
fn without_signed_in_bots(text: &str) -> String {
    let Some(start) = text.find("Signed-in bots:") else {
        return text.to_owned();
    };
    match text[start..].find("\n\n") {
        Some(end) => format!("{}{}", &text[..start], &text[start + end + 2..]),
        None => text.to_owned(),
    }
}

fn assembled(bound: Vec<assembly::Bound>) -> Vec<Assembled> {
    bound
        .into_iter()
        .map(|b| Assembled {
            descriptor: b.descriptor(),
            bound: b,
        })
        .collect()
}

fn shared_names(tools: &[assembly::Tool]) -> Vec<String> {
    tools
        .iter()
        .filter(|t| t.shared == "allow")
        .map(|t| t.name.clone())
        .collect()
}

fn main() {
    let env: Env = std::env::vars().collect();
    let surface: Value = serde_json::from_str(SURFACE).expect("surface.json is valid JSON");
    let gateway = match env.get("GATEWAY_URL").filter(|g| !g.is_empty()) {
        Some(g) => g.trim_end_matches('/').to_owned(),
        None => "http://gateway:8000".to_owned(),
    };
    let bot_accounts = assembly::switched_on("browser_bots", &env);
    let instructions = surface["instructions"].as_str().unwrap_or("").to_owned();
    let instructions = if bot_accounts {
        instructions
    } else {
        without_signed_in_bots(&instructions)
    };

    let mut tools = Vec::new();
    let mut bound = Vec::new();
    let mut late = None;
    if assembly::env_str(&env, "VEXA_MCP_ASSEMBLY_OFF").is_empty() {
        let found = assembly::discover(&env).and_then(|d| {
            let b = assembly::bind(&d.assembly, &d.openapi, &d.bases)?;
            Ok((d, b))
        });
        match found {
            Ok((d, b)) => {
                tools = d.assembly.tools;
                bound = b;
                if !d.pending.is_empty() {
                    late = Some(assembly::Late {
                        pending: d.pending.into(),
                        bases: d.bases.into(),
                    });
                }
            }
            Err(e) => {
                eprintln!("vexa-mcp: refusing to boot: {}", e.0);
                std::process::exit(1);
            }
        }
    }
    let app: &'static App = Box::leak(Box::new(App {
        gateway,
        policy: mcp::Policy::from_env(&env),
        builtins: builtins(&surface, bot_accounts),
        assembled: RwLock::new(assembled(bound)),
        shared: RwLock::new(shared_names(&tools)),
        sessions: Default::default(),
        instructions,
        surface,
        env,
    }));
    let registered: Vec<String> = app
        .builtins
        .iter()
        .map(|b| b.name.clone())
        .chain(
            app.assembled
                .read()
                .unwrap()
                .iter()
                .map(|a| a.bound.name().to_owned()),
        )
        .collect();
    let unknown = app.policy.unknown(&registered);
    if !unknown.is_empty() {
        eprintln!(
            "mcp tool visibility names tools this deployment does not serve: {}",
            unknown.join(", ")
        );
    }
    if let Some(late) = late {
        let every = assembly::refresh_interval(&app.env);
        std::thread::spawn(move || loop {
            if late.pending.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(every);
            let taken = |name: &str| {
                app.builtins.iter().any(|b| b.name == name)
                    || app
                        .assembled
                        .read()
                        .unwrap()
                        .iter()
                        .any(|a| a.bound.name() == name)
            };
            for (bound, tools) in assembly::poll_late(&late, &app.env, &taken) {
                app.assembled.write().unwrap().extend(assembled(bound));
                app.shared.write().unwrap().extend(shared_names(&tools));
            }
        });
    }
    let host = assembly::env_str(&app.env, "HOST");
    let host = if host.is_empty() { "0.0.0.0" } else { host };
    let port = assembly::env_str(&app.env, "PORT");
    let port = if port.is_empty() { "8010" } else { port };
    let listener = match TcpListener::bind(format!("{host}:{port}")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("vexa-mcp: cannot listen on {host}:{port}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("vexa-mcp: listening on {host}:{port}");
    server::serve(app, listener);
}
