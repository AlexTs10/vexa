//! ASSEMBLY — the tools the deployed domains declare (mcp.tools.v1), asked for at boot,
//! checked against each domain's OpenAPI, and served as routes `/tools/<name>` that are
//! one MCP tool each. Every rule that fails the Python boot fails this one, by name.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::net;

pub const CONTRACT: &str = "mcp.tools.v1";
const CREDENTIAL_ARGUMENTS: [&str; 9] = [
    "token",
    "api_key",
    "apikey",
    "key",
    "access_token",
    "bearer",
    "credential",
    "password",
    "secret",
];
const DOMAINS: [&str; 9] = [
    "meetings",
    "identity",
    "flows",
    "agent",
    "gateway",
    "rehearse",
    "billing",
    "workspaces",
    "crm",
];
const IDENTITIES: [&str; 4] = ["user", "admin", "operator", "none"];
const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const AUTHS: [&str; 3] = ["subject", "admin", "none"];
pub const PLACEHOLDER_KEYS: [&str; 7] = [
    "changeme",
    "change-me",
    "CHANGE-ME",
    "default",
    "secret",
    "vexa-internal-secret",
    "lite-internal-secret",
];

/// The domains this edge can be pointed at, and the variable that points it.
pub const DOMAIN_URL_ENV: [(&str, &str); 5] = [
    ("identity", "ADMIN_API_URL"),
    ("meetings", "MEETING_API_URL"),
    ("flows", "FLOWS_API_URL"),
    ("agent", "AGENT_API_URL"),
    ("crm", "CRM_API_URL"),
];
const MANIFEST_PATH: &str = "/.well-known/mcp-tools.json";
const OPENAPI_PATH: &str = "/openapi.json";
const OPTIONAL_DOMAINS: [&str; 4] = ["flows", "agent", "crm", "meetings"];
const RETRY_WHEN_EMPTY: [&str; 1] = ["meetings"];
pub const TOOL_TIMEOUT: Duration = Duration::from_secs(35);

pub type Env = HashMap<String, String>;

pub fn env_str<'a>(env: &'a Env, key: &str) -> &'a str {
    env.get(key).map(String::as_str).unwrap_or("")
}

#[derive(Debug)]
pub struct ManifestError(pub String);

fn fail<T>(msg: String) -> Result<T, ManifestError> {
    Err(ManifestError(msg))
}

#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub domain: String,
    pub identity: String,
    pub route: Option<(String, String)>,
    pub arguments: Vec<String>,
    pub auth: String,
    pub admin_auth: Option<(String, String)>,
    pub forward: Option<(String, String)>,
    pub shared: String,
}

#[derive(Debug, Default)]
pub struct Assembly {
    pub tools: Vec<Tool>,
    has_entitlement: Option<String>,
}

fn pyrepr(v: Option<&Value>) -> String {
    vexa_native_kit::pyjson::py_repr(v.unwrap_or(&Value::Null))
}

fn sorted_list(items: &[&str]) -> String {
    let mut s: Vec<&str> = items.to_vec();
    s.sort();
    vexa_native_kit::pyjson::py_repr(&json!(s))
}

fn prefix(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    (s.starts_with('/') && s.ends_with('/') && !s.contains('{')).then(|| s.to_owned())
}

/// A manifest's `forward` as (edge_prefix, upstream_prefix).
fn forward_of(doc: &Value) -> Result<Option<(String, String)>, ManifestError> {
    let Some(raw) = doc.get("forward").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    match (prefix(raw.get("edge_prefix")), prefix(raw.get("upstream_prefix"))) {
        (Some(e), Some(u)) if raw.is_object() => Ok(Some((e, u))),
        _ => fail(format!(
            "{}: forward must be two absolute prefixes ending at a segment, {{\"edge_prefix\": \"/x/\", \"upstream_prefix\": \"/y/\"}} (got {})",
            vexa_native_kit::pyjson::py_str(doc.get("domain").unwrap_or(&Value::Null)),
            pyrepr(Some(raw))
        )),
    }
}

fn admin_auth(doc: &Value) -> Option<(String, String)> {
    let aa = doc.get("admin_auth")?.as_object()?;
    let text = |k: &str| {
        aa.get(k)
            .filter(|v| vexa_native_kit::pyjson::truthy(Some(v)))
            .map(vexa_native_kit::pyjson::py_str)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let (header, key_env) = (text("header"), text("key_env"));
    (!header.is_empty() && !key_env.is_empty()).then_some((header, key_env))
}

fn tools_of(doc: &Value) -> Vec<Value> {
    doc.get("tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// One manifest on its own.
pub fn validate(doc: &Value) -> Result<(), ManifestError> {
    if !doc.is_object() || doc.get("contract").and_then(Value::as_str) != Some(CONTRACT) {
        return fail(format!("not a {CONTRACT} manifest"));
    }
    let domain = s(doc, "domain");
    if !DOMAINS.contains(&domain) || !doc["domain"].is_string() {
        return fail(format!("unknown domain {}", pyrepr(doc.get("domain"))));
    }
    if !matches!(
        doc.get("source").and_then(Value::as_str),
        Some("oss" | "mounted")
    ) {
        return fail(format!("{domain}: source must be oss or mounted"));
    }
    let depends = doc.get("depends_on");
    let ok_depends = depends
        .and_then(Value::as_array)
        .is_some_and(|d| d.iter().all(|x| x.as_str() == Some("identity")));
    if !ok_depends {
        return fail(format!(
            "{domain}: depends_on may name identity and nothing else (got {}) — identity is the only domain everyone may depend on",
            pyrepr(depends)
        ));
    }
    if domain == "identity"
        && depends
            .and_then(Value::as_array)
            .is_some_and(|d| !d.is_empty())
    {
        return fail("identity: depends_on must be empty — it depends on nothing".into());
    }
    let tools = tools_of(doc);
    for t in &tools {
        let name = match t.get("name").and_then(Value::as_str) {
            Some(n) if !n.is_empty() => n,
            _ => return fail(format!("{domain}: a tool with no name")),
        };
        if !t
            .get("identity")
            .and_then(Value::as_str)
            .is_some_and(|i| IDENTITIES.contains(&i))
        {
            return fail(format!(
                "{domain}/{name}: identity must be one of {}",
                sorted_list(&IDENTITIES)
            ));
        }
        let auth = t.get("auth").and_then(Value::as_str);
        if !auth.is_some_and(|a| AUTHS.contains(&a)) {
            return fail(format!(
                "{domain}/{name}: auth must be one of {} (got {}) — every tool states which credential its door reads. There is no default: the default is what this edge used to guess, and it guessed wrong for every operator-keyed route.",
                sorted_list(&AUTHS),
                pyrepr(t.get("auth"))
            ));
        }
        if auth == Some("admin") && admin_auth(doc).is_none() {
            return fail(format!(
                "{domain}/{name}: auth is admin, so {domain} must declare admin_auth {{\"header\": …, \"key_env\": …}} — a deployment cannot hold a key it cannot spell, and this edge will not invent the header the door reads."
            ));
        }
        if !matches!(t.get("shared"), None | Some(Value::Null))
            && !matches!(
                t.get("shared").and_then(Value::as_str),
                Some("allow" | "refuse")
            )
        {
            return fail(format!(
                "{domain}/{name}: shared must be allow or refuse (got {})",
                pyrepr(t.get("shared"))
            ));
        }
        let requires: Vec<&str> = match t.get("requires").and_then(Value::as_array) {
            Some(r) if !r.is_empty() => r.iter().map(|x| x.as_str().unwrap_or("\u{0}")).collect(),
            _ => {
                return fail(format!(
                    "{domain}/{name}: requires must name at least one domain"
                ))
            }
        };
        let composes = doc.get("composes") == Some(&Value::Bool(true));
        let allowed: Vec<&str> = if composes {
            DOMAINS.to_vec()
        } else {
            vec![domain, "identity"]
        };
        if !requires.iter().all(|r| allowed.contains(r)) {
            return fail(format!(
                "{domain}/{name}: requires may name {} (got {}) — a tool that needs another domain is a composition, and a composition has an owner. A manifest whose whole job IS composing across domains declares `\"composes\": true`",
                sorted_list(&allowed),
                sorted_list(&requires)
            ));
        }
        for arg in t
            .get("arguments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let text = vexa_native_kit::pyjson::py_str(arg);
            if CREDENTIAL_ARGUMENTS.contains(&text.trim().to_lowercase().as_str()) {
                return fail(format!(
                    "{domain}/{name}: declares a credential argument {} — this edge has exactly one authentication path (a bearer header, session-bound). A credential in an argument list is in the transcript forever.",
                    pyrepr(Some(arg))
                ));
            }
        }
        match t.get("route").filter(|r| !r.is_null()) {
            None => {
                if vexa_native_kit::pyjson::truthy(doc.get("base_url_env")) {
                    return fail(format!(
                        "{domain}/{name}: route is null but this domain HAS a door ({}) — a tool with a door must name its route",
                        vexa_native_kit::pyjson::py_str(&doc["base_url_env"])
                    ));
                }
            }
            Some(route) => {
                let method_ok = route
                    .get("method")
                    .and_then(Value::as_str)
                    .is_some_and(|m| METHODS.contains(&m));
                let path_ok = route
                    .get("path")
                    .map(vexa_native_kit::pyjson::py_str)
                    .is_some_and(|p| p.starts_with('/'));
                if !method_ok || !path_ok {
                    return fail(format!(
                        "{domain}/{name}: route needs a method and an absolute path"
                    ));
                }
            }
        }
    }
    check_aliases(domain, &tools)?;
    if let Some((_, upstream)) = forward_of(doc)? {
        for t in &tools {
            let path = t
                .get("route")
                .and_then(|r| r.get("path"))
                .map(vexa_native_kit::pyjson::py_str)
                .unwrap_or_default();
            if !path.starts_with(&upstream) {
                return fail(format!(
                    "{domain}/{}: route {} is outside the domain's forward ({upstream}…) — a forwarded domain's tools live under its upstream prefix",
                    s(t, "name"),
                    vexa_native_kit::pyjson::py_str_repr(&path)
                ));
            }
        }
    }
    if let Some(ent) = doc.get("entitlement").filter(|e| !e.is_null()) {
        if !ent.is_object()
            || !vexa_native_kit::pyjson::truthy(ent.get("route"))
            || !vexa_native_kit::pyjson::truthy(ent.get("answers"))
        {
            return fail(format!(
                "{domain}: entitlement needs a route and what it answers"
            ));
        }
    }
    Ok(())
}

fn check_aliases(domain: &str, tools: &[Value]) -> Result<(), ManifestError> {
    let mut first: Vec<((Value, Value), String)> = Vec::new();
    let by_name: HashMap<&str, &Value> = tools.iter().map(|t| (s(t, "name"), t)).collect();
    let route_of = |t: &Value| {
        t.get("route")
            .filter(|r| !r.is_null())
            .cloned()
            .unwrap_or(json!({}))
    };
    for t in tools {
        let route = route_of(t);
        let key = (
            route.get("method").cloned().unwrap_or(Value::Null),
            route.get("path").cloned().unwrap_or(Value::Null),
        );
        if let Some(alias) = t.get("alias_of").filter(|a| !a.is_null()) {
            let target = alias.as_str().and_then(|a| by_name.get(a));
            let bad = alias.as_str() == Some(s(t, "name"))
                || match target {
                    None => true,
                    Some(tg) => {
                        route_of(tg) != route
                            || tg.get("arguments").cloned().unwrap_or(json!([]))
                                != t.get("arguments").cloned().unwrap_or(json!([]))
                            || tg.get("alias_of").is_some_and(|a| !a.is_null())
                    }
                };
            if bad {
                return fail(format!(
                    "{domain}/{}: alias_of must name another, non-alias tool on the same route with the same arguments (got {})",
                    s(t, "name"),
                    pyrepr(Some(alias))
                ));
            }
            continue;
        }
        let has_route = route.as_object().is_some_and(|r| !r.is_empty());
        if has_route {
            if let Some((_, prior)) = first.iter().find(|(k, _)| *k == key) {
                return fail(format!(
                    "{domain}: {} and {} are bound to the same route {} {} — declare the second as \"alias_of\": {} if the second name is deliberate",
                    vexa_native_kit::pyjson::py_str_repr(prior),
                    vexa_native_kit::pyjson::py_str_repr(s(t, "name")),
                    vexa_native_kit::pyjson::py_str(&key.0),
                    vexa_native_kit::pyjson::py_str(&key.1),
                    vexa_native_kit::pyjson::py_str_repr(prior)
                ));
            }
            first.push((key, s(t, "name").to_owned()));
        }
    }
    Ok(())
}

/// The union of the manifests, every combination rule applied.
pub fn assemble(
    manifests: &[Value],
    deployed: &BTreeSet<String>,
    env: &Env,
) -> Result<Assembly, ManifestError> {
    let mut out = Assembly::default();
    let mut claimed: HashMap<String, (String, String)> = HashMap::new();
    for doc in manifests {
        validate(doc)?;
        let (domain, source) = (s(doc, "domain").to_owned(), s(doc, "source").to_owned());
        if doc
            .get("entitlement")
            .is_some_and(|e| !e.is_null() && vexa_native_kit::pyjson::truthy(Some(e)))
        {
            if let Some(prior) = &out.has_entitlement {
                return fail(format!(
                    "two manifests declare an entitlement hook ({prior} and {domain}) — 'may this person act' is not a question with two answers"
                ));
            }
            out.has_entitlement = Some(domain.clone());
        }
        let forward = forward_of(doc)?;
        for t in tools_of(doc) {
            let name = s(&t, "name").to_owned();
            if let Some((pd, ps)) = claimed.get(&name) {
                return fail(format!(
                    "the tool name {} is claimed by two manifests ({pd}/{ps} and {domain}/{source}) — a duplicate is a design question and a person has to answer it; a mounted manifest never wins by default",
                    vexa_native_kit::pyjson::py_str_repr(&name)
                ));
            }
            claimed.insert(name.clone(), (domain.clone(), source.clone()));
            let requires: Vec<String> = t["requires"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| r.as_str().map(str::to_owned))
                .collect();
            if !requires.iter().all(|r| deployed.contains(r)) {
                continue;
            }
            let auth = s(&t, "auth").to_owned();
            let admin = if auth == "admin" {
                admin_auth(doc)
            } else {
                None
            };
            if let Some((_, key_env)) = &admin {
                let held = env_str(env, key_env).trim();
                if held.is_empty() || PLACEHOLDER_KEYS.contains(&held) {
                    return fail(format!(
                        "{domain}/{name} needs the operator credential this deployment does not hold: {key_env} is {}. Refusing to serve a tool that would be listed and then refused by its own door — set it, or take the tool out of this deployment's manifest.",
                        if held.is_empty() { "unset" } else { "a published placeholder" }
                    ));
                }
            }
            let route = t.get("route").filter(|r| !r.is_null()).map(|r| {
                (
                    s(r, "method").to_owned(),
                    vexa_native_kit::pyjson::py_str(&r["path"]),
                )
            });
            out.tools.push(Tool {
                name,
                domain: domain.clone(),
                identity: s(&t, "identity").to_owned(),
                route,
                arguments: t
                    .get("arguments")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(vexa_native_kit::pyjson::py_str)
                    .collect(),
                auth,
                admin_auth: admin,
                forward: forward.clone(),
                shared: t
                    .get("shared")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            });
        }
    }
    Ok(out)
}

// ─── features (VEXA_FEATURES) ─────────────────────────────────────────────────

/// agent-api's install_defaults rule: "", "all", "a,b", "all,-a".
pub fn switched_on(name: &str, env: &Env) -> bool {
    let mut on = false;
    for token in env_str(env, "VEXA_FEATURES")
        .split(',')
        .map(|t| t.trim().to_lowercase())
    {
        if token.is_empty() {
            continue;
        }
        let value = !token.starts_with('-');
        let token = token.trim_start_matches(['-', '+']).trim().to_owned();
        if token == "all" || token == name {
            on = value;
        }
    }
    on
}

fn drop_switched_off(assembly: &mut Assembly, env: &Env) {
    if !switched_on("crm", env) {
        assembly.tools.retain(|t| t.domain != "crm");
    }
}

// ─── discovery ────────────────────────────────────────────────────────────────

pub struct Silent(pub String);

fn number(v: Option<&String>, fallback: f64) -> f64 {
    match v.and_then(|t| t.trim().parse::<f64>().ok()) {
        Some(x) if x >= 0.0 => x,
        _ => fallback,
    }
}

/// One boot fetch: Ok(Some(doc)) served, Ok(None) answered with nothing, Err never answered.
fn probe(url: &str, attempts: usize, pause: f64) -> Result<Option<Value>, Silent> {
    let mut last = String::new();
    for attempt in 1..=attempts {
        match net::request("GET", url, &[], None, Duration::from_secs(5)) {
            Err(net::NetError::Timeout) => last = "ReadTimeout: timed out".into(),
            Err(net::NetError::Failed(e)) => last = format!("ConnectError: {e}"),
            Ok(r) if r.status < 500 => {
                if r.status != 200 {
                    return Ok(None);
                }
                return Ok(crate::pyjson_decode::loads_bytes(&r.body).ok());
            }
            Ok(r) => last = format!("HTTP {}", r.status),
        }
        if attempt < attempts && pause > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(pause));
        }
    }
    Err(Silent(format!(
        "{attempts} attempts at {url}, last: {}",
        if last.is_empty() {
            "no response"
        } else {
            &last
        }
    )))
}

fn silent(domain: &str, base: &str, what: &str, s: &Silent) -> ManifestError {
    ManifestError(format!(
        "{domain} is configured ({base}) but never answered its {what} — {}. Refusing to boot with {domain}'s tools silently absent: a deployment that names a domain is promising its tools, and an agent handed a short tools/list has no way to know one is missing.",
        s.0
    ))
}

/// {domain: base_url} for every domain this deployment names, in a fixed order.
pub fn deployed_domains(env: &Env) -> Vec<(String, String)> {
    DOMAIN_URL_ENV
        .iter()
        .filter_map(|(d, k)| {
            let url = env_str(env, k).trim().trim_end_matches('/');
            (!url.is_empty()).then(|| (d.to_string(), url.to_owned()))
        })
        .collect()
}

fn load_mounted(dir: &str) -> Result<Vec<Value>, ManifestError> {
    if dir.is_empty() {
        return Ok(Vec::new());
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut files: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".mcp.tools.v1.json"))
        })
        .collect();
    files.sort();
    let mut out = Vec::new();
    for f in files {
        let name = f
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        let text = std::fs::read_to_string(&f).map_err(|e| {
            ManifestError(format!("mounted manifest {name} could not be read: {e}"))
        })?;
        let mut doc = crate::pyjson_decode::loads(&text).map_err(|e| {
            ManifestError(format!(
                "mounted manifest {name} could not be read: {}",
                e.text()
            ))
        })?;
        let Some(obj) = doc.as_object_mut() else {
            return fail(format!("mounted manifest {name} is not an object"));
        };
        obj.insert("source".into(), "mounted".into());
        out.push(doc);
    }
    Ok(out)
}

pub struct Discovered {
    pub assembly: Assembly,
    pub openapi: HashMap<String, Value>,
    pub bases: Vec<(String, String)>,
    pub pending: Vec<(String, String)>,
}

pub fn discover(env: &Env) -> Result<Discovered, ManifestError> {
    let attempts = (number(env.get("VEXA_MCP_BOOT_PROBE_ATTEMPTS"), 5.0) as usize).max(1);
    let pause = number(env.get("VEXA_MCP_BOOT_PROBE_PAUSE_SECONDS"), 2.0);
    let mut bases = deployed_domains(env);
    let mut pending = Vec::new();
    let mut manifests = Vec::new();
    let mut openapi = HashMap::new();
    for (domain, base) in bases.clone() {
        let optional = OPTIONAL_DOMAINS.contains(&domain.as_str());
        let tries = if optional { 1 } else { attempts };
        let mut park = |why: String, bases: &mut Vec<(String, String)>| {
            eprintln!("mcp: {domain} ({base}) {why}; serving without its tools and asking again");
            pending.push((domain.clone(), base.clone()));
            bases.retain(|(d, _)| d != &domain);
        };
        let doc = match probe(&format!("{base}{MANIFEST_PATH}"), tries, pause) {
            Ok(d) => d,
            Err(s) if optional => {
                park(format!("did not answer at boot ({})", s.0), &mut bases);
                continue;
            }
            Err(s) => return Err(silent(&domain, &base, "manifest", &s)),
        };
        if doc.is_none() && optional && RETRY_WHEN_EMPTY.contains(&domain.as_str()) {
            park(
                "answered with no manifest at boot (still rolling?)".into(),
                &mut bases,
            );
            continue;
        }
        let Some(doc) = doc else { continue };
        let spec = match probe(&format!("{base}{OPENAPI_PATH}"), tries, pause) {
            Ok(s) => s,
            Err(s) if optional => {
                park(
                    format!("did not serve its OpenAPI at boot ({})", s.0),
                    &mut bases,
                );
                continue;
            }
            Err(s) => return Err(silent(&domain, &base, "OpenAPI", &s)),
        };
        manifests.push(doc);
        let Some(spec) = spec else {
            return fail(format!("{domain} published a manifest but its OpenAPI at {base}{OPENAPI_PATH} did not answer — refusing to bind a tool blind"));
        };
        openapi.insert(domain, spec);
    }
    for doc in load_mounted(env_str(env, "VEXA_MCP_MANIFEST_DIR"))? {
        let domain = vexa_native_kit::pyjson::py_str(doc.get("domain").unwrap_or(&Value::Null));
        let key = format!("{}_API_URL", domain.to_uppercase());
        let base = env_str(env, &key).trim().trim_end_matches('/').to_owned();
        if base.is_empty() {
            return fail(format!(
                "a mounted manifest for {} is present but {key} is unset — a private domain that cannot be reached is a tool list that lies",
                vexa_native_kit::pyjson::py_str_repr(&domain)
            ));
        }
        bases.retain(|(d, _)| d != &domain);
        bases.push((domain.clone(), base.clone()));
        manifests.push(doc);
        let spec = probe(&format!("{base}{OPENAPI_PATH}"), attempts, pause)
            .map_err(|s| silent(&domain, &base, "OpenAPI", &s))?;
        let Some(spec) = spec else {
            return fail(format!(
                "{domain} (mounted): no OpenAPI at {base}{OPENAPI_PATH}"
            ));
        };
        openapi.insert(domain, spec);
    }
    let deployed: BTreeSet<String> = bases.iter().map(|(d, _)| d.clone()).collect();
    let mut assembly = assemble(&manifests, &deployed, env)?;
    drop_switched_off(&mut assembly, env);
    Ok(Discovered {
        assembly,
        openapi,
        bases,
        pending,
    })
}

// ─── binding ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Bound {
    pub tool: Tool,
    pub description: String,
    /// Declared arguments (path parameters excluded), in manifest order, with the owning route's schema.
    pub params: Vec<(String, Value)>,
    pub path_params: Vec<String>,
    pub body_params: Vec<String>,
    pub base: String,
}

fn describe(op: &Value) -> String {
    let summary = op
        .get("summary")
        .map(vexa_native_kit::pyjson::py_str)
        .filter(|_| vexa_native_kit::pyjson::truthy(op.get("summary")))
        .unwrap_or_default();
    let body = op
        .get("description")
        .map(vexa_native_kit::pyjson::py_str)
        .filter(|_| vexa_native_kit::pyjson::truthy(op.get("description")))
        .unwrap_or_default();
    let (summary, body) = (summary.trim(), body.trim());
    if body.is_empty() {
        return summary.to_owned();
    }
    if summary.is_empty() || body.to_lowercase().contains(&summary.to_lowercase()) {
        return body.to_owned();
    }
    format!("{summary}\n\n{body}")
}

fn resolve_ref(schema: &Value, openapi: &Value) -> Value {
    let Some(r) = schema
        .get("$ref")
        .filter(|r| vexa_native_kit::pyjson::truthy(Some(r)))
    else {
        return if schema.is_object() {
            schema.clone()
        } else {
            json!({})
        };
    };
    let name = vexa_native_kit::pyjson::py_str(r)
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_owned();
    openapi
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(|s| s.get(&name))
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or(json!({}))
}

fn inline(schema: &Value, openapi: &Value, depth: usize) -> Value {
    match schema {
        Value::Array(items) => {
            Value::Array(items.iter().map(|s| inline(s, openapi, depth)).collect())
        }
        Value::Object(obj) if obj.contains_key("$ref") => {
            if depth >= 6 {
                return json!({"type": "object"});
            }
            let mut merged = resolve_ref(schema, openapi)
                .as_object()
                .cloned()
                .unwrap_or_default();
            for (k, v) in obj {
                if k != "$ref" {
                    merged.insert(k.clone(), v.clone());
                }
            }
            inline(&Value::Object(merged), openapi, depth + 1)
        }
        Value::Object(obj) => Value::Object(
            obj.iter()
                .map(|(k, v)| (k.clone(), inline(v, openapi, depth)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn body_params(op: &Value, openapi: &Value) -> Vec<(String, Value)> {
    let Some(content) = op
        .get("requestBody")
        .filter(|r| r.is_object())
        .and_then(|r| r.get("content"))
        .and_then(|c| c.get("application/json"))
        .filter(|c| c.is_object())
    else {
        return Vec::new();
    };
    let schema = resolve_ref(
        content
            .get("schema")
            .filter(|s| s.is_object())
            .unwrap_or(&json!({})),
        openapi,
    );
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    let empty = json!({});
    props
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                inline(if v.is_object() { v } else { &empty }, openapi, 0),
            )
        })
        .collect()
}

pub fn path_params_of(path: &str) -> Vec<String> {
    Regex::new(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
        .unwrap()
        .captures_iter(path)
        .map(|c| c[1].to_owned())
        .collect()
}

pub fn bind(
    assembly: &Assembly,
    openapi: &HashMap<String, Value>,
    bases: &[(String, String)],
) -> Result<Vec<Bound>, ManifestError> {
    let mut out = Vec::new();
    for tool in &assembly.tools {
        let Some((method, path)) = &tool.route else {
            continue;
        };
        let (d, n) = (&tool.domain, &tool.name);
        let Some(spec) = openapi
            .get(d)
            .filter(|s| vexa_native_kit::pyjson::truthy(Some(s)))
        else {
            return fail(format!("{d}/{n}: no OpenAPI from {d} — refusing to bind a tool blind; a surface nobody checked is a surface nobody can trust"));
        };
        let Some(op) = spec
            .get("paths")
            .and_then(|p| p.get(path))
            .filter(|i| i.is_object())
            .and_then(|i| i.get(method.to_lowercase()))
            .filter(|o| o.is_object())
        else {
            return fail(format!("{d}/{n}: {d} does not serve {method} {path} — the manifest names a route its own service does not have"));
        };
        let mut query: Vec<(String, Value)> = Vec::new();
        for p in op
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(name) = p
                .get("name")
                .filter(|v| vexa_native_kit::pyjson::truthy(Some(v)))
                .map(vexa_native_kit::pyjson::py_str)
            else {
                continue;
            };
            let mut schema = p
                .get("schema")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if let Some(desc) = p
                .get("description")
                .filter(|v| vexa_native_kit::pyjson::truthy(Some(v)))
            {
                schema.entry("description").or_insert(desc.clone());
            }
            match query.iter_mut().find(|(k, _)| *k == name) {
                Some(slot) => slot.1 = Value::Object(schema),
                None => query.push((name, Value::Object(schema))),
            }
        }
        let body = body_params(op, spec);
        let mut collision: Vec<&str> = query
            .iter()
            .filter(|(k, _)| body.iter().any(|(b, _)| b == k))
            .map(|(k, _)| k.as_str())
            .collect();
        if !collision.is_empty() {
            collision.sort();
            return fail(format!(
                "{d}/{n}: {method} {path} names {} in both its query parameters and its JSON body — one route, one place to look an argument up",
                vexa_native_kit::pyjson::py_repr(&json!(collision))
            ));
        }
        let path_params = path_params_of(path);
        let mut params = Vec::new();
        let mut body_declared = Vec::new();
        for arg in &tool.arguments {
            if path_params.contains(arg) {
                continue;
            }
            let schema = body
                .iter()
                .chain(query.iter())
                .rev()
                .find(|(k, _)| k == arg)
                .map(|(_, v)| v.clone());
            let Some(schema) = schema else {
                return fail(format!(
                    "{d}/{n}: declares the argument {}, which {method} {path} does not take — an argument the route ignores is a success the agent reports for something that did not happen",
                    vexa_native_kit::pyjson::py_str_repr(arg)
                ));
            };
            match params
                .iter_mut()
                .find(|(k, _): &&mut (String, Value)| k == arg)
            {
                Some(slot) => slot.1 = schema,
                None => params.push((arg.clone(), schema)),
            }
            if body.iter().any(|(k, _)| k == arg) && !body_declared.contains(arg) {
                body_declared.push(arg.clone());
            }
        }
        let base = bases
            .iter()
            .find(|(dd, _)| dd == d)
            .map(|(_, b)| b.clone())
            .unwrap_or_default();
        out.push(Bound {
            tool: tool.clone(),
            description: describe(op),
            params,
            path_params,
            body_params: body_declared,
            base,
        });
    }
    Ok(out)
}

// ─── the published tool ───────────────────────────────────────────────────────

/// register._json_type: the JSON type an owning route published for one argument.
fn json_type(schema: &Value) -> String {
    if let Some(t) = schema
        .get("type")
        .filter(|t| vexa_native_kit::pyjson::truthy(Some(t)))
    {
        return vexa_native_kit::pyjson::py_str(t);
    }
    if schema
        .get("$ref")
        .is_some_and(|r| vexa_native_kit::pyjson::truthy(Some(r)))
    {
        return "object".into();
    }
    for key in ["anyOf", "oneOf"] {
        for b in schema
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if b.is_object() && b.get("type").and_then(Value::as_str) != Some("null") {
                return json_type(b);
            }
        }
    }
    "string".into()
}

/// The edge's own annotation for one argument: Optional[int|float|bool|str|list|dict].
pub fn edge_type(schema: &Value) -> &'static str {
    match json_type(schema).as_str() {
        "integer" => "integer",
        "number" => "number",
        "boolean" => "boolean",
        "array" => "array",
        "object" => "object",
        _ => "string",
    }
}

/// pydantic's schema for Optional[T] of the edge's annotation.
pub fn optional_schema(kind: &str) -> Value {
    let inner = match kind {
        "array" => json!({"items": {}, "type": "array"}),
        "object" => json!({"additionalProperties": true, "type": "object"}),
        t => json!({"type": t}),
    };
    json!({"anyOf": [inner, {"type": "null"}]})
}

fn declares_keys(schema: &Value) -> bool {
    if schema.get("properties").is_some_and(Value::is_object)
        && schema.get("additionalProperties") == Some(&Value::Bool(false))
    {
        return true;
    }
    ["anyOf", "oneOf"].iter().any(|k| {
        schema
            .get(*k)
            .and_then(Value::as_array)
            .is_some_and(|bs| bs.iter().any(|b| b.is_object() && declares_keys(b)))
    })
}

fn declares_items(schema: &Value) -> bool {
    if schema.get("type").and_then(Value::as_str) == Some("array")
        && schema
            .get("items")
            .and_then(Value::as_object)
            .is_some_and(|i| !i.is_empty())
    {
        return true;
    }
    ["anyOf", "oneOf"].iter().any(|k| {
        schema
            .get(*k)
            .and_then(Value::as_array)
            .is_some_and(|bs| bs.iter().any(|b| b.is_object() && declares_items(b)))
    })
}

fn vocabulary(schema: &Value) -> Option<Value> {
    let values = schema
        .get("enum")
        .filter(|v| vexa_native_kit::pyjson::truthy(Some(v)))
        .or_else(|| schema.get("examples"));
    values
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
        .map(|v| Value::Array(v.clone()))
}

/// get_single_param_type_from_schema.
fn single_type(schema: &Value) -> Value {
    if let Some(branches) = schema.get("anyOf").and_then(Value::as_array) {
        return branches
            .iter()
            .filter_map(|b| {
                b.get("type")
                    .filter(|t| vexa_native_kit::pyjson::truthy(Some(t)))
            })
            .find(|t| t.as_str() != Some("null"))
            .cloned()
            .unwrap_or_else(|| "string".into());
    }
    schema
        .get("type")
        .cloned()
        .unwrap_or_else(|| "string".into())
}

/// Python's str.title().
pub fn title(text: &str) -> String {
    let mut out = String::new();
    let mut prev_cased = false;
    for c in text.chars() {
        if c.is_alphabetic() {
            if prev_cased {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            prev_cased = true;
        } else {
            out.push(c);
            prev_cased = false;
        }
    }
    out
}

impl Bound {
    pub fn name(&self) -> &str {
        &self.tool.name
    }

    pub fn method(&self) -> &str {
        &self.tool.route.as_ref().unwrap().0
    }

    pub fn template(&self) -> &str {
        &self.tool.route.as_ref().unwrap().1
    }

    pub fn declared(&self) -> impl Iterator<Item = &(String, Value)> {
        self.params
            .iter()
            .filter(|(n, _)| !self.path_params.contains(n))
    }

    pub fn query_declared(&self) -> Vec<&(String, Value)> {
        self.declared()
            .filter(|(n, _)| !self.body_params.contains(n))
            .collect()
    }

    pub fn body_declared(&self) -> Vec<&(String, Value)> {
        self.declared()
            .filter(|(n, _)| self.body_params.contains(n))
            .collect()
    }

    /// The route's own description: the bound one, or "<domain>: <METHOD> <path>".
    fn route_description(&self) -> String {
        let d = if self.description.is_empty() {
            format!(
                "{}: {} {}",
                self.tool.domain,
                self.method(),
                self.template()
            )
        } else {
            self.description.clone()
        };
        d.split('\u{c}').next().unwrap_or("").trim().to_owned()
    }

    /// The MCP tool fastapi-mcp derives from this route, its schema closed.
    pub fn descriptor(&self) -> Value {
        let summary = title(&self.tool.name.replace('_', " "));
        let mut description = summary;
        let route = self.route_description();
        if !route.is_empty() {
            description.push_str("\n\n");
            description.push_str(&route);
        }
        description.push_str("\n\n### Responses:\n\n**200**: Successful Response (Success Response)\nContent-Type: application/json");
        let mut props = Map::new();
        let mut required = Vec::new();
        for name in &self.path_params {
            props.insert(name.clone(), json!({"type": "string", "description": format!("part of this tool's address: {}", self.template()), "title": name}));
            required.push(Value::String(name.clone()));
        }
        for (name, schema) in self.declared() {
            let desc = schema
                .get("description")
                .filter(|d| vexa_native_kit::pyjson::truthy(Some(d)))
                .cloned();
            let prop = if self.body_params.contains(name)
                && (declares_keys(schema) || declares_items(schema))
            {
                let mut declared: Map<String, Value> =
                    schema.as_object().cloned().unwrap_or_default();
                declared.shift_remove("title");
                if let Some(d) = &desc {
                    declared.entry("description").or_insert(d.clone());
                }
                declared.insert("title".into(), name.clone().into());
                if !declared.contains_key("type") {
                    let t = single_type(&Value::Object(declared.clone()));
                    declared.insert("type".into(), t);
                }
                Value::Object(declared)
            } else {
                let kind = edge_type(schema);
                let mut p = optional_schema(kind).as_object().cloned().unwrap();
                if let Some(d) = desc {
                    p.insert("description".into(), d);
                }
                if let Some(words) = vocabulary(schema) {
                    p.insert("examples".into(), words);
                }
                p.insert("title".into(), name.clone().into());
                p.insert("type".into(), kind.into());
                Value::Object(p)
            };
            props.insert(name.clone(), prop);
        }
        let mut input = Map::new();
        input.insert("type".into(), "object".into());
        input.insert("properties".into(), Value::Object(props));
        input.insert(
            "title".into(),
            format!("{}Arguments", self.tool.name).into(),
        );
        if !required.is_empty() {
            input.insert("required".into(), Value::Array(required));
        }
        input.insert("additionalProperties".into(), false.into());
        json!({"name": self.tool.name, "description": description, "inputSchema": input})
    }
}

// ─── late domains ─────────────────────────────────────────────────────────────

/// An optional domain that was down at boot, asked again until it answers.
pub struct Late {
    pub pending: Mutex<Vec<(String, String)>>,
    pub bases: Mutex<Vec<(String, String)>>,
}

/// One round over the pending domains; returns, per domain that joined, its bound tools and its
/// assembled tools (route-less ones included).
pub fn poll_late(
    late: &Late,
    env: &Env,
    taken: &dyn Fn(&str) -> bool,
) -> Vec<(Vec<Bound>, Vec<Tool>)> {
    let mut joined = Vec::new();
    let pending = late.pending.lock().unwrap().clone();
    for (domain, base) in pending {
        let Ok(doc) = probe(&format!("{base}{MANIFEST_PATH}"), 1, 0.0) else {
            continue;
        };
        let Some(doc) = doc else {
            if !RETRY_WHEN_EMPTY.contains(&domain.as_str()) {
                late.pending.lock().unwrap().retain(|(d, _)| d != &domain);
                eprintln!("mcp: {domain} answered with no manifest; no tools from it");
            }
            continue;
        };
        let Ok(spec) = probe(&format!("{base}{OPENAPI_PATH}"), 1, 0.0) else {
            continue;
        };
        let attempt = || -> Result<(Vec<Bound>, Vec<Tool>), ManifestError> {
            let Some(spec) = spec else {
                return fail(format!("{domain}: manifest without an OpenAPI"));
            };
            let mut deployed: BTreeSet<String> = late
                .bases
                .lock()
                .unwrap()
                .iter()
                .map(|(d, _)| d.clone())
                .collect();
            deployed.insert(domain.clone());
            let mut assembly = assemble(&[doc], &deployed, env)?;
            drop_switched_off(&mut assembly, env);
            let mut clash: Vec<&str> = assembly
                .tools
                .iter()
                .filter(|t| taken(&t.name))
                .map(|t| t.name.as_str())
                .collect();
            if !clash.is_empty() {
                clash.sort();
                return fail(format!(
                    "{domain} claims tool names already served: {}",
                    vexa_native_kit::pyjson::py_repr(&json!(clash))
                ));
            }
            let openapi = HashMap::from([(domain.clone(), spec)]);
            let bound = bind(&assembly, &openapi, &[(domain.clone(), base.clone())])?;
            Ok((bound, assembly.tools))
        };
        match attempt() {
            Ok((bound, tools)) => {
                late.bases
                    .lock()
                    .unwrap()
                    .push((domain.clone(), base.clone()));
                late.pending.lock().unwrap().retain(|(d, _)| d != &domain);
                eprintln!(
                    "mcp: {domain} answered; its {} tool(s) joined the surface",
                    tools.len()
                );
                joined.push((bound, tools));
            }
            Err(e) => eprintln!(
                "mcp: {domain} answered but its tools cannot be served: {}",
                e.0
            ),
        }
    }
    joined
}

/// VEXA_MCP_REFRESH_SECONDS (default 30; a zero or unreadable value is the default).
pub fn refresh_interval(env: &Env) -> Duration {
    let s = number(env.get("VEXA_MCP_REFRESH_SECONDS"), 30.0);
    Duration::from_secs_f64(if s > 0.0 && s.is_finite() { s } else { 30.0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_and_features() {
        assert_eq!(title("get recording"), "Get Recording");
        assert_eq!(title("v2thing x"), "V2Thing X");
        let env: Env = [("VEXA_FEATURES".to_string(), "all,-crm".to_string())].into();
        assert!(switched_on("browser_bots", &env) && !switched_on("crm", &env));
        assert!(!switched_on("crm", &Env::new()));
    }

    #[test]
    fn manifest_rules() {
        let ok = json!({"contract": "mcp.tools.v1", "domain": "flows", "source": "oss", "depends_on": [],
                        "tools": [{"name": "a", "identity": "user", "auth": "subject", "requires": ["flows"],
                                   "route": {"method": "GET", "path": "/a"}}]});
        assert!(validate(&ok).is_ok());
        let mut cred = ok.clone();
        cred["tools"][0]["arguments"] = json!(["Token"]);
        assert!(validate(&cred)
            .unwrap_err()
            .0
            .contains("credential argument 'Token'"));
        let mut admin = ok.clone();
        admin["tools"][0]["auth"] = json!("admin");
        admin["admin_auth"] = json!({"header": "X-K", "key_env": "K"});
        let deployed: BTreeSet<String> = ["flows".to_string()].into();
        let refused = assemble(
            &[admin.clone()],
            &deployed,
            &[("K".to_string(), "changeme".to_string())].into(),
        );
        assert!(refused.unwrap_err().0.contains("a published placeholder"));
        assert_eq!(
            assemble(
                &[admin],
                &deployed,
                &[("K".to_string(), "real".to_string())].into()
            )
            .unwrap()
            .tools
            .len(),
            1
        );
    }
}
