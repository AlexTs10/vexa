//! vexa-crm: the Vexa CRM (core/crm, contract crm.v1) as a native process.
//!
//! crm-api's entry: the config.v1 preflight, then configured_app — the database (its own role and
//! the schema version this code knows), the audit retention, the desk limits, the org resolver,
//! the outbox loop when the desktop combines delivery — then the service on 127.0.0.1 and
//! VEXA_CRM_PORT (0.0.0.0:8300 without it).
#![allow(dead_code)]

mod api;
mod blocks;
mod bootstrap;
mod caller;
mod card_face;
mod card_ops;
mod card_templates;
mod db;
mod desk;
mod err;
mod fact_envelope;
mod fact_keys;
mod features;
mod field_classes;
mod layouts;
mod markdown_links;
mod member_settings;
mod migrate;
mod net;
mod orgs;
mod outbox;
mod person_profiles;
mod persons;
mod policies;
mod preflight;
mod privacy;
mod profiles;
mod retention;
mod schema;
mod store;
mod val;
mod validate;

use std::net::TcpListener;
use std::sync::Arc;

use vexa_native_kit::httpd::{self, Exchange};
use vexa_native_kit::pg::Pool;

/// The stack of each connection's thread (the PostgreSQL client needs more than the default).
const STACK_BYTES: usize = 8 * 1024 * 1024;
/// SQLAlchemy's pool_size=3, max_overflow=0.
const POOL_SIZE: usize = 3;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

fn fail(message: &str) -> ! {
    eprintln!("ERROR:crm.api:{message}");
    std::process::exit(1);
}

/// configured_app: the app as the deployment's environment configures it.
fn configured_app() -> Result<api::App, String> {
    let url = env("CRM_DATABASE_URL");
    let base = env("ADMIN_API_URL");
    let secret = env("INTERNAL_API_SECRET");
    let org_id = val::strip(&env("CRM_ORG_ID")).to_owned();
    if url.is_empty() || base.is_empty() || secret.is_empty() || org_id.is_empty() {
        return Err("CRM_DATABASE_URL, ADMIN_API_URL, INTERNAL_API_SECRET and CRM_ORG_ID are required for CRM service".into());
    }
    if !url.starts_with("postgresql+pg8000://") && !url.starts_with("postgresql://") {
        return Err("CRM deployment requires PostgreSQL".into());
    }
    let pool = Pool::new(&url, POOL_SIZE).map_err(|e| format!("CRM database: {}", e.message))?;
    // its own role, never a superuser, and the schema version this code knows
    migrate::check(&pool)?;
    let store = Arc::new(store::Store::new(pool.clone()));
    // the audit expires on schedule, through the migrations path's function only (retention.rs)
    retention::start(store.clone());
    // the desk limits' source: _global/POLICIES.md through agent-api's door (CRM_AGENT_API_URL,
    // optional — unset, the defaults apply), with the internal tier's secret
    let limits = Arc::new(policies::Policies::new(&env(policies::DOOR_ENV), &secret));
    // an individual's personal CRM is made on its first use (only with personal_crm on), through
    // the migrations path's function: crm-api's role cannot write orgs, policies or definitions
    let for_orgs = store.clone();
    let ensure: orgs::EnsureOrg = Box::new(move |org: &str, name: &str| bootstrap::ensure_personal_org(&for_orgs, org, name));
    let resolver = orgs::OrgResolver::new(&org_id, &base, &secret, Some(ensure));
    let app = api::create_app(
        store,
        api::identity(&base, &secret),
        &org_id,
        &secret,
        Some(limits.clone()),
        Some(card_ops::PolicyText::new(Some(limits))),
        Some(profiles::ProfileClient::new(&base, &secret)),
        Some(resolver),
    )?;
    // Desktop-only process merge. The flag is explicit so a server deployment never takes the
    // outbox key or starts a second delivery loop by accident.
    if api::outbox_enabled(&|k| std::env::var(k).ok()) {
        // the outbox starts in the app's lifespan: uvicorn ends a failed startup with exit 3
        let delivery = match outbox::start(pool, None) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("ERROR:crm.api:{e}");
                eprintln!("ERROR:    Application startup failed. Exiting.");
                std::process::exit(3);
            }
        };
        std::mem::forget(delivery);
    }
    Ok(app)
}

/// One request off the connection, answered by the app.
fn serve(app: &api::App, ex: &mut Exchange) {
    let body = match ex.read_body(None) {
        Ok(b) => b,
        Err(_) => {
            ex.close_after();
            let r = api::Response::bytes(400, "application/json", br#"{"detail":"There was an error parsing the body"}"#.to_vec());
            let _ = ex.respond(r.status, &r.headers, &r.body);
            return;
        }
    };
    let request = api::Request {
        method: ex.head.method.clone(),
        path: httpd::decode_path(&ex.head.raw_path),
        query: ex.head.query.clone(),
        headers: ex.head.headers.clone(),
        body,
    };
    let response = app.handle(&request);
    eprintln!(
        "INFO:     {} - \"{} {} {}\" {} {}",
        ex.peer,
        request.method,
        ex.head.target,
        ex.head.version,
        response.status,
        vexa_native_kit::reason::phrase(response.status)
    );
    let _ = ex.respond(response.status, &response.headers, &response.body);
}

fn main() {
    preflight::preflight();
    let app = match configured_app() {
        Ok(app) => app,
        Err(e) => fail(&e),
    };
    let port = env("VEXA_CRM_PORT");
    let address = if port.is_empty() { "0.0.0.0:8300".to_owned() } else { format!("127.0.0.1:{port}") };
    let listener = match TcpListener::bind(&address) {
        Ok(l) => l,
        Err(e) => fail(&format!("cannot listen on {address}: {e}")),
    };
    eprintln!("INFO:     Uvicorn running on http://{address} (Press CTRL+C to quit)");
    let app: &'static api::App = Box::leak(Box::new(app));
    let handler: Arc<dyn Fn(&mut Exchange) + Send + Sync> = Arc::new(move |ex: &mut Exchange| serve(app, ex));
    httpd::serve_with_stack(listener, handler, STACK_BYTES);
}
