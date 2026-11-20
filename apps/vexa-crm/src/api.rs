//! crm-api: the CRM's one door (api.py). The gateway MCP assembles its tools from this OpenAPI.
//!
//! Every person-facing route resolves the caller through identity (`caller::resolve`): who they
//! are, their live workspace memberships narrowed to a worker's ceiling, and whether the turn is one
//! other people read. Every route is audited with the caller's kind and the session's trace. The
//! internal routes (`/internal/*`) take the internal tier's secret and act for nobody: they carry
//! facts in (a workspace's references at a commit, an account that signed in), never answers out.

use std::sync::{Arc, OnceLock};

use serde_json::{json, Map, Value};

use crate::caller::{self, Caller, ResolveError};
use crate::card_ops::{Cards, PolicyText};
use crate::db::{self, Pending};
use crate::desk::Desk;
use crate::err::{CrmError, Detail, R};
use crate::features;
use crate::member_settings::MemberSettings;
use crate::orgs::{OrgError, OrgResolver};
use crate::policies::Policies;
use crate::privacy;
use crate::profiles::{self as profiles_mod, ProfileClient};
use crate::store::{check_workspace, Store};
use crate::validate;
use crate::val::{g, m, pystr, truthy, Obj};

pub const TRACE_HEADER: &str = "x-trace-id";
pub const OUTBOX_ENABLED_ENV: &str = "VEXA_CRM_OUTBOX_ENABLED";
pub const TITLE: &str = "Vexa CRM";
pub const VERSION: &str = "0.13.3";

const OPENAPI: &str = include_str!("openapi.json");
const MANIFEST: &str = include_str!("mcp.tools.v1.json");
const PAGES: &str = include_str!("pages.json");

/// True only when the desktop deployment explicitly combines CRM delivery.
///
/// The normal server deployment keeps the API and the delivery worker as two services. The
/// desktop overlay sets this flag after it gives this process the outbox's narrow publish key and
/// private seal key.
pub fn outbox_enabled(env: &dyn Fn(&str) -> Option<String>) -> bool {
    crate::val::lower(crate::val::strip(&env(OUTBOX_ENABLED_ENV).unwrap_or_default())) == "true"
}

// ── the request and the answer ─────────────────────────────────────────────────────────────────

/// One HTTP request as the routes read it.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    /// The percent-decoded path (ASGI `path`).
    pub path: String,
    /// The query string, as sent.
    pub query: String,
    /// Lower-case names in the order received.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first value of a header (Starlette's `request.headers.get`).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// Lower-case names, in the order written (content-length included).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, v: &Value) -> Self {
        Self::bytes(status, "application/json", crate::val::response_text(v).into_bytes())
    }
    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Response {
            status,
            headers: vec![("content-length".into(), body.len().to_string()), ("content-type".into(), content_type.into())],
            body,
        }
    }
    /// ServerErrorMiddleware's answer to an exception no handler takes.
    pub fn internal_error() -> Self {
        Self::bytes(500, "text/plain; charset=utf-8", b"Internal Server Error".to_vec())
    }
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.iter().any(|(k, _)| k == name)
    }
    /// The answer to an exception: its handler's JSON, or None for the plain-text 500.
    pub fn from_error(e: &CrmError) -> Option<Self> {
        match e.answer() {
            (status, Some(body)) => Some(Self::json(status, &body)),
            (_, None) => None,
        }
    }
}

/// HTTPException(status, detail).
fn http(status: u16, detail: impl Into<Value>) -> CrmError {
    CrmError::http(status, detail)
}

/// RequestValidationError: 422 with the error list as the detail.
fn invalid_request(errors: Vec<Value>) -> CrmError {
    CrmError::new("RequestValidationError", 422, Detail::Http(Value::Array(errors)))
}

// ── identity ───────────────────────────────────────────────────────────────────────────────────

/// Resolves a bearer through identity's `/internal/validate` — the one resolver.
pub type Identity = Box<dyn Fn(&Request) -> R<Caller> + Send + Sync>;

/// Identity(base, secret): the x-api-key header, else an Authorization bearer.
pub fn identity(base: &str, secret: &str) -> Identity {
    let base = base.trim_end_matches('/').to_owned();
    let secret = secret.to_owned();
    Box::new(move |request: &Request| {
        let mut token = request.header("x-api-key").unwrap_or("").to_owned();
        if token.is_empty() {
            let auth = request.header("authorization").unwrap_or("");
            let (scheme, value) = auth.split_once(' ').unwrap_or((auth, ""));
            token = if crate::val::lower(scheme) == "bearer" { value.to_owned() } else { String::new() };
        }
        if token.is_empty() {
            return Err(http(401, "Caller credential required"));
        }
        caller::resolve(&base, &secret, &token, request.header(TRACE_HEADER).unwrap_or("")).map_err(|e| match e {
            ResolveError::Unknown => http(401, "Invalid caller credential"),
            ResolveError::Unavailable(_) => http(503, "Identity service unavailable"),
        })
    })
}

// ── the routes ─────────────────────────────────────────────────────────────────────────────────

/// Which credential a route's dependency takes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Dep {
    /// A person (or their worker), through identity.
    Person,
    /// A person's own terminal session: no API key, no delegation.
    Session,
    /// The internal tier's secret.
    Internal,
}

/// Every POST route with a body: path, body model, dependency.
pub const POSTS: &[(&str, &str, Dep)] = &[
    ("/describe", "Describe", Dep::Person),
    ("/search", "Search", Dep::Person),
    ("/resolve", "Resolve", Dep::Person),
    ("/read", "Read", Dep::Person),
    ("/change", "Change", Dep::Person),
    ("/history", "Read", Dep::Person),
    ("/review", "Review", Dep::Session),
    ("/configure", "Configure", Dep::Person),
    ("/bind", "Bind", Dep::Person),
    ("/profile/link", "ProfileLink", Dep::Person),
    ("/profile/read", "Read", Dep::Person),
    ("/blocks/read", "BlockRead", Dep::Person),
    ("/desk/read", "DeskRead", Dep::Person),
    ("/desk/arrange", "DeskArrange", Dep::Person),
    ("/desk/arrange/propose", "DeskPropose", Dep::Person),
    ("/desk/proposal", "DeskProposalReview", Dep::Person),
    ("/desk/undo", "DeskUndo", Dep::Person),
    ("/desk/workspaces/read", "WorkspaceSettingsRead", Dep::Person),
    ("/desk/workspaces/set", "WorkspaceSettingsSet", Dep::Person),
    ("/card/list", "CardList", Dep::Person),
    ("/card/propose", "CardPropose", Dep::Person),
    ("/card/update/propose", "CardUpdatePropose", Dep::Person),
    ("/card/read", "CardRead", Dep::Person),
    ("/card/inbox", "CardInbox", Dep::Person),
    ("/card/seen", "CardRef", Dep::Session),
    ("/card/nonce", "CardRef", Dep::Session),
    ("/card/decide", "CardDecide", Dep::Session),
    ("/card/create", "CardCreate", Dep::Person),
    ("/card/update", "CardUpdate", Dep::Person),
    ("/card/members", "CardMembers", Dep::Person),
    ("/card/membership", "CardMembership", Dep::Person),
    ("/internal/references", "Snapshot", Dep::Internal),
    ("/internal/cards/offer", "MeetingOffer", Dep::Internal),
    ("/person/me", "PersonMe", Dep::Person),
    ("/person/merge", "PersonMerge", Dep::Session),
    ("/person/profile", "PersonProfile", Dep::Session),
    ("/internal/profiles", "Accounts", Dep::Internal),
    ("/internal/profiles/public", "Handle", Dep::Internal),
    ("/internal/persons", "Accounts", Dep::Internal),
    ("/internal/accounts", "Account", Dep::Internal),
];

/// The GET routes (FastAPI's own documents first, as it registers them).
pub const GETS: &[&str] = &["/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc", "/health", "/.well-known/mcp-tools.json"];

/// The body model of a POST route.
pub fn body_model(path: &str) -> Option<&'static str> {
    POSTS.iter().find(|(p, _, _)| *p == path).map(|(_, model, _)| *model)
}

/// `/internal/orgs/{org}/erase`: the org segment.
fn erase_param(path: &str) -> Option<&str> {
    let org = path.strip_prefix("/internal/orgs/")?.strip_suffix("/erase")?;
    (!org.is_empty() && !org.contains('/')).then_some(org)
}

/// Starlette's route match for a path: Some(methods) when a route has this path.
fn route_methods(path: &str) -> Option<&'static str> {
    if GETS.contains(&path) {
        Some("GET")
    } else if body_model(path).is_some() || erase_param(path).is_some() {
        Some("POST")
    } else {
        None
    }
}

// ── the app ────────────────────────────────────────────────────────────────────────────────────

pub struct App {
    pub store: Arc<Store>,
    identity: Identity,
    pub org_id: String,
    internal_secret: String,
    pub cards: Arc<Cards>,
    pub desk: Desk,
    pub member_settings: MemberSettings,
    pub profiles: Option<ProfileClient>,
    pub resolver: OrgResolver,
}

/// create_app(store, identity, org_id, internal_secret, limits, policy_text, profiles, org_resolver).
#[allow(clippy::too_many_arguments)]
pub fn create_app(
    store: Arc<Store>,
    identity: Identity,
    org_id: &str,
    internal_secret: &str,
    limits: Option<Arc<Policies>>,
    policy_text: Option<PolicyText>,
    profiles: Option<ProfileClient>,
    org_resolver: Option<OrgResolver>,
) -> Result<App, String> {
    if crate::val::strip(org_id).is_empty() {
        return Err("CRM_ORG_ID is required".into());
    }
    // the desk's limits: the company's `_global/POLICIES.md` (policies.rs), the defaults without one;
    // cards: lifecycles from the same file, the same limits as the desk
    let cards = Arc::new(Cards::new(store.clone(), policy_text, limits.clone()));
    let _ = store.cards.set(cards.clone());
    let desk = Desk::new(store.clone(), limits);
    let member_settings = MemberSettings::new(store.clone());
    // Which CRM org serves the caller (orgs.rs): the install org, unless `personal_crm` is on and
    // identity says the caller is an individual with an org of one — their personal CRM.
    let resolver = org_resolver.unwrap_or_else(|| OrgResolver::new(org_id, "", "", None));
    if let Some(p) = &profiles {
        // identity's old profile hands its values to the claimed profile, once
        let _ = store.legacy.set(p.clone());
    }
    Ok(App {
        store,
        identity,
        org_id: org_id.to_owned(),
        internal_secret: internal_secret.to_owned(),
        cards,
        desk,
        member_settings,
        profiles,
        resolver,
    })
}

/// The answer of a route: JSON, or a ready response (a document, a redirect).
enum Answer {
    Json(Value),
    Ready(Response),
}

/// Resets the pending audit row when the operation ends, however it ends.
struct PendingGuard(Option<Option<Pending>>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if let Some(prev) = self.0.take() {
            db::pending_set(prev);
        }
    }
}

fn docs() -> &'static Value {
    static D: OnceLock<Value> = OnceLock::new();
    D.get_or_init(|| serde_json::from_str(OPENAPI).expect("openapi.json is valid JSON"))
}

fn pages() -> &'static Value {
    static P: OnceLock<Value> = OnceLock::new();
    P.get_or_init(|| serde_json::from_str(PAGES).expect("pages.json is valid JSON"))
}

/// The record ids an answer carries, comma-joined (H9: a search names what it returned).
pub fn returned_ids(result: &Value) -> String {
    let Some(obj) = result.as_object() else { return String::new() };
    if truthy(m(obj, "record_id")) {
        return pystr(m(obj, "record_id"));
    }
    let mut ids = Vec::new();
    for key in ["records", "cards", "rows"] {
        if let Some(items) = m(obj, key).as_array() {
            for r in items {
                if r.is_object() && truthy(g(r, "id")) {
                    ids.push(pystr(g(r, "id")));
                }
            }
        }
    }
    ids.join(",")
}

fn s_of(b: &Obj, k: &str) -> String {
    crate::val::s(m(b, k))
}

fn opt_of(b: &Obj, k: &str) -> Option<String> {
    m(b, k).as_str().map(str::to_owned)
}

fn int_of(b: &Obj, k: &str) -> i64 {
    m(b, k).as_i64().unwrap_or(0)
}

fn bool_of(b: &Obj, k: &str) -> bool {
    m(b, k).as_bool().unwrap_or(false)
}

fn obj_of(b: &Obj, k: &str) -> Obj {
    m(b, k).as_object().cloned().unwrap_or_default()
}

/// `value or None` for a string.
fn or_none(v: &str) -> Option<&str> {
    (!v.is_empty()).then_some(v)
}

impl App {
    /// The whole request, through the middlewares in order: check_binding (outermost),
    /// privacy_label, feature_switch, then the router.
    pub fn handle(&self, request: &Request) -> Response {
        // check_binding
        if let Some(binding) = request.header("x-crm-org") {
            if binding != self.org_id {
                return Response::json(403, &json!({"detail": "CRM instance binding mismatch"}));
            }
        }
        // privacy_label: every CRM answer is the person's private data; an unhandled error never
        // reaches it (the plain-text 500 carries no label)
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.feature_switch(request)));
        match caught {
            Ok(Some(mut response)) => {
                if !response.has_header(privacy::LABEL_HEADER) {
                    response.headers.push((privacy::LABEL_HEADER.into(), privacy::CRM_LABEL.into()));
                }
                response
            }
            Ok(None) | Err(_) => Response::internal_error(),
        }
    }

    /// VEXA_FEATURES (features.rs): a release install does not serve the unproven CRM. Its rows
    /// stay; every route but liveness, the manifest and the OpenAPI refuses before it
    /// authenticates. The desk rides `desktop` as well, and needs both.
    fn feature_switch(&self, request: &Request) -> Option<Response> {
        let path = url_path(&request.path);
        let refuse = |detail: Value| Some(Response::json(403, &json!({"detail": detail})));
        if path.starts_with(features::CARD_PREFIX) && !features::cards_served() {
            return refuse(features::refusal(features::CARDS, features::CARDS_SUMMARY));
        }
        if path.starts_with(features::DESK_PREFIX) && !features::desk_served() {
            return refuse(features::refusal(features::DESKTOP, features::DESKTOP_SUMMARY));
        }
        // erasure is never switched off: an account's personal CRM must go when the account does
        if !features::ALWAYS_SERVED.contains(&path) && !features::is_erase_path(path) && !features::switched_on(features::FEATURE) {
            return refuse(features::refusal(features::FEATURE, features::SUMMARY));
        }
        // public profiles (profiles.rs): explicit — on only when VEXA_FEATURES names it
        if path.starts_with(profiles_mod::PREFIX) && !profiles_mod::switched_on() {
            return refuse(features::refusal(profiles_mod::FEATURE, profiles_mod::SUMMARY));
        }
        self.route(request)
    }

    /// The router: a route's answer, 405 for a known path with another method, a slash redirect,
    /// or 404. None: an unhandled error (the plain-text 500).
    fn route(&self, request: &Request) -> Option<Response> {
        let path = request.path.as_str();
        match route_methods(path) {
            Some(method) if method == request.method => {
                let result = if method == "GET" { self.get(path) } else { self.post(path, request) };
                match result {
                    Ok(Answer::Json(v)) => Some(Response::json(200, &v)),
                    Ok(Answer::Ready(r)) => Some(r),
                    Err(e) => Response::from_error(&e),
                }
            }
            Some(method) => {
                let mut r = Response::json(405, &json!({"detail": "Method Not Allowed"}));
                r.headers.insert(0, ("allow".into(), method.into()));
                Some(r)
            }
            None => {
                if path != "/" {
                    let other = match path.strip_suffix('/') {
                        Some(p) => p.to_owned(),
                        None => format!("{path}/"),
                    };
                    if route_methods(&other).is_some() {
                        let host = request.header("host").unwrap_or("");
                        let query = if request.query.is_empty() { String::new() } else { format!("?{}", request.query) };
                        return Some(Response {
                            status: 307,
                            headers: vec![("content-length".into(), "0".into()), ("location".into(), format!("http://{host}{other}{query}"))],
                            body: Vec::new(),
                        });
                    }
                }
                Some(Response::json(404, &json!({"detail": "Not Found"})))
            }
        }
    }

    fn get(&self, path: &str) -> R<Answer> {
        match path {
            "/health" => Ok(Answer::Json(json!({"status": "ok", "domain": "crm"}))),
            "/.well-known/mcp-tools.json" => Ok(Answer::Json(manifest())),
            "/openapi.json" => Ok(Answer::Json(docs().clone())),
            page => {
                let p = g(pages(), page);
                let status = p.get("status").and_then(Value::as_u64).unwrap_or(200) as u16;
                let ct = p.get("content-type").and_then(Value::as_str).unwrap_or("text/html; charset=utf-8");
                Ok(Answer::Ready(Response::bytes(status, ct, crate::val::s(g(p, "body")).into_bytes())))
            }
        }
    }

    // ── the dependencies ───────────────────────────────────────────────────────────────────────

    /// The caller, its CRM org, its account attached (ADR-0047 d3) and its profile claimed (D35).
    pub fn person(&self, request: &Request) -> R<Caller> {
        let mut caller = (self.identity)(request)?;
        caller.org = match self.resolver.org_for(&caller) {
            Ok(org) => org,
            Err(OrgError::Identity(_)) => return Err(http(503, "Identity service unavailable")),
            Err(OrgError::Crm(e)) => return Err(e),
        };
        match self.store.ensure_account(&caller.org, &caller) {
            Ok(_) => {}
            Err(e) if e.is_crm() => {} // a clash is the admin's to merge, not a 500
            Err(e) => return Err(e),
        }
        // D35: the one record matching the verified address is claimed as this person's profile,
        // and identity's retired profile's entries move into it (once, while it is empty); a claim
        // is never a 500
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let profiles = crate::person_profiles::Profiles::new(&self.store);
            if let Ok(Some(claimed)) = self.store.engine_begin(|c| profiles.auto_claim(c, &caller.org, &caller)) {
                let _ = profiles.carry_legacy(&caller.org, &caller.subject, &claimed);
            }
        }));
        Ok(caller)
    }

    /// D13: a decision takes the terminal's SESSION credential: no API key (a browser-scoped one
    /// included), no delegation token. Refused before anything is read.
    pub fn session_person(&self, request: &Request) -> R<Caller> {
        let caller = self.person(request)?;
        if caller.delegated || caller.credential_class != "session" {
            return Err(CrmError::refused(caller::session_refusal()));
        }
        Ok(caller)
    }

    pub fn internal(&self, request: &Request) -> R<Caller> {
        let presented = request.header("x-internal-secret").unwrap_or("");
        if self.internal_secret.is_empty() || presented.is_empty() || !constant_time_eq(presented.as_bytes(), self.internal_secret.as_bytes()) {
            return Err(http(403, "Internal credential required"));
        }
        Ok(Caller { internal: true, trace: request.header(TRACE_HEADER).unwrap_or("").to_owned(), ..Default::default() })
    }

    fn dependency(&self, dep: Dep, request: &Request) -> R<Caller> {
        match dep {
            Dep::Person => self.person(request),
            Dep::Session => self.session_person(request),
            Dep::Internal => self.internal(request),
        }
    }

    // ── the audit ──────────────────────────────────────────────────────────────────────────────

    /// H9: every route is audited with the caller's kind, principal, the person acted for and the
    /// workspace. A write path writes its row IN ITS OWN TRANSACTION (`Store::begin` reads the
    /// pending row), so no write commits without one; a read path, which commits nothing, writes it
    /// here before the answer leaves, so no answer is returned without one. A refusal is audited too.
    pub fn audited(&self, op: &str, caller: &Caller, record_id: &str, call: impl FnOnce() -> R<Value>) -> R<Value> {
        self.audited_with(op, caller, record_id, call, returned_ids)
    }

    fn audited_with<T>(&self, op: &str, caller: &Caller, record_id: &str, call: impl FnOnce() -> R<T>, ids: impl Fn(&T) -> String) -> R<T> {
        let org = if caller.org.is_empty() { self.org_id.clone() } else { caller.org.clone() };
        let pending = Pending { org: org.clone(), caller: caller.clone(), op: op.to_owned(), record_id: record_id.to_owned(), written: false };
        let _guard = PendingGuard(Some(db::pending_set(Some(pending))));
        let result = match call() {
            Ok(r) => r,
            Err(e) => {
                if e.is_crm() {
                    self.store.audit(&org, caller, op, record_id, e.class)?;
                }
                return Err(e);
            }
        };
        if !db::pending_get().is_some_and(|p| p.written) {
            let rid = if record_id.is_empty() { ids(&result) } else { record_id.to_owned() };
            self.store.audit(&org, caller, op, &rid, "ok")?;
        }
        Ok(result)
    }

    // ── the POST routes ────────────────────────────────────────────────────────────────────────

    fn post(&self, path: &str, request: &Request) -> R<Answer> {
        if let Some(org) = erase_param(path) {
            let caller = self.internal(request)?;
            return self.erase_org(org, &caller).map(Answer::Json);
        }
        let Some((_, model, dep)) = POSTS.iter().find(|(p, _, _)| *p == path) else {
            return Err(http(404, "Not Found"));
        };
        // the body is read (a JSON decode error answers first), then the dependency, then the model
        let raw = match validate::read(request.header("content-type"), &request.body) {
            Ok(b) => b,
            Err(validate::BodyFail::Decode(e)) => return Err(invalid_request(vec![e])),
            Err(validate::BodyFail::Parse) => return Err(http(400, "There was an error parsing the body")),
            Err(validate::BodyFail::Internal) => return Err(CrmError::internal("the body is not UTF-8")),
        };
        let caller = self.dependency(*dep, request)?;
        let body = validate::body(model, &raw).map_err(invalid_request)?;
        let raw_json = match &raw {
            validate::Body::Json(v) => v.clone(),
            _ => Value::Null,
        };
        self.dispatch(path, request, &caller, &body, &raw_json).map(Answer::Json)
    }

    fn dispatch(&self, path: &str, request: &Request, caller: &Caller, b: &Obj, raw: &Value) -> R<Value> {
        let store = &*self.store;
        let org = caller.org.as_str();
        match path {
            "/describe" => {
                let ot = s_of(b, "object_type");
                self.audited("describe", caller, "", || store.describe(org, caller, or_none(&ot)))
            }
            "/search" => self.audited("search", caller, "", || {
                store.search(org, caller, &s_of(b, "object_type"), &obj_of(b, "filters"), int_of(b, "limit"), int_of(b, "offset"))
            }),
            "/resolve" => self.audited("resolve", caller, "", || store.resolve_name(org, caller, &s_of(b, "name"))),
            "/read" => {
                let rid = s_of(b, "record_id");
                self.audited("read", caller, &rid, || store.get(org, caller, &rid))
            }
            "/change" => self.change(request, caller, b),
            "/history" => {
                let rid = s_of(b, "record_id");
                self.audited("history", caller, &rid, || store.history(org, caller, &rid))
            }
            "/review" => {
                let pid = s_of(b, "proposal_id");
                self.audited("review", caller, &pid, || store.review(org, caller, &pid, bool_of(b, "accept")))
            }
            "/configure" => self.audited("configure", caller, "", || {
                let layout = m(b, "layout");
                store.configure(org, caller, &s_of(b, "object_type"), truthy(layout).then_some(layout), int_of(b, "expected_version"), &s_of(b, "reason"))
            }),
            "/bind" => {
                let bound = bool_of(b, "bound");
                let rid = s_of(b, "record_id");
                self.audited(if bound { "bind" } else { "unbind" }, caller, &rid, || store.bind(org, caller, &s_of(b, "workspace"), &rid, bound))
            }
            "/profile/link" => self.profile_link(caller, b),
            "/profile/read" => self.profile_read(caller, b),
            "/blocks/read" => self.block_read(caller, b),
            // ── the desk ──
            "/desk/read" => self.audited("desk.read", caller, "", || self.desk.read(org, caller)),
            "/desk/arrange" => self.audited("desk.arrange", caller, "", || {
                let name = opt_of(b, "name");
                self.desk.arrange(org, caller, m(b, "ops"), int_of(b, "base_version"), name.as_deref())
            }),
            "/desk/arrange/propose" => self.audited("desk.propose", caller, "", || self.desk.propose(org, caller, m(b, "ops"), &s_of(b, "reason"))),
            "/desk/proposal" => {
                let pid = s_of(b, "proposal_id");
                self.audited("desk.proposal", caller, &pid, || self.desk.review(org, caller, &pid, bool_of(b, "apply"), int_of(b, "base_version")))
            }
            "/desk/undo" => self.audited("desk.undo", caller, "", || self.desk.undo(org, caller, int_of(b, "version"), int_of(b, "base_version"))),
            "/desk/workspaces/read" => self.audited("desk.workspaces.read", caller, "", || self.member_settings.read(org, caller)),
            "/desk/workspaces/set" => {
                // settings.model_dump(exclude_unset=True): the keys sent, in the model's order
                let given = g(raw, "settings");
                let settings: Obj = obj_of(b, "settings").into_iter().filter(|(k, _)| given.get(k).is_some()).collect();
                let settings = Value::Object(settings);
                self.audited("desk.workspaces.set", caller, "", || self.member_settings.set(org, caller, &s_of(b, "workspace"), &settings))
            }
            // ── cards ──
            "/card/list" => self.audited("card.list", caller, "", || {
                let (ws, about, state) = (opt_of(b, "workspace"), opt_of(b, "about"), opt_of(b, "state"));
                self.cards.list(org, caller, ws.as_deref(), about.as_deref(), state.as_deref(), bool_of(b, "mine"), int_of(b, "limit"))
            }),
            "/card/propose" => {
                let ws = opt_of(b, "workspace");
                if ws.as_deref().is_some_and(|w| !w.is_empty()) {
                    // onto a board its members read (the person's own desktop is theirs)
                    privacy::hold(request.header(privacy::STATE_HEADER), caller, "card_proposal")?;
                }
                self.audited("card.propose", caller, "", || {
                    let (about, parent) = (opt_of(b, "about"), opt_of(b, "parent"));
                    let face = m(b, "face");
                    self.cards.propose(org, caller, &s_of(b, "title"), ws.as_deref(), about.as_deref(), &s_of(b, "type"), parent.as_deref(),
                        &obj_of(b, "fields"), (!face.is_null()).then_some(face), &s_of(b, "reason"))
                })
            }
            "/card/update/propose" => {
                privacy::hold(request.header(privacy::STATE_HEADER), caller, "card_proposal")?;
                let card = s_of(b, "card");
                self.audited("card.update.propose", caller, &card, || {
                    let face = m(b, "face");
                    let transition = opt_of(b, "transition");
                    self.cards.update_propose(org, caller, &card, int_of(b, "expected_revision"), &obj_of(b, "fields"), (!face.is_null()).then_some(face),
                        transition.as_deref(), &s_of(b, "reason"))
                })
            }
            "/card/read" => {
                let card = s_of(b, "card");
                self.audited("card.read", caller, &card, || self.cards.read(org, caller, &card))
            }
            "/card/inbox" => self.audited("card.inbox", caller, "", || self.cards.inbox(org, caller)),
            "/card/seen" => {
                let card = s_of(b, "card");
                self.audited("card.seen", caller, &card, || self.cards.seen(org, caller, &card))
            }
            "/card/nonce" => {
                let card = s_of(b, "card");
                self.audited("card.nonce", caller, &card, || self.cards.nonce(org, caller, &card))
            }
            "/card/decide" => {
                let card = s_of(b, "card");
                let action = s_of(b, "action");
                self.audited(&format!("card.decide.{action}"), caller, &card, || {
                    let evidence = m(b, "evidence");
                    let (receipt, answer, reason) = (opt_of(b, "receipt"), opt_of(b, "answer"), opt_of(b, "reason"));
                    self.cards.decide(org, caller, &card, &action, &s_of(b, "nonce"), &s_of(b, "content_hash"), (!evidence.is_null()).then_some(evidence),
                        receipt.as_deref(), answer.as_deref(), reason.as_deref())
                })
            }
            "/card/create" => self.audited("card.create", caller, "", || {
                let (ws, about, parent, description) = (opt_of(b, "workspace"), opt_of(b, "about"), opt_of(b, "parent"), opt_of(b, "description"));
                let face = m(b, "face");
                self.cards.create(org, caller, &s_of(b, "title"), ws.as_deref(), about.as_deref(), &s_of(b, "type"), parent.as_deref(), &obj_of(b, "fields"),
                    (!face.is_null()).then_some(face), description.as_deref())
            }),
            "/card/update" => {
                let card = s_of(b, "card");
                self.audited("card.update", caller, &card, || {
                    let face = m(b, "face");
                    let transition = opt_of(b, "transition");
                    self.cards.update(org, caller, &card, int_of(b, "expected_revision"), &obj_of(b, "fields"), (!face.is_null()).then_some(face), transition.as_deref())
                })
            }
            "/card/members" => {
                let card = s_of(b, "card");
                self.audited("card.members", caller, &card, || self.cards.members(org, caller, &card, &s_of(b, "subject"), bool_of(b, "add")))
            }
            "/card/membership" => {
                let card = s_of(b, "card");
                self.audited("card.membership", caller, &card, || self.cards.membership(org, caller, &card, bool_of(b, "accept")))
            }
            // ── the internal tier ──
            "/internal/references" => self.audited("references", caller, "", || {
                let refs: Vec<Value> = m(b, "references").as_array().cloned().unwrap_or_default();
                let members = m(b, "members").as_array().cloned();
                store.apply_workspace_snapshot(&self.org_id, &s_of(b, "workspace"), &s_of(b, "commit"), &s_of(b, "committed_at"), &refs, members.as_deref())
            }),
            "/internal/cards/offer" => self.cards_offer(caller, b),
            // ── D35: one Person, many addresses ──
            "/person/me" => self.audited("person.me", caller, "", || crate::persons::Persons::new(store).me(org, caller)),
            "/person/merge" => self.person_merge(caller, b),
            "/person/profile" => self.person_profile(caller, b),
            "/internal/profiles" => {
                let accounts: Vec<Value> = m(b, "accounts").as_array().cloned().unwrap_or_default();
                let out = crate::person_profiles::Profiles::new(store).directory(&self.org_id, &accounts)?;
                store.audit(&self.org_id, caller, "profiles.directory", "", "ok")?;
                Ok(json!({"profiles": out}))
            }
            "/internal/profiles/public" => match crate::person_profiles::Profiles::new(store).public(&s_of(b, "handle"))? {
                Some(page) => Ok(page),
                None => Err(http(404, "No public profile")),
            },
            "/internal/persons" => {
                let accounts: Vec<Value> = m(b, "accounts").as_array().cloned().unwrap_or_default();
                let out = crate::persons::Persons::new(store).group(&self.org_id, &accounts)?;
                store.audit(&self.org_id, caller, "persons", "", "ok")?;
                Ok(json!({"persons": out}))
            }
            "/internal/accounts" => {
                let email = crate::val::lower(crate::val::strip(&s_of(b, "email")));
                let record_id = store.ensure_account(&self.org_id, &Caller { email, ..Caller::subject(s_of(b, "subject")) })?;
                store.audit(&self.org_id, caller, "account", record_id.as_deref().unwrap_or(""), "ok")?;
                Ok(json!({"record_id": record_id}))
            }
            _ => Err(http(404, "Not Found")),
        }
    }

    /// Create a record, change one, propose a change, or merge a duplicate into the survivor.
    fn change(&self, request: &Request, caller: &Caller, b: &Obj) -> R<Value> {
        // D6: a CRM write is read by the org — a marked session's write is held for the person.
        privacy::hold(request.header(privacy::STATE_HEADER), caller, "crm_write")?;
        let store = &*self.store;
        let org = caller.org.as_str();
        let action = s_of(b, "action");
        let rid = s_of(b, "record_id");
        let narrative = opt_of(b, "narrative");
        let evidence = m(b, "evidence");
        if action == "create" {
            if s_of(b, "idempotency_key").is_empty() {
                return Err(http(400, "Create requires an idempotency_key"));
            }
            let matches: Vec<Value> = m(b, "match").as_array().cloned().unwrap_or_default();
            return self.audited("create", caller, "", || {
                store.create(org, caller, &s_of(b, "object_type"), &obj_of(b, "fields"), narrative.as_deref().unwrap_or(""), &s_of(b, "reason"), evidence,
                    &s_of(b, "idempotency_key"), &matches)
            });
        }
        if action == "merge" {
            if s_of(b, "into").is_empty() {
                return Err(http(400, "Merge requires into"));
            }
            return self.audited("merge", caller, &rid, || store.merge(org, caller, &rid, &s_of(b, "into"), &s_of(b, "reason")));
        }
        self.audited(&action, caller, &rid, || {
            store.change(org, caller, &rid, int_of(b, "expected_revision"), &obj_of(b, "fields"), narrative.as_deref(), &s_of(b, "reason"), evidence,
                action == "propose")
        })
    }

    /// Link this record to a person's published public profile (by its handle), or unlink it.
    fn profile_link(&self, caller: &Caller, b: &Obj) -> R<Value> {
        let Some(profiles) = &self.profiles else { return Err(http(503, "Public profiles are not configured")) };
        let linked = bool_of(b, "linked");
        let handle = s_of(b, "handle");
        let rid = s_of(b, "record_id");
        if linked && (handle.is_empty() || !profiles_mod::is_handle(&handle)) {
            return Err(http(422, "A profile handle is required"));
        }
        let org = caller.org.as_str();
        // The record first: someone who may not change it learns nothing about the profile.
        let _current = self.store.profile_link_of(org, caller, &rid)?;
        let unavailable = |_| http(503, "Identity service unavailable");
        if linked && profiles.public(&handle).map_err(unavailable)?.is_none() {
            return Err(http(404, "No published profile with that handle"));
        }
        let result = self.audited(if linked { "profile_link" } else { "profile_unlink" }, caller, &rid, || {
            self.store.profile_link(org, caller, &rid, &handle, linked)
        })?;
        let gone = g(&result, "previous");
        let differs = if linked { gone.as_str() != Some(handle.as_str()) } else { !gone.is_null() };
        if truthy(gone) && differs {
            profiles.tell(&pystr(gone), org, false).map_err(unavailable)?;
        }
        if linked && gone.as_str() != Some(handle.as_str()) {
            profiles.tell(&handle, org, true).map_err(unavailable)?;
        }
        let key = |k: &str| result.get(k).cloned().ok_or_else(|| CrmError::internal(format!("KeyError: '{k}'")));
        Ok(json!({"record_id": key("record_id")?, "linked": linked, "handle": key("handle")?}))
    }

    /// The public profile this record links to, read live — or none (unlinked, or withdrawn).
    fn profile_read(&self, caller: &Caller, b: &Obj) -> R<Value> {
        let rid = s_of(b, "record_id");
        let (rid, handle) =
            self.audited_with("profile.read", caller, &rid, || self.store.profile_link_of(&caller.org, caller, &rid), |_| String::new())?;
        let Some(handle) = handle.filter(|h| !h.is_empty()) else {
            return Ok(json!({"record_id": rid, "linked": false, "profile": null, "withdrawn": false}));
        };
        let Some(profiles) = &self.profiles else { return Err(http(503, "Public profiles are not configured")) };
        let prof = profiles.public(&handle).map_err(|_| http(503, "Identity service unavailable"))?;
        let withdrawn = prof.is_none();
        Ok(json!({"record_id": rid, "linked": true, "profile": prof, "withdrawn": withdrawn}))
    }

    /// A page's `{{crm …}}` block, for this one viewer: the rows they may read, each field marked
    /// `shared` when the page's workspace may see it too. No totals. A room is refused.
    fn block_read(&self, caller: &Caller, b: &Obj) -> R<Value> {
        if caller.shared {
            return Err(http(403, json!({"reason": "person_only", "detail": "A page block is rendered for one person."})));
        }
        let mut args = Map::new();
        for (k, v) in obj_of(b, "args").iter().take(8) {
            let key: String = k.chars().take(40).collect();
            let value: String = pystr(v).chars().take(200).collect();
            args.insert(key, Value::String(value));
        }
        self.audited("block.read", caller, "", || {
            crate::blocks::read_block(&self.store, &caller.org, caller, &s_of(b, "workspace"), &s_of(b, "view"), &args)
        })
    }

    /// The post-meeting run offers the meeting's follow-ups as cards of a kind, AS THE ROOM'S
    /// WORKSPACE PRINCIPAL: shared, never admin, the members' intersection — the same
    /// `card_propose` path with the same caps. Internal tier only.
    fn cards_offer(&self, internal: &Caller, b: &Obj) -> R<Value> {
        let ws_given = s_of(b, "workspace");
        let ws = if ws_given.is_empty() { None } else { Some(check_workspace(&ws_given)?) };
        let on_behalf_of = s_of(b, "on_behalf_of");
        let mut extra = Map::new();
        extra.insert("on_behalf_of".into(), on_behalf_of.clone().into());
        if let Some(w) = &ws {
            extra.insert("principal_kind".into(), "workspace".into());
            extra.insert("principal_workspace".into(), w.clone().into());
        }
        let list: Vec<String> = ws.iter().cloned().collect();
        let actor = Caller {
            subject: s_of(b, "principal"),
            workspaces: list.clone(),
            writable: Some(list),
            delegated: true,
            regime: "autonomous".into(),
            shared: ws.is_some(),
            session: s_of(b, "session"),
            trace: internal.trace.clone(),
            credential_class: "delegation".into(),
            extra,
            ..Default::default()
        };
        let specs: Vec<Value> = m(b, "cards")
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| {
                let mut fields = Map::new();
                fields.insert("Kind".into(), g(c, "kind").clone());
                fields.insert("NextActor".into(), g(c, "next_actor").clone());
                let requester = crate::val::s(g(c, "requester"));
                fields.insert("Requester".into(), (if requester.is_empty() { on_behalf_of.clone() } else { requester }).into());
                if truthy(g(c, "due")) {
                    fields.insert("Due".into(), g(c, "due").clone());
                }
                json!({"title": g(c, "title"), "about": g(c, "about"), "fields": fields})
            })
            .collect();
        self.audited("card.offer", &actor, "", || self.cards.offer_many(&self.org_id, &actor, ws.as_deref(), &s_of(b, "origin"), &specs, &s_of(b, "reason")))
    }

    /// Erase an individual's personal CRM: the rows keyed to their org of one (`p-<id>`), on
    /// account delete. Never the install's org, never any other shape of org.
    fn erase_org(&self, org: &str, _caller: &Caller) -> R<Value> {
        if org == self.org_id || !crate::orgs::is_personal_org(org) {
            return Err(http(400, "Only an individual account's own CRM (p-<id>) can be erased"));
        }
        let mut out = Map::new();
        out.insert("org".into(), org.into());
        if let Value::Object(rest) = self.store.erase_org(org)? {
            for (k, v) in rest {
                out.insert(k, v);
            }
        }
        Ok(Value::Object(out))
    }

    /// The person's own act on their merge card: confirm (with the primary address), decline,
    /// change the primary later, or offer another address of theirs.
    fn person_merge(&self, caller: &Caller, b: &Obj) -> R<Value> {
        let p = crate::persons::Persons::new(&self.store);
        let org = caller.org.as_str();
        let action = s_of(b, "action");
        let card = s_of(b, "card");
        let primary = s_of(b, "primary");
        self.audited(&format!("person.merge.{action}"), caller, &card, || match action.as_str() {
            "confirm" => p.confirm(org, caller, &card, or_none(&primary)),
            "decline" => p.decline(org, caller, &card),
            "primary" => p.set_primary(org, caller, &primary),
            _ => p.offer_for_address(org, caller, &s_of(b, "address")),
        })
    }

    /// The person's own profile: read, edit (theirs only), claim, unclaim, the public page.
    fn person_profile(&self, caller: &Caller, b: &Obj) -> R<Value> {
        let p = crate::person_profiles::Profiles::new(&self.store);
        let org = caller.org.as_str();
        let action = s_of(b, "action");
        let rid = s_of(b, "record_id");
        self.audited(&format!("person.profile.{action}"), caller, &rid, || match action.as_str() {
            "read" => p.mine(org, caller),
            "edit" => p.edit(org, caller, &Value::Object(obj_of(b, "fields")), or_none(&rid)),
            "claim" => {
                let result = p.claim(org, caller, or_none(&rid))?;
                if g(&result, "status").as_str() == Some("claimed") {
                    // the claim stands without it
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if let Some(record) = result.get("record_id") {
                            let _ = p.carry_legacy(org, &caller.subject, &pystr(record));
                        }
                    }));
                }
                Ok(result)
            }
            "unclaim" => p.unclaim(org, caller),
            "publish" => {
                let public_fields = m(b, "public_fields");
                let list: Option<Vec<String>> = public_fields
                    .as_array()
                    .map(|a| a.iter().map(pystr).collect());
                p.publish(org, caller, bool_of(b, "public"), list.as_deref())
            }
            "import" => p.import_profile(org, caller, &s_of(b, "source")),
            other => Err(CrmError::internal(format!("KeyError: '{other}'"))),
        })
    }
}

/// The manifest the MCP edge assembles crm_* tools from, filtered by what this install serves.
pub fn manifest() -> Value {
    let mut doc: Value = serde_json::from_str(MANIFEST).expect("mcp.tools.v1.json is valid JSON");
    let tools: Vec<Value> = doc.get("tools").and_then(Value::as_array).cloned().unwrap_or_default();
    let tools: Vec<Value> = if !features::switched_on(features::FEATURE) {
        Vec::new() // switched off: the MCP edge assembles no crm_* tool
    } else if !features::desk_served() {
        // the desk's tools, and every other tool on a /desk/ route (workspace settings)
        tools
            .into_iter()
            .filter(|t| {
                !crate::val::s(g(t, "name")).starts_with(features::DESK_TOOL_PREFIX)
                    && !crate::val::s(g(g(t, "route"), "path")).starts_with(features::DESK_PREFIX)
            })
            .collect()
    } else {
        tools
    };
    let tools: Vec<Value> = if !features::cards_served() {
        tools.into_iter().filter(|t| !crate::val::s(g(t, "name")).starts_with(features::CARD_TOOL_PREFIX)).collect()
    } else {
        tools
    };
    if let Some(o) = doc.as_object_mut() {
        o.insert("tools".into(), Value::Array(tools));
    }
    doc
}

/// request.url.path: the decoded path up to a "?" or "#" it may carry.
fn url_path(path: &str) -> &str {
    path.split(['?', '#']).next().unwrap_or("")
}

/// hmac.compare_digest.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

