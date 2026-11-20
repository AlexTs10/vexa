//! The Vexa application services as host processes.
//!
//! Each service keeps its Compose configuration names. A value that an
//! operator can set in Compose `.env` is read from `native.env` with the same
//! Compose default (`pass`). Service addresses point at 127.0.0.1 and the
//! native ports; key and state volumes become folders below the Vexa folder.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::pyapp::PyApp;
use crate::stack::Stack;
use crate::supervisor::{Ready, Spec, Supervisor};

const PROD: &[&str] = &["--no-dev", "--group", "production"];
const NO_DEV: &[&str] = &["--no-dev"];

pub const ADMIN: PyApp = PyApp {
    name: "admin-api",
    context: "core/identity/services/admin-api",
    dockerfile: "core/identity/services/admin-api/Dockerfile",
    project: "core/identity/services/admin-api",
    sync: PROD,
    pythonpath: "app/src",
    workdir: "app",
};
pub const MEETING: PyApp = PyApp {
    name: "meeting-api",
    context: ".",
    dockerfile: "core/meetings/services/meeting-api/Dockerfile",
    project: "core/meetings/services/meeting-api",
    sync: PROD,
    pythonpath: "app/src",
    workdir: "app",
};
pub const AGENT: PyApp = PyApp {
    name: "agent-api",
    context: ".",
    dockerfile: "core/agent/services/agent-api/Dockerfile",
    project: "core/agent",
    sync: &["--no-default-groups", "--group", "control-plane"],
    pythonpath: "app",
    workdir: "app",
};
pub const GATEWAY: PyApp = PyApp {
    name: "gateway",
    context: ".",
    dockerfile: "core/gateway/services/gateway/Dockerfile",
    project: "core/gateway/services/gateway",
    sync: PROD,
    pythonpath: "app/src",
    workdir: "app",
};
pub const MCP: PyApp = PyApp {
    name: "mcp",
    context: "core/gateway/services/mcp",
    dockerfile: "core/gateway/services/mcp/Dockerfile",
    project: "core/gateway/services/mcp",
    sync: PROD,
    pythonpath: "app/src",
    workdir: "app",
};
pub const BROKER: PyApp = PyApp {
    name: "credential-broker",
    context: "core/agent/services/credential-broker",
    dockerfile: "core/agent/services/credential-broker/Dockerfile",
    project: "core/agent/services/credential-broker",
    sync: NO_DEV,
    pythonpath: "app/src",
    workdir: "app",
};
pub const CRM: PyApp = PyApp {
    name: "crm",
    context: "core/crm",
    dockerfile: "core/crm/Dockerfile",
    project: "core/crm",
    sync: NO_DEV,
    pythonpath: "app/src",
    workdir: "app",
};
pub const FLOWS: PyApp = PyApp {
    name: "flows",
    context: ".",
    dockerfile: "core/flows/Dockerfile",
    project: "core/flows",
    sync: NO_DEV,
    pythonpath: "app/src",
    workdir: "app/src",
};

/// The services of the core process group.
const CORE_APPS: [&PyApp; 7] = [&BROKER, &ADMIN, &MEETING, &GATEWAY, &MCP, &CRM, &FLOWS];

/// The meeting-bot profile's deployment-wide floor (`profiles.default_registry`).
const BOT_TUNING_ENV: [&str; 14] = [
    "BOT_ALONE_SILENCE_WINDOW_MS",
    "BOT_SPEAKER_MIN_AUDIO_SEC",
    "BOT_SPEAKER_SUBMIT_INTERVAL_SEC",
    "BOT_SPEAKER_CONFIRM_THRESHOLD",
    "BOT_SPEAKER_MAX_BUFFER_SEC",
    "BOT_SPEAKER_IDLE_TIMEOUT_SEC",
    "BOT_SPEAKER_MIN_FINAL_AUDIO_SEC",
    "BOT_STT_TIMEOUT_SEC",
    "BOT_TRANSCRIPTION_LATENCY",
    "BOT_STT_CONFIDENCE_FILTER",
    "BOT_TRANSCRIPT_RECONFIRM_SEC",
    "VEXA_GOOGLE_JOIN_MAX_KNOCKS",
    "VEXA_GOOGLE_REKNOCK_BACKOFF_MS",
    "VEXA_GOOGLE_REKNOCK_WIPE",
];

/// The merged environment of the core process group (merge_groups.py).
pub const CORE_ENV: PyApp = PyApp {
    name: "group-core",
    context: "apps/vexa-daemon/python/groups/core",
    dockerfile: "",
    project: "apps/vexa-daemon/python/groups/core",
    sync: NO_DEV,
    pythonpath: "",
    workdir: "",
};

/// The agent worker the runtime spawns per dispatch (core/agent/worker/Dockerfile).
pub const WORKER: PyApp = PyApp {
    name: "agent-worker",
    context: ".",
    dockerfile: "core/agent/worker/Dockerfile",
    project: "core/agent",
    sync: &["--no-default-groups"],
    pythonpath: "app",
    workdir: "app",
};

pub const ALL: [&PyApp; 9] = [&ADMIN, &MEETING, &AGENT, &GATEWAY, &MCP, &BROKER, &CRM, &FLOWS, &WORKER];

/// The npm packages the worker image installs globally (`npm install -g ...`).
pub fn worker_cli_packages(dockerfile: &str) -> Vec<String> {
    dockerfile
        .lines()
        .find_map(|line| line.trim().strip_prefix("npm install -g "))
        .map(|rest| {
            rest.split_whitespace()
                .take_while(|word| *word != "&&" && *word != "\\")
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Paths of the key and state volumes on the host.
pub struct Keys {
    root: PathBuf,
}

impl Keys {
    pub fn new(state: &Path) -> Self {
        Self { root: state.join("keys") }
    }
    fn p(&self, rel: &str) -> String {
        self.root.join(rel).display().to_string()
    }
    pub fn identity_signing(&self) -> String {
        self.p("identity/signing/key.pem")
    }
    pub fn identity_public(&self) -> String {
        self.p("identity/public/key.pem")
    }
    pub fn subject_ticket(&self, issuer: &str) -> String {
        self.p(&format!("subject-ticket/{issuer}/key.pem"))
    }
    pub fn subject_ticket_public_dir(&self) -> String {
        self.p("subject-ticket/public")
    }
    pub fn fact_seal(&self) -> String {
        self.p("fact-seal/crm.pem")
    }
    pub fn fact_verify_dir(&self) -> String {
        self.p("fact-verify")
    }
    pub fn connections_dir(&self) -> String {
        self.p("connections")
    }
    pub fn connection(&self, role: &str) -> String {
        self.p(&format!("connections/{role}/key"))
    }
}

fn url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

impl Stack {
    fn keys(&self) -> Keys {
        Keys::new(&self.layout.state())
    }

    fn launcher(&self) -> String {
        self.source.join("apps/vexa-daemon/python/native_launch.py").display().to_string()
    }

    fn redis_url(&self) -> String {
        format!("redis://:{}@127.0.0.1:{}/0", self.env.get("REDIS_PASSWORD"), self.env.port("VEXA_REDIS_PORT"))
    }

    fn p(&self, key: &str) -> String {
        url(self.env.port(key))
    }

    /// The desktop product runs the CRM, so its URL is always set.
    fn crm_url(&self) -> String {
        self.p("VEXA_CRM_PORT")
    }

    fn workspaces_dir(&self) -> PathBuf {
        self.layout.data().join("workspaces")
    }

    /// The setting from native.env, else the Compose default.
    fn pass(&self, mut spec: Spec, keys: &[(&str, &str)]) -> Spec {
        for (key, default) in keys {
            let value = self.env.get(key);
            spec = spec.env(key, if value.is_empty() { default.to_string() } else { value });
        }
        spec
    }

    /// A Python process in a service's image layout and environment.
    fn py(&self, name: &str, app: &PyApp, args: &[String], ready: Ready) -> Spec {
        let runtime = self.layout.runtime();
        let root = app.root(&runtime);
        let venv = self.venv_of(app);
        Spec::new(name, venv.join("bin/python"), ready)
            .args(args.iter().cloned())
            .cwd(root.join(app.workdir))
            .env("PATH", format!("{}:{}", venv.join("bin").display(), self.tools.path))
            .env("TZ", "UTC")
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("PYTHONPATH", root.join(app.pythonpath).display().to_string())
            .env("PYTHONUNBUFFERED", "1")
            .env("PYTHONPYCACHEPREFIX", runtime.join("pycache").display().to_string())
            .env("LOG_LEVEL", self.env.get("LOG_LEVEL"))
            .timeout(Duration::from_secs(120))
    }

    fn module(&self, name: &str, app: &PyApp, module: &str, ready: Ready) -> Spec {
        self.py(name, app, &["-m".to_owned(), module.to_owned()], ready)
    }

    fn db(&self, spec: Spec) -> Spec {
        spec.env("DB_HOST", "127.0.0.1")
            .env("DB_PORT", self.env.get("VEXA_PG_PORT"))
            .env("DB_NAME", self.env.get("DB_NAME"))
            .env("DB_USER", self.env.get("DB_USER"))
            .env("DB_PASSWORD", self.env.get("DB_PASSWORD"))
    }

    fn pg_url(&self, user: &str, password: &str) -> String {
        format!(
            "postgresql+pg8000://{user}:{password}@127.0.0.1:{}/{}",
            self.env.get("VEXA_PG_PORT"),
            self.env.get("DB_NAME")
        )
    }

    /// Prepare every Python service: image layout and locked environment.
    /// One process per service (`VEXA_NATIVE_SPLIT=1`) instead of the process groups.
    fn split(&self) -> bool {
        std::env::var("VEXA_NATIVE_SPLIT").as_deref() == Ok("1")
    }

    /// The environment a member's process runs in: the core group's for a
    /// core member (also for its key and schema jobs), else its own.
    fn venv_of(&self, app: &PyApp) -> PathBuf {
        let runtime = self.layout.runtime();
        if !self.split() && CORE_APPS.iter().any(|m| m.name == app.name) {
            CORE_ENV.venv(&runtime)
        } else {
            app.venv(&runtime)
        }
    }

    /// The image layout of every service, and the environments the processes
    /// use: per service when split; else the core group's, agent-api's and
    /// the agent worker's.
    pub fn prepare_python(&self) -> Result<(), String> {
        let runtime = self.layout.runtime();
        let (uv, path) = (&self.tools.uv, &self.tools.path);
        for app in ALL {
            if self.split() || !CORE_APPS.iter().any(|m| m.name == app.name) {
                app.prepare(&self.source, &runtime, uv, path)?;
            } else {
                app.assemble_tree(&self.source, &runtime)?;
            }
        }
        if !self.split() {
            CORE_ENV.prepare_env(&self.source, &runtime, uv, path)?;
        }
        self.ensure_worker_clis()
    }

    /// The agent worker's pinned CLIs (claude-code, codex) in runtime/node-tools.
    fn ensure_worker_clis(&self) -> Result<(), String> {
        let dockerfile = std::fs::read_to_string(self.source.join(WORKER.dockerfile)).map_err(|e| e.to_string())?;
        let packages = worker_cli_packages(&dockerfile);
        if packages.is_empty() {
            return Err("cannot read the worker CLIs from core/agent/worker/Dockerfile".to_owned());
        }
        let prefix = self.layout.runtime().join("node-tools");
        let stamp = prefix.join(".vexa-stamp");
        let want = packages.join(" ");
        if std::fs::read_to_string(&stamp).is_ok_and(|old| old == want) {
            return Ok(());
        }
        std::fs::create_dir_all(&prefix).map_err(|e| e.to_string())?;
        println!("vexa-daemon: installing worker CLIs: {want}");
        let output = std::process::Command::new("npm")
            .args(["install", "--no-save", "--no-audit", "--no-fund", "--prefix"])
            .arg(&prefix)
            .args(&packages)
            .env("PATH", &self.tools.path)
            .output()
            .map_err(|e| format!("cannot run npm: {e}"))?;
        if !output.status.success() {
            return Err(format!("npm install failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
        std::fs::write(&stamp, want).map_err(|e| e.to_string())
    }

    /// The Compose key jobs. Each keeps an existing key.
    pub fn key_jobs(&self) -> Vec<Spec> {
        let keys = self.keys();
        for dir in ["identity/signing", "identity/public", "subject-ticket/public", "fact-seal", "fact-verify"] {
            let _ = std::fs::create_dir_all(keys.root.join(dir));
        }
        for issuer in ["meetings", "agent", "mail"] {
            let _ = std::fs::create_dir_all(keys.root.join("subject-ticket").join(issuer));
        }
        let tool = self.layout.runtime().join("apps/gateway/app/src/gateway/identity_token.py").display().to_string();
        let mut jobs = vec![self.py(
            "identity-keys",
            &GATEWAY,
            &[tool.clone(), "keygen".into(), keys.identity_signing(), keys.identity_public()],
            Ready::Exit,
        )];
        for issuer in ["meetings", "agent", "mail"] {
            jobs.push(self.py(
                &format!("subject-ticket-keys-{issuer}"),
                &GATEWAY,
                &[
                    tool.clone(),
                    "keygen".into(),
                    keys.subject_ticket(issuer),
                    format!("{}/{issuer}.pem", keys.subject_ticket_public_dir()),
                ],
                Ready::Exit,
            ));
        }
        jobs.push(self.py(
            "fact-seal-keys",
            &CRM,
            &[
                "-m".into(),
                "crm.fact_keys".into(),
                "keygen".into(),
                keys.fact_seal(),
                format!("{}/crm.pem", keys.fact_verify_dir()),
            ],
            Ready::Exit,
        ));
        jobs.push(self.py(
            "connections-keys",
            &BROKER,
            &[self.launcher(), "connections-keys".into(), keys.connections_dir()],
            Ready::Exit,
        ));
        jobs
    }

    /// The Compose schema jobs.
    pub fn schema_jobs(&self) -> Vec<Spec> {
        vec![
            self.db(self.module("admin-schema-init", &ADMIN, "admin_api.migrate", Ready::Exit)),
            self.db(self.py(
                "agent-sessions-init",
                &AGENT,
                &["-m".into(), "control_plane.session_schema".into(), "init".into()],
                Ready::Exit,
            ))
            .env("VEXA_SESSIONS_DB_USER", "vexa_agent_sessions")
            .env("VEXA_SESSIONS_DB_PASSWORD", self.env.get("VEXA_SESSIONS_DB_PASSWORD")),
            self.pass(
                self.db(self.py("crm-init", &CRM, &["-m".into(), "crm.migrate".into(), "init".into()], Ready::Exit)),
                &[("CRM_ORG_ID", ""), ("CRM_ORG_NAME", ""), ("CRM_AUDIT_RETENTION_DAYS", "365")],
            )
            .env("CRM_DB_USER", self.env.get("CRM_DB_USER"))
            .env("CRM_DB_PASSWORD", self.env.get("CRM_DB_PASSWORD")),
        ]
    }

    fn storage_env(&self, spec: Spec) -> Spec {
        spec.env("MINIO_ENDPOINT", format!("127.0.0.1:{}", self.env.get("VEXA_STORAGE_PORT")))
            .env("MINIO_BUCKET", self.env.get("MINIO_BUCKET"))
            .env("MINIO_SECURE", "false")
    }

    pub fn admin_api(&self) -> Spec {
        let port = self.env.port("VEXA_ADMIN_API_PORT");
        let spec = self.db(self.module("admin-api", &ADMIN, "admin_api", Ready::Http(port, "/health".into())))
            .env("HOST", "127.0.0.1")
            .env("PORT", port.to_string())
            .env("ADMIN_API_TOKEN", self.env.get("ADMIN_TOKEN"))
            .env("INTERNAL_API_SECRET", self.env.get("INTERNAL_API_SECRET"))
            .env("VEXA_TERMINAL_SESSION_SECRET", self.env.get("VEXA_TERMINAL_SESSION_SECRET"))
            .env("VEXA_MCP_DELEGATION_SECRET", self.env.get("VEXA_MCP_DELEGATION_SECRET"))
            .env("REDIS_URL", self.redis_url())
            .env("VEXA_FLOWS_API_KEY", self.env.get("VEXA_FLOWS_API_KEY"))
            .env("VEXA_PHOTOS_S3_ACCESS_KEY", self.env.get("VEXA_PHOTOS_S3_ACCESS_KEY"))
            .env("VEXA_PHOTOS_S3_SECRET_KEY", self.env.get("VEXA_PHOTOS_S3_SECRET_KEY"))
            .env("CRM_API_URL", self.crm_url());
        self.pass(
            self.storage_env(spec),
            &[
                ("VEXA_FEATURES", ""),
                ("VEXA_SIGNIN_ALLOW", ""),
                ("VEXA_SIGNIN_INVITES_ADMIT", "1"),
                ("VEXA_CALENDAR_FEED_ALLOW", ""),
                ("VEXA_ADMIN_EMAILS", ""),
                ("VEXA_ADMIN_ACCOUNT", ""),
                ("CRM_ORG_ID", ""),
                ("VEXA_FLOWS_API_URL", ""),
                ("S3_ENDPOINT", ""),
                ("VEXA_PERSON_GRAVATAR", "true"),
                ("GOOGLE_CLIENT_ID", ""),
                ("VEXA_OIDC_ISSUER", ""),
                ("VEXA_OIDC_CLIENT_ID", ""),
                ("VEXA_OIDC_CA_FILE", ""),
            ],
        )
    }

    /// The runtime (runtime.v1 and schedule.v1) that runs inside the daemon
    /// (`crate::runtime`), with the settings the Python runtime had.
    pub fn runtime_config(&self) -> crate::runtime::Config {
        let port = self.env.port("VEXA_RUNTIME_PORT");
        let runtime_dir = self.layout.runtime();
        let workspaces = self.workspaces_dir();
        let _ = std::fs::create_dir_all(&workspaces);
        let logs = self.layout.logs().join("workloads");
        let _ = std::fs::create_dir_all(&logs);
        let launchers = self.source.join("apps/vexa-daemon/bin");
        let spec = Spec::new("runtime", "", Ready::Tcp(port))
            .env("HOST", "127.0.0.1")
            .env("PORT", port.to_string())
            .env("RUNTIME_BACKEND", "process")
            .env("REDIS_URL", self.redis_url())
            .env("RUNTIME_API_TOKEN", self.env.get("RUNTIME_API_TOKEN"))
            .env("PROCESS_LOG_DIR", logs.display().to_string())
            .env("BROWSER_IMAGE", "native-process")
            .env("AGENT_IMAGE", "native-process")
            .env("VEXA_WORKSPACE_MOUNT_TARGET", workspaces.display().to_string())
            // Host plumbing the process backend passes to each bot (workload_env.PROCESS_PLUMBING_ENV).
            .env("PLAYWRIGHT_BROWSERS_PATH", runtime_dir.join("ms-playwright").display().to_string())
            .env("VEXA_HF_CACHE", runtime_dir.join("hf-cache").display().to_string())
            .env("VEXA_NATIVE_SOURCE_DIR", self.source.display().to_string())
            .env("VEXA_NATIVE_RUNTIME_DIR", runtime_dir.display().to_string());
        let spec = self.pass(
            spec,
            &[
                ("BOT_ALONE_SILENCE_WINDOW_MS", ""),
                ("BOT_SPEAKER_MIN_AUDIO_SEC", ""),
                ("BOT_SPEAKER_SUBMIT_INTERVAL_SEC", ""),
                ("BOT_SPEAKER_CONFIRM_THRESHOLD", ""),
                ("BOT_SPEAKER_MAX_BUFFER_SEC", ""),
                ("BOT_SPEAKER_IDLE_TIMEOUT_SEC", ""),
                ("BOT_SPEAKER_MIN_FINAL_AUDIO_SEC", ""),
                ("BOT_STT_TIMEOUT_SEC", ""),
                ("BOT_TRANSCRIPTION_LATENCY", ""),
                ("BOT_STT_CONFIDENCE_FILTER", ""),
                ("BOT_TRANSCRIPT_RECONFIRM_SEC", ""),
                ("VEXA_GOOGLE_JOIN_MAX_KNOCKS", ""),
                ("VEXA_GOOGLE_REKNOCK_BACKOFF_MS", ""),
                ("VEXA_GOOGLE_REKNOCK_WIPE", ""),
                ("HOST_CLAUDE_CREDENTIALS", ""),
                ("HOST_CLAUDE_DIR", ""),
                ("HOST_CODEX_CREDENTIALS", ""),
                ("VEXA_MIDTURN_INJECT", ""),
            ],
        );
        // What a child may inherit: the daemon's plumbing, then the runtime's settings.
        let mut env: BTreeMap<String, String> = ["HOME", "LANG", "LC_ALL", "TMPDIR", "USER"]
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
            .collect();
        env.insert("PATH".into(), self.tools.path.clone());
        env.insert("TZ".into(), "UTC".into());
        env.insert("PYTHONUNBUFFERED".into(), "1".into());
        env.extend(spec.env);
        let bot_tuning = BOT_TUNING_ENV
            .iter()
            .filter_map(|k| env.get(*k).filter(|v| !v.trim().is_empty()).map(|v| (k.to_string(), v.clone())))
            .collect();
        let profiles = vec![
            crate::runtime::kernel::Profile {
                name: "meeting-bot".into(),
                command: vec![launchers.join("vexa-bot-launch").display().to_string()],
                base_env: bot_tuning,
                forward_env: Vec::new(),
            },
            crate::runtime::kernel::Profile {
                name: "agent".into(),
                command: vec![launchers.join("vexa-agent-worker").display().to_string()],
                base_env: BTreeMap::new(),
                forward_env: crate::runtime::workload_env::WORKER_FORWARD_ENV.to_vec(),
            },
        ];
        crate::runtime::Config {
            port,
            env,
            profiles,
            declaration: self.source.join("core/runtime/src/runtime_kernel/config.v1.json"),
            log_file: self.layout.logs().join("runtime.log"),
        }
    }

    /// Start the runtime; it is ready when this returns.
    pub fn start_runtime(&self) -> Result<crate::runtime::Handle, String> {
        let handle = crate::runtime::start(self.runtime_config())?;
        println!("vexa-daemon: runtime is ready (in the daemon, port {})", self.env.port("VEXA_RUNTIME_PORT"));
        Ok(handle)
    }

    pub fn agent_api(&self) -> Spec {
        let port = self.env.port("VEXA_AGENT_API_PORT");
        let root = AGENT.root(&self.layout.runtime()).join("app");
        let keys = self.keys();
        let spec = self
            .py(
                "agent-api",
                &AGENT,
                &[
                    "-m".into(),
                    "uvicorn".into(),
                    "control_plane.api:app".into(),
                    "--host".into(),
                    "127.0.0.1".into(),
                    "--port".into(),
                    port.to_string(),
                ],
                Ready::Http(port, "/health".into()),
            )
            .env("VEXA_AGENT_API_PORT", port.to_string())
            .env("VEXA_RUNTIME_API_URL", self.p("VEXA_RUNTIME_PORT"))
            .env("VEXA_MEETING_API_URL", self.p("VEXA_MEETING_API_PORT"))
            .env("VEXA_AGENT_API_SELF_URL", url(port))
            .env("VEXA_AGENT_PROFILE", "agent")
            .env("VEXA_WORKSPACES_DIR", self.workspaces_dir().display().to_string())
            .env("VEXA_WORKSPACE_SEEDS_DIR", root.join("workspace-seeds").display().to_string())
            .env("VEXA_TOOLS_SEED_DIR", root.join("tools-seed").display().to_string())
            .env("VEXA_ADMIN_API_URL", self.p("VEXA_ADMIN_API_PORT"))
            .env("INTERNAL_API_SECRET", self.env.get("INTERNAL_API_SECRET"))
            .env("RUNTIME_API_TOKEN", self.env.get("RUNTIME_API_TOKEN"))
            .env("VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE", keys.identity_public())
            .env("VEXA_SUBJECT_TICKET_KEY_FILE", keys.subject_ticket("agent"))
            .env("VEXA_ADMIN_API_TOKEN", self.env.get("ADMIN_TOKEN"))
            .env("VEXA_LOG_LEVEL", self.env.get("LOG_LEVEL"))
            .env("VEXA_REDIS_URL", self.redis_url())
            .env("VEXA_DISPATCH_SIGNING_KEY", self.env.get("VEXA_DISPATCH_SIGNING_KEY"))
            .env("VEXA_MCP_URL", format!("{}/mcp", self.p("VEXA_GATEWAY_PORT")))
            .env("VEXA_MCP_DELEGATION_SECRET", self.env.get("VEXA_MCP_DELEGATION_SECRET"))
            .env("VEXA_MODEL_PROXY_URL", self.p("VEXA_MODEL_PROXY_PORT"))
            .env("VEXA_MODEL_PROXY_SECRET", self.env.get("VEXA_MODEL_PROXY_SECRET"))
            .env("VEXA_GATEWAY_URL", self.p("VEXA_GATEWAY_PORT"))
            .env("VEXA_CONNECTIONS_BROKER_URL", self.p("VEXA_CREDENTIAL_BROKER_PORT"))
            .env("VEXA_CONNECTIONS_AGENT_KEY_FILE", keys.connection("agent"))
            .env("VEXA_GIT_STORE_BROKER_URL", self.p("VEXA_CREDENTIAL_BROKER_PORT"))
            .env("VEXA_GIT_STORE_KEY_FILE", keys.connection("git"))
            .env("VEXA_FLOWS_API_URL", self.p("VEXA_FLOWS_PORT"))
            .env("VEXA_FLOWS_API_KEY", self.env.get("VEXA_FLOWS_API_KEY"))
            .env("DB_HOST", "127.0.0.1")
            .env("DB_PORT", self.env.get("VEXA_PG_PORT"))
            .env("DB_NAME", self.env.get("DB_NAME"))
            .env("VEXA_SESSIONS_DB_USER", "vexa_agent_sessions")
            .env("VEXA_SESSIONS_DB_PASSWORD", self.env.get("VEXA_SESSIONS_DB_PASSWORD"))
            .env("VEXA_SESSIONS_S3_ENDPOINT", format!("127.0.0.1:{}", self.env.get("VEXA_STORAGE_PORT")))
            .env("VEXA_SESSIONS_S3_SECURE", "false")
            .env("VEXA_SESSIONS_S3_BUCKET", self.env.get("VEXA_SESSIONS_S3_BUCKET"))
            .env("VEXA_SESSIONS_S3_ACCESS_KEY", self.env.get("VEXA_SESSIONS_S3_ACCESS_KEY"))
            .env("VEXA_SESSIONS_S3_SECRET_KEY", self.env.get("VEXA_SESSIONS_S3_SECRET_KEY"))
            .env("CRM_API_URL", self.crm_url());
        self.pass(
            spec,
            &[
                ("VEXA_BUILD_SHA", "native"),
                ("VEXA_WORKSPACE_BACKEND", "volume"),
                ("VEXA_WORKSPACE_CACHE_MAX_BYTES", "0"),
                ("VEXA_SECRETS_KEY", ""),
                ("VEXA_GIT_PROVIDERS", ""),
                ("VEXA_GIT_ALLOWED_INTERNAL_HOSTS", ""),
                ("VEXA_ROOM_WS_PRINCIPAL", "true"),
                ("VEXA_AGENT_MODEL", ""),
                ("VEXA_MODEL_BASE_URL_ALLOW", ""),
                ("ANTHROPIC_API_KEY", ""),
                ("ANTHROPIC_MODEL", ""),
                ("ANTHROPIC_DEFAULT_OPUS_MODEL", ""),
                ("ANTHROPIC_DEFAULT_SONNET_MODEL", ""),
                ("ANTHROPIC_DEFAULT_HAIKU_MODEL", ""),
                ("VEXA_GLOBAL_SYSTEM_WORKSPACE_PATH", ""),
                ("VEXA_GLOBAL_SYSTEM_WORKSPACE_REF", ""),
                ("VEXA_UI_URL", ""),
                ("VEXA_BOT_API_KEY", ""),
                ("VEXA_CRM_REFERENCES_POLL_S", "0"),
                ("LIVEKIT_URL", ""),
                ("LIVEKIT_INTERNAL_URL", ""),
                ("LIVEKIT_API_KEY", ""),
                ("LIVEKIT_API_SECRET", ""),
                ("HOST_CLAUDE_CREDENTIALS", ""),
                ("HOST_CLAUDE_DIR", ""),
                ("VEXA_FEATURES", ""),
                ("VEXA_AGENT_ALLOW", ""),
                ("VEXA_LLM_KILL_SWITCH", ""),
            ],
        )
    }

    pub fn model_proxy(&self) -> Spec {
        let port = self.env.port("VEXA_MODEL_PROXY_PORT");
        self.py("model-proxy", &AGENT, &[self.launcher(), "model-proxy".into()], Ready::Http(port, "/health".into()))
            .env("VEXA_MODEL_PROXY_PORT", port.to_string())
            .env("VEXA_REDIS_URL", self.redis_url())
            .env("VEXA_MODEL_PROXY_SECRET", self.env.get("VEXA_MODEL_PROXY_SECRET"))
            .env("VEXA_LOG_LEVEL", self.env.get("LOG_LEVEL"))
    }

    pub fn meeting_api(&self) -> Spec {
        let port = self.env.port("VEXA_MEETING_API_PORT");
        let keys = self.keys();
        let stt = self.env.get("TRANSCRIPTION_SERVICE_URL");
        let spec = self
            .db(self.module("meeting-api", &MEETING, "meeting_api", Ready::Http(port, "/health".into())))
            .env("HOST", "127.0.0.1")
            .env("PORT", port.to_string())
            .env("REDIS_URL", self.redis_url())
            .env("RUNTIME_API_URL", self.p("VEXA_RUNTIME_PORT"))
            .env("RUNTIME_API_TOKEN", self.env.get("RUNTIME_API_TOKEN"))
            // The URL each bot calls back on (Compose: http://meeting-api:8080).
            .env("MEETING_API_URL", url(port))
            .env("INTERNAL_API_SECRET", self.env.get("INTERNAL_API_SECRET"))
            .env("VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE", keys.identity_public())
            .env("VEXA_SUBJECT_TICKET_KEY_FILE", keys.subject_ticket("meetings"))
            .env("ADMIN_API_URL", self.p("VEXA_ADMIN_API_PORT"))
            .env("ADMIN_TOKEN", self.env.get("ADMIN_TOKEN"))
            .env(
                "TRANSCRIPTION_SERVICE_URL",
                if stt.is_empty() { self.p("VEXA_STT_PORT") } else { stt },
            )
            .env("TRANSCRIPTION_SERVICE_TOKEN", self.env.get("TRANSCRIPTION_SERVICE_TOKEN"))
            .env("MINIO_ACCESS_KEY", self.env.get("MINIO_ACCESS_KEY"))
            .env("MINIO_SECRET_KEY", self.env.get("MINIO_SECRET_KEY"))
            .env("VEXA_FLOWS_API_KEY", self.env.get("VEXA_FLOWS_API_KEY"))
            .env("VEXA_BOT_ACCOUNTS_BROKER_URL", self.p("VEXA_CREDENTIAL_BROKER_PORT"))
            .env("VEXA_BOT_ACCOUNTS_KEY_FILE", keys.connection("bots"));
        self.pass(
            self.storage_env(spec),
            &[
                ("DEFAULT_BOT_NAME", "Vexa"),
                ("VEXA_CALENDAR_FEED_ALLOW", ""),
                ("VEXA_AUTO_JOIN_BLOCK", ""),
                ("VEXA_MEETING_HOST_ALLOW", ""),
                ("TRANSCRIPTION_MODEL", ""),
                ("DEFAULT_TRANSCRIPTION_LANGUAGE", ""),
                ("DEFAULT_TRANSCRIPTION_ALLOWED_LANGUAGES", ""),
                ("TRANSCRIBE_ENABLED", "true"),
                ("RECORDING_ENABLED", "true"),
                ("BOT_AUTHENTICATED", "false"),
                ("BOT_USERDATA_S3_PATH", ""),
                ("BOT_S3_ENDPOINT", ""),
                ("BOT_S3_BUCKET", ""),
                ("BOT_S3_ACCESS_KEY", ""),
                ("BOT_S3_SECRET_KEY", ""),
                ("VEXA_SERVICE_AUTHORITY_CONFIG", ""),
                ("VEXA_SERVICE_AUTHORITY_SECRET", ""),
                ("LIVEKIT_URL", ""),
                ("LIVEKIT_INTERNAL_URL", ""),
                ("LIVEKIT_API_KEY", ""),
                ("LIVEKIT_API_SECRET", ""),
                ("CALL_MAX_DURATION_SEC", "14400"),
                ("CALL_EMPTY_GRACE_SEC", "30"),
                ("CALL_FIRST_JOIN_TIMEOUT_SEC", "30"),
                ("CALL_MAX_PARTICIPANTS", "50"),
                ("CALL_TRANSCRIPTION_SWITCHABLE", "false"),
                ("CALL_TRANSCRIBE_SHARED_SCREEN", "true"),
                ("VEXA_SYSTEM_WEBHOOK_URL", ""),
                ("VEXA_SYSTEM_WEBHOOK_SECRET", ""),
                ("VEXA_SYSTEM_WEBHOOK_ALLOW_PRIVATE_HTTP", "false"),
                ("VEXA_SYSTEM_WEBHOOK_TIMEOUT_S", "10"),
                ("VOICE_NOTE_MAX_DURATION_SEC", "1800"),
                ("VOICE_NOTE_IDLE_TIMEOUT_SEC", "120"),
                ("VEXA_FLOWS_API_URL", ""),
                ("VEXA_JITSI_HOSTS", ""),
                ("S3_ENDPOINT", ""),
                ("S3_ACCESS_KEY", ""),
                ("S3_SECRET_KEY", ""),
                ("VEXA_BOT_SIGNIN_EXTRA_HOSTS", ""),
                ("VEXA_FEATURES", ""),
            ],
        )
    }

    /// The Python gateway in place of the native one (`VEXA_NATIVE_PY_GATEWAY=1`):
    /// a member of the core group again, with its service door.
    fn py_gateway(&self) -> bool {
        std::env::var("VEXA_NATIVE_PY_GATEWAY").as_deref() == Ok("1")
    }

    /// gateway (api.v1, ws.v1) and its service door: the native process
    /// (`apps/vexa-gateway`), or the Python service when `VEXA_NATIVE_PY_GATEWAY=1`.
    /// Both read the same environment.
    pub fn gateway(&self) -> Result<Spec, String> {
        let port = self.env.port("VEXA_GATEWAY_PORT");
        let keys = self.keys();
        let ready = Ready::Http(port, "/health".into());
        let spec = if self.py_gateway() {
            self.module("gateway", &GATEWAY, "gateway", ready)
        } else {
            self.base(Spec::new("gateway", self.native_binary("vexa-gateway", "VEXA_GATEWAY_BIN", "VEXA_NATIVE_PY_GATEWAY")?, ready))
                .env("VEXA_SOURCE_DIR", self.source.display().to_string())
                .timeout(Duration::from_secs(60))
        };
        let spec = spec
            .env("HOST", "127.0.0.1")
            .env("PORT", port.to_string())
            .env("VEXA_GATEWAY_SERVICE_DOOR_PORT", self.env.get("VEXA_GATEWAY_SERVICE_DOOR_PORT"))
            .env("ADMIN_API_URL", self.p("VEXA_ADMIN_API_PORT"))
            .env("MEETING_API_URL", self.p("VEXA_MEETING_API_PORT"))
            .env("MCP_URL", self.p("VEXA_MCP_PORT"))
            .env("AGENT_API_URL", self.p("VEXA_AGENT_API_PORT"))
            .env("REDIS_URL", self.redis_url())
            .env("INTERNAL_API_SECRET", self.env.get("INTERNAL_API_SECRET"))
            .env("VEXA_FLOWS_SERVICE_KEY", self.env.get("VEXA_FLOWS_SERVICE_KEY"))
            .env("FLOWS_API_URL", self.p("VEXA_FLOWS_PORT"))
            .env("VEXA_GATEWAY_IDENTITY_SIGNING_KEY_FILE", keys.identity_signing())
            .env("VEXA_SUBJECT_TICKET_KEYS_DIR", keys.subject_ticket_public_dir())
            .env("CRM_API_URL", self.crm_url());
        Ok(self.pass(
            spec,
            &[
                ("VEXA_AGENT_ALLOW", ""),
                ("VEXA_JITSI_HOSTS", ""),
                ("GUARD_ENABLED", "true"),
                ("GUARD_WS_ENABLED", "false"),
                ("GUARD_ENABLE_REDIS", "true"),
                ("GUARD_RATE_LIMIT_RPM", "600"),
                ("GUARD_RATE_LIMIT_WINDOW", "60"),
                ("GUARD_AUTO_BAN_THRESHOLD", "10"),
                ("GUARD_AUTO_BAN_DURATION", "3600"),
                ("GUARD_IP_WHITELIST", ""),
                ("GUARD_IP_BLACKLIST", ""),
                ("GUARD_TRUSTED_PROXIES", ""),
                ("GUARD_TRUST_X_FORWARDED_PROTO", "false"),
                ("GUARD_BLOCKED_COUNTRIES", ""),
                ("GUARD_BLOCK_CLOUD_PROVIDERS", ""),
            ],
        ))
    }

    /// The Python mcp in place of the native one (`VEXA_NATIVE_PY_MCP=1`):
    /// a member of the core group again.
    fn py_mcp(&self) -> bool {
        std::env::var("VEXA_NATIVE_PY_MCP").as_deref() == Ok("1")
    }

    /// A native binary (`vexa_native_kit::binary::find`), or why it is missing.
    fn native_binary(&self, name: &str, var: &str, fallback: &str) -> Result<PathBuf, String> {
        vexa_native_kit::binary::find(&self.source, name, var)
            .ok_or_else(|| format!("cannot find {name}; build apps/{name}, set {var}, or set {fallback}=1"))
    }

    /// The URLs mcp waits for before it starts: it assembles their tools at boot.
    fn mcp_wait(&self) -> Vec<(u16, &'static str)> {
        ["VEXA_AGENT_API_PORT", "VEXA_FLOWS_PORT", "VEXA_CRM_PORT"].iter().map(|key| (self.env.port(key), "/health")).collect()
    }

    /// mcp (mcp.tools.v1): the native process (`apps/vexa-mcp`), or the Python
    /// service when `VEXA_NATIVE_PY_MCP=1`. Both read the same environment.
    pub fn mcp(&self) -> Result<Spec, String> {
        let port = self.env.port("VEXA_MCP_PORT");
        let ready = Ready::Http(port, "/health".into());
        let spec = if self.py_mcp() {
            self.module("mcp", &MCP, "vexa_mcp", ready)
        } else {
            self.base(Spec::new("mcp", self.native_binary("vexa-mcp", "VEXA_MCP_BIN", "VEXA_NATIVE_PY_MCP")?, ready))
        };
        let spec = spec
            .env("HOST", "127.0.0.1")
            .env("PORT", port.to_string())
            .env("GATEWAY_URL", self.p("VEXA_GATEWAY_PORT"))
            .env("ADMIN_API_URL", self.p("VEXA_ADMIN_API_PORT"))
            .env("MEETING_API_URL", self.p("VEXA_MEETING_API_PORT"))
            .env("AGENT_API_URL", self.p("VEXA_AGENT_API_PORT"))
            .env("FLOWS_API_URL", self.p("VEXA_FLOWS_PORT"))
            .env("VEXA_FLOWS_API_KEY", self.env.get("VEXA_FLOWS_API_KEY"))
            .env("CRM_API_URL", self.crm_url());
        Ok(self.pass(
            spec,
            &[
                ("VEXA_FEATURES", ""),
                ("VEXA_MCP_MANIFEST_DIR", ""),
                ("VEXA_MCP_TOOLS_ALLOW", ""),
                ("VEXA_MCP_TOOLS_DENY", ""),
                ("VEXA_MCP_TOOLS_COHORT", ""),
                ("VEXA_ENV", "development"),
                ("VEXA_JITSI_HOSTS", ""),
                ("VEXA_TICKET_SINK_URL", ""),
                ("VEXA_TICKET_SINK_TOKEN", ""),
                ("VEXA_TICKET_SINK_FORMAT", ""),
                ("VEXA_TICKET_SINK_LABELS", ""),
                ("VEXA_TICKET_FINGERPRINT_SALT", ""),
            ],
        )
        // mcp asks every domain for its tools once at boot; it can wait for them.
        .timeout(Duration::from_secs(180)))
    }

    /// The Python credential broker in place of the native one
    /// (`VEXA_NATIVE_PY_CREDENTIAL_BROKER=1`): a member of the core group again.
    fn py_broker(&self) -> bool {
        std::env::var("VEXA_NATIVE_PY_CREDENTIAL_BROKER").as_deref() == Ok("1")
    }

    /// The native credential broker (`apps/vexa-credential-broker`).
    fn broker_binary(&self) -> Result<PathBuf, String> {
        self.native_binary("vexa-credential-broker", "VEXA_CREDENTIAL_BROKER_BIN", "VEXA_NATIVE_PY_CREDENTIAL_BROKER")
    }

    /// credential-broker (credential-broker.v1): the native process, or the
    /// Python service when `VEXA_NATIVE_PY_CREDENTIAL_BROKER=1`. Both read the
    /// same environment and the same state directory.
    pub fn credential_broker(&self) -> Result<Spec, String> {
        let port = self.env.port("VEXA_CREDENTIAL_BROKER_PORT");
        let keys = self.keys();
        let state = self.layout.data().join("connections-state");
        let _ = std::fs::create_dir_all(&state);
        let ready = Ready::Http(port, "/ready".into());
        let mut spec = if self.py_broker() {
            self.py(
                "credential-broker",
                &BROKER,
                &[
                    "-m".into(),
                    "uvicorn".into(),
                    "credential_broker.main:app".into(),
                    "--host".into(),
                    "127.0.0.1".into(),
                    "--port".into(),
                    port.to_string(),
                    "--no-access-log".into(),
                ],
                ready,
            )
        } else {
            self.base(Spec::new("credential-broker", self.broker_binary()?, ready))
                .args(["--port".to_owned(), port.to_string()])
                .timeout(Duration::from_secs(60))
        }
        .env("VEXA_CONNECTIONS_STATE_DIR", state.display().to_string())
        .env("VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE", keys.identity_public());
        for role in ["agent", "human", "git", "bots", "sensors", "signals", "store"] {
            spec = spec.env(&format!("VEXA_CONNECTIONS_{}_KEY_FILE", role.to_uppercase()), keys.connection(role));
        }
        Ok(self.pass(
            spec,
            &[
                ("VEXA_CONNECTIONS_STORE", "local"),
                ("VEXA_CONNECTIONS_OPENBAO_ADDR", ""),
                ("VEXA_CONNECTIONS_OPENBAO_TOKEN_FILE", ""),
                ("VEXA_CONNECTIONS_OPENBAO_MOUNT", "connections"),
                ("VEXA_CONNECTIONS_GOOGLE_CLIENT_ID", ""),
                ("VEXA_CONNECTIONS_GOOGLE_CLIENT_SECRET", ""),
                ("VEXA_CONNECTIONS_PRODUCT_REDIRECT", ""),
            ],
        ))
    }

    /// The Python crm in place of the native one (`VEXA_NATIVE_PY_CRM=1`):
    /// a member of the core group again.
    fn py_crm(&self) -> bool {
        std::env::var("VEXA_NATIVE_PY_CRM").as_deref() == Ok("1")
    }

    /// crm-api with its outbox loop in the same process (the desktop CRM overlay):
    /// the native process (`apps/vexa-crm`), or the Python service when
    /// `VEXA_NATIVE_PY_CRM=1`. Both read the same environment.
    pub fn crm(&self) -> Result<Spec, String> {
        let port = self.env.port("VEXA_CRM_PORT");
        let ready = Ready::Http(port, "/health".into());
        let spec = if self.py_crm() {
            self.py("crm", &CRM, &[self.launcher(), "crm".into()], ready)
        } else {
            self.base(Spec::new("crm", self.native_binary("vexa-crm", "VEXA_CRM_BIN", "VEXA_NATIVE_PY_CRM")?, ready))
                .env("TZ", "UTC")
                .timeout(Duration::from_secs(60))
        };
        let spec = spec
            .env("VEXA_CRM_PORT", port.to_string())
            .env("CRM_DATABASE_URL", self.pg_url(&self.env.get("CRM_DB_USER"), &self.env.get("CRM_DB_PASSWORD")))
            .env("ADMIN_API_URL", self.p("VEXA_ADMIN_API_PORT"))
            .env("INTERNAL_API_SECRET", self.env.get("INTERNAL_API_SECRET"))
            .env("CRM_AGENT_API_URL", self.p("VEXA_AGENT_API_PORT"))
            .env("VEXA_CRM_OUTBOX_ENABLED", "true")
            .env("FLOWS_API_URL", self.p("VEXA_FLOWS_PORT"))
            .env("FLOWS_PUBLISH_KEY", self.env.get("VEXA_FLOWS_CRM_PUBLISH_KEY"))
            .env("VEXA_FACT_SEAL_KEY_FILE", self.keys().fact_seal());
        Ok(self.pass(spec, &[("CRM_ORG_ID", ""), ("VEXA_FEATURES", "")]))
    }

    /// flows-api with its worker in the same process (the desktop Flows overlay).
    pub fn flows(&self) -> Spec {
        let port = self.env.port("VEXA_FLOWS_PORT");
        let keys = self.keys();
        let door = self.p("VEXA_GATEWAY_SERVICE_DOOR_PORT");
        // The desktop Flows overlay: the agent and CRM doors are always on.
        let agent_url = format!("{door}/agent");
        let crm_url = format!("{door}/crm");
        let spec = self
            .module("flows", &FLOWS, "flows_combined", Ready::Http(port, "/health".into()))
            .env("VEXA_FLOWS_API_HOST", "127.0.0.1")
            .env("VEXA_FLOWS_API_PORT", port.to_string())
            .env("VEXA_FLOWS_DB_URL", self.pg_url(&self.env.get("DB_USER"), &self.env.get("DB_PASSWORD")))
            .env("VEXA_FLOWS_API_KEY", self.env.get("VEXA_FLOWS_API_KEY"))
            .env("VEXA_FLOWS_SERVICE_KEY", self.env.get("VEXA_FLOWS_SERVICE_KEY"))
            .env("VEXA_FLOWS_TIMELINE_KEY", self.env.get("VEXA_FLOWS_TIMELINE_KEY"))
            .env("VEXA_FACT_VERIFY_KEYS_DIR", keys.fact_verify_dir())
            .env("VEXA_FLOWS_MAIL_TICKET_KEY_FILE", keys.subject_ticket("mail"))
            .env("VEXA_FLOWS_CRM_PUBLISH_KEY", self.env.get("VEXA_FLOWS_CRM_PUBLISH_KEY"))
            .env("VEXA_FLOWS_ADMIN_API_URL", format!("{door}/identity"))
            .env("VEXA_FLOWS_GATEWAY_URL", format!("{door}/meetings"))
            .env("VEXA_FLOWS_AGENT_API_URL", agent_url)
            .env("VEXA_FLOWS_CRM_API_URL", crm_url)
            .env("VEXA_FLOWS_SENSORS_BROKER_URL", self.p("VEXA_CREDENTIAL_BROKER_PORT"))
            .env("VEXA_FLOWS_SENSORS_KEY_FILE", keys.connection("sensors"))
            .env("VEXA_BEHAVIOR_DIR", self.env.get("VEXA_BEHAVIOR_DIR"));
        self.pass(
            spec,
            &[
                ("VEXA_FLOWS_NUDGES", ""),
                ("VEXA_FLOWS_NUDGE_IDLE_FLOOR_MIN", "5"),
                ("VEXA_FLOWS_NUDGE_BUDGET_CEILING", "12"),
                ("VEXA_FLOWS_DEFS_EXTRA", ""),
                ("VEXA_UI_URL", ""),
                ("VEXA_MAIL_INBOX", "imap"),
                ("VEXA_MAIL_ADDR", ""),
                ("VEXA_MAIL_APP_PASSWORD", ""),
                ("VEXA_MAIL_SMTP_HOST", ""),
                ("VEXA_MAIL_SMTP_PORT", "25"),
                ("VEXA_MAIL_SMTP_SECURE", ""),
                ("VEXA_MAIL_SMTP_TLS_INSECURE", ""),
                ("VEXA_MAIL_SMTP_USER", ""),
                ("VEXA_MAIL_SMTP_PASSWORD", ""),
                ("VEXA_MAIL_SMTP_PASSWORD_REF", ""),
                ("VEXA_MAIL_RECIPIENT_ALLOW", ""),
                ("VEXA_MAIL_SMTP_TLS", "auto"),
                ("VEXA_MAIL_SMTP_FROM", ""),
                ("VEXA_MAIL_REPLY_TO", ""),
                ("VEXA_MAIL_RELAY", ""),
                ("VEXA_MAIL_CAPTURE_SMTP", ""),
                ("VEXA_MAIL_MAX_PER_DAY", "2000"),
                ("VEXA_MAIL_KINDS_DEFAULT", "shipped"),
                ("VEXA_MAIL_INBOUND_FILTER", "vexa"),
                ("VEXA_MAIL_SMTP_CA_FILE", ""),
                ("VEXA_MAIL_IMAP_HOST", "imap.gmail.com"),
                ("VEXA_FLOWS_MAIL_AUTHSERV_ID", ""),
                ("VEXA_FLOWS_MAIL_AUTH_MODE", "mta"),
                ("VEXA_MAIL_IMAP_PORT", ""),
                ("VEXA_MAIL_IMAP_TLS", "tls"),
                ("VEXA_MAIL_IMAP_USER", ""),
                ("VEXA_MAIL_IMAP_FOLDER", "INBOX"),
                ("VEXA_MAIL_IMAP_CA_FILE", ""),
                ("VEXA_MAILPIT_URL", ""),
                ("VEXA_MAILPIT_LOOKBACK_S", "300"),
                ("VEXA_NOTIFY_CHANNEL", "smtp"),
                ("VEXA_GRAPH_TENANT_ID", ""),
                ("VEXA_GRAPH_CLIENT_ID", ""),
                ("VEXA_GRAPH_CLIENT_SECRET", ""),
                ("VEXA_GRAPH_MAILBOX", ""),
                ("VEXA_FLOWS_MAIL_DOMAINS", ""),
                ("VEXA_FLOWS_MAIL_QUARANTINE_REPLY", ""),
                ("VEXA_FLOWS_MAIL_RATE_PER_SENDER", "12"),
                ("VEXA_FLOWS_MAIL_RATE_GLOBAL", "120"),
                ("VEXA_FLOWS_SCHEDULE_CATCHUP_S", "3600"),
                ("VEXA_FLOWS_FACT_RETENTION_DAYS", "90"),
                ("VEXA_FLOWS_LOOP_LIMIT", "1"),
                ("VEXA_FLOWS_MAX_HOPS", "8"),
                ("VEXA_FLOWS_USER_ACTIVE_FLOWS", "20"),
                ("VEXA_FLOWS_USER_MIN_INTERVAL_S", "900"),
                ("VEXA_FLOWS_USER_RUNS_PER_DAY", "48"),
                ("VEXA_FLOWS_USER_MESSAGES_PER_DAY", "100"),
                ("VEXA_FLOWS_MAIL_RATE_WINDOW_S", "3600"),
                ("VEXA_FLOWS_MAIL_BODY_MAX", "4000"),
                ("VEXA_FLOWS_ATTENDEE_DOMAINS", ""),
                ("VEXA_FLOWS_DATA_STATEMENT", ""),
                ("VEXA_JITSI_HOSTS", ""),
                ("VEXA_TIMELINE_SCAN_ROWS", "2000"),
            ],
        )
    }

    fn group_runner(&self) -> String {
        self.source.join("apps/vexa-daemon/python/native_group.py").display().to_string()
    }

    /// The core process group: admin-api, meeting-api, and flows with its
    /// worker, in one interpreter (native_group.py); credential-broker, the
    /// gateway with its door, mcp and crm too when they are the Python ones.
    /// agent-api is not a member: it needs other values than meeting-api for
    /// VEXA_FLOWS_API_URL and VEXA_SUBJECT_TICKET_KEY_FILE, and one process has
    /// one environment.
    /// The member specs of the core group, as each service runs alone.
    pub fn core_members(&self) -> Result<Vec<Spec>, String> {
        let mut members = Vec::new();
        if self.py_broker() {
            members.push(self.credential_broker()?);
        }
        members.extend([self.admin_api(), self.meeting_api()]);
        if self.py_gateway() {
            members.push(self.gateway()?);
        }
        if self.py_mcp() {
            members.push(self.mcp()?);
        }
        if self.py_crm() {
            members.push(self.crm()?);
        }
        members.push(self.flows());
        Ok(members)
    }

    pub fn core_group(&self) -> Result<Spec, String> {
        let runtime = self.layout.runtime();
        let members = self.core_members()?;
        let pythonpath = CORE_APPS
            .iter()
            .map(|app| app.root(&runtime).join(app.pythonpath).display().to_string())
            .collect::<Vec<_>>()
            .join(":");
        // Every listener of the group starts at once; admin-api answering is the group answering.
        let ready = if self.py_gateway() { "VEXA_GATEWAY_PORT" } else { "VEXA_ADMIN_API_PORT" };
        let mut base = Spec::new("core", CORE_ENV.venv(&runtime).join("bin/python"), Ready::Http(self.env.port(ready), "/health".into()))
            .args([self.group_runner(), "core".to_owned()])
            .cwd(GATEWAY.root(&runtime).join(GATEWAY.workdir))
            .env("PATH", format!("{}:{}", CORE_ENV.venv(&runtime).join("bin").display(), self.tools.path))
            .env("PYTHONPATH", pythonpath)
            .env("VEXA_FLOWS_API_PORT", self.env.get("VEXA_FLOWS_PORT"))
            .env("VEXA_NATIVE_PY_CREDENTIAL_BROKER", if self.py_broker() { "1" } else { "0" })
            .env("VEXA_NATIVE_PY_MCP", if self.py_mcp() { "1" } else { "0" })
            .env("VEXA_NATIVE_PY_GATEWAY", if self.py_gateway() { "1" } else { "0" })
            .env("VEXA_NATIVE_PY_CRM", if self.py_crm() { "1" } else { "0" })
            .env(
                "VEXA_NATIVE_MCP_WAIT_URLS",
                self.mcp_wait().iter().map(|(port, path)| format!("{}{path}", url(*port))).collect::<Vec<_>>().join(","),
            )
            .timeout(Duration::from_secs(180));
        for key in [
            "VEXA_ADMIN_API_PORT",
            "VEXA_MEETING_API_PORT",
            "VEXA_GATEWAY_PORT",
            "VEXA_MCP_PORT",
            "VEXA_CREDENTIAL_BROKER_PORT",
            "VEXA_CRM_PORT",
        ] {
            base = base.env(key, self.env.get(key));
        }
        merge_specs(base, &members)
    }

    /// The agent process group: agent-api and model-proxy (one environment).
    pub fn agent_group(&self) -> Result<Spec, String> {
        let runtime = self.layout.runtime();
        let port = self.env.port("VEXA_AGENT_API_PORT");
        let members = [self.agent_api(), self.model_proxy()];
        let base = Spec::new("agent", AGENT.venv(&runtime).join("bin/python"), Ready::Http(port, "/health".into()))
            .args([self.group_runner(), "agent".to_owned()])
            .cwd(AGENT.root(&runtime).join(AGENT.workdir))
            .env("PATH", format!("{}:{}", AGENT.venv(&runtime).join("bin").display(), self.tools.path))
            .env("PYTHONPATH", AGENT.root(&runtime).join(AGENT.pythonpath).display().to_string())
            .env("VEXA_AGENT_API_PORT", port.to_string())
            .env("VEXA_MODEL_PROXY_PORT", self.env.get("VEXA_MODEL_PROXY_PORT"))
            .timeout(Duration::from_secs(120));
        merge_specs(base, &members)
    }

    /// The Next.js terminal (clients/terminal) as a host Node process.
    pub fn terminal(&self) -> Result<Spec, String> {
        let dir = self.source.join("clients/terminal");
        if !dir.join(".next/BUILD_ID").is_file() {
            return Err("the terminal is not built; run `pnpm --filter @vexa/terminal run build`".to_owned());
        }
        let node = self
            .tools
            .path
            .split(':')
            .map(|d| PathBuf::from(d).join("node"))
            .find(|p| p.is_file())
            .ok_or("cannot find node on PATH")?;
        let port = self.env.port("VEXA_TERMINAL_PORT");
        let stt = self.env.get("TRANSCRIPTION_SERVICE_URL");
        let spec = Spec::new("terminal", node, Ready::Tcp(port))
            .args(["server.mjs"])
            .cwd(dir)
            .env("PATH", self.tools.path.clone())
            .env("TZ", "UTC")
            .env("NODE_ENV", "production")
            .env("HOST", "127.0.0.1")
            .env("PORT", port.to_string())
            .env("GATEWAY_URL", self.p("VEXA_GATEWAY_PORT"))
            .env("VEXA_API_URL", self.p("VEXA_GATEWAY_PORT"))
            .env("AGENT_API_URL", self.p("VEXA_AGENT_API_PORT"))
            .env("VEXA_ADMIN_API_URL", self.p("VEXA_ADMIN_API_PORT"))
            .env("VEXA_ADMIN_API_KEY", self.env.get("ADMIN_TOKEN"))
            .env("VEXA_INTERNAL_API_SECRET", self.env.get("INTERNAL_API_SECRET"))
            .env("VEXA_TERMINAL_SESSION_SECRET", self.env.get("VEXA_TERMINAL_SESSION_SECRET"))
            .env("NEXTAUTH_SECRET", self.env.get("NEXTAUTH_SECRET"))
            // The terminal's public URL; next-auth refuses an empty one.
            .env("NEXTAUTH_URL", {
                let url = self.env.get("NEXTAUTH_URL");
                if url.is_empty() { format!("http://localhost:{port}") } else { url }
            })
            .env("TRANSCRIPTION_SERVICE_URL", if stt.is_empty() { self.p("VEXA_STT_PORT") } else { stt })
            .env("TRANSCRIPTION_SERVICE_TOKEN", self.env.get("TRANSCRIPTION_SERVICE_TOKEN"))
            .env("VEXA_FLOWS_API_URL", format!("{}/to-flows", self.p("VEXA_GATEWAY_SERVICE_DOOR_PORT")))
            .env("VEXA_CONNECTIONS_BROKER_URL", self.p("VEXA_CREDENTIAL_BROKER_PORT"))
            .env("VEXA_CONNECTIONS_HUMAN_KEY_FILE", self.keys().connection("human"))
            .timeout(Duration::from_secs(120));
        Ok(self.pass(
            spec,
            &[
                ("TERMINAL_CANVAS_ORIGIN", ""),
                ("TRANSCRIPTION_MODEL", ""),
                ("VEXA_BOT_API_KEY", ""),
                ("VEXA_JITSI_HOSTS", ""),
                ("MAGIC_LINK_SECRET", ""),
                ("TERMINAL_TRUSTED_PROXIES", ""),
                ("VEXA_ADMIN_ACCOUNT", ""),
                ("LIVEKIT_URL", ""),
                ("GOOGLE_CLIENT_ID", ""),
                ("GOOGLE_CLIENT_SECRET", ""),
                ("MICROSOFT_CLIENT_ID", ""),
                ("MICROSOFT_CLIENT_SECRET", ""),
                ("MICROSOFT_TENANT_ID", "common"),
                ("VEXA_OIDC_ISSUER", ""),
                ("VEXA_OIDC_CLIENT_ID", ""),
                ("VEXA_OIDC_CLIENT_SECRET", ""),
                ("VEXA_OIDC_SCOPES", ""),
                ("VEXA_OIDC_RESOURCE", ""),
                ("VEXA_OIDC_DISPLAY_NAME", ""),
                ("VEXA_OIDC_CA_FILE", ""),
                ("VEXA_OIDC_EMAIL_CLAIM", ""),
                ("VEXA_OIDC_NAME_CLAIM", ""),
                ("VEXA_OIDC_REQUIRE_EMAIL_VERIFIED", ""),
                ("VEXA_SIGNIN_METHODS", ""),
                ("VEXA_DEV_TEST_USERS", ""),
                ("VEXA_MAIL_SMTP_HOST", ""),
                ("VEXA_MAIL_SMTP_PORT", ""),
                ("VEXA_MAIL_SMTP_FROM", ""),
                ("VEXA_MAIL_REPLY_TO", ""),
                ("VEXA_MAIL_RELAY", ""),
                ("VEXA_MAIL_CAPTURE_SMTP", ""),
                ("VEXA_MAIL_SMTP_USER", ""),
                ("VEXA_MAIL_SMTP_PASSWORD", ""),
                ("VEXA_MAIL_SMTP_PASSWORD_REF", ""),
                ("VEXA_MAIL_RECIPIENT_ALLOW", ""),
                ("VEXA_MAIL_SMTP_SECURE", ""),
                ("VEXA_MAIL_SMTP_TLS_INSECURE", ""),
                ("VEXA_CONNECTIONS_PUBLIC_ORIGIN", ""),
            ],
        ))
    }

    /// Start the application services in Compose dependency order. By
    /// default related services share a process (`native_group.py`);
    /// `VEXA_NATIVE_SPLIT=1` runs one process per service for diagnosis.
    pub fn start_services(&self, supervisor: &mut Supervisor) -> Result<crate::runtime::Handle, String> {
        if self.split() {
            return self.start_services_split(supervisor);
        }
        self.prepare_python()?;
        for job in self.key_jobs() {
            supervisor.start(job)?;
        }
        for job in self.schema_jobs() {
            supervisor.start(job)?;
        }
        let runtime = self.start_runtime()?;
        if !self.py_broker() {
            supervisor.start(self.credential_broker()?)?;
        }
        supervisor.start(self.core_group()?)?;
        if !self.py_crm() {
            supervisor.start(self.crm()?)?;
        }
        if !self.py_gateway() {
            supervisor.start(self.gateway()?)?;
        }
        supervisor.start(self.agent_group()?)?;
        if !self.py_mcp() {
            // In VEXA_NATIVE_MCP_WAIT_URLS order: mcp assembles their tools at boot.
            for (port, path) in self.mcp_wait() {
                supervisor.await_ready("mcp dependency", &Ready::Http(port, path.into()), Duration::from_secs(180))?;
            }
            supervisor.start(self.mcp()?)?;
        }
        supervisor.await_ready(
            "mcp",
            &Ready::Http(self.env.port("VEXA_MCP_PORT"), "/health".into()),
            Duration::from_secs(180),
        )?;
        Ok(runtime)
    }

    fn start_services_split(&self, supervisor: &mut Supervisor) -> Result<crate::runtime::Handle, String> {
        self.prepare_python()?;
        for job in self.key_jobs() {
            supervisor.start(job)?;
        }
        for job in self.schema_jobs() {
            supervisor.start(job)?;
        }
        supervisor.start(self.admin_api())?;
        supervisor.start(self.credential_broker()?)?;
        let runtime = self.start_runtime()?;
        supervisor.start(self.model_proxy())?;
        supervisor.start(self.meeting_api())?;
        supervisor.start(self.agent_api())?;
        supervisor.start(self.crm()?)?;
        supervisor.start(self.gateway()?)?;
        supervisor.start(self.flows())?;
        supervisor.start(self.mcp()?)?;
        Ok(runtime)
    }
}

/// Keys that every member sets for itself; the group sets its own values.
const PER_PROCESS_KEYS: [&str; 4] = ["HOST", "PORT", "PATH", "PYTHONPATH"];

/// Merge the environments of several service specs into one group spec.
/// Two members that need different values for one key are an error: one
/// process has one environment.
pub fn merge_specs(base: Spec, members: &[Spec]) -> Result<Spec, String> {
    let mut merged = base;
    let mut conflicts = Vec::new();
    for member in members {
        for (key, value) in &member.env {
            if PER_PROCESS_KEYS.contains(&key.as_str()) || merged.env.contains_key(key) && base_owned(key) {
                continue;
            }
            match merged.env.get(key) {
                Some(existing) if existing != value => conflicts.push(format!("{key} ({} vs {})", merged.name, member.name)),
                Some(_) => {}
                None => {
                    merged.env.insert(key.clone(), value.clone());
                }
            }
        }
    }
    if conflicts.is_empty() {
        Ok(merged)
    } else {
        Err(format!("{}: members need different values for {}", merged.name, conflicts.join(", ")))
    }
}

/// Keys the group spec sets itself (ports of the members).
fn base_owned(key: &str) -> bool {
    key.starts_with("VEXA_") && key.ends_with("_PORT")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_pinned_worker_clis() {
        let text = "RUN ln -s x && \\\n    npm install -g @anthropic-ai/claude-code@2.1.293 @openai/codex@0.146.0 && \\\n    apt-get clean";
        assert_eq!(worker_cli_packages(text), vec!["@anthropic-ai/claude-code@2.1.293", "@openai/codex@0.146.0"]);
    }

    #[test]
    fn merge_accepts_equal_values_and_rejects_conflicts() {
        let base = Spec::new("group", "/bin/true", Ready::Exit).env("VEXA_A_PORT", "1");
        let a = Spec::new("a", "/bin/true", Ready::Exit).env("SHARED", "x").env("PORT", "1").env("VEXA_A_PORT", "9");
        let b = Spec::new("b", "/bin/true", Ready::Exit).env("SHARED", "x").env("PORT", "2").env("ONLY_B", "y");
        let merged = merge_specs(base.clone(), &[a.clone(), b]).unwrap();
        assert_eq!(merged.env["SHARED"], "x");
        assert_eq!(merged.env["ONLY_B"], "y");
        assert_eq!(merged.env["VEXA_A_PORT"], "1");
        assert!(!merged.env.contains_key("PORT"));
        let c = Spec::new("c", "/bin/true", Ready::Exit).env("SHARED", "z");
        let error = merge_specs(base, &[a, c]).unwrap_err();
        assert!(error.contains("SHARED"), "{error}");
    }
}
