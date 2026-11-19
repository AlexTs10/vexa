//! The native Vexa stack: which host processes the daemon runs, in order.
//!
//! The Compose stack stays the behavior reference. Each process here keeps
//! the same program, configuration names and contracts as its Compose
//! service; only the host addresses and folders change.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::config::{self, NativeEnv};
use crate::supervisor::{Ready, Spec, Supervisor};

/// The local Vexa folders below `~/Library/Application Support/Vexa`.
#[derive(Clone, Debug)]
pub struct Layout {
    pub root: PathBuf,
}

impl Layout {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    pub fn config(&self) -> PathBuf {
        self.root.join("config")
    }
    pub fn data(&self) -> PathBuf {
        self.root.join("data")
    }
    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }
    pub fn state(&self) -> PathBuf {
        self.root.join("state")
    }
    pub fn runtime(&self) -> PathBuf {
        self.root.join("runtime")
    }

    pub fn create(&self) -> Result<(), String> {
        for dir in [
            self.config(),
            self.data(),
            self.logs(),
            self.state(),
            self.runtime(),
            self.root.join("recordings"),
        ] {
            std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        }
        Ok(())
    }
}

/// Host tools the stack needs. Each can be overridden by an environment
/// variable so a bundled app can point at its own copies.
#[derive(Clone, Debug)]
pub struct Tools {
    pub pg_bin: PathBuf,
    pub redis_server: PathBuf,
    pub versitygw: PathBuf,
    pub uv: PathBuf,
    pub path: String,
}

fn which(name: &str, path: &str) -> Option<PathBuf> {
    path.split(':')
        .map(|dir| Path::new(dir).join(name))
        .find(|candidate| candidate.is_file())
}

impl Tools {
    pub fn discover() -> Result<Self, String> {
        let home = std::env::var("HOME").unwrap_or_default();
        let inherited = std::env::var("PATH").unwrap_or_default();
        // An app started by Finder has a short PATH. Add the usual tool folders.
        let path = format!("{inherited}:/opt/homebrew/bin:/usr/local/bin:{home}/.local/bin:/usr/bin:/bin");
        let pick = |env: &str, names: &[&str]| -> Result<PathBuf, String> {
            if let Ok(value) = std::env::var(env) {
                return Ok(PathBuf::from(value));
            }
            names
                .iter()
                .find_map(|name| which(name, &path))
                .ok_or_else(|| format!("cannot find {} on PATH; install it or set {env}", names.join(" or ")))
        };
        let pg_bin = match std::env::var("VEXA_PG_BIN_DIR") {
            Ok(dir) => PathBuf::from(dir),
            Err(_) => ["/opt/homebrew/opt/postgresql@17/bin", "/usr/local/opt/postgresql@17/bin"]
                .iter()
                .map(PathBuf::from)
                .find(|dir| dir.join("postgres").is_file())
                .ok_or("cannot find PostgreSQL 17; run `brew install postgresql@17` or set VEXA_PG_BIN_DIR")?,
        };
        Ok(Self {
            pg_bin,
            // Valkey or a BSD-licensed Redis (7.2 or earlier): the same program
            // as the Compose `redis` service.
            redis_server: pick("VEXA_REDIS_SERVER", &["valkey-server", "redis-server"])?,
            versitygw: pick("VEXA_VERSITYGW", &["versitygw"])?,
            uv: pick("VEXA_UV", &["uv"])?,
            path,
        })
    }
}

/// The checkout that holds the Vexa sources (the Python and Node services).
pub fn source_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("VEXA_SOURCE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    exe.ancestors()
        .find(|dir| dir.join("core").is_dir() && dir.join("apps/vexa-daemon").is_dir())
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot find the Vexa sources; set VEXA_SOURCE_DIR to the checkout".to_owned())
}

pub struct Stack {
    pub layout: Layout,
    pub env: NativeEnv,
    pub tools: Tools,
    pub source: PathBuf,
}

impl Stack {
    pub(crate) fn base(&self, spec: Spec) -> Spec {
        spec.env("PATH", self.tools.path.clone())
            .env("TZ", "UTC")
            // A container has no AWS profile. The user's ~/.aws files (for
            // example a default region) must not change how a service talks
            // to the local storage.
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
    }

    pub fn pg_data(&self) -> PathBuf {
        self.layout.data().join("postgres")
    }

    fn pg_socket_dir(&self) -> PathBuf {
        self.layout.state().join("pg")
    }

    /// Create the PostgreSQL cluster once, with a password on every login.
    pub fn ensure_pg_cluster(&self) -> Result<(), String> {
        let data = self.pg_data();
        if data.join("PG_VERSION").is_file() {
            return Ok(());
        }
        std::fs::create_dir_all(&data).map_err(|error| error.to_string())?;
        let pwfile = self.layout.state().join("pg-initdb-password");
        config::write_private(&pwfile, self.env.get("DB_PASSWORD").as_bytes())?;
        println!("vexa-daemon: creating the PostgreSQL cluster at {}", data.display());
        let output = Command::new(self.tools.pg_bin.join("initdb"))
            .arg("-D")
            .arg(&data)
            .args(["-U", &self.env.get("DB_USER"), "--auth=scram-sha-256", "--encoding=UTF8", "--locale=C"])
            .arg(format!("--pwfile={}", pwfile.display()))
            .env("TZ", "UTC")
            .output()
            .map_err(|error| format!("cannot run initdb: {error}"))?;
        let _ = std::fs::remove_file(&pwfile);
        if !output.status.success() {
            let _ = std::fs::remove_dir_all(&data);
            return Err(format!("initdb failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
        Ok(())
    }

    pub fn postgres(&self) -> Spec {
        let _ = std::fs::create_dir_all(self.pg_socket_dir());
        let port = self.env.port("VEXA_PG_PORT");
        // Low-memory settings for one local user. The Compose service uses
        // the image defaults plus the idle transaction timeout.
        let settings = [
            "listen_addresses=127.0.0.1",
            "shared_buffers=32MB",
            "max_connections=120",
            "work_mem=2MB",
            "maintenance_work_mem=32MB",
            "effective_cache_size=256MB",
            "max_wal_size=256MB",
            "min_wal_size=32MB",
            "timezone=UTC",
            "log_timezone=UTC",
            "idle_in_transaction_session_timeout=60000",
            "unix_socket_permissions=0700",
        ];
        let mut args = vec![
            "-D".to_owned(),
            self.pg_data().display().to_string(),
            "-p".to_owned(),
            port.to_string(),
            "-k".to_owned(),
            self.pg_socket_dir().display().to_string(),
        ];
        for setting in settings {
            args.push("-c".to_owned());
            args.push(setting.to_owned());
        }
        self.base(Spec::new("postgres", self.tools.pg_bin.join("postgres"), Ready::Tcp(port)))
            .args(args)
            .env("PGTZ", "UTC")
    }

    /// Create the application database when it does not exist.
    pub fn ensure_database(&self) -> Result<(), String> {
        let port = self.env.port("VEXA_PG_PORT").to_string();
        let name = self.env.get("DB_NAME");
        let psql = |sql: &str| {
            Command::new(self.tools.pg_bin.join("psql"))
                .args(["-h", "127.0.0.1", "-p", &port, "-U", &self.env.get("DB_USER"), "-d", "postgres"])
                .args(["-v", "ON_ERROR_STOP=1", "-tAc", sql])
                .env("PGPASSWORD", self.env.get("DB_PASSWORD"))
                .output()
                .map_err(|error| format!("cannot run psql: {error}"))
        };
        // Wait for the server to accept logins, not only TCP connections.
        let mut exists = None;
        for _ in 0..50 {
            let output = psql(&format!("SELECT 1 FROM pg_database WHERE datname = '{name}'"))?;
            if output.status.success() {
                exists = Some(String::from_utf8_lossy(&output.stdout).trim() == "1");
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        match exists {
            Some(true) => Ok(()),
            Some(false) => {
                let output = psql(&format!("CREATE DATABASE \"{name}\""))?;
                if output.status.success() {
                    println!("vexa-daemon: created database {name}");
                    Ok(())
                } else {
                    Err(format!("cannot create database {name}: {}", String::from_utf8_lossy(&output.stderr).trim()))
                }
            }
            None => Err("PostgreSQL does not accept logins; read logs/postgres.log".to_owned()),
        }
    }

    pub fn redis(&self) -> Result<Spec, String> {
        let port = self.env.port("VEXA_REDIS_PORT");
        let dir = self.layout.data().join("redis");
        std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
        // The password stays out of the process list: it is in a private file.
        let conf = self.layout.state().join("redis.conf");
        let text = format!(
            "bind 127.0.0.1\nport {port}\nprotected-mode yes\ndir \"{}\"\nappendonly yes\nappendfsync everysec\nrequirepass {}\n",
            dir.display(),
            self.env.get("REDIS_PASSWORD")
        );
        config::write_private(&conf, text.as_bytes())?;
        Ok(self
            .base(Spec::new("redis", self.tools.redis_server.clone(), Ready::Tcp(port)))
            .args([conf.display().to_string()]))
    }

    pub fn storage(&self) -> Result<Spec, String> {
        let port = self.env.port("VEXA_STORAGE_PORT");
        let data = self.layout.data().join("storage");
        let iam = self.layout.state().join("storage-iam");
        for dir in [&data, &iam] {
            std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
        }
        Ok(self
            .base(Spec::new("storage", self.tools.versitygw.clone(), Ready::Http(port, "/health".to_owned())))
            .args([
                "--port".to_owned(),
                format!("127.0.0.1:{port}"),
                "--health".to_owned(),
                "/health".to_owned(),
                "--iam-dir".to_owned(),
                iam.display().to_string(),
                "--quiet".to_owned(),
                "posix".to_owned(),
                data.display().to_string(),
            ])
            .env("ROOT_ACCESS_KEY", self.env.get("MINIO_ACCESS_KEY"))
            .env("ROOT_SECRET_KEY", self.env.get("MINIO_SECRET_KEY")))
    }

    /// A Python program run by uv in its project's locked environment. Each
    /// project gets its own environment below `runtime/venvs`, as in Lite.
    pub fn uv_python(&self, name: &str, project: &str, venv: &str, args: &[&str], ready: Ready) -> Spec {
        let mut full = vec!["run", "--frozen", "--no-dev", "--project", project, "python"];
        full.extend_from_slice(args);
        self.base(Spec::new(name, self.tools.uv.clone(), ready))
            .args(full.iter().map(|arg| arg.to_string()))
            .cwd(self.source.clone())
            .env("UV_PROJECT_ENVIRONMENT", self.layout.runtime().join("venvs").join(venv).display().to_string())
            .env("UV_PYTHON", "3.12")
            .env("PYTHONUNBUFFERED", "1")
    }

    pub fn storage_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.env.port("VEXA_STORAGE_PORT"))
    }

    /// The Compose storage-init step: bucket, probe and scoped accounts.
    pub fn storage_init(&self) -> Spec {
        let endpoint = self.storage_url();
        let mut spec = self
            .uv_python(
                "storage-init",
                "deploy/storage",
                "storage-tools",
                &["deploy/storage/storage_init.py"],
                Ready::Exit,
            )
            .timeout(Duration::from_secs(300))
            .env("STORAGE_ENDPOINT", endpoint.clone())
            .env("MINIO_ENDPOINT", endpoint)
            .env("MINIO_SECURE", "false");
        for key in [
            "MINIO_ACCESS_KEY",
            "MINIO_SECRET_KEY",
            "MINIO_BUCKET",
            "VEXA_SESSIONS_S3_BUCKET",
            "VEXA_SESSIONS_S3_ACCESS_KEY",
            "VEXA_SESSIONS_S3_SECRET_KEY",
            "VEXA_PHOTOS_S3_ACCESS_KEY",
            "VEXA_PHOTOS_S3_SECRET_KEY",
        ] {
            spec = spec.env(key, self.env.get(key));
        }
        spec
    }

    /// The native transcription service (`apps/vexa-stt`): the Compose
    /// `transcription` contract on whisper.cpp with Metal.
    pub fn stt(&self) -> Result<Spec, String> {
        let binary = match std::env::var("VEXA_STT_BIN") {
            Ok(path) => PathBuf::from(path),
            Err(_) => {
                let beside = std::env::current_exe()
                    .ok()
                    .and_then(|exe| exe.parent().map(|dir| dir.join("vexa-stt")));
                [
                    beside,
                    Some(self.source.join("apps/vexa-stt/target/release/vexa-stt")),
                    Some(self.source.join("apps/vexa-stt/target/debug/vexa-stt")),
                ]
                .into_iter()
                .flatten()
                .find(|path| path.is_file())
                .ok_or("cannot find vexa-stt; build apps/vexa-stt or set VEXA_STT_BIN")?
            }
        };
        let port = self.env.port("VEXA_STT_PORT");
        let mut spec = self
            .base(Spec::new("stt", binary, Ready::Http(port, "/health".to_owned())))
            .env("VEXA_STT_PORT", port.to_string())
            .env("TRANSCRIPTION_SERVICE_TOKEN", self.env.get("TRANSCRIPTION_SERVICE_TOKEN"))
            .env("VEXA_STT_MODEL_DIR", self.layout.data().join("models").display().to_string())
            .env("VEXA_STT_ENGINE_LOG", self.layout.logs().join("whisper-server.log").display().to_string())
            // The first start downloads the model (about 265 MB).
            .timeout(Duration::from_secs(900));
        for key in ["VEXA_STT_MODEL", "VEXA_STT_IDLE_SEC", "VEXA_STT_THREADS", "VEXA_WHISPER_SERVER", "MAX_ACTIVE_REQUESTS"] {
            let value = self.env.get(key);
            if !value.is_empty() {
                spec = spec.env(key, value);
            }
        }
        Ok(spec)
    }

    /// Start the infrastructure group: database, bus, object storage and
    /// transcription.
    pub fn start_infra(&self, supervisor: &mut Supervisor) -> Result<(), String> {
        self.ensure_pg_cluster()?;
        supervisor.start(self.postgres())?;
        self.ensure_database()?;
        supervisor.start(self.redis()?)?;
        supervisor.start(self.storage()?)?;
        supervisor.start(self.storage_init())?;
        // An operator who sets TRANSCRIPTION_SERVICE_URL uses another service.
        if self.env.get("TRANSCRIPTION_SERVICE_URL").is_empty() {
            supervisor.start(self.stt()?)?;
        }
        Ok(())
    }
}
