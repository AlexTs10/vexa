//! The Vexa runtime inside the daemon: runtime.v1 (spawn, observe and stop
//! meeting bots and agent workers as host processes) and schedule.v1 (the
//! durable cron), served on `127.0.0.1:<VEXA_RUNTIME_PORT>`.
//!
//! It is the `process` backend of `core/runtime` (`runtime_kernel`) for one
//! Mac user: the same HTTP contract, callback signatures, Redis schedule keys
//! and config.v1 declaration. Additions for the desktop: a watcher reports a
//! workload that exits by itself within seconds, a sweep retries callbacks
//! the receiver did not acknowledge, and a daemon stop stops every workload.

pub mod api;
pub mod callbacks;
pub mod clock;
pub mod kernel;
pub mod preflight;
pub mod redis;
pub mod scheduler;
pub mod workload_env;

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vexa_native_kit::http;
use vexa_native_kit::json::{self, object, Value};

use callbacks::CallbackQueue;
use kernel::{Kernel, Profile};
use preflight::Declaration;
use scheduler::Scheduler;

/// The runtime's log file (`logs/runtime.log`): plain lines and logevent.v1 JSON lines.
pub struct Log {
    file: Mutex<Option<File>>,
}

impl Log {
    pub fn open(path: &Path) -> Self {
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        Self { file: Mutex::new(file) }
    }

    pub fn line(&self, text: &str) {
        if let Some(file) = self.file.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            let _ = writeln!(file, "{text}");
        }
    }

    /// One logevent.v1 line.
    pub fn event(&self, event: &str, audience: &str, level: &str, span: &str, fields: Value) {
        let envelope = object(vec![
            ("ts", clock::now_iso().replace("+00:00", "Z").into()),
            ("level", level.into()),
            ("service", "runtime".into()),
            ("trace_id", TRACE.with(|t| t.borrow().clone()).unwrap_or_else(new_trace_id).into()),
            ("audience", audience.into()),
            ("event", event.into()),
            ("span", span.into()),
            ("fields", fields),
        ]);
        self.line(&json::write(&envelope));
    }
}

thread_local! {
    static TRACE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn new_trace_id() -> String {
    let mut buf = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    vexa_native_kit::sha256::hex(&buf)
}

pub struct Config {
    pub port: u16,
    /// The runtime's own environment: its settings and what a child may inherit.
    pub env: BTreeMap<String, String>,
    pub profiles: Vec<Profile>,
    /// The runtime's config.v1 declaration.
    pub declaration: PathBuf,
    pub log_file: PathBuf,
}

pub struct Runtime {
    pub token: String,
    pub kernel: Arc<Kernel>,
    pub scheduler: Option<Scheduler>,
    pub declaration: Declaration,
    pub log: Arc<Log>,
}

/// The running runtime; `shutdown` stops every workload.
pub struct Handle {
    runtime: Arc<Runtime>,
    stopping: Arc<AtomicBool>,
}

fn seconds(env: &BTreeMap<String, String>, key: &str, default: f64) -> f64 {
    env.get(key).and_then(|v| v.trim().parse::<f64>().ok()).unwrap_or(default)
}

pub fn start(config: Config) -> Result<Handle, String> {
    let env = config.env;
    let log = Arc::new(Log::open(&config.log_file));
    let declaration = Declaration::load(&config.declaration)?;
    declaration.preflight(&env)?;
    let token = declaration.caller_token(&env)?;
    let store = workload_env::StoreConfig::from_env(&env).map_err(|e| e.0)?;
    let log_dir = env
        .get("PROCESS_LOG_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("vexa-workloads"));
    // The stop window: the backend grace (RUNTIME_STOP_GRACE_SEC, default 30) plus a margin.
    let grace = Duration::from_secs_f64(seconds(&env, "RUNTIME_STOP_GRACE_SEC", 30.0).max(1.0) + 5.0);

    let queue = Arc::new(CallbackQueue::new(token.clone()));
    let sink_queue = Arc::clone(&queue);
    let sink_log = Arc::clone(&log);
    let sink: kernel::EventSink = Box::new(move |event, url| {
        if let Some(url) = url.filter(|u| !u.is_empty()) {
            sink_queue.enqueue(&url, event, &sink_log);
        }
    });
    let kernel = Arc::new(Kernel::new(config.profiles, env.clone(), store, log_dir, grace, Arc::clone(&log), sink));

    let scheduler = match env.get("REDIS_URL").filter(|u| !u.trim().is_empty()) {
        Some(url) => {
            let scheduler = Scheduler::new(redis::Redis::new(redis::parse_url(url.trim())?));
            match scheduler.recover_orphans(&log) {
                Ok(0) => {}
                Ok(n) => log.line(&format!("scheduler recovered {n} orphaned job(s)")),
                Err(e) => log.line(&format!("WARNING scheduler orphan recovery failed: {e}")),
            }
            Some(scheduler)
        }
        None => None,
    };
    let capabilities = declaration.capability_health(&env);
    for (name, row) in capabilities.as_object().unwrap_or(&[]) {
        log.line(&format!("config.v1 capability {name}: {}", row.get("state").and_then(Value::as_str).unwrap_or("?")));
    }

    let host = env.get("HOST").cloned().unwrap_or_else(|| "127.0.0.1".to_owned());
    let listener = TcpListener::bind((host.as_str(), config.port)).map_err(|e| format!("runtime: cannot listen on {host}:{}: {e}", config.port))?;
    let runtime = Arc::new(Runtime { token, kernel, scheduler, declaration, log: Arc::clone(&log) });
    let stopping = Arc::new(AtomicBool::new(false));

    let server = Arc::clone(&runtime);
    std::thread::Builder::new()
        .name("runtime-http".into())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                let runtime = Arc::clone(&server);
                std::thread::spawn(move || serve(&runtime, stream));
            }
        })
        .map_err(|e| e.to_string())?;

    // A workload that exits by itself is seen (and its callback sent) within seconds.
    background(&stopping, "runtime-watch", Duration::from_secs(2), {
        let kernel = Arc::clone(&runtime.kernel);
        move || {
            kernel.list();
        }
    });
    background(&stopping, "runtime-callbacks", Duration::from_secs(15), {
        let (queue, log) = (Arc::clone(&queue), Arc::clone(&log));
        move || {
            queue.sweep(&log);
        }
    });
    if runtime.scheduler.is_some() {
        let tick = Duration::from_secs_f64(seconds(&env, "SCHED_TICK_SEC", 5.0).max(0.5));
        let (rt, log) = (Arc::clone(&runtime), Arc::clone(&log));
        background(&stopping, "runtime-scheduler", tick, move || {
            if let Some(scheduler) = &rt.scheduler {
                if let Err(e) = scheduler.tick(&log) {
                    log.line(&format!("WARNING scheduler tick error: {e}"));
                }
            }
        });
    }
    log.line(&format!("runtime listens on {host}:{} (process backend)", config.port));
    Ok(Handle { runtime, stopping })
}

fn background(stopping: &Arc<AtomicBool>, name: &str, every: Duration, work: impl Fn() + Send + 'static) {
    let stopping = Arc::clone(stopping);
    let _ = std::thread::Builder::new().name(name.into()).spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            std::thread::sleep(every);
            work();
        }
    });
}

fn serve(runtime: &Runtime, mut stream: std::net::TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let response = match http::read_request(&stream) {
        Ok(request) => {
            // Reuse the caller's trace id so this hop's logs join its trace.
            let trace = request.header("x-trace-id").map(str::to_owned).unwrap_or_else(new_trace_id);
            TRACE.with(|t| *t.borrow_mut() = Some(trace.clone()));
            let response = api::handle(runtime, &request).with_header("x-trace-id", &trace);
            TRACE.with(|t| *t.borrow_mut() = None);
            response
        }
        Err(error) => http::Response::json(400, json::write(&object(vec![("detail", error.into())]))),
    };
    let _ = response.write(&mut stream);
}

impl Handle {
    /// Stop every workload (SIGTERM, then the group kill after `grace`), so
    /// no bot or worker outlives the daemon.
    pub fn shutdown(&self, grace: Duration) {
        self.stopping.store(true, Ordering::SeqCst);
        self.runtime.kernel.stop_all(grace);
        self.runtime.log.line("runtime stopped its workloads");
    }
}
