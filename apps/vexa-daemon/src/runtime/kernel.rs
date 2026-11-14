//! The runtime kernel: runtime.v1's lifecycle over the process backend.
//!
//! A workload is a child process in a session (and process group) of its
//! own. Its output goes to `<PROCESS_LOG_DIR>/<name>.log`. Every path that
//! ends a workload signals its whole group, so the bot's Chromium tree goes
//! with it. A stop sends SIGTERM to the leader only (the bot leaves the
//! meeting in its SIGTERM handler), waits for the grace time, then kills the
//! group. Each transition emits a RuntimeEvent.

use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vexa_native_kit::json::{object, Value};

use super::clock::now_iso;
use super::workload_env::{child_environment, declared_mounts, name_component, workload_env, StoreConfig};
use super::Log;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    Starting,
    Running,
    Stopping,
    Stopped,
    Destroyed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Starting => "starting",
            State::Running => "running",
            State::Stopping => "stopping",
            State::Stopped => "stopped",
            State::Destroyed => "destroyed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StopReason {
    Completed,
    Stopped,
    IdleTimeout,
    Failed,
    Oom,
    StartFailed,
    MaxLifetime,
}

impl StopReason {
    pub const ALL: [StopReason; 7] = [
        StopReason::Completed,
        StopReason::Stopped,
        StopReason::IdleTimeout,
        StopReason::Failed,
        StopReason::Oom,
        StopReason::StartFailed,
        StopReason::MaxLifetime,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::Completed => "completed",
            StopReason::Stopped => "stopped",
            StopReason::IdleTimeout => "idle_timeout",
            StopReason::Failed => "failed",
            StopReason::Oom => "oom",
            StopReason::StartFailed => "start_failed",
            StopReason::MaxLifetime => "max_lifetime",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == text)
    }
}

/// The parts of a runtime.v1 WorkloadSpec the process backend uses.
#[derive(Clone, Debug)]
pub struct Spec {
    pub workload_id: String,
    pub profile: String,
    pub env: BTreeMap<String, String>,
    pub callback_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Status {
    pub workload_id: String,
    pub profile: String,
    pub state: State,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
    pub exit_code: Option<i64>,
    pub stop_reason: Option<StopReason>,
    /// `{}` once running (the process backend publishes no ports).
    pub ports: bool,
}

impl Status {
    fn new(spec: &Spec) -> Self {
        Self {
            workload_id: spec.workload_id.clone(),
            profile: spec.profile.clone(),
            state: State::Starting,
            started_at: None,
            stopped_at: None,
            exit_code: None,
            stop_reason: None,
            ports: false,
        }
    }

    /// The runtime.v1 WorkloadStatus (`model_dump(exclude_none=True)` order).
    pub fn to_json(&self) -> Value {
        let mut out = object(vec![
            ("workloadId", self.workload_id.clone().into()),
            ("profile", self.profile.clone().into()),
            ("state", self.state.as_str().into()),
            ("backend", "process".into()),
        ]);
        if self.ports {
            out.set("ports", Value::Object(Vec::new()));
        }
        if let Some(at) = &self.started_at {
            out.set("startedAt", at.clone().into());
        }
        if let Some(at) = &self.stopped_at {
            out.set("stoppedAt", at.clone().into());
        }
        if let Some(code) = self.exit_code {
            out.set("exitCode", code.into());
        }
        if let Some(reason) = self.stop_reason {
            out.set("stopReason", reason.as_str().into());
        }
        out
    }
}

/// How to run one workload kind on this host.
#[derive(Clone, Debug)]
pub struct Profile {
    pub name: String,
    pub command: Vec<String>,
    /// The deployment-wide floor the spec's env is layered on.
    pub base_env: BTreeMap<String, String>,
    /// Settings forwarded from the runtime's own environment.
    pub forward_env: Vec<&'static str>,
}

#[derive(Debug)]
pub enum CreateError {
    /// The spec names something the runtime refuses (400).
    Invalid(String),
    /// The backend could not start the workload (502).
    StartFailed(String),
}

/// A started workload process.
pub struct Proc {
    id: String,
    pid: i32,
    child: Mutex<Child>,
    code: Mutex<Option<i64>>,
    log_path: Option<PathBuf>,
    reported: AtomicBool,
    reaped: AtomicBool,
}

fn signal_group(pgid: i32, signal: i32) {
    // ESRCH (the group is gone) is the common case: nothing to reap.
    unsafe {
        libc::killpg(pgid, signal);
    }
}

fn tail(path: &PathBuf, limit: u64) -> String {
    let Ok(mut file) = std::fs::File::open(path) else { return String::new() };
    let size = file.seek(SeekFrom::End(0)).unwrap_or(0);
    let _ = file.seek(SeekFrom::Start(size.saturating_sub(limit)));
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).trim().to_owned()
}

impl Proc {
    /// None while running; the exit code once exited (a signal is minus its
    /// number). The first observation of an exit kills what is left of the
    /// group, and a non-zero exit logs the output tail once.
    pub fn exit_code(&self, log: &Log) -> Option<i64> {
        let code = {
            let mut code = self.code.lock().unwrap_or_else(|e| e.into_inner());
            if code.is_none() {
                if let Ok(Some(status)) = self.child.lock().unwrap_or_else(|e| e.into_inner()).try_wait() {
                    *code = Some(status.code().map(i64::from).unwrap_or_else(|| -i64::from(status.signal().unwrap_or(0))));
                }
            }
            (*code)?
        };
        if !self.reaped.swap(true, Ordering::SeqCst) {
            signal_group(self.pid, libc::SIGKILL);
        }
        if code != 0 && !self.reported.swap(true, Ordering::SeqCst) {
            let path = self.log_path.as_ref().map_or("not captured".to_owned(), |p| p.display().to_string());
            let text = self.log_path.as_ref().map(|p| tail(p, 4096)).unwrap_or_default();
            log.line(&format!(
                "ERROR workload {} exited {code} — output tail (full log: {path}):\n{}",
                self.id,
                if text.is_empty() { "<no output captured>" } else { &text }
            ));
        }
        Some(code)
    }

    /// Graceful stop: SIGTERM to the leader only.
    fn terminate(&self, log: &Log) {
        if self.exit_code(log).is_none() {
            self.reported.store(true, Ordering::SeqCst);
            unsafe {
                libc::kill(self.pid, libc::SIGTERM);
            }
        }
    }

    /// Force stop: SIGKILL to the whole group.
    fn kill(&self) {
        self.reported.store(true, Ordering::SeqCst);
        signal_group(self.pid, libc::SIGKILL);
    }

    fn cleanup(&self, log: &Log) {
        self.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.exit_code(log).is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

pub type EventSink = Box<dyn Fn(Value, Option<String>) + Send + Sync>;

pub struct Kernel {
    pub profiles: Vec<Profile>,
    /// The runtime's own environment: what a child may inherit from.
    pub parent_env: BTreeMap<String, String>,
    pub store: StoreConfig,
    pub log_dir: PathBuf,
    pub grace: Duration,
    pub log: Arc<Log>,
    records: Mutex<Vec<(Spec, Status)>>,
    handles: Mutex<HashMap<String, Arc<Proc>>>,
    sink: EventSink,
}

impl Kernel {
    pub fn new(
        profiles: Vec<Profile>,
        parent_env: BTreeMap<String, String>,
        store: StoreConfig,
        log_dir: PathBuf,
        grace: Duration,
        log: Arc<Log>,
        sink: EventSink,
    ) -> Self {
        Self {
            profiles,
            parent_env,
            store,
            log_dir,
            grace,
            log,
            records: Mutex::new(Vec::new()),
            handles: Mutex::new(HashMap::new()),
            sink,
        }
    }

    fn emit(&self, workload_id: &str, state: State, extra: Vec<(&str, Value)>) {
        let mut event = object(vec![("workloadId", workload_id.into()), ("state", state.as_str().into()), ("at", now_iso().into())]);
        for (k, v) in extra {
            event.set(k, v);
        }
        let url = self.record(workload_id).and_then(|(spec, _)| spec.callback_url);
        (self.sink)(event, url);
    }

    fn persist(&self, spec: &Spec, status: &Status) {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        match records.iter_mut().find(|(s, _)| s.workload_id == spec.workload_id) {
            Some(slot) => *slot = (spec.clone(), status.clone()),
            None => records.push((spec.clone(), status.clone())),
        }
    }

    fn record(&self, workload_id: &str) -> Option<(Spec, Status)> {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(s, _)| s.workload_id == workload_id).cloned()
    }

    fn handle(&self, workload_id: &str) -> Option<Arc<Proc>> {
        self.handles.lock().unwrap_or_else(|e| e.into_inner()).get(workload_id).cloned()
    }

    /// runtime.v1 create. `workloadId` is the idempotency key: a create for a
    /// workload that is starting or running returns its status unchanged.
    pub fn create(&self, spec: Spec) -> Result<Status, CreateError> {
        if let Some(existing) = self.get(&spec.workload_id) {
            if matches!(existing.state, State::Starting | State::Running) {
                return Ok(existing);
            }
        }
        let profile = self
            .profiles
            .iter()
            .find(|p| p.name == spec.profile)
            .ok_or_else(|| CreateError::Invalid(format!("unknown profile: '{}'", spec.profile)))?;
        let mut layered = profile.base_env.clone();
        layered.extend(spec.env.iter().map(|(k, v)| (k.clone(), v.clone())));
        let env = workload_env(&layered, &self.store).map_err(|refused| CreateError::Invalid(refused.0))?;

        let mut status = Status::new(&spec);
        self.persist(&spec, &status);
        self.emit(&spec.workload_id, State::Starting, vec![]);
        match self.start(&spec.workload_id, profile, &env) {
            Ok(proc) => {
                self.handles.lock().unwrap_or_else(|e| e.into_inner()).insert(spec.workload_id.clone(), Arc::new(proc));
            }
            Err(error) => {
                status.state = State::Stopped;
                status.stop_reason = Some(StopReason::StartFailed);
                status.stopped_at = Some(now_iso());
                self.persist(&spec, &status);
                self.emit(&spec.workload_id, State::Stopped, vec![("stopReason", StopReason::StartFailed.as_str().into())]);
                return Err(CreateError::StartFailed(error));
            }
        }
        status.state = State::Running;
        status.started_at = Some(now_iso());
        status.ports = true;
        self.persist(&spec, &status);
        self.emit(&spec.workload_id, State::Running, vec![("ports", Value::Object(Vec::new()))]);
        Ok(status)
    }

    fn start(&self, workload_id: &str, profile: &Profile, env: &BTreeMap<String, String>) -> Result<Proc, String> {
        let Some((program, args)) = profile.command.split_first() else {
            return Err("process backend requires a command".to_owned());
        };
        if let Ok(mounts) = declared_mounts(env) {
            if mounts.len() > 1 {
                let slugs: Vec<&str> = mounts.iter().map(|m| m.get("slug").and_then(Value::as_str).unwrap_or("?")).collect();
                self.log.line(&format!("workload {workload_id}: {} active workspace mounts: {}", mounts.len(), slugs.join(", ")));
            }
        }
        // Built from scratch: the runtime's caller token and every service
        // secret stay out of the child.
        let child_env = child_environment(env, &profile.forward_env, &self.parent_env);
        let log_path = self.log_dir.join(format!("{}.log", name_component(workload_id)));
        let log_file = std::fs::create_dir_all(&self.log_dir).and_then(|_| {
            OpenOptions::new().create(true).append(true).mode(0o644).open(&log_path)
        });
        let mut command = Command::new(program);
        command.args(args).env_clear().envs(&child_env).stdin(Stdio::null());
        let log_path = match log_file.and_then(|f| f.try_clone().map(|g| (f, g))) {
            Ok((out, err)) => {
                command.stdout(Stdio::from(out)).stderr(Stdio::from(err));
                Some(log_path)
            }
            Err(error) => {
                self.log.line(&format!("WARNING workload {workload_id}: cannot capture output ({error}) — falling back to /dev/null"));
                command.stdout(Stdio::null()).stderr(Stdio::null());
                None
            }
        };
        // A session of its own: the workload leads its own process group.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|e| format!("cannot start {program}: {e}"))?;
        Ok(Proc {
            id: workload_id.to_owned(),
            pid: child.id() as i32,
            child: Mutex::new(child),
            code: Mutex::new(None),
            log_path,
            reported: AtomicBool::new(false),
            reaped: AtomicBool::new(false),
        })
    }

    /// The status, with a self-exit of a running workload reflected.
    pub fn get(&self, workload_id: &str) -> Option<Status> {
        let (spec, mut status) = self.record(workload_id)?;
        if status.state == State::Running {
            if let Some(code) = self.handle(workload_id).and_then(|h| h.exit_code(&self.log)) {
                // Reflect only if no stop moved the record on meanwhile.
                let reason = if code == 0 { StopReason::Completed } else { StopReason::Failed };
                {
                    let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
                    let Some(slot) = records.iter_mut().find(|(s, _)| s.workload_id == workload_id) else { return Some(status) };
                    if slot.1.state != State::Running {
                        return Some(slot.1.clone());
                    }
                    status.state = State::Stopped;
                    status.exit_code = Some(code);
                    status.stopped_at = Some(now_iso());
                    status.stop_reason = Some(reason);
                    *slot = (spec, status.clone());
                }
                self.emit(workload_id, State::Stopped, vec![("exitCode", code.into()), ("stopReason", reason.as_str().into())]);
            }
        }
        Some(status)
    }

    pub fn list(&self) -> Vec<Status> {
        let ids: Vec<String> = self.records.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(s, _)| s.workload_id.clone()).collect();
        ids.iter().filter_map(|id| self.get(id)).collect()
    }

    pub fn stop(&self, workload_id: &str, reason: StopReason) -> Option<Status> {
        self.stop_within(workload_id, reason, self.grace)
    }

    fn stop_within(&self, workload_id: &str, reason: StopReason, grace: Duration) -> Option<Status> {
        let (spec, mut status) = self.record(workload_id)?;
        if matches!(status.state, State::Stopped | State::Destroyed) {
            return Some(status);
        }
        status.state = State::Stopping;
        self.persist(&spec, &status);
        self.emit(workload_id, State::Stopping, vec![]);
        let code = match self.handle(workload_id) {
            Some(proc) => {
                proc.terminate(&self.log);
                let deadline = Instant::now() + grace;
                while proc.exit_code(&self.log).is_none() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if proc.exit_code(&self.log).is_none() {
                    proc.kill();
                    let killed = Instant::now() + Duration::from_secs(2);
                    while proc.exit_code(&self.log).is_none() && Instant::now() < killed {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
                proc.exit_code(&self.log)
            }
            None => None,
        };
        status.state = State::Stopped;
        status.exit_code = code;
        status.stopped_at = Some(now_iso());
        status.stop_reason = Some(reason);
        self.persist(&spec, &status);
        let mut extra = vec![("stopReason", reason.as_str().into())];
        if let Some(code) = code {
            extra.insert(0, ("exitCode", code.into()));
        }
        self.emit(workload_id, State::Stopped, extra);
        Some(status)
    }

    pub fn destroy(&self, workload_id: &str) -> Option<Status> {
        let (spec, mut status) = self.record(workload_id)?;
        if let Some(proc) = self.handle(workload_id) {
            proc.cleanup(&self.log);
        }
        status.state = State::Destroyed;
        self.persist(&spec, &status);
        self.emit(workload_id, State::Destroyed, vec![]);
        Some(status)
    }

    /// Stop every running workload at once (the daemon is stopping), each
    /// with at most `grace` before its group is killed.
    pub fn stop_all(self: &Arc<Self>, grace: Duration) {
        let running: Vec<String> = self
            .list()
            .into_iter()
            .filter(|s| matches!(s.state, State::Starting | State::Running))
            .map(|s| s.workload_id)
            .collect();
        let threads: Vec<_> = running
            .into_iter()
            .map(|id| {
                let kernel = Arc::clone(self);
                std::thread::spawn(move || {
                    kernel.stop_within(&id, StopReason::Stopped, grace);
                })
            })
            .collect();
        for thread in threads {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(dir: &std::path::Path, events: Arc<Mutex<Vec<String>>>) -> Arc<Kernel> {
        let log = Arc::new(Log::open(&dir.join("runtime.log")));
        let profile = |name: &str, script: &str| Profile {
            name: name.into(),
            command: vec!["/bin/sh".into(), "-c".into(), script.into()],
            base_env: BTreeMap::new(),
            forward_env: vec![],
        };
        let parent: BTreeMap<String, String> =
            [("PATH", "/usr/bin:/bin"), ("RUNTIME_API_TOKEN", "secret")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Arc::new(Kernel::new(
            vec![
                profile("sleeper", "trap 'exit 0' TERM; echo up; while true; do sleep 0.05; done"),
                profile("quick", "echo \"token=${RUNTIME_API_TOKEN:-none} x=$X\"; exit 3"),
                profile("stubborn", "trap '' TERM; while true; do sleep 0.05; done"),
            ],
            parent,
            StoreConfig::from_env(&BTreeMap::new()).unwrap(),
            dir.join("workloads"),
            Duration::from_millis(500),
            log,
            Box::new(move |event, _url| {
                let state = event.get("state").and_then(Value::as_str).unwrap_or("").to_owned();
                events.lock().unwrap().push(state);
            }),
        ))
    }

    fn spec(id: &str, profile: &str) -> Spec {
        Spec {
            workload_id: id.into(),
            profile: profile.into(),
            env: [("X".to_string(), "1".to_string())].into_iter().collect(),
            callback_url: None,
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vexa-kernel-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn runs_stops_and_destroys_a_workload() {
        let dir = temp("stop");
        let events = Arc::new(Mutex::new(Vec::new()));
        let k = kernel(&dir, events.clone());
        let status = k.create(spec("w-1", "sleeper")).unwrap();
        assert_eq!(status.state, State::Running);
        assert_eq!(status.to_json().get("ports"), Some(&Value::Object(vec![])));
        // A second create is a touch, not a respawn.
        assert_eq!(k.create(spec("w-1", "sleeper")).unwrap().started_at, status.started_at);
        // Stop after the trap is set (the script prints "up" after it).
        let deadline = Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(dir.join("workloads/w-1.log")).unwrap_or_default().contains("up") && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let stopped = k.stop("w-1", StopReason::Stopped).unwrap();
        assert_eq!((stopped.state, stopped.exit_code, stopped.stop_reason), (State::Stopped, Some(0), Some(StopReason::Stopped)));
        assert_eq!(k.destroy("w-1").unwrap().state, State::Destroyed);
        assert_eq!(*events.lock().unwrap(), ["starting", "running", "stopping", "stopped", "destroyed"]);
    }

    #[test]
    fn reflects_a_self_exit_and_keeps_secrets_out() {
        let dir = temp("exit");
        let events = Arc::new(Mutex::new(Vec::new()));
        let k = kernel(&dir, events.clone());
        k.create(spec("w-2", "quick")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            let s = k.get("w-2").unwrap();
            if s.state == State::Stopped || Instant::now() > deadline {
                break s;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!((status.exit_code, status.stop_reason), (Some(3), Some(StopReason::Failed)));
        let output = std::fs::read_to_string(dir.join("workloads/w-2.log")).unwrap();
        assert_eq!(output.trim(), "token=none x=1");
        assert_eq!(events.lock().unwrap().last().map(String::as_str), Some("stopped"));
    }

    #[test]
    fn kills_a_workload_that_ignores_sigterm() {
        let dir = temp("kill");
        let k = kernel(&dir, Arc::new(Mutex::new(Vec::new())));
        k.create(spec("w-3", "stubborn")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let stopped = k.stop("w-3", StopReason::Stopped).unwrap();
        assert_eq!(stopped.state, State::Stopped);
        assert_eq!(stopped.exit_code, Some(-9));
    }

    #[test]
    fn refuses_unknown_profiles_and_reports_start_failures() {
        let dir = temp("fail");
        let mut k = Arc::try_unwrap(kernel(&dir, Arc::new(Mutex::new(Vec::new())))).ok().unwrap();
        assert!(matches!(k.create(spec("w-4", "nope")), Err(CreateError::Invalid(m)) if m == "unknown profile: 'nope'"));
        k.profiles.push(Profile { name: "missing".into(), command: vec!["/nonexistent/bin".into()], base_env: BTreeMap::new(), forward_env: vec![] });
        assert!(matches!(k.create(spec("w-5", "missing")), Err(CreateError::StartFailed(_))));
        let status = k.get("w-5").unwrap();
        assert_eq!((status.state, status.stop_reason), (State::Stopped, Some(StopReason::StartFailed)));
    }
}
