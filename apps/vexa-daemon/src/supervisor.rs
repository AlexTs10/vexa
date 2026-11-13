//! A small process supervisor for the native Vexa stack.
//!
//! Each [`Spec`] is one host process. The supervisor starts the specs in
//! order, waits until each is ready, restarts a process that stops, and stops
//! every process in reverse order when the daemon receives SIGINT or SIGTERM.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Install SIGINT and SIGTERM handlers that ask the supervisor to stop.
pub fn install_signal_handlers() {
    let handler = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Ready {
    /// The process accepts TCP connections on 127.0.0.1:port.
    Tcp(u16),
    /// The process answers HTTP 200 on 127.0.0.1:port at this path.
    Http(u16, String),
    /// The process is a one-shot step; it must exit with code 0.
    Exit,
}

#[derive(Clone, Debug)]
pub struct Spec {
    pub name: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub ready: Ready,
    pub ready_timeout: Duration,
}

impl Spec {
    pub fn new(name: &str, program: impl Into<PathBuf>, ready: Ready) -> Self {
        Self {
            name: name.to_owned(),
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            ready,
            ready_timeout: Duration::from_secs(60),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, key: &str, value: impl Into<String>) -> Self {
        self.env.insert(key.to_owned(), value.into());
        self
    }

    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.ready_timeout = timeout;
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcStatus {
    pub name: String,
    pub pid: Option<u32>,
    pub state: String,
    pub restarts: u32,
}

pub type SharedStatus = Arc<Mutex<Vec<ProcStatus>>>;

struct Running {
    spec: Spec,
    child: Option<Child>,
    started: Instant,
    restarts: u32,
    next_restart: Option<Instant>,
}

/// Keys that every child receives from the daemon, in addition to its spec env.
const PLUMBING_ENV: [&str; 6] = ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER"];

fn spawn(spec: &Spec, log_dir: &PathBuf) -> Result<Child, String> {
    let log_path = log_dir.join(format!("{}.log", spec.name));
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("{}: cannot open log {}: {error}", spec.name, log_path.display()))?;
    let err = log
        .try_clone()
        .map_err(|error| format!("{}: cannot open log: {error}", spec.name))?;
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        // A process group of its own: a terminal Ctrl-C reaches only the
        // daemon, which then stops the children in order.
        .process_group(0);
    for key in PLUMBING_ENV {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    command.envs(&spec.env);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    command
        .spawn()
        .map_err(|error| format!("{}: cannot start {}: {error}", spec.name, spec.program.display()))
}

pub fn port_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .is_ok()
}

pub fn http_ok(port: u16, path: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(500),
    ) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0_u8; 32];
    let Ok(length) = stream.read(&mut head) else {
        return false;
    };
    let line = String::from_utf8_lossy(&head[..length]);
    line.starts_with("HTTP/1.1 200") || line.starts_with("HTTP/1.0 200")
}

fn is_ready(ready: &Ready) -> bool {
    match ready {
        Ready::Tcp(port) => port_open(*port),
        Ready::Http(port, path) => http_ok(*port, path),
        Ready::Exit => true,
    }
}

fn signal_group(child: &Child, signal: libc::c_int) {
    // The child leads its own process group (process_group(0)).
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), signal);
    }
}

fn stop_child(name: &str, child: &mut Child, grace: Duration) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    signal_group(child, libc::SIGTERM);
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            println!("vexa-daemon: {name} stopped");
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    eprintln!("vexa-daemon: {name} did not stop in {grace:?}; killing it");
    signal_group(child, libc::SIGKILL);
    let _ = child.wait();
}

fn set_status(shared: &SharedStatus, name: &str, pid: Option<u32>, state: &str, restarts: u32) {
    let mut list = shared.lock().expect("status lock");
    match list.iter_mut().find(|entry| entry.name == name) {
        Some(entry) => {
            entry.pid = pid;
            entry.state = state.to_owned();
            entry.restarts = restarts;
        }
        None => list.push(ProcStatus {
            name: name.to_owned(),
            pid,
            state: state.to_owned(),
            restarts,
        }),
    }
}

pub struct Supervisor {
    log_dir: PathBuf,
    running: Vec<Running>,
    status: SharedStatus,
    grace: Duration,
}

impl Supervisor {
    pub fn new(log_dir: PathBuf, status: SharedStatus) -> Self {
        Self {
            log_dir,
            running: Vec::new(),
            status,
            grace: Duration::from_secs(15),
        }
    }

    /// Start one spec and wait until it is ready. A one-shot step must exit 0.
    pub fn start(&mut self, spec: Spec) -> Result<(), String> {
        if stop_requested() {
            return Err("stop requested".to_owned());
        }
        if let Ready::Tcp(port) | Ready::Http(port, _) = &spec.ready {
            if port_open(*port) {
                return Err(format!(
                    "{}: port {port} is already in use; stop the other process or change the port in native.env",
                    spec.name
                ));
            }
        }
        println!("vexa-daemon: starting {}", spec.name);
        set_status(&self.status, &spec.name, None, "starting", 0);
        let mut child = spawn(&spec, &self.log_dir)?;
        let deadline = Instant::now() + spec.ready_timeout;
        loop {
            if stop_requested() {
                stop_child(&spec.name, &mut child, self.grace);
                return Err("stop requested".to_owned());
            }
            if let Ok(Some(status)) = child.try_wait() {
                if spec.ready == Ready::Exit && status.success() {
                    println!("vexa-daemon: {} finished", spec.name);
                    set_status(&self.status, &spec.name, None, "done", 0);
                    return Ok(());
                }
                set_status(&self.status, &spec.name, None, "failed", 0);
                return Err(format!(
                    "{} stopped during start ({status}); read {}",
                    spec.name,
                    self.log_dir.join(format!("{}.log", spec.name)).display()
                ));
            }
            if spec.ready != Ready::Exit && is_ready(&spec.ready) {
                break;
            }
            if Instant::now() >= deadline {
                stop_child(&spec.name, &mut child, self.grace);
                set_status(&self.status, &spec.name, None, "failed", 0);
                return Err(format!(
                    "{} did not become ready in {:?}; read {}",
                    spec.name,
                    spec.ready_timeout,
                    self.log_dir.join(format!("{}.log", spec.name)).display()
                ));
            }
            thread::sleep(Duration::from_millis(200));
        }
        println!("vexa-daemon: {} is ready (pid {})", spec.name, child.id());
        set_status(&self.status, &spec.name, Some(child.id()), "ready", 0);
        self.running.push(Running {
            spec,
            child: Some(child),
            started: Instant::now(),
            restarts: 0,
            next_restart: None,
        });
        Ok(())
    }

    /// Watch the running processes until a stop is requested.
    pub fn watch(&mut self) {
        while !stop_requested() {
            for entry in &mut self.running {
                if let Some(child) = &mut entry.child {
                    if let Ok(Some(status)) = child.try_wait() {
                        eprintln!("vexa-daemon: {} stopped unexpectedly ({status})", entry.spec.name);
                        // A process that ran for a minute gets a fresh backoff.
                        if entry.started.elapsed() > Duration::from_secs(60) {
                            entry.restarts = 0;
                        }
                        let delay = Duration::from_secs(1 << entry.restarts.min(5));
                        entry.child = None;
                        entry.next_restart = Some(Instant::now() + delay);
                        set_status(&self.status, &entry.spec.name, None, "restarting", entry.restarts);
                    }
                } else if entry.next_restart.is_some_and(|at| Instant::now() >= at) {
                    entry.restarts += 1;
                    entry.next_restart = None;
                    match spawn(&entry.spec, &self.log_dir) {
                        Ok(child) => {
                            println!("vexa-daemon: restarted {} (pid {})", entry.spec.name, child.id());
                            set_status(&self.status, &entry.spec.name, Some(child.id()), "running", entry.restarts);
                            entry.child = Some(child);
                            entry.started = Instant::now();
                        }
                        Err(error) => {
                            eprintln!("vexa-daemon: {error}");
                            entry.next_restart = Some(Instant::now() + Duration::from_secs(30));
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    /// Stop every running process in reverse start order.
    pub fn shutdown(&mut self) {
        while let Some(mut entry) = self.running.pop() {
            if let Some(child) = &mut entry.child {
                println!("vexa-daemon: stopping {}", entry.spec.name);
                stop_child(&entry.spec.name, child, self.grace);
            }
            set_status(&self.status, &entry.spec.name, None, "stopped", entry.restarts);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vexa-supervisor-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn one_shot_step_must_exit_zero() {
        let status = SharedStatus::default();
        let mut sup = Supervisor::new(temp_dir("oneshot"), status.clone());
        assert!(sup.start(Spec::new("ok", "/usr/bin/true", Ready::Exit)).is_ok());
        let error = sup
            .start(Spec::new("bad", "/usr/bin/false", Ready::Exit))
            .unwrap_err();
        assert!(error.contains("bad stopped during start"));
        let list = status.lock().unwrap();
        assert_eq!(list.iter().find(|e| e.name == "ok").unwrap().state, "done");
        assert_eq!(list.iter().find(|e| e.name == "bad").unwrap().state, "failed");
    }

    #[test]
    fn child_gets_only_plumbing_and_spec_env() {
        let dir = temp_dir("env");
        let mut sup = Supervisor::new(dir.clone(), SharedStatus::default());
        std::env::set_var("VEXA_SUPERVISOR_TEST_LEAK", "leaked");
        let spec = Spec::new("envcheck", "/bin/sh", Ready::Exit)
            .args(["-c", "env > \"$OUT\""])
            .env("OUT", dir.join("env.txt").display().to_string())
            .env("GIVEN", "yes");
        sup.start(spec).unwrap();
        let env = std::fs::read_to_string(dir.join("env.txt")).unwrap();
        assert!(env.contains("GIVEN=yes"));
        assert!(!env.contains("VEXA_SUPERVISOR_TEST_LEAK"));
    }

    #[test]
    fn long_running_process_is_stopped_on_shutdown() {
        let dir = temp_dir("stop");
        let status = SharedStatus::default();
        let mut sup = Supervisor::new(dir, status.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let spec = Spec::new("listener", "/usr/bin/python3", Ready::Tcp(port))
            .args([
                "-c".to_owned(),
                format!("import socket,time; s=socket.socket(); s.bind(('127.0.0.1',{port})); s.listen(); time.sleep(60)"),
            ])
            .timeout(Duration::from_secs(10));
        sup.start(spec).unwrap();
        assert!(port_open(port));
        sup.shutdown();
        assert!(!port_open(port));
        assert_eq!(status.lock().unwrap()[0].state, "stopped");
    }
}
