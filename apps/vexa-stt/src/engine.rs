//! The whisper.cpp engine: a `whisper-server` child process with Metal.
//!
//! The engine starts on the first transcription and stops after an idle
//! time, so the model memory is free when there is no meeting. The model
//! files download once into the model folder.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::json::{self, Value};
use crate::multipart::{self, Part};

const MODEL_BASE_URL: &str = "https://huggingface.co/ggerganov/whisper.cpp/resolve/main";
const VAD_MODEL: &str = "ggml-silero-v5.1.2.bin";
const VAD_URL: &str = "https://huggingface.co/ggml-org/whisper-vad/resolve/main/ggml-silero-v5.1.2.bin";

#[derive(Clone, Debug)]
pub struct Config {
    pub whisper_server: PathBuf,
    pub model_dir: PathBuf,
    /// The whisper.cpp model name, for example `small-q8_0` (ggml-small-q8_0.bin).
    pub model: String,
    pub engine_port: u16,
    pub threads: u32,
    pub idle: Duration,
    pub timeout: Duration,
    pub log_file: Option<PathBuf>,
}

impl Config {
    pub fn model_file(&self) -> PathBuf {
        self.model_dir.join(format!("ggml-{}.bin", self.model))
    }
    pub fn vad_file(&self) -> PathBuf {
        self.model_dir.join(VAD_MODEL)
    }
}

#[derive(Debug)]
pub enum EngineError {
    /// The model is not on disk yet (download running).
    NotReady(String),
    /// whisper-server rejected the request (for example an unknown audio format).
    BadRequest(String),
    Timeout,
    Failed(String),
}

struct State {
    child: Option<Child>,
    last_used: Instant,
}

pub struct Engine {
    pub config: Config,
    state: Mutex<State>,
    downloading: AtomicBool,
}

fn download(url: &str, target: &Path) -> Result<(), String> {
    let partial = target.with_extension("part");
    let status = Command::new("/usr/bin/curl")
        .args(["-fL", "--retry", "3", "--silent", "--show-error", "-o"])
        .arg(&partial)
        .arg(url)
        .status()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&partial);
        return Err(format!("download failed: {url}"));
    }
    std::fs::rename(&partial, target).map_err(|e| e.to_string())
}

fn port_open(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(200)).is_ok()
}

impl Engine {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            state: Mutex::new(State { child: None, last_used: Instant::now() }),
            downloading: AtomicBool::new(false),
        }
    }

    pub fn model_present(&self) -> bool {
        self.config.model_file().is_file()
    }

    pub fn loaded(&self) -> bool {
        let mut state = self.state.lock().expect("engine lock");
        match &mut state.child {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Download missing model files in the background.
    pub fn fetch_models(self: &std::sync::Arc<Self>) {
        if self.model_present() && self.config.vad_file().is_file() {
            return;
        }
        if self.downloading.swap(true, Ordering::SeqCst) {
            return;
        }
        let engine = self.clone();
        std::thread::spawn(move || {
            let _ = std::fs::create_dir_all(&engine.config.model_dir);
            let model = engine.config.model_file();
            if !model.is_file() {
                let url = format!("{MODEL_BASE_URL}/ggml-{}.bin", engine.config.model);
                eprintln!("vexa-stt: downloading {url}");
                if let Err(error) = download(&url, &model) {
                    eprintln!("vexa-stt: {error}");
                }
            }
            if !engine.config.vad_file().is_file() {
                if let Err(error) = download(VAD_URL, &engine.config.vad_file()) {
                    eprintln!("vexa-stt: {error}; transcription runs without VAD");
                }
            }
            engine.downloading.store(false, Ordering::SeqCst);
        });
    }

    fn spawn(&self) -> Result<Child, EngineError> {
        let c = &self.config;
        let mut command = Command::new(&c.whisper_server);
        command
            .arg("-m")
            .arg(c.model_file())
            .args(["--host", "127.0.0.1", "--port", &c.engine_port.to_string()])
            .args(["-l", "auto", "-t", &c.threads.to_string()])
            // The Python service's decoding settings (core/meetings/services/transcription).
            .args(["-bs", "5", "-bo", "5", "-nf", "-nth", "0.6", "-lpt", "-1.0"])
            .stdin(Stdio::null());
        if c.vad_file().is_file() {
            command
                .arg("--vad")
                .arg("-vm")
                .arg(c.vad_file())
                .args(["-vt", "0.5", "-vsd", "160", "-vmsd", "15"]);
        }
        match &c.log_file {
            Some(path) => {
                let log = std::fs::OpenOptions::new().create(true).append(true).open(path)
                    .map_err(|e| EngineError::Failed(e.to_string()))?;
                let err = log.try_clone().map_err(|e| EngineError::Failed(e.to_string()))?;
                command.stdout(Stdio::from(log)).stderr(Stdio::from(err));
            }
            None => {
                command.stdout(Stdio::null()).stderr(Stdio::null());
            }
        }
        command
            .spawn()
            .map_err(|e| EngineError::Failed(format!("cannot start {}: {e}", c.whisper_server.display())))
    }

    /// Start whisper-server when it is not running, and wait until it listens.
    fn ensure_running(&self) -> Result<(), EngineError> {
        let mut state = self.state.lock().expect("engine lock");
        state.last_used = Instant::now();
        if let Some(child) = &mut state.child {
            if matches!(child.try_wait(), Ok(None)) {
                return Ok(());
            }
            state.child = None;
        }
        if !self.model_present() {
            return Err(EngineError::NotReady("the transcription model is downloading".into()));
        }
        let started = Instant::now();
        let mut child = self.spawn()?;
        let deadline = started + Duration::from_secs(60);
        while !port_open(self.config.engine_port) {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(EngineError::Failed(format!("whisper-server stopped during start ({status})")));
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(EngineError::Failed("whisper-server did not start in 60 s".into()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        eprintln!("vexa-stt: model {} loaded in {:?}", self.config.model, started.elapsed());
        state.child = Some(child);
        Ok(())
    }

    /// Stop whisper-server when nobody used it for the idle time.
    pub fn unload_if_idle(&self, busy: bool) {
        let mut state = self.state.lock().expect("engine lock");
        if busy || state.last_used.elapsed() < self.config.idle {
            return;
        }
        if let Some(mut child) = state.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("vexa-stt: model unloaded after {:?} idle", self.config.idle);
        }
    }

    pub fn stop(&self) {
        if let Some(mut child) = self.state.lock().expect("engine lock").child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn transcribe(&self, fields: &[(&str, String)], file: &Part) -> Result<Value, EngineError> {
        self.ensure_running()?;
        let (body, boundary) = multipart::build(fields, file);
        let result = self.post(&body, &boundary);
        self.state.lock().expect("engine lock").last_used = Instant::now();
        let (status, text) = result?;
        if status == 200 {
            let value = json::parse(&text).map_err(|e| EngineError::Failed(format!("bad engine answer: {e}")))?;
            if let Some(error) = value.get("error").and_then(Value::as_str) {
                return Err(EngineError::BadRequest(format!("Invalid audio format: {error}")));
            }
            return Ok(value);
        }
        if (400..500).contains(&status) {
            return Err(EngineError::BadRequest(format!("Invalid audio format or request: {}", text.trim())));
        }
        Err(EngineError::Failed(format!("whisper-server answered {status}: {}", text.trim())))
    }

    fn post(&self, body: &[u8], boundary: &str) -> Result<(u16, String), EngineError> {
        let address = SocketAddr::from(([127, 0, 0, 1], self.config.engine_port));
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .map_err(|e| EngineError::Failed(e.to_string()))?;
        stream.set_read_timeout(Some(self.config.timeout)).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
        let head = format!(
            "POST /inference HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).map_err(|e| EngineError::Failed(e.to_string()))?;
        stream.write_all(body).map_err(|e| EngineError::Failed(e.to_string()))?;
        let mut raw = Vec::new();
        if let Err(error) = stream.read_to_end(&mut raw) {
            return Err(match error.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => EngineError::Timeout,
                _ => EngineError::Failed(error.to_string()),
            });
        }
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").ok_or(EngineError::Failed("empty engine answer".into()))?;
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or(EngineError::Failed("bad engine status line".into()))?;
        let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            dechunk(body)
        } else {
            body.to_owned()
        };
        Ok((status, body))
    }
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size, after)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size.trim(), 16) else { break };
        if size == 0 || after.len() < size {
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].trim_start_matches("\r\n");
    }
    out
}
