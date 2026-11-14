//! vexa-stt: the Vexa transcription service as a native macOS process.
//!
//! It serves the contract of `core/meetings/services/transcription` (an
//! OpenAI-compatible `POST /v1/audio/transcriptions` plus `GET /health`) and
//! runs whisper.cpp with Metal through a `whisper-server` child process that
//! is loaded on demand. Callers keep `TRANSCRIPTION_SERVICE_URL` and
//! `TRANSCRIPTION_SERVICE_TOKEN` unchanged.

mod convert;
mod engine;
mod multipart;

use std::env;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use engine::{Config, Engine, EngineError};
use vexa_native_kit::{http, json};
use http::{Request, Response};
use json::{object, Value};

struct Service {
    engine: Arc<Engine>,
    token: String,
    max_active: usize,
    active: AtomicUsize,
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_owned())
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = format!("{}:/opt/homebrew/bin:/usr/local/bin", env::var("PATH").unwrap_or_default());
    path.split(':').map(|dir| PathBuf::from(dir).join(name)).find(|p| p.is_file())
}

/// UTC time as `YYYY-MM-DDTHH:MM:SS.ffffff` (the Python service's isoformat).
fn utc_iso(now: SystemTime) -> String {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:06}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_micros()
    )
}

impl Service {
    fn authorized(&self, request: &Request) -> bool {
        if self.token.is_empty() {
            return true;
        }
        if request.header("x-api-key") == Some(self.token.as_str()) {
            return true;
        }
        request
            .header("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| t.trim() == self.token)
    }

    fn health(&self) -> Response {
        let ready = self.engine.model_present();
        let body = object(vec![
            ("status", Value::String(if ready { "healthy" } else { "unhealthy" }.into())),
            ("worker_id", Value::String("vexa-stt".into())),
            ("timestamp", Value::String(utc_iso(SystemTime::now()))),
            ("model", Value::String(self.engine.config.model.clone())),
            ("device", Value::String("metal".into())),
            ("gpu_available", Value::Bool(true)),
            ("loaded", Value::Bool(self.engine.loaded())),
        ]);
        Response::json(if ready { 200 } else { 503 }, json::write(&body))
    }

    fn root(&self) -> Response {
        let body = object(vec![
            ("service", Value::String("Vexa Transcription Service".into())),
            ("worker_id", Value::String("vexa-stt".into())),
            ("model", Value::String(self.engine.config.model.clone())),
            ("device", Value::String("metal".into())),
            ("status", Value::String(if self.engine.model_present() { "ready" } else { "initializing" }.into())),
            (
                "endpoints",
                object(vec![
                    ("transcribe", Value::String("/v1/audio/transcriptions".into())),
                    ("health", Value::String("/health".into())),
                ]),
            ),
        ]);
        Response::json(200, json::write(&body))
    }

    fn transcribe(&self, request: &Request) -> Response {
        if !self.authorized(request) {
            return Response::detail(401, "Invalid or missing API token");
        }
        let Some(boundary) = request.header("content-type").and_then(multipart::boundary) else {
            return Response::detail(400, "Expected multipart/form-data");
        };
        let parts = match multipart::parse(&request.body, &boundary) {
            Ok(parts) => parts,
            Err(error) => return Response::detail(400, &error),
        };
        let field = |name: &str| {
            parts
                .iter()
                .find(|p| p.name == name && p.filename.is_none())
                .map(|p| String::from_utf8_lossy(&p.data).trim().to_owned())
        };
        let Some(file) = parts.iter().find(|p| p.name == "file") else {
            return Response::missing_field("file");
        };
        match field("model") {
            None => return Response::missing_field("model"),
            Some(model) if model.is_empty() => return Response::detail(400, "Model parameter is required"),
            Some(_) => {}
        }
        let temperature: f64 = field("temperature").and_then(|t| t.parse().ok()).unwrap_or(0.0);
        let language = field("language").filter(|l| !l.is_empty());
        let want_words = field("timestamp_granularities").unwrap_or_default().contains("word")
            || parts.iter().any(|p| p.name == "timestamp_granularities[]" && p.data == b"word");

        // Fail fast when busy, as the Python service does (FAIL_FAST_WHEN_BUSY).
        if self.active.fetch_add(1, Ordering::SeqCst) >= self.max_active {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return Response::detail(503, "Service busy. Please retry later.").with_header("Retry-After", "1");
        }
        let mut fields = vec![
            ("response_format", "verbose_json".to_owned()),
            ("temperature", format!("{temperature}")),
            ("temperature_inc", "0".to_owned()),
            ("language", language.clone().unwrap_or_else(|| "auto".to_owned())),
        ];
        if let Some(prompt) = field("prompt").filter(|p| !p.is_empty()) {
            fields.push(("prompt", prompt));
        }
        if field("task").as_deref() == Some("translate") {
            fields.push(("translate", "true".to_owned()));
        }
        let result = self.engine.transcribe(&fields, file);
        self.active.fetch_sub(1, Ordering::SeqCst);
        match result {
            Ok(whisper) => {
                let out = convert::convert(
                    &whisper,
                    &convert::Request { language: language.as_deref(), temperature, want_words },
                );
                Response::json(200, json::write(&out))
            }
            Err(EngineError::NotReady(message)) => Response::detail(503, &message).with_header("Retry-After", "5"),
            Err(EngineError::BadRequest(message)) => Response::detail(400, &message),
            Err(EngineError::Timeout) => {
                // A hung engine holds the GPU; restart it on the next request.
                self.engine.stop();
                Response::detail(504, "Transcription timed out")
            }
            Err(EngineError::Failed(message)) => {
                eprintln!("vexa-stt: {message}");
                Response::detail(500, &message)
            }
        }
    }

    fn handle(&self, request: &Request) -> Response {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/health") => self.health(),
            ("GET", "/") => self.root(),
            ("POST", "/v1/audio/transcriptions") => self.transcribe(request),
            (_, "/health" | "/" | "/v1/audio/transcriptions") => Response::detail(405, "Method Not Allowed"),
            _ => Response::detail(404, "Not Found"),
        }
    }
}

fn main() {
    let port: u16 = env_or("VEXA_STT_PORT", "23083").parse().expect("VEXA_STT_PORT is not a port");
    let home = env::var("HOME").unwrap_or_default();
    let default_models = format!("{home}/Library/Application Support/Vexa/data/models");
    let Some(whisper_server) = env::var("VEXA_WHISPER_SERVER").ok().map(PathBuf::from).or_else(|| find_on_path("whisper-server")) else {
        eprintln!("vexa-stt: cannot find whisper-server; run `brew install whisper-cpp` or set VEXA_WHISPER_SERVER");
        std::process::exit(1);
    };
    let config = Config {
        whisper_server,
        model_dir: PathBuf::from(env_or("VEXA_STT_MODEL_DIR", &default_models)),
        model: env_or("VEXA_STT_MODEL", "small-q8_0"),
        engine_port: env_or("VEXA_STT_ENGINE_PORT", &(port + 1).to_string()).parse().expect("engine port"),
        threads: env_or("VEXA_STT_THREADS", "4").parse().unwrap_or(4),
        idle: Duration::from_secs(env_or("VEXA_STT_IDLE_SEC", "300").parse().unwrap_or(300)),
        timeout: Duration::from_secs(env_or("TRANSCRIPTION_TIMEOUT_S", "120").parse().unwrap_or(120)),
        log_file: env::var("VEXA_STT_ENGINE_LOG").ok().map(PathBuf::from),
    };
    let service = Arc::new(Service {
        engine: Arc::new(Engine::new(config)),
        token: env::var("TRANSCRIPTION_SERVICE_TOKEN").or_else(|_| env::var("API_TOKEN")).unwrap_or_default(),
        max_active: env_or("MAX_ACTIVE_REQUESTS", "2").parse().unwrap_or(2),
        active: AtomicUsize::new(0),
    });
    if service.token.is_empty() {
        eprintln!("vexa-stt: no TRANSCRIPTION_SERVICE_TOKEN; every request is allowed");
    }
    service.engine.fetch_models();

    let reaper = service.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        reaper.engine.unload_if_idle(reaper.active.load(Ordering::SeqCst) > 0);
    });
    // Stop the engine child with this process.
    let stopper = service.clone();
    std::thread::spawn(move || {
        wait_for_stop_signal();
        stopper.engine.stop();
        std::process::exit(0);
    });

    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| {
        eprintln!("vexa-stt: cannot listen on 127.0.0.1:{port}: {e}");
        std::process::exit(1);
    });
    eprintln!("vexa-stt: listening on http://127.0.0.1:{port} (model {})", service.engine.config.model);
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let service = service.clone();
        std::thread::spawn(move || {
            let response = match http::read_request(&stream) {
                Ok(request) => service.handle(&request),
                Err(error) if error.contains("too large") => Response::detail(413, &error),
                Err(error) => Response::detail(400, &error),
            };
            let _ = response.write(&mut stream);
        });
    }
}

/// Block until SIGINT or SIGTERM arrives.
fn wait_for_stop_signal() {
    use std::sync::atomic::AtomicBool;
    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn on_signal(_: i32) {
        STOP.store(true, Ordering::SeqCst);
    }
    extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }
    // SIGINT = 2, SIGTERM = 15 on macOS.
    unsafe {
        signal(2, on_signal);
        signal(15, on_signal);
    }
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_time_like_python_isoformat() {
        let t = UNIX_EPOCH + Duration::from_micros(1_794_595_011_421_712);
        assert_eq!(utc_iso(t), "2026-11-13T18:36:51.421712");
    }
}
