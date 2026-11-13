mod config;
mod stack;
mod supervisor;

use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use supervisor::SharedStatus;

static STATUS: OnceLock<SharedStatus> = OnceLock::new();

fn shared_status() -> SharedStatus {
    STATUS.get_or_init(SharedStatus::default).clone()
}

const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:13001/";
const DEFAULT_TERMINAL_URL: &str = "http://127.0.0.1:13000/";
const SHELL_HTML: &str = include_str!("../../vexa-mac/static/index.html");
const SHELL_CSS: &str = include_str!("../../vexa-mac/static/app.css");

struct Service {
    name: &'static str,
    port: u16,
}

const SERVICES: [Service; 6] = [
    Service {
        name: "terminal",
        port: 13000,
    },
    Service {
        name: "gateway",
        port: 18056,
    },
    Service {
        name: "agent-api",
        port: 18100,
    },
    Service {
        name: "meeting-api",
        port: 18080,
    },
    Service {
        name: "runtime",
        port: 18090,
    },
    Service {
        name: "mcp",
        port: 18010,
    },
];

fn app_support_dir() -> PathBuf {
    if let Ok(path) = env::var("VEXA_APP_SUPPORT_DIR") {
        return PathBuf::from(path);
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Vexa")
}

fn daemon_url() -> String {
    env::var("VEXA_DAEMON_URL").unwrap_or_else(|_| DEFAULT_DAEMON_URL.to_owned())
}

fn terminal_url() -> String {
    env::var("VEXA_TERMINAL_URL").unwrap_or_else(|_| DEFAULT_TERMINAL_URL.to_owned())
}

fn socket_address(url: &str) -> Option<SocketAddr> {
    let without_scheme = url.split_once("://")?.1;
    let authority = without_scheme.split('/').next()?;
    let host_port = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    host_port.to_socket_addrs().ok()?.next()
}

fn is_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(350),
    )
    .is_ok()
}

fn status_json() -> String {
    let services = SERVICES
        .iter()
        .map(|service| {
            format!(
                r#"{{"name":"{}","port":{},"ready":{}}}"#,
                service.name,
                service.port,
                is_open(service.port)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let processes = shared_status()
        .lock()
        .expect("status lock")
        .iter()
        .map(|entry| {
            format!(
                r#"{{"name":"{}","state":"{}","pid":{},"restarts":{}}}"#,
                entry.name,
                entry.state,
                entry.pid.map_or("null".to_owned(), |pid| pid.to_string()),
                entry.restarts
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"app_support":"{}","services":[{}],"processes":[{}]}}"#,
        app_support_dir().display(),
        services,
        processes
    )
}

fn init() -> Result<(), String> {
    let path = app_support_dir();
    stack::Layout::new(path.clone()).create()?;
    println!("Vexa local folders are ready at {}", path.display());
    Ok(())
}

fn store_path() -> PathBuf {
    app_support_dir().join("data").join("vexa.sqlite3")
}

fn init_store() -> Result<(), String> {
    init()?;
    let schema = r#"
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS local_settings (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS migration_state (name TEXT PRIMARY KEY NOT NULL, version INTEGER NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        INSERT INTO migration_state (name, version) VALUES ('local-store', 1)
          ON CONFLICT(name) DO UPDATE SET version = excluded.version, updated_at = CURRENT_TIMESTAMP;
    "#;
    let output = Command::new("/usr/bin/sqlite3")
        .arg(store_path())
        .arg(schema)
        .output()
        .map_err(|error| format!("could not run the macOS SQLite tool: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    println!(
        "Vexa local SQLite store is ready at {}",
        store_path().display()
    );
    Ok(())
}

fn http_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(body);
    response
}

fn response_for_path(path: &str) -> Vec<u8> {
    match path {
        "/" => {
            let html = SHELL_HTML.replace("__VEXA_TERMINAL_URL__", &terminal_url());
            http_response("200 OK", "text/html; charset=utf-8", html.as_bytes())
        }
        "/app.css" => http_response("200 OK", "text/css; charset=utf-8", SHELL_CSS.as_bytes()),
        "/health" => http_response(
            "200 OK",
            "application/json; charset=utf-8",
            br#"{"status":"ok","service":"vexa-daemon"}"#,
        ),
        "/status" => {
            let body = status_json();
            http_response("200 OK", "application/json; charset=utf-8", body.as_bytes())
        }
        _ => http_response(
            "404 Not Found",
            "application/json; charset=utf-8",
            br#"{"error":"not found"}"#,
        ),
    }
}

fn handle_request(mut stream: TcpStream) -> Result<(), String> {
    let mut request = [0_u8; 2048];
    let length = stream
        .read(&mut request)
        .map_err(|error| error.to_string())?;
    let request =
        std::str::from_utf8(&request[..length]).map_err(|_| "request is not UTF-8".to_owned())?;
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let response = response_for_path(path);
    stream
        .write_all(&response)
        .map_err(|error| error.to_string())
}

fn serve_http(listener: TcpListener) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_request(stream) {
                    eprintln!("vexa-daemon: request failed: {error}");
                }
            }
            Err(error) => eprintln!("vexa-daemon: connection failed: {error}"),
        }
    }
}

/// The groups of the native stack, in start order. `VEXA_NATIVE_GROUPS`
/// selects a subset (comma-separated); `none` runs only the shell.
fn native_groups() -> Vec<String> {
    let value = env::var("VEXA_NATIVE_GROUPS").unwrap_or_else(|_| "infra".to_owned());
    value
        .split(',')
        .map(|group| group.trim().to_owned())
        .filter(|group| !group.is_empty() && group != "none")
        .collect()
}

fn serve() -> Result<(), String> {
    init_store()?;
    supervisor::install_signal_handlers();
    let url = daemon_url();
    let address = socket_address(&url).ok_or_else(|| format!("invalid VEXA_DAEMON_URL: {url}"))?;
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("cannot start Vexa daemon at {url}: {error}"))?;
    println!("Vexa daemon is listening on {url}");
    std::thread::spawn(move || serve_http(listener));

    let groups = native_groups();
    let layout = stack::Layout::new(app_support_dir());
    layout.create()?;
    let mut supervisor = supervisor::Supervisor::new(layout.logs(), shared_status());
    let result = (|| -> Result<(), String> {
        if groups.is_empty() {
            return Ok(());
        }
        let stack = stack::Stack {
            env: config::load_or_create(&layout.config())?,
            tools: stack::Tools::discover()?,
            source: stack::source_dir()?,
            layout: layout.clone(),
        };
        for group in &groups {
            match group.as_str() {
                "infra" => stack.start_infra(&mut supervisor)?,
                other => return Err(format!("unknown native group `{other}`")),
            }
        }
        println!("vexa-daemon: native stack is ready ({})", groups.join(", "));
        Ok(())
    })();
    match result {
        Ok(()) => supervisor.watch(),
        Err(error) if supervisor::stop_requested() => eprintln!("vexa-daemon: {error}"),
        Err(error) => {
            eprintln!("vexa-daemon: {error}");
            supervisor.shutdown();
            return Err("the native stack did not start".to_owned());
        }
    }
    supervisor.shutdown();
    println!("vexa-daemon: stopped");
    Ok(())
}

fn usage() {
    eprintln!("Usage: vexa-daemon <init|store-init|status|serve>");
}

fn main() {
    let result = match env::args().nth(1).as_deref() {
        Some("init") => init(),
        Some("store-init") => init_store(),
        Some("status") => {
            println!("{}", status_json());
            Ok(())
        }
        Some("serve") => serve(),
        _ => {
            usage();
            Err("missing or invalid command".to_string())
        }
    };
    if let Err(error) = result {
        eprintln!("vexa-daemon: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{http_response, response_for_path, socket_address, SHELL_CSS, SHELL_HTML};

    #[test]
    fn parses_local_daemon_address() {
        assert_eq!(
            socket_address("http://127.0.0.1:13001/"),
            Some("127.0.0.1:13001".parse().unwrap())
        );
    }

    #[test]
    fn preserves_the_moved_shell_assets() {
        assert!(SHELL_HTML.contains("Vexa Mac"));
        assert!(SHELL_HTML.contains("/status"));
        assert!(SHELL_CSS.contains("--surface"));
    }

    #[test]
    fn produces_http_responses() {
        let response = String::from_utf8(http_response("200 OK", "text/plain", b"ok")).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("ok"));
    }

    #[test]
    fn keeps_the_shell_group_routes() {
        let root = String::from_utf8(response_for_path("/")).unwrap();
        let health = String::from_utf8(response_for_path("/health")).unwrap();
        let status = String::from_utf8(response_for_path("/status")).unwrap();
        let stylesheet = String::from_utf8(response_for_path("/app.css")).unwrap();

        assert!(root.contains("HTTP/1.1 200 OK"));
        assert!(root.contains("Open current Vexa"));
        assert!(health.contains(r#""service":"vexa-daemon""#));
        assert!(status.contains(r#""name":"terminal""#));
        assert!(status.contains(r#""name":"gateway""#));
        assert!(stylesheet.contains("text/css"));
    }
}
