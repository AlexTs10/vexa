use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

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
    format!(
        r#"{{"app_support":"{}","services":[{}]}}"#,
        app_support_dir().display(),
        services
    )
}

fn init() -> Result<(), String> {
    let path = app_support_dir();
    for child in ["config", "data", "logs", "recordings", "state"] {
        std::fs::create_dir_all(path.join(child)).map_err(|error| error.to_string())?;
    }
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

fn serve() -> Result<(), String> {
    init_store()?;
    let url = daemon_url();
    let address = socket_address(&url).ok_or_else(|| format!("invalid VEXA_DAEMON_URL: {url}"))?;
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("cannot start Vexa daemon at {url}: {error}"))?;
    println!("Vexa daemon is listening on {url}");
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
