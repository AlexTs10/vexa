use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

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

fn is_open(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_millis(350)).is_ok()
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
        CREATE TABLE IF NOT EXISTS local_settings (
          key TEXT PRIMARY KEY NOT NULL,
          value TEXT NOT NULL,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS migration_state (
          name TEXT PRIMARY KEY NOT NULL,
          version INTEGER NOT NULL,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO migration_state (name, version)
          VALUES ('local-store', 1)
          ON CONFLICT(name) DO UPDATE SET version = excluded.version,
            updated_at = CURRENT_TIMESTAMP;
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

fn print_status() {
    println!("{}", status_json());
}

fn serve() -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:13001").map_err(|error| error.to_string())?;
    println!("Vexa daemon is listening on http://127.0.0.1:13001");
    for stream in listener.incoming() {
        let mut stream = stream.map_err(|error| error.to_string())?;
        let mut request = [0_u8; 1024];
        let length = stream.read(&mut request).unwrap_or(0);
        let route = std::str::from_utf8(&request[..length]).unwrap_or("");
        let (status, body) = if route.starts_with("GET /health ") {
            (
                "200 OK",
                r#"{"status":"ok","service":"vexa-daemon"}"#.to_string(),
            )
        } else if route.starts_with("GET /status ") {
            ("200 OK", status_json())
        } else {
            ("404 Not Found", r#"{"error":"not found"}"#.to_string())
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
    }
    Ok(())
}

fn usage() {
    eprintln!("Usage: vexa-daemon <init|store-init|status|serve>");
}

fn main() {
    let command = env::args().nth(1);
    let result = match command.as_deref() {
        Some("init") => init(),
        Some("store-init") => init_store(),
        Some("status") => {
            print_status();
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
