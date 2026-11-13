use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

const APP_NAME: &str = "Vexa";
const STATE_VERSION: &str = "1";

struct Service {
    name: &'static str,
    url: &'static str,
}

const SERVICES: &[Service] = &[
    Service {
        name: "Terminal UI",
        url: "http://127.0.0.1:13000/",
    },
    Service {
        name: "Gateway",
        url: "http://127.0.0.1:18056/health",
    },
    Service {
        name: "Meeting API",
        url: "http://127.0.0.1:18080/health",
    },
    Service {
        name: "Agent API",
        url: "http://127.0.0.1:18100/health",
    },
    Service {
        name: "Flows API",
        url: "http://127.0.0.1:18200/health",
    },
    Service {
        name: "MCP",
        url: "http://127.0.0.1:18010/health",
    },
    Service {
        name: "Runtime",
        url: "http://127.0.0.1:18090/health",
    },
    Service {
        name: "Admin API",
        url: "http://127.0.0.1:18057/health",
    },
];

fn usage() {
    println!(
        "Vexa local bootstrap\n\nUSAGE:\n  vexa-bootstrap init [--data-dir PATH]\n  vexa-bootstrap status\n\nCOMMANDS:\n  init     Create private local folders. It does not start or change services.\n  status   Check the current local Vexa HTTP services.\n\nENVIRONMENT:\n  VEXA_DESKTOP_HOME  Override the local Application Support folder."
    );
}

fn default_data_dir() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("VEXA_DESKTOP_HOME") {
        return Ok(PathBuf::from(path));
    }

    let home = env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join(APP_NAME))
}

fn create_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    Ok(())
}

fn init(data_dir: PathBuf) -> Result<(), String> {
    for name in ["config", "state", "logs", "runtime", "recordings"] {
        create_dir(&data_dir.join(name))?;
    }

    let state_file = data_dir.join("state").join("bootstrap-state.toml");
    if !state_file.exists() {
        fs::write(
            &state_file,
            format!("state_version = \"{STATE_VERSION}\"\nmanaged_by = \"vexa-bootstrap\"\n"),
        )
        .map_err(|error| format!("cannot write {}: {error}", state_file.display()))?;
    }

    println!("Local Vexa folder is ready: {}", data_dir.display());
    println!("No service was started or changed.");
    Ok(())
}

fn parse_http_url(url: &str) -> Result<(&str, u16, &str), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http URLs are supported: {url}"))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("missing port: {url}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid port: {url}"))?;
    Ok((
        host,
        port,
        if path.is_empty() {
            "/"
        } else {
            &url[url.len() - path.len() - 1..]
        },
    ))
}

fn health(url: &str) -> Result<u16, String> {
    let (host, port, path) = parse_http_url(url)?;
    let address = format!("{host}:{port}");
    let socket = address
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve {address}: {error}"))?
        .next()
        .ok_or_else(|| format!("cannot resolve {address}"))?;
    let timeout = Duration::from_secs(2);
    let mut stream = TcpStream::connect_timeout(&socket, timeout)
        .map_err(|error| format!("cannot connect to {address}: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    response
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("invalid HTTP response from {url}"))?
        .parse::<u16>()
        .map_err(|_| format!("invalid HTTP status from {url}"))
}

fn status() -> Result<(), String> {
    let mut failed = false;
    println!("Vexa local service status");
    for service in SERVICES {
        match health(service.url) {
            Ok(200) => println!("OK      {}", service.name),
            Ok(code) => {
                println!("NOT READY  {} (HTTP {code})", service.name);
                failed = true;
            }
            Err(error) => {
                println!("NOT READY  {} ({error})", service.name);
                failed = true;
            }
        }
    }
    if failed {
        Err("one or more required Vexa services are not ready".to_string())
    } else {
        Ok(())
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let command = args.next();
    let result = match command.as_deref() {
        Some("init") => {
            let mut data_dir = match default_data_dir() {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    std::process::exit(2);
                }
            };
            match (args.next().as_deref(), args.next()) {
                (None, None) => {}
                (Some("--data-dir"), Some(path)) => data_dir = PathBuf::from(path),
                _ => {
                    usage();
                    std::process::exit(2);
                }
            }
            init(data_dir)
        }
        Some("status") if args.next().is_none() => status(),
        Some("help") | Some("--help") | Some("-h") | None => {
            usage();
            Ok(())
        }
        _ => {
            usage();
            Err("unknown command".to_string())
        }
    };

    if let Err(error) = result {
        eprintln!("ERROR: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_http_url;

    #[test]
    fn parses_local_health_url() {
        assert_eq!(
            parse_http_url("http://127.0.0.1:18056/health").unwrap(),
            ("127.0.0.1", 18056, "/health")
        );
    }

    #[test]
    fn rejects_https_until_tls_is_added() {
        assert!(parse_http_url("https://localhost:443/health").is_err());
    }
}
