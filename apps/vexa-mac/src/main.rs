use std::{
    env,
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    process::{Command, ExitCode},
    time::Duration,
};

const DEFAULT_TERMINAL_URL: &str = "http://127.0.0.1:13000/";
const DEFAULT_GATEWAY_URL: &str = "http://127.0.0.1:18056/health";
const DEFAULT_SHELL_URL: &str = "http://127.0.0.1:13001/";
const SHELL_HTML: &str = include_str!("../static/index.html");
const SHELL_CSS: &str = include_str!("../static/app.css");

struct Service {
    name: &'static str,
    url: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vexa-mac: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let command = env::args().nth(1).unwrap_or_else(|| "open".to_owned());
    match command.as_str() {
        "open" => open_terminal(),
        "serve" => serve_static_shell(),
        "status" => show_status(),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        unknown => Err(format!("unknown command `{unknown}`; run `vexa-mac help`")),
    }
}

fn services() -> [Service; 2] {
    [
        Service {
            name: "terminal",
            url: env::var("VEXA_TERMINAL_URL").unwrap_or_else(|_| DEFAULT_TERMINAL_URL.to_owned()),
        },
        Service {
            name: "gateway",
            url: env::var("VEXA_GATEWAY_URL").unwrap_or_else(|_| DEFAULT_GATEWAY_URL.to_owned()),
        },
    ]
}

fn open_terminal() -> Result<(), String> {
    let terminal = services()
        .into_iter()
        .next()
        .expect("terminal service exists");
    if !is_reachable(&terminal.url) {
        return Err(format!(
            "Vexa is not running at {}. Start the local stack first, then run `vexa-mac open`.",
            terminal.url
        ));
    }

    Command::new("open")
        .arg(&terminal.url)
        .status()
        .map_err(|error| format!("cannot open Vexa: {error}"))?
        .success()
        .then_some(())
        .ok_or_else(|| "macOS could not open the Vexa URL".to_owned())
}

fn show_status() -> Result<(), String> {
    let services = services();
    let mut all_reachable = true;
    for service in &services {
        let reachable = is_reachable(&service.url);
        let state = if reachable { "ready" } else { "not running" };
        println!("{}: {state} ({})", service.name, service.url);
        all_reachable &= reachable;
    }

    if all_reachable {
        Ok(())
    } else {
        Err("one or more local Vexa services are not running".to_owned())
    }
}

fn serve_static_shell() -> Result<(), String> {
    let shell_url = env::var("VEXA_MAC_SHELL_URL").unwrap_or_else(|_| DEFAULT_SHELL_URL.to_owned());
    let address = socket_address(&shell_url)
        .ok_or_else(|| format!("invalid VEXA_MAC_SHELL_URL: {shell_url}"))?;
    let listener = std::net::TcpListener::bind(address)
        .map_err(|error| format!("cannot start the Vexa Mac shell at {shell_url}: {error}"))?;

    println!("Vexa Mac shell: {shell_url}");
    println!("Press Control-C to stop it.");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_shell_request(stream) {
                    eprintln!("vexa-mac: shell request failed: {error}");
                }
            }
            Err(error) => eprintln!("vexa-mac: shell connection failed: {error}"),
        }
    }
    Ok(())
}

fn handle_shell_request(mut stream: TcpStream) -> Result<(), String> {
    let mut request = [0_u8; 2048];
    let count = stream
        .read(&mut request)
        .map_err(|error| format!("cannot read shell request: {error}"))?;
    let first_line = std::str::from_utf8(&request[..count])
        .map_err(|_| "shell request is not UTF-8".to_owned())?
        .lines()
        .next()
        .unwrap_or_default();
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    let response = match path {
        "/" => {
            let terminal_url = services()
                .into_iter()
                .next()
                .expect("terminal service exists")
                .url;
            let html = SHELL_HTML.replace("__VEXA_TERMINAL_URL__", &terminal_url);
            http_response("200 OK", "text/html; charset=utf-8", html.as_bytes())
        }
        "/app.css" => http_response("200 OK", "text/css; charset=utf-8", SHELL_CSS.as_bytes()),
        "/status" => {
            let body = status_json();
            http_response("200 OK", "application/json; charset=utf-8", body.as_bytes())
        }
        _ => http_response("404 Not Found", "text/plain; charset=utf-8", b"Not found\n"),
    };
    stream
        .write_all(&response)
        .map_err(|error| format!("cannot write shell response: {error}"))?;
    Ok(())
}

fn status_json() -> String {
    let entries = services()
        .iter()
        .map(|service| {
            format!(
                r#"{{"name":"{}","url":"{}","ready":{}}}"#,
                service.name,
                service.url,
                is_reachable(&service.url)
            )
        })
        .collect::<Vec<_>>();
    format!(r#"{{"services":[{}]}}"#, entries.join(","))
}

fn http_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn is_reachable(url: &str) -> bool {
    let Some(address) = socket_address(url) else {
        return false;
    };
    TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok()
}

fn socket_address(url: &str) -> Option<SocketAddr> {
    let without_scheme = url.split_once("://")?.1;
    let authority = without_scheme.split('/').next()?;
    let host_port = if authority.contains(':') {
        authority.to_owned()
    } else if url.starts_with("https://") {
        format!("{authority}:443")
    } else {
        format!("{authority}:80")
    };
    host_port.to_socket_addrs().ok()?.next()
}

fn print_help() {
    println!(
        "vexa-mac\n\nUSAGE:\n  vexa-mac [open|serve|status|help]\n\nCOMMANDS:\n  open    Open the running local Vexa terminal in the default browser.\n  serve   Serve the static local Mac shell.\n  status  Show terminal and gateway reachability.\n  help    Show this help.\n\nENVIRONMENT:\n  VEXA_TERMINAL_URL  Default: {DEFAULT_TERMINAL_URL}\n  VEXA_GATEWAY_URL   Default: {DEFAULT_GATEWAY_URL}\n  VEXA_MAC_SHELL_URL Default: {DEFAULT_SHELL_URL}"
    );
}

#[cfg(test)]
mod tests {
    use super::{http_response, socket_address, SHELL_CSS, SHELL_HTML};

    #[test]
    fn parses_local_http_address() {
        assert_eq!(
            socket_address("http://127.0.0.1:13000/"),
            Some("127.0.0.1:13000".parse().unwrap())
        );
    }

    #[test]
    fn rejects_urls_without_a_scheme() {
        assert_eq!(socket_address("127.0.0.1:13000"), None);
    }

    #[test]
    fn creates_a_status_response() {
        let response = String::from_utf8(http_response("200 OK", "text/plain", b"ok")).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("ok"));
    }

    #[test]
    fn includes_the_static_shell_assets() {
        assert!(SHELL_HTML.contains("Vexa Mac"));
        assert!(SHELL_CSS.contains("--surface"));
    }
}
