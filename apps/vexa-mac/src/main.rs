use std::{
    env,
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::PathBuf,
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:13001/";
const DEFAULT_TERMINAL_URL: &str = "http://127.0.0.1:23000/";

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
    match env::args()
        .nth(1)
        .unwrap_or_else(|| "open".to_owned())
        .as_str()
    {
        "open" => open_shell(),
        "start" => ensure_daemon(),
        "daemon" | "serve" => run_daemon_foreground(),
        "status" => show_status(),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        unknown => Err(format!("unknown command `{unknown}`; run `vexa-mac help`")),
    }
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

fn daemon_is_ready() -> bool {
    let Some(address) = socket_address(&daemon_url()) else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(350)) else {
        return false;
    };
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).is_ok()
        && response.contains("200 OK")
        && response.contains("vexa-daemon")
}

fn daemon_binary() -> Result<PathBuf, String> {
    if let Ok(path) = env::var("VEXA_DAEMON_BIN") {
        return Ok(PathBuf::from(path));
    }
    let executable =
        env::current_exe().map_err(|error| format!("cannot find Vexa app path: {error}"))?;
    let parent = executable
        .parent()
        .ok_or_else(|| "cannot find the Vexa app folder".to_owned())?;
    let mut candidates = vec![parent.join("vexa-daemon")];
    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join("apps/vexa-daemon/target/debug/vexa-daemon"));
        candidates.push(cwd.join("apps/vexa-daemon/target/release/vexa-daemon"));
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| "cannot find vexa-daemon; build it first or set VEXA_DAEMON_BIN".to_owned())
}

fn ensure_daemon() -> Result<(), String> {
    if daemon_is_ready() {
        println!("Vexa daemon is ready at {}", daemon_url());
        return Ok(());
    }
    let binary = daemon_binary()?;
    Command::new(binary)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start Vexa daemon: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if daemon_is_ready() {
            println!("Vexa daemon started at {}", daemon_url());
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("Vexa daemon did not become ready; run `vexa-mac daemon` to see its error".to_owned())
}

fn run_daemon_foreground() -> Result<(), String> {
    let status = Command::new(daemon_binary()?)
        .arg("serve")
        .status()
        .map_err(|error| format!("cannot run Vexa daemon: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "Vexa daemon stopped with an error".to_owned())
}

fn open_shell() -> Result<(), String> {
    ensure_daemon()?;
    let terminal = terminal_url();
    if !is_reachable(&terminal) {
        return Err(format!("Vexa terminal is not running at {terminal}. Start the local stack, then run `vexa-mac open`."));
    }
    Command::new("open")
        .arg(daemon_url())
        .status()
        .map_err(|error| format!("cannot open Vexa: {error}"))?
        .success()
        .then_some(())
        .ok_or_else(|| "macOS could not open the Vexa app".to_owned())
}

fn show_status() -> Result<(), String> {
    if !daemon_is_ready() {
        return Err(format!(
            "Vexa daemon is not running at {}; run `vexa-mac start`",
            daemon_url()
        ));
    }
    println!("daemon: ready ({})", daemon_url());
    println!(
        "terminal: {} ({})",
        if is_reachable(&terminal_url()) {
            "ready"
        } else {
            "not running"
        },
        terminal_url()
    );
    Ok(())
}

fn is_reachable(url: &str) -> bool {
    socket_address(url)
        .is_some_and(|address| TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok())
}

fn print_help() {
    println!("vexa-mac\n\nUSAGE:\n  vexa-mac [open|start|status|daemon|help]\n\nCOMMANDS:\n  open    Start the native daemon and open the local Mac shell.\n  start   Start the native daemon without opening a browser.\n  status  Show daemon and terminal readiness.\n  daemon  Run the native daemon in the foreground.\n  serve   Alias for daemon.\n  help    Show this help.\n\nENVIRONMENT:\n  VEXA_DAEMON_BIN  Path to vexa-daemon during development.\n  VEXA_DAEMON_URL  Default: {DEFAULT_DAEMON_URL}\n  VEXA_TERMINAL_URL Default: {DEFAULT_TERMINAL_URL}");
}

#[cfg(test)]
mod tests {
    use super::socket_address;
    #[test]
    fn parses_local_daemon_address() {
        assert_eq!(
            socket_address("http://127.0.0.1:13001/"),
            Some("127.0.0.1:13001".parse().unwrap())
        );
    }
    #[test]
    fn rejects_a_url_without_a_scheme() {
        assert_eq!(socket_address("127.0.0.1:13001"), None);
    }
}
