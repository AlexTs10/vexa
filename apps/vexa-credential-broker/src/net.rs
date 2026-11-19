//! An HTTP/1.1 client for the broker's upstreams: Google's fixed https hosts,
//! a person's custom service (dialled at a checked, pinned address), and an
//! OpenBao server. One request per connection; no redirect is ever followed.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::util;

/// Why a request got no usable answer.
#[derive(Debug, Clone, PartialEq)]
pub enum NetError {
    /// The name did not resolve to any address.
    NoName,
    /// The resolver failed.
    Resolve,
    /// No connection opened (TCP or TLS handshake): nothing reached the server.
    Connect,
    /// The deadline passed after the connection opened.
    Timeout,
    /// The connection failed after it opened.
    Io,
    /// The server answered with something that is not HTTP.
    Protocol,
    /// The URL cannot be requested.
    Url,
}

impl NetError {
    /// httpx's split: no answer at all (timeout, network) versus an unusable one.
    pub fn no_answer(&self) -> bool {
        matches!(self, NetError::NoName | NetError::Resolve | NetError::Connect | NetError::Timeout | NetError::Io)
    }
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
    /// The body was longer than the limit; body holds limit + 1 bytes.
    pub over_limit: bool,
}

impl Answer {
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Dial this address instead of resolving the host (Host and SNI stay the host).
    pub pin: Option<IpAddr>,
    pub connect_timeout: Duration,
    pub deadline: Duration,
    /// Read at most limit + 1 body bytes.
    pub limit: usize,
}

impl<'a> Request<'a> {
    pub fn new(method: &'a str, url: &'a str, timeout: Duration) -> Self {
        Self { method, url, headers: Vec::new(), body: Vec::new(), pin: None, connect_timeout: timeout, deadline: timeout, limit: 64 * 1024 * 1024 }
    }
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
    pub fn json(mut self, value: &serde_json::Value) -> Self {
        self.body = serde_json::to_vec(value).unwrap_or_default();
        self.header("Content-Type", "application/json")
    }
    pub fn form(mut self, pairs: &[(&str, String)]) -> Self {
        self.body = util::urlencode(pairs).into_bytes();
        self.header("Content-Type", "application/x-www-form-urlencoded")
    }
}

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

/// Every address host resolves to, in resolver order without repeats.
pub fn resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, NetError> {
    let addrs = (host, port).to_socket_addrs().map_err(|e| {
        let text = e.to_string().to_lowercase();
        if text.contains("nodename nor servname") || text.contains("not known") || text.contains("no address") {
            NetError::NoName
        } else {
            NetError::Resolve
        }
    })?;
    let mut out: Vec<IpAddr> = Vec::new();
    for a in addrs {
        if !out.contains(&a.ip()) {
            out.push(a.ip());
        }
    }
    if out.is_empty() {
        return Err(NetError::NoName);
    }
    Ok(out)
}

pub fn send(req: &Request) -> Result<Answer, NetError> {
    let start = Instant::now();
    let split = util::urlsplit(req.url).map_err(|_| NetError::Url)?;
    let tls = match split.scheme.as_str() {
        "https" => true,
        "http" => false,
        _ => return Err(NetError::Url),
    };
    let host = split.hostname().ok_or(NetError::Url)?;
    let port = split.port().map_err(|_| NetError::Url)?.unwrap_or(if tls { 443 } else { 80 });
    let ips = match req.pin {
        Some(ip) => vec![ip],
        None => resolve(&host, port)?,
    };
    let tcp = TcpStream::connect_timeout(&SocketAddr::new(ips[0], port), req.connect_timeout).map_err(|_| NetError::Connect)?;
    let left = |start: Instant| req.deadline.checked_sub(start.elapsed()).filter(|d| !d.is_zero());
    let set = |tcp: &TcpStream, start: Instant| -> Result<(), NetError> {
        let t = left(start).ok_or(NetError::Timeout)?;
        tcp.set_read_timeout(Some(t)).map_err(|_| NetError::Io)?;
        tcp.set_write_timeout(Some(t)).map_err(|_| NetError::Io)?;
        Ok(())
    };
    tcp.set_read_timeout(Some(req.connect_timeout)).ok();
    tcp.set_write_timeout(Some(req.connect_timeout)).ok();
    let probe = tcp.try_clone().map_err(|_| NetError::Connect)?;
    let mut stream: Box<dyn Stream> = if tls {
        let connector = native_tls::TlsConnector::new().map_err(|_| NetError::Connect)?;
        Box::new(connector.connect(&host, tcp).map_err(|_| NetError::Connect)?)
    } else {
        Box::new(tcp)
    };
    set(&probe, start)?;
    let mut target = if split.path.is_empty() { "/".to_owned() } else { split.path.clone() };
    if !split.query.is_empty() {
        target.push('?');
        target.push_str(&split.query);
    }
    let default_port = if tls { 443 } else { 80 };
    let host_header = match split.port() {
        Ok(Some(p)) if p != default_port => format!("{}:{p}", bracket(&host)),
        _ => bracket(&host),
    };
    let mut head = format!("{} {target} HTTP/1.1\r\nHost: {host_header}\r\nAccept-Encoding: identity\r\nConnection: close\r\n", req.method);
    let has = |n: &str| req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    if !has("user-agent") {
        head.push_str("User-Agent: vexa-credential-broker\r\n");
    }
    if !has("accept") {
        head.push_str("Accept: */*\r\n");
    }
    for (name, value) in &req.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if !req.body.is_empty() || matches!(req.method, "POST" | "PUT" | "PATCH") {
        head.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    head.push_str("\r\n");
    let io = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => NetError::Timeout,
        _ => NetError::Io,
    };
    stream.write_all(head.as_bytes()).map_err(io)?;
    stream.write_all(&req.body).map_err(io)?;
    stream.flush().map_err(io)?;
    set(&probe, start)?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(io)?;
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(NetError::Protocol);
    }
    let status: u16 = parts.next().and_then(|s| s.trim().parse().ok()).ok_or(NetError::Protocol)?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(io)? == 0 {
            return Err(NetError::Protocol);
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let (name, value) = trimmed.split_once(':').ok_or(NetError::Protocol)?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let get = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    let cap = req.limit.saturating_add(1);
    let mut body = Vec::new();
    let no_body = req.method == "HEAD" || status == 204 || status == 304 || (100..200).contains(&status);
    if no_body {
    } else if get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        loop {
            set(&probe, start)?;
            line.clear();
            reader.read_line(&mut line).map_err(io)?;
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16).map_err(|_| NetError::Protocol)?;
            if size == 0 {
                break;
            }
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk).map_err(|e| if e.kind() == std::io::ErrorKind::UnexpectedEof { NetError::Protocol } else { io(e) })?;
            body.extend_from_slice(&chunk);
            line.clear();
            reader.read_line(&mut line).map_err(io)?;
            if body.len() >= cap {
                break;
            }
        }
    } else if let Some(length) = get("content-length") {
        let length: usize = length.parse().map_err(|_| NetError::Protocol)?;
        let want = length.min(cap);
        body = vec![0; want];
        let mut read = 0;
        while read < want {
            set(&probe, start)?;
            let n = reader.read(&mut body[read..]).map_err(io)?;
            if n == 0 {
                return Err(NetError::Protocol);
            }
            read += n;
        }
    } else {
        let mut buf = [0u8; 65536];
        loop {
            set(&probe, start)?;
            let n = reader.read(&mut buf).map_err(io)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
            if body.len() >= cap {
                break;
            }
        }
    }
    let over_limit = body.len() > req.limit;
    body.truncate(cap);
    Ok(Answer { status, body, over_limit })
}

fn bracket(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn serve(answer: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            s.write_all(answer).unwrap();
        });
        port
    }

    #[test]
    fn reads_length_chunked_and_close_delimited_bodies() {
        let p = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let url = format!("http://127.0.0.1:{p}/x?a=1");
        let a = send(&Request::new("GET", &url, Duration::from_secs(2))).unwrap();
        assert_eq!((a.status, a.body.as_slice()), (200, b"ok".as_slice()));
        let p = serve(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n");
        let url = format!("http://127.0.0.1:{p}/");
        assert_eq!(send(&Request::new("POST", &url, Duration::from_secs(2))).unwrap().json().unwrap(), serde_json::json!({}));
        let p = serve(b"HTTP/1.1 200 OK\r\n\r\n0123456789");
        let url = format!("http://127.0.0.1:{p}/");
        let mut r = Request::new("GET", &url, Duration::from_secs(2));
        r.limit = 4;
        let a = send(&r).unwrap();
        assert!(a.over_limit && a.body.len() == 5);
        let p = serve(b"garbage\r\n\r\n");
        let url = format!("http://127.0.0.1:{p}/");
        assert_eq!(send(&Request::new("GET", &url, Duration::from_secs(2))).unwrap_err(), NetError::Protocol);
    }

    #[test]
    fn a_closed_port_is_a_connect_failure() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/");
        assert_eq!(send(&Request::new("GET", &url, Duration::from_secs(1))).unwrap_err(), NetError::Connect);
    }
}
