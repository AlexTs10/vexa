//! An HTTP/1.1 client for http:// and https:// (the platform's TLS): bodies sent whole or as a
//! stream (chunked), answers read whole or as a stream, separate connect / read / write
//! deadlines (httpx.Timeout), and the open socket handed over for a websocket upgrade. One request
//! per connection.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum NetError {
    /// The connection was not made (httpx.ConnectError).
    Connect(String),
    /// The connection was not made in time (httpx.ConnectTimeout).
    ConnectTimeout,
    /// A deadline passed after the connection was made (httpx.ReadTimeout / WriteTimeout).
    Timeout,
    /// Anything else that left no usable answer (httpx.RequestError).
    Failed(String),
}

impl NetError {
    /// The httpx exception class name the Python side would name in its error text.
    pub fn class_name(&self) -> &'static str {
        match self {
            NetError::Connect(_) => "ConnectError",
            NetError::ConnectTimeout => "ConnectTimeout",
            NetError::Timeout => "ReadTimeout",
            NetError::Failed(_) => "RemoteProtocolError",
        }
    }
    /// httpx.TimeoutException: a connect, read or write deadline passed.
    pub fn is_timeout(&self) -> bool {
        matches!(self, NetError::Timeout | NetError::ConnectTimeout)
    }
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Connect(m) | NetError::Failed(m) => f.write_str(m),
            NetError::Timeout | NetError::ConnectTimeout => f.write_str("timed out"),
        }
    }
}

fn io_error(e: io::Error) -> NetError {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => NetError::Timeout,
        _ => NetError::Failed(e.to_string()),
    }
}

/// The deadlines of one request (httpx.Timeout). None waits for ever.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub connect: Duration,
    pub read: Option<Duration>,
    pub write: Duration,
}

impl Timeouts {
    pub fn all(d: Duration) -> Self {
        Timeouts { connect: d, read: Some(d), write: d }
    }
}

pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// A parsed http(s) URL.
#[derive(Debug, Clone)]
pub struct Url {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// The authority as written (the Host header).
    pub authority: String,
    /// Path and query as written, starting with `/`.
    pub target: String,
}

pub fn parse_url(url: &str) -> Result<Url, NetError> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("wss://") {
        (true, r)
    } else {
        return Err(NetError::Failed(format!("Request URL is missing an 'http://' or 'https://' protocol: {url}")));
    };
    let cut = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..cut];
    let mut target = rest[cut..].to_owned();
    if !target.starts_with('/') {
        target.insert(0, '/');
    }
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let (h, tail) = inner.split_once(']').unwrap_or((inner, ""));
        (h.to_owned(), tail.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().ok()),
            None => (hostport.to_owned(), None),
        }
    };
    if host.is_empty() {
        return Err(NetError::Failed(format!("Invalid URL {url}")));
    }
    Ok(Url { tls, port: port.unwrap_or(if tls { 443 } else { 80 }), host, authority: authority.to_owned(), target })
}

/// Open a connection (TLS for https/wss) with the given deadlines set on it.
pub fn connect(url: &Url, t: Timeouts) -> Result<Box<dyn Stream>, NetError> {
    let addrs: Vec<_> = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|e| NetError::Connect(e.to_string()))?
        .collect();
    let mut timed_out = false;
    let mut tcp = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, t.connect) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => timed_out = true,
            Err(_) => {}
        }
    }
    let tcp = match tcp {
        Some(t) => t,
        None if timed_out => return Err(NetError::ConnectTimeout),
        None => return Err(NetError::Connect("All connection attempts failed".into())),
    };
    let _ = tcp.set_nodelay(true);
    tcp.set_read_timeout(t.read).ok();
    tcp.set_write_timeout(Some(t.write)).ok();
    if !url.tls {
        return Ok(Box::new(tcp));
    }
    #[cfg(feature = "tls")]
    {
        let connector = native_tls::TlsConnector::new().map_err(|e| NetError::Connect(e.to_string()))?;
        return connector.connect(&url.host, tcp).map(|s| Box::new(s) as Box<dyn Stream>).map_err(|e| match e {
            native_tls::HandshakeError::Failure(e) => NetError::Connect(e.to_string()),
            native_tls::HandshakeError::WouldBlock(_) => NetError::ConnectTimeout,
        });
    }
    #[cfg(not(feature = "tls"))]
    Err(NetError::Connect("https is not built into this binary".into()))
}

/// The body of a request.
pub enum Body<'a> {
    /// No body and no Content-Length (a GET or DELETE as httpx sends it).
    None,
    /// A whole body with its Content-Length (sent even when empty).
    Bytes(&'a [u8]),
    /// A body relayed as it arrives, chunked.
    Stream(&'a mut dyn Read),
}

pub struct Answer {
    pub status: u16,
    /// Lower-case names, in the order received.
    pub headers: Vec<(String, String)>,
    body: Box<dyn Read + Send>,
}

impl Answer {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    /// The next piece of the body; empty at its end.
    pub fn chunk(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.body.read(buf).map_err(io_error)
    }
    /// The whole body.
    pub fn bytes(mut self) -> Result<Vec<u8>, NetError> {
        let mut out = Vec::new();
        self.body.read_to_end(&mut out).map_err(io_error)?;
        Ok(out)
    }
}

/// Send one request and read the answer's head; the body is read from the Answer.
pub fn open(method: &str, url: &str, headers: &[(String, String)], body: Body, t: Timeouts) -> Result<Answer, NetError> {
    let u = parse_url(url)?;
    let mut stream = connect(&u, t)?;
    let mut head = format!("{method} {} HTTP/1.1\r\nhost: {}\r\n", u.target, u.authority);
    let has = |n: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    if !has("accept") {
        head.push_str("accept: */*\r\n");
    }
    head.push_str("connection: close\r\n");
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("connection") || k.eq_ignore_ascii_case("host") {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    match &body {
        Body::None => {}
        Body::Bytes(b) => head.push_str(&format!("content-length: {}\r\n", b.len())),
        Body::Stream(_) => head.push_str("transfer-encoding: chunked\r\n"),
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).map_err(io_error)?;
    match body {
        Body::None => {}
        Body::Bytes(b) => stream.write_all(b).map_err(io_error)?,
        Body::Stream(src) => {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = src.read(&mut buf).map_err(|e| NetError::Failed(e.to_string()))?;
                if n == 0 {
                    break;
                }
                stream.write_all(format!("{n:x}\r\n").as_bytes()).map_err(io_error)?;
                stream.write_all(&buf[..n]).map_err(io_error)?;
                stream.write_all(b"\r\n").map_err(io_error)?;
            }
            stream.write_all(b"0\r\n\r\n").map_err(io_error)?;
        }
    }
    stream.flush().map_err(io_error)?;
    read_answer(stream, method == "HEAD")
}

/// Send one request and read the whole answer.
pub fn request(method: &str, url: &str, headers: &[(String, String)], body: Body, t: Timeouts) -> Result<(u16, Vec<(String, String)>, Vec<u8>), NetError> {
    let a = open(method, url, headers, body, t)?;
    let (status, h) = (a.status, a.headers.clone());
    Ok((status, h, a.bytes()?))
}

fn read_head(reader: &mut impl BufRead) -> Result<(u16, Vec<(String, String)>), NetError> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(io_error)? == 0 {
            return Err(NetError::Failed("Server disconnected without sending a response.".into()));
        }
        let status: u16 = line
            .split(' ')
            .nth(1)
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| NetError::Failed(format!("bad status line {line:?}")))?;
        let mut headers = Vec::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).map_err(io_error)? == 0 {
                return Err(NetError::Failed("Server disconnected without sending a response.".into()));
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
            }
        }
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        return Ok((status, headers));
    }
}

fn read_answer(stream: Box<dyn Stream>, head_only: bool) -> Result<Answer, NetError> {
    let mut reader = BufReader::with_capacity(64 * 1024, stream);
    let (status, headers) = read_head(&mut reader)?;
    let find = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    let body: Box<dyn Read + Send> = if head_only || status == 204 || status == 304 {
        Box::new(io::empty())
    } else if find("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        Box::new(Chunked { inner: reader, left: 0, done: false })
    } else if let Some(n) = find("content-length").and_then(|v| v.parse::<u64>().ok()) {
        Box::new(Exact { inner: reader, left: n })
    } else {
        Box::new(reader)
    };
    Ok(Answer { status, headers, body })
}

struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = self.left.min(buf.len() as u64) as usize;
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed connection without sending complete message body"));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

struct Chunked<R> {
    inner: R,
    left: u64,
    done: bool,
}

impl<R: BufRead> Read for Chunked<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut line = String::new();
            if self.inner.read_line(&mut line)? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed connection without sending complete message body"));
            }
            let size = u64::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
            if size == 0 {
                loop {
                    line.clear();
                    if self.inner.read_line(&mut line)? == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                self.done = true;
                return Ok(0);
            }
            self.left = size;
        }
        let want = self.left.min(buf.len() as u64) as usize;
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed connection without sending complete message body"));
        }
        self.left -= n as u64;
        if self.left == 0 {
            let mut crlf = String::new();
            self.inner.read_line(&mut crlf)?;
        }
        Ok(n)
    }
}

/// urllib.parse.quote(value, safe=""): one opaque path segment.
pub fn quote(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_a_body_both_ways() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h: std::sync::Arc<dyn Fn(&mut crate::httpd::Exchange) + Send + Sync> = std::sync::Arc::new(|ex: &mut crate::httpd::Exchange| {
            let body = ex.read_body(None).unwrap();
            let mut s = ex.stream(201, &[]).unwrap();
            s.send(&body).unwrap();
            s.send(b"+").unwrap();
            s.finish().unwrap();
        });
        std::thread::spawn(move || crate::httpd::serve(listener, h));
        let mut src: &[u8] = b"hello";
        let a = open("POST", &format!("http://127.0.0.1:{port}/x"), &[], Body::Stream(&mut src), Timeouts::all(Duration::from_secs(5))).unwrap();
        assert_eq!(a.status, 201);
        assert_eq!(a.bytes().unwrap(), b"hello+");
        let e = request("GET", "http://127.0.0.1:1/", &[], Body::None, Timeouts::all(Duration::from_secs(1))).err().unwrap();
        assert!(matches!(e, NetError::Connect(_)));
        assert_eq!(quote("a b/é."), "a%20b%2F%C3%A9.");
    }
}
