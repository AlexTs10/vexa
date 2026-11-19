//! The client side of every hop this edge makes: the gateway, the domains, the ticket sink.
//! HTTP/1.1, one request per connection, http:// and https:// (the platform's TLS).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum NetError {
    /// The deadline passed (httpx.TimeoutException).
    Timeout,
    /// Nothing usable came back: refused, unresolvable, reset (httpx.RequestError).
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    /// Lower-case names, in the order received.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

fn io_error(e: std::io::Error) -> NetError {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => NetError::Timeout,
        _ => NetError::Failed(e.to_string()),
    }
}

struct Target {
    tls: bool,
    host: String,
    port: u16,
    /// The Host header: the authority as written.
    authority: String,
    /// Path and query, as written.
    target: String,
}

fn parse(url: &str) -> Result<Target, NetError> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        return Err(NetError::Failed(format!(
            "Request URL is missing an 'http://' or 'https://' protocol: {url}"
        )));
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
        (
            h.to_owned(),
            tail.strip_prefix(':').and_then(|p| p.parse().ok()),
        )
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().ok()),
            None => (hostport.to_owned(), None),
        }
    };
    if host.is_empty() {
        return Err(NetError::Failed(format!("Invalid URL {url}")));
    }
    Ok(Target {
        tls,
        port: port.unwrap_or(if tls { 443 } else { 80 }),
        host,
        authority: authority.to_owned(),
        target,
    })
}

/// One request. `body` None sends no body at all.
pub fn request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<Reply, NetError> {
    let t = parse(url)?;
    let addrs: Vec<_> = (t.host.as_str(), t.port)
        .to_socket_addrs()
        .map_err(|e| NetError::Failed(e.to_string()))?
        .collect();
    let mut tcp = None;
    let mut last = String::from("no address");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err(NetError::Timeout),
            Err(e) => last = e.to_string(),
        }
    }
    let tcp =
        tcp.ok_or_else(|| NetError::Failed(format!("All connection attempts failed ({last})")))?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    let mut stream: Box<dyn Stream> = if t.tls {
        let connector =
            native_tls::TlsConnector::new().map_err(|e| NetError::Failed(e.to_string()))?;
        Box::new(connector.connect(&t.host, tcp).map_err(|e| match e {
            native_tls::HandshakeError::Failure(e) => NetError::Failed(e.to_string()),
            native_tls::HandshakeError::WouldBlock(_) => NetError::Timeout,
        })?)
    } else {
        Box::new(tcp)
    };
    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\n",
        t.target, t.authority
    );
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept"))
    {
        head.push_str("Accept: */*\r\n");
    }
    head.push_str("Connection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(b) = body {
        head.push_str(&format!("Content-Length: {}\r\n", b.len()));
    } else if matches!(method, "POST" | "PUT" | "PATCH") {
        head.push_str("Content-Length: 0\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).map_err(io_error)?;
    if let Some(b) = body {
        stream.write_all(b).map_err(io_error)?;
    }
    stream.flush().map_err(io_error)?;
    read_reply(stream, method == "HEAD")
}

fn read_reply(stream: Box<dyn Stream>, head_only: bool) -> Result<Reply, NetError> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(io_error)? == 0 {
            return Err(NetError::Failed(
                "Server disconnected without sending a response.".into(),
            ));
        }
        let status: u16 = line
            .split(' ')
            .nth(1)
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| NetError::Failed(format!("bad status line {line:?}")))?;
        let mut headers = Vec::new();
        loop {
            line.clear();
            reader.read_line(&mut line).map_err(io_error)?;
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
            }
        }
        if (100..200).contains(&status) {
            continue;
        }
        let find = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        let body = if head_only || status == 204 || status == 304 {
            Vec::new()
        } else if find("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
        {
            chunked(&mut reader)?
        } else if let Some(n) = find("content-length").and_then(|v| v.parse::<usize>().ok()) {
            let mut data = vec![0; n];
            reader.read_exact(&mut data).map_err(io_error)?;
            data
        } else {
            let mut data = Vec::new();
            reader.read_to_end(&mut data).map_err(io_error)?;
            data
        };
        return Ok(Reply {
            status,
            headers,
            body,
        });
    }
}

fn chunked(reader: &mut impl BufRead) -> Result<Vec<u8>, NetError> {
    let mut body = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).map_err(io_error)?;
        let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|_| NetError::Failed("invalid chunk size".into()))?;
        if size == 0 {
            loop {
                line.clear();
                if reader.read_line(&mut line).map_err(io_error)? == 0 || line.trim().is_empty() {
                    return Ok(body);
                }
            }
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..]).map_err(io_error)?;
        line.clear();
        reader.read_line(&mut line).map_err(io_error)?;
    }
}

/// urllib.parse.quote_plus(value, safe=""): the query-string spelling httpx sends.
pub fn quote_plus(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// urllib.parse.quote(value, safe=""): one opaque path segment.
pub fn quote(value: &str) -> String {
    quote_plus(value).replace('+', "%20")
}

/// A URL with httpx-style `params` appended.
pub fn with_query(url: &str, params: &[(String, String)]) -> String {
    if params.is_empty() {
        return url.to_owned();
    }
    let q = params
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{url}{}{q}", if url.contains('?') { "&" } else { "?" })
}

#[cfg(test)]
mod tests {
    #[test]
    fn quoting_like_urllib() {
        assert_eq!(super::quote("a/b c"), "a%2Fb%20c");
        assert_eq!(
            super::quote_plus("{\"crm\": \"a\"}"),
            "%7B%22crm%22%3A+%22a%22%7D"
        );
        assert_eq!(
            super::with_query("http://x/m", &[("limit".into(), "5".into())]),
            "http://x/m?limit=5"
        );
    }
}
