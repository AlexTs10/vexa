//! A minimal HTTP/1.1 server side (request reader, response writer) and a
//! client for plain `http://` URLs. One request per connection.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// The largest request body the service accepts (the Compose nginx limit).
pub const MAX_BODY: usize = 500 * 1024 * 1024;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// The text after `?` in the request target (empty when there is none).
    pub query: String,
    /// Header names in lower case.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// One query parameter, percent-decoded (`+` is a space).
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key) == name).then(|| decode(value))
        })
    }
}

/// Percent-decode one URL component (`+` is a space).
pub fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn read_request(stream: &TcpStream) -> Result<Request, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("empty request")?.to_owned();
    let target = parts.next().ok_or("no request target")?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (path, query) = (path.to_owned(), query.to_owned());
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let chunked = headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        read_chunked(&mut reader)?
    } else {
        let length: usize = headers
            .get("content-length")
            .map_or(Ok(0), |v| v.parse())
            .map_err(|_| "invalid Content-Length")?;
        if length > MAX_BODY {
            return Err("request body is too large".to_owned());
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).map_err(|e| e.to_string())?;
        body
    };
    Ok(Request { method, path, query, headers, body })
}

fn read_chunked(reader: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        let size_text = line.trim().split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_text, 16).map_err(|_| "invalid chunk size")?;
        if size == 0 {
            // Trailers end with an empty line.
            loop {
                line.clear();
                reader.read_line(&mut line).map_err(|e| e.to_string())?;
                if line.trim().is_empty() {
                    return Ok(body);
                }
            }
        }
        if body.len() + size > MAX_BODY {
            return Err("request body is too large".to_owned());
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..]).map_err(|e| e.to_string())?;
        line.clear();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn json(status: u16, body: String) -> Self {
        Self { status, content_type: "application/json".to_owned(), body, headers: Vec::new() }
    }

    /// A FastAPI-style error body: `{"detail": "..."}`.
    pub fn detail(status: u16, detail: &str) -> Self {
        Self::json(status, format!("{{\"detail\":{}}}", crate::json::quote(detail)))
    }

    /// FastAPI's validation answer for a missing form field.
    pub fn missing_field(field: &str) -> Self {
        Self::json(
            422,
            format!(
                "{{\"detail\":[{{\"type\":\"missing\",\"loc\":[\"body\",{}],\"msg\":\"Field required\",\"input\":null}}]}}",
                crate::json::quote(field)
            ),
        )
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn write(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let reason = match self.status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Payload Too Large",
            422 => "Unprocessable Entity",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Unknown",
        };
        let mut head = format!(
            "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.content_type,
            self.body.len()
        );
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
        stream.write_all(self.body.as_bytes())
    }
}

/// The answer of a client request: the status and the body text.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub reason: String,
    pub body: String,
}

/// Send one request to a plain `http://` URL and read the whole answer.
/// `Err` is a transport failure (no connection, timeout, bad answer).
pub fn send(method: &str, url: &str, headers: &[(String, String)], body: &[u8], timeout: Duration) -> Result<Answer, String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| format!("only http:// URLs are supported: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let address = if authority.contains(':') { authority.to_owned() } else { format!("{authority}:80") };
    let socket = address
        .to_socket_addrs()
        .map_err(|e| format!("{authority}: {e}"))?
        .next()
        .ok_or_else(|| format!("{authority}: no address"))?;
    let mut stream = TcpStream::connect_timeout(&socket, timeout).map_err(|e| format!("{authority}: {e}"))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut parts = line.splitn(3, ' ');
    let _version = parts.next();
    let status: u16 = parts.next().and_then(|s| s.trim().parse().ok()).ok_or_else(|| format!("bad status line {line:?}"))?;
    let reason = parts.next().unwrap_or("").trim().to_owned();
    let mut answer_headers = BTreeMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            answer_headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let chunked = answer_headers.get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let bytes = if chunked {
        read_chunked(&mut reader)?
    } else if let Some(length) = answer_headers.get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        let mut data = vec![0; length.min(MAX_BODY)];
        reader.read_exact(&mut data).map_err(|e| e.to_string())?;
        data
    } else {
        let mut data = Vec::new();
        reader.read_to_end(&mut data).map_err(|e| e.to_string())?;
        data
    };
    Ok(Answer { status, reason, body: String::from_utf8_lossy(&bytes).into_owned() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn decodes_a_chunked_body() {
        let mut input = Cursor::new(b"4\r\nWiki\r\n5;x=1\r\npedia\r\n0\r\n\r\n".to_vec());
        assert_eq!(read_chunked(&mut input).unwrap(), b"Wikipedia");
    }

    #[test]
    fn decodes_query_values() {
        assert_eq!(decode("a%20b+c%2F"), "a b c/");
        assert_eq!(decode("100%"), "100%");
    }

    #[test]
    fn a_client_request_reaches_a_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&stream).unwrap();
            assert_eq!((request.method.as_str(), request.path.as_str()), ("POST", "/x"));
            assert_eq!(request.query_param("limit").as_deref(), Some("5"));
            assert_eq!(request.body, b"{}");
            Response::json(201, "{\"ok\":true}".to_owned()).write(&mut stream).unwrap();
        });
        let answer = send("POST", &format!("http://127.0.0.1:{port}/x?limit=5"), &[], b"{}", Duration::from_secs(2)).unwrap();
        server.join().unwrap();
        assert_eq!((answer.status, answer.body.as_str()), (201, "{\"ok\":true}"));
    }
}
