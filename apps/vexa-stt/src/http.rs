//! A minimal HTTP/1.1 request reader and response writer.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// The largest request body the service accepts (the Compose nginx limit).
pub const MAX_BODY: usize = 500 * 1024 * 1024;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Header names in lower case.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

pub fn read_request(stream: &TcpStream) -> Result<Request, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("empty request")?.to_owned();
    let target = parts.next().ok_or("no request target")?;
    let path = target.split('?').next().unwrap_or("/").to_owned();
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
    Ok(Request { method, path, headers, body })
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
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn json(status: u16, body: String) -> Self {
        Self { status, body, headers: Vec::new() }
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
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Payload Too Large",
            422 => "Unprocessable Entity",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Unknown",
        };
        let mut head = format!(
            "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn decodes_a_chunked_body() {
        let mut input = Cursor::new(b"4\r\nWiki\r\n5;x=1\r\npedia\r\n0\r\n\r\n".to_vec());
        assert_eq!(read_chunked(&mut input).unwrap(), b"Wikipedia");
    }
}
