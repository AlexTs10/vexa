//! One request and one answer, as the edge's routes see them — whether it came off the socket
//! or from a tool call replayed in process.

use serde_json::{json, Value};
use vexa_native_kit::pyjson::Dumps;

#[derive(Debug, Clone, Default)]
pub struct Req {
    pub method: String,
    pub path: String,
    /// The raw query string (after `?`).
    pub raw_query: String,
    /// Decoded pairs, in order (Starlette's `parse_qsl(keep_blank_values=True)`).
    pub query: Vec<(String, String)>,
    /// Lower-case names, in order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The last value of a query parameter (what a scalar FastAPI parameter reads).
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// urllib.parse.unquote_plus.
pub fn unquote_plus(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// urllib.parse.parse_qsl(query, keep_blank_values=True).
pub fn parse_qsl(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (unquote_plus(k), unquote_plus(v))
        })
        .collect()
}

pub struct Resp {
    pub status: u16,
    /// Every header but Content-Length, in order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// An answer that stays open (the session's event stream).
    pub stream: Option<Box<dyn FnOnce(&mut std::net::TcpStream) + Send>>,
    /// Starlette's outermost 500: written below the trace middleware, so it carries no x-trace-id.
    pub untraced: bool,
}

impl Resp {
    pub fn new(status: u16) -> Self {
        Resp {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            stream: None,
            untraced: false,
        }
    }

    /// Starlette's JSONResponse: compact, non-ASCII kept.
    pub fn json(status: u16, value: &Value) -> Self {
        Resp::new(status)
            .header("content-type", "application/json")
            .body(compact(value))
    }

    /// HTTPException(status, detail): `{"detail": ...}`.
    pub fn detail(status: u16, detail: impl Into<Value>) -> Self {
        Resp::json(status, &json!({"detail": detail.into()}))
    }

    /// A Starlette Response with no media type: the text and no Content-Type at all.
    pub fn bare(status: u16, text: &str) -> Self {
        Resp::new(status).body(text)
    }

    /// The ServerErrorMiddleware answer.
    pub fn internal_error() -> Self {
        let mut r = Resp::new(500)
            .header("content-type", "text/plain; charset=utf-8")
            .body("Internal Server Error");
        r.untraced = true;
        r
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// json.dumps(value, separators=(",", ":"), ensure_ascii=False).
pub fn compact(value: &Value) -> String {
    Dumps::COMPACT.ascii(false).text(value)
}

/// json.dumps(value, indent=2, ensure_ascii=False).
pub fn indented(value: &Value) -> String {
    Dumps::DEFAULT.indent(2).ascii(false).text(value)
}

/// An HTTPException raised inside a route.
#[derive(Debug, Clone)]
pub struct HttpError {
    pub status: u16,
    pub detail: Value,
    pub headers: Vec<(String, String)>,
    /// An unhandled failure: the plain 500 and nothing of the detail.
    pub internal: bool,
}

impl HttpError {
    pub fn new(status: u16, detail: impl Into<Value>) -> Self {
        HttpError {
            status,
            detail: detail.into(),
            headers: Vec::new(),
            internal: false,
        }
    }

    pub fn internal() -> Self {
        HttpError {
            status: 500,
            detail: Value::Null,
            headers: Vec::new(),
            internal: true,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn into_resp(self) -> Resp {
        if self.internal {
            return Resp::internal_error();
        }
        let mut r = Resp::detail(self.status, self.detail);
        r.headers.extend(self.headers);
        r
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn query_decoding() {
        assert_eq!(
            super::parse_qsl("a=1&b=&c&d=x+y%2F%zz"),
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "".into()),
                ("c".into(), "".into()),
                ("d".into(), "x y/%zz".into())
            ]
        );
    }
}
