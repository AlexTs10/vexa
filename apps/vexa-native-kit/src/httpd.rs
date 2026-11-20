//! An HTTP/1.1 server side with keep-alive, request bodies read whole or as a stream
//! (Content-Length or chunked, `Expect: 100-continue`), and answers written whole or as a
//! stream (chunked, or raw under a declared Content-Length). A handler may also take the
//! connection over (a websocket upgrade). One thread per connection.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// The longest request head (request line and headers) a connection may send.
pub const MAX_HEAD: usize = 64 * 1024;
/// How long an idle keep-alive connection is held open (uvicorn's `timeout_keep_alive`).
pub const KEEP_ALIVE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct Head {
    pub method: String,
    /// The request target as sent (path and query, still percent-encoded).
    pub target: String,
    /// The path part of the target, still percent-encoded (ASGI `raw_path`).
    pub raw_path: String,
    /// The text after `?` (empty when there is none).
    pub query: String,
    /// `HTTP/1.1` or `HTTP/1.0`.
    pub version: String,
    /// Lower-case names, in the order received; repeated names are kept.
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// The first value of a header (Starlette's `request.headers.get`).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn wants_close(&self) -> bool {
        let conn = self.header("connection").unwrap_or("").to_ascii_lowercase();
        if self.version == "HTTP/1.0" {
            !conn.contains("keep-alive")
        } else {
            conn.split(',').any(|t| t.trim() == "close")
        }
    }
}

/// The percent-decoded path, as ASGI `path` (bytes decoded, then UTF-8 with replacement).
pub fn decode_path(raw: &str) -> String {
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug)]
pub enum BodyError {
    /// More than the limit the caller gave.
    TooLarge,
    /// The client went away or sent a malformed body.
    Io(String),
}

enum Framing {
    Length(u64),
    Chunked { left: u64, done: bool },
}

pub struct Conn {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    pub peer: SocketAddr,
}

/// One request on a connection, and the answer to it.
pub struct Exchange<'a> {
    pub head: Head,
    pub peer: SocketAddr,
    conn: &'a mut Conn,
    framing: Framing,
    expect_continue: bool,
    responded: bool,
    keep_alive: bool,
    taken: bool,
}

impl Read for Exchange<'_> {
    /// The request body as it arrives.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.expect_continue {
            self.expect_continue = false;
            if !self.responded {
                self.conn.writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            }
        }
        match &mut self.framing {
            Framing::Length(left) => {
                if *left == 0 {
                    return Ok(0);
                }
                let want = (*left).min(buf.len() as u64) as usize;
                let n = self.conn.reader.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the client closed the body"));
                }
                *left -= n as u64;
                Ok(n)
            }
            Framing::Chunked { left, done } => {
                if *done {
                    return Ok(0);
                }
                if *left == 0 {
                    let mut line = String::new();
                    self.conn.reader.read_line(&mut line)?;
                    let size = u64::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
                    if size == 0 {
                        loop {
                            line.clear();
                            if self.conn.reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
                                break;
                            }
                        }
                        *done = true;
                        return Ok(0);
                    }
                    *left = size;
                }
                let want = (*left).min(buf.len() as u64) as usize;
                let n = self.conn.reader.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the client closed the body"));
                }
                *left -= n as u64;
                if *left == 0 {
                    let mut crlf = String::new();
                    self.conn.reader.read_line(&mut crlf)?;
                }
                Ok(n)
            }
        }
    }
}

impl<'a> Exchange<'a> {
    /// The declared Content-Length, when the body has one.
    pub fn declared_length(&self) -> Option<u64> {
        match self.framing {
            Framing::Length(n) => Some(n),
            Framing::Chunked { .. } => None,
        }
    }

    /// The whole body, or TooLarge as soon as it passes `max` bytes.
    pub fn read_body(&mut self, max: Option<usize>) -> Result<Vec<u8>, BodyError> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = self.read(&mut buf).map_err(|e| {
                self.keep_alive = false;
                BodyError::Io(e.to_string())
            })?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
            if max.is_some_and(|m| out.len() > m) {
                self.keep_alive = false;
                return Err(BodyError::TooLarge);
            }
        }
    }

    /// Write a whole answer. `headers` are written as given (lower-case names); a
    /// Content-Length is added unless the headers carry one or the status has no body. The
    /// body is left out for a HEAD request.
    pub fn respond(&mut self, status: u16, headers: &[(String, String)], body: &[u8]) -> io::Result<()> {
        let mut head = status_line(status);
        let mut has_length = false;
        for (k, v) in headers {
            has_length |= k.eq_ignore_ascii_case("content-length");
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        if !has_length && !(status < 200 || status == 204 || status == 304) {
            head.push_str(&format!("content-length: {}\r\n", body.len()));
        }
        if !self.keep_alive {
            head.push_str("connection: close\r\n");
        }
        head.push_str("\r\n");
        self.responded = true;
        let w = &mut self.conn.writer;
        w.write_all(head.as_bytes())?;
        if self.head.method != "HEAD" {
            w.write_all(body)?;
        }
        w.flush()
    }

    /// Start a streamed answer. Without a Content-Length in `headers` the body is chunked;
    /// with one, it is written raw and the connection is closed after it.
    pub fn stream(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<Streamer<'_>> {
        let mut head = status_line(status);
        let mut has_length = false;
        for (k, v) in headers {
            has_length |= k.eq_ignore_ascii_case("content-length");
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        let bodyless = self.head.method == "HEAD" || status < 200 || status == 204 || status == 304;
        let chunked = !has_length && !bodyless;
        if chunked {
            head.push_str("transfer-encoding: chunked\r\n");
        }
        if has_length {
            // A relayed body may end short of what it declared; the connection then ends with it.
            self.keep_alive = false;
            head.push_str("connection: close\r\n");
        } else if !self.keep_alive {
            head.push_str("connection: close\r\n");
        }
        head.push_str("\r\n");
        self.responded = true;
        self.conn.writer.write_all(head.as_bytes())?;
        self.conn.writer.flush()?;
        Ok(Streamer { writer: &mut self.conn.writer, chunked, bodyless, ended: false, keep_alive: &mut self.keep_alive })
    }

    /// Take the connection over (a websocket upgrade): the socket, the bytes already read past
    /// the request head, and a second handle to the socket. The connection is not reused.
    pub fn take(&mut self) -> io::Result<(TcpStream, Vec<u8>)> {
        self.taken = true;
        self.keep_alive = false;
        self.responded = true;
        let leftover = self.conn.reader.buffer().to_vec();
        self.conn.reader.consume(leftover.len());
        Ok((self.conn.writer.try_clone()?, leftover))
    }

    /// A clone of the connection's socket (to shut it down from another thread).
    pub fn socket(&self) -> io::Result<TcpStream> {
        self.conn.writer.try_clone()
    }

    pub fn close_after(&mut self) {
        self.keep_alive = false;
    }
}

pub struct Streamer<'a> {
    writer: &'a mut TcpStream,
    chunked: bool,
    bodyless: bool,
    ended: bool,
    keep_alive: &'a mut bool,
}

impl Streamer<'_> {
    /// Send one piece of the body as it is.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        if self.bodyless || data.is_empty() {
            return Ok(());
        }
        let result = if self.chunked {
            self.writer
                .write_all(format!("{:x}\r\n", data.len()).as_bytes())
                .and_then(|_| self.writer.write_all(data))
                .and_then(|_| self.writer.write_all(b"\r\n"))
        } else {
            self.writer.write_all(data)
        };
        result.and_then(|_| self.writer.flush()).inspect_err(|_| *self.keep_alive = false)
    }

    /// End the body. Not calling it (an upstream that failed mid-way) closes the connection.
    pub fn finish(mut self) -> io::Result<()> {
        self.ended = true;
        if self.chunked {
            self.writer.write_all(b"0\r\n\r\n")?;
        }
        self.writer.flush()
    }
}

impl Drop for Streamer<'_> {
    fn drop(&mut self) {
        if !self.ended {
            *self.keep_alive = false;
        }
    }
}

fn status_line(status: u16) -> String {
    format!("HTTP/1.1 {status} {}\r\n", crate::reason::phrase(status))
}

fn read_head(reader: &mut BufReader<TcpStream>) -> Result<Option<Head>, String> {
    let mut line = String::new();
    let mut total = 0usize;
    // Blank lines before a request line are skipped (RFC 9112 section 2.2).
    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(None);
        }
        total += n;
        if !line.trim().is_empty() {
            break;
        }
        if total > MAX_HEAD {
            return Err("request head too large".into());
        }
    }
    let mut parts = line.trim_end_matches(['\r', '\n']).split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("invalid request line".into());
    };
    if parts.next().is_some() || method.is_empty() || !version.starts_with("HTTP/1.") || target.is_empty() {
        return Err("invalid request line".into());
    }
    let (method, target, version) = (method.to_owned(), target.to_owned(), version.to_owned());
    let mut headers = Vec::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed in the request head".into());
        }
        total += n;
        if total > MAX_HEAD {
            return Err("request head too large".into());
        }
        let t = line.trim_end_matches(['\r', '\n']);
        if t.is_empty() {
            break;
        }
        let Some((k, v)) = t.split_once(':') else {
            return Err("invalid header line".into());
        };
        if k.is_empty() || k.contains(' ') {
            return Err("invalid header name".into());
        }
        headers.push((k.to_ascii_lowercase(), v.trim().to_owned()));
    }
    let (raw_path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (target.clone(), String::new()),
    };
    Ok(Some(Head { method, target, raw_path, query, version, headers }))
}

fn framing(head: &Head) -> Result<Framing, String> {
    if head
        .headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"))
    {
        return Ok(Framing::Chunked { left: 0, done: false });
    }
    match head.header("content-length") {
        Some(v) => v.trim().parse::<u64>().map(Framing::Length).map_err(|_| "invalid Content-Length".into()),
        None => Ok(Framing::Length(0)),
    }
}

fn bad_request(writer: &mut TcpStream) {
    let body = b"Invalid HTTP request received.";
    let head = format!(
        "HTTP/1.1 400 Bad Request\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = writer.write_all(head.as_bytes());
    let _ = writer.write_all(body);
}

/// Serve one connection: requests one after the other until either side closes.
pub fn serve_connection<F>(stream: TcpStream, handler: &F)
where
    F: Fn(&mut Exchange) + ?Sized,
{
    let _ = stream.set_nodelay(true);
    let Ok(peer) = stream.peer_addr() else { return };
    let Ok(writer) = stream.try_clone() else { return };
    let mut conn = Conn { reader: BufReader::with_capacity(16 * 1024, stream), writer, peer };
    loop {
        let _ = conn.writer.set_read_timeout(Some(KEEP_ALIVE));
        let head = match read_head(&mut conn.reader) {
            Ok(Some(h)) => h,
            Ok(None) => return,
            Err(e) if e.contains("timed out") || e.contains("Resource temporarily unavailable") => return,
            Err(_) => {
                bad_request(&mut conn.writer);
                return;
            }
        };
        let _ = conn.writer.set_read_timeout(Some(Duration::from_secs(300)));
        let framing = match framing(&head) {
            Ok(f) => f,
            Err(_) => {
                bad_request(&mut conn.writer);
                return;
            }
        };
        let expect_continue = head.header("expect").is_some_and(|e| e.eq_ignore_ascii_case("100-continue"));
        let keep_alive = !head.wants_close();
        let mut ex = Exchange {
            head,
            peer,
            conn: &mut conn,
            framing,
            expect_continue,
            responded: false,
            keep_alive,
            taken: false,
        };
        handler(&mut ex);
        if ex.taken {
            return;
        }
        if !ex.responded {
            let _ = ex.respond(500, &[("content-type".into(), "text/plain; charset=utf-8".into())], b"Internal Server Error");
        }
        let mut keep = ex.keep_alive;
        if keep {
            // What the handler left of the body is read away (a little), else the connection ends.
            let mut sink = [0u8; 8192];
            let mut drained = 0usize;
            loop {
                match ex.read(&mut sink) {
                    Ok(0) => break,
                    Ok(n) => {
                        drained += n;
                        if drained > 256 * 1024 {
                            keep = false;
                            break;
                        }
                    }
                    Err(_) => {
                        keep = false;
                        break;
                    }
                }
            }
        }
        drop(ex);
        if !keep {
            let _ = conn.writer.flush();
            let _ = conn.writer.shutdown(std::net::Shutdown::Write);
            return;
        }
    }
}

/// Accept connections for ever, one thread each.
pub fn serve<F>(listener: TcpListener, handler: Arc<F>)
where
    F: Fn(&mut Exchange) + Send + Sync + 'static + ?Sized,
{
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let handler = Arc::clone(&handler);
        let _ = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || serve_connection(stream, &*handler));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn decodes_paths_like_asgi() {
        assert_eq!(decode_path("/a%20b/%2F/%zz/%4"), "/a b///%zz/%4");
    }

    #[test]
    fn keep_alive_chunked_body_and_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler: Arc<dyn Fn(&mut Exchange) + Send + Sync> = Arc::new(|ex: &mut Exchange| {
            let body = ex.read_body(None).unwrap();
            if ex.head.raw_path == "/s" {
                let mut s = ex.stream(200, &[("content-type".into(), "text/plain".into())]).unwrap();
                s.send(&body).unwrap();
                s.send(b"!").unwrap();
                s.finish().unwrap();
            } else {
                ex.respond(200, &[], &body).unwrap();
            }
        });
        std::thread::spawn(move || serve(listener, handler));
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(b"POST /a HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n").unwrap();
        c.write_all(b"POST /s HTTP/1.1\r\nhost: x\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi").unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nabc"), "{out}");
        assert!(out.contains("transfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nhi\r\n1\r\n!\r\n0\r\n\r\n"), "{out}");
    }
}
