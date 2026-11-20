//! RFC 6455 over a connection this process owns: the server's answer to an upgrade, the client's
//! handshake, and frames read on one thread while any thread writes. No extension is negotiated.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use vexa_native_kit::b64;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// SHA-1 (FIPS 180-4), for Sec-WebSocket-Accept and EVALSHA names.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn accept_key(key: &str) -> String {
    b64::encode(&sha1(format!("{}{GUID}", key.trim()).as_bytes()))
}

/// The subprotocols a client offered (`Sec-WebSocket-Protocol`, comma-separated, every header).
pub fn offered(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(k, _)| k == "sec-websocket-protocol")
        .flat_map(|(_, v)| v.split(',').map(|p| p.trim().to_owned()))
        .filter(|p| !p.is_empty())
        .collect()
}

#[derive(Debug)]
pub enum Msg {
    Text(String),
    Binary(Vec<u8>),
    /// The peer closed (its code, if it sent one).
    Close(Option<u16>),
}

pub struct Writer {
    out: Mutex<TcpStream>,
    mask: bool,
    closed: AtomicBool,
}

impl Writer {
    fn frame(&self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mut head = vec![0x80 | opcode];
        let m = if self.mask { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => head.push(m | n as u8),
            n if n <= 0xffff => {
                head.push(m | 126);
                head.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                head.push(m | 127);
                head.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        let mut body = payload.to_vec();
        if self.mask {
            let key = vexa_native_kit::ids::random_bytes(4);
            head.extend_from_slice(&key);
            for (i, b) in body.iter_mut().enumerate() {
                *b ^= key[i % 4];
            }
        }
        head.extend_from_slice(&body);
        let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
        out.write_all(&head)?;
        out.flush()
    }

    pub fn text(&self, s: &str) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the websocket is closed"));
        }
        self.frame(0x1, s.as_bytes())
    }

    pub fn binary(&self, b: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the websocket is closed"));
        }
        self.frame(0x2, b)
    }

    pub fn send(&self, m: &Msg) -> io::Result<()> {
        match m {
            Msg::Text(t) => self.text(t),
            Msg::Binary(b) => self.binary(b),
            Msg::Close(c) => self.close(c.unwrap_or(1000)),
        }
    }

    /// Send a close frame once; the socket's read side is shut down after a moment so a reader
    /// waiting on a peer that never answers the close stops.
    pub fn close(&self, code: u16) -> io::Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let r = self.frame(0x8, &code.to_be_bytes());
        if let Ok(s) = self.out.lock().unwrap_or_else(|p| p.into_inner()).try_clone() {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(2));
                let _ = s.shutdown(std::net::Shutdown::Both);
            });
        }
        r
    }

    pub fn shutdown(&self) {
        let _ = self.out.lock().unwrap_or_else(|p| p.into_inner()).shutdown(std::net::Shutdown::Both);
    }
}

/// After a close this side sent: read until the peer's answering close (at most 2 s), then close
/// the connection.
pub fn linger(reader: &mut Reader) {
    let _ = reader.w.out.lock().unwrap_or_else(|p| p.into_inner()).set_read_timeout(Some(Duration::from_secs(2)));
    while let Ok(m) = reader.next() {
        if matches!(m, Msg::Close(_)) {
            break;
        }
    }
    reader.w.shutdown();
}

pub struct Reader {
    inp: BufReader<Box<dyn Read + Send>>,
    /// The writer, to answer pings and closes.
    pub w: std::sync::Arc<Writer>,
    max: Option<usize>,
}

impl Reader {
    /// The next data message; pings are answered here.
    pub fn next(&mut self) -> io::Result<Msg> {
        let mut message: Vec<u8> = Vec::new();
        let mut first_op = None;
        loop {
            let mut h = [0u8; 2];
            if let Err(e) = self.inp.read_exact(&mut h) {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    return Ok(Msg::Close(None));
                }
                return Err(e);
            }
            let fin = h[0] & 0x80 != 0;
            let op = h[0] & 0x0f;
            let masked = h[1] & 0x80 != 0;
            let mut len = (h[1] & 0x7f) as u64;
            if len == 126 {
                let mut b = [0u8; 2];
                self.inp.read_exact(&mut b)?;
                len = u16::from_be_bytes(b) as u64;
            } else if len == 127 {
                let mut b = [0u8; 8];
                self.inp.read_exact(&mut b)?;
                len = u64::from_be_bytes(b);
            }
            if self.max.is_some_and(|m| message.len() as u64 + len > m as u64) {
                let _ = self.w.close(1009);
                return Err(io::Error::new(io::ErrorKind::InvalidData, "message too big"));
            }
            let mut key = [0u8; 4];
            if masked {
                self.inp.read_exact(&mut key)?;
            }
            let mut payload = vec![0u8; len as usize];
            self.inp.read_exact(&mut payload)?;
            if masked {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= key[i % 4];
                }
            }
            match op {
                0x8 => {
                    let code = (payload.len() >= 2).then(|| u16::from_be_bytes([payload[0], payload[1]]));
                    let _ = self.w.close(code.filter(|c| *c != 1005 && *c != 1006).unwrap_or(1000));
                    return Ok(Msg::Close(code));
                }
                0x9 => {
                    let _ = self.w.frame(0xA, &payload);
                    continue;
                }
                0xA => continue,
                0x0 | 0x1 | 0x2 => {
                    if op != 0 {
                        first_op = Some(op);
                    }
                    message.extend_from_slice(&payload);
                    if !fin {
                        continue;
                    }
                    return match first_op {
                        Some(0x1) => String::from_utf8(message)
                            .map(Msg::Text)
                            .map_err(|_| {
                                let _ = self.w.close(1007);
                                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in a text frame")
                            }),
                        _ => Ok(Msg::Binary(message)),
                    };
                }
                _ => {
                    let _ = self.w.close(1002);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown opcode"));
                }
            }
        }
    }
}

/// Answer an upgrade (`101 Switching Protocols`) on a socket taken over from the HTTP server.
pub fn accept(mut sock: TcpStream, leftover: Vec<u8>, key: &str, subprotocol: Option<&str>) -> io::Result<(Reader, std::sync::Arc<Writer>)> {
    let mut head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {}\r\n",
        accept_key(key)
    );
    if let Some(p) = subprotocol {
        head.push_str(&format!("sec-websocket-protocol: {p}\r\n"));
    }
    head.push_str("\r\n");
    sock.write_all(head.as_bytes())?;
    sock.set_read_timeout(None)?;
    let reader: Box<dyn Read + Send> = Box::new(io::Cursor::new(leftover).chain(sock.try_clone()?));
    let w = std::sync::Arc::new(Writer { out: Mutex::new(sock), mask: false, closed: AtomicBool::new(false) });
    Ok((Reader { inp: BufReader::new(reader), w: w.clone(), max: Some(16 * 1024 * 1024) }, w))
}

/// Refuse an upgrade before accepting it (uvicorn's answer to a close before accept).
pub fn refuse(mut sock: TcpStream) {
    let _ = sock.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
}

pub enum DialError {
    /// The upstream answered the upgrade with an HTTP status.
    Status(u16),
    /// No connection, a timeout, or a handshake that was not one.
    Failed(String),
}

pub struct Upstream {
    pub reader: Reader,
    pub writer: std::sync::Arc<Writer>,
    pub subprotocol: Option<String>,
}

/// Open a client websocket (`ws://` only) with these headers and subprotocols.
pub fn dial(url: &str, headers: &[(String, String)], protocols: &[String], open_timeout: Duration, max: Option<usize>) -> Result<Upstream, DialError> {
    use vexa_native_kit::client::{parse_url, Timeouts};
    let u = parse_url(url).map_err(|e| DialError::Failed(e.to_string()))?;
    if u.tls {
        return Err(DialError::Failed("wss:// upstreams are not supported by this edge".into()));
    }
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(u.host.as_str(), u.port))
        .map_err(|e| DialError::Failed(e.to_string()))?
        .next()
        .ok_or_else(|| DialError::Failed("no address".into()))?;
    let _ = Timeouts::all(open_timeout);
    let mut sock = TcpStream::connect_timeout(&addr, open_timeout).map_err(|e| DialError::Failed(e.to_string()))?;
    sock.set_nodelay(true).ok();
    sock.set_read_timeout(Some(open_timeout)).ok();
    let key = b64::encode(&vexa_native_kit::ids::random_bytes(16));
    let mut head = format!(
        "GET {} HTTP/1.1\r\nhost: {}\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: {key}\r\nsec-websocket-version: 13\r\n",
        u.target, u.authority
    );
    if !protocols.is_empty() {
        head.push_str(&format!("sec-websocket-protocol: {}\r\n", protocols.join(", ")));
    }
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    sock.write_all(head.as_bytes()).map_err(|e| DialError::Failed(e.to_string()))?;
    let mut reader = BufReader::new(sock.try_clone().map_err(|e| DialError::Failed(e.to_string()))?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| DialError::Failed(e.to_string()))?;
    let status: u16 = line.split(' ').nth(1).and_then(|s| s.trim().parse().ok()).ok_or_else(|| DialError::Failed("InvalidMessage".into()))?;
    let mut answer = Vec::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(|e| DialError::Failed(e.to_string()))? == 0 {
            return Err(DialError::Failed("InvalidMessage".into()));
        }
        let t = line.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            answer.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
        }
    }
    if status != 101 {
        return Err(DialError::Status(status));
    }
    let get = |n: &str| answer.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    if get("sec-websocket-accept").as_deref() != Some(accept_key(&key).as_str()) {
        return Err(DialError::Failed("InvalidHeaderValue".into()));
    }
    sock.set_read_timeout(None).ok();
    let leftover = reader.buffer().to_vec();
    let inp: Box<dyn Read + Send> = Box::new(io::Cursor::new(leftover).chain(sock.try_clone().map_err(|e| DialError::Failed(e.to_string()))?));
    let w = std::sync::Arc::new(Writer { out: Mutex::new(sock), mask: true, closed: AtomicBool::new(false) });
    Ok(Upstream { reader: Reader { inp: BufReader::new(inp), w: w.clone(), max }, writer: w, subprotocol: get("sec-websocket-protocol") })
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc_vectors() {
        assert_eq!(vexa_native_kit::sha256::hex(&super::sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(super::accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
