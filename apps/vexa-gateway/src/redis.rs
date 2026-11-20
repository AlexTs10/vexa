//! A small RESP2 client over one TCP connection: commands, pipelines, pub/sub, streams and scripts —
//! what the edge asks of Redis (the /ws fan-in, transcript signals, the privacy mark, the guard's
//! rate limit). A URL `redis://[user:password@]host:port/db`, as redis-py reads it.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Nil,
    Ok(String),
    Int(i64),
    Bulk(Vec<u8>),
    Array(Vec<Reply>),
    Error(String),
}

impl Reply {
    pub fn text(&self) -> Option<String> {
        match self {
            Reply::Bulk(b) => Some(String::from_utf8_lossy(b).into_owned()),
            Reply::Ok(s) => Some(s.clone()),
            Reply::Int(i) => Some(i.to_string()),
            _ => None,
        }
    }
    pub fn items(&self) -> &[Reply] {
        match self {
            Reply::Array(a) => a,
            _ => &[],
        }
    }
}

#[derive(Clone, Debug)]
pub struct Target {
    host: String,
    port: u16,
    user: Option<String>,
    password: Option<String>,
    db: u32,
}

fn unquote(s: &str) -> String {
    vexa_native_kit::http::decode(&s.replace('+', "%2B"))
}

pub fn parse_url(url: &str) -> Result<Target, String> {
    let rest = url.strip_prefix("redis://").ok_or_else(|| format!("unsupported Redis URL scheme: {url}"))?;
    let (auth, hostpart) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, rest),
    };
    let (hostport, path) = hostpart.split_once('/').unwrap_or((hostpart, ""));
    let path = path.split('?').next().unwrap_or("");
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse().map_err(|_| format!("invalid Redis port in {url}"))?),
        None => (hostport.to_owned(), 6379),
    };
    let (user, password) = match auth {
        None => (None, None),
        Some(a) => match a.split_once(':') {
            Some((u, p)) => ((!u.is_empty()).then(|| unquote(u)), Some(unquote(p))),
            None => ((!a.is_empty()).then(|| unquote(a)), None),
        },
    };
    let db = if path.is_empty() { 0 } else { path.parse().map_err(|_| format!("invalid Redis database in {url}"))? };
    Ok(Target { host: if host.is_empty() { "localhost".into() } else { host }, port, user, password, db })
}

pub struct Conn {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

fn encode(args: &[&[u8]], out: &mut Vec<u8>) {
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
}

impl Conn {
    /// Connect (5 s), authenticate and select the database; replies wait up to `timeout`.
    pub fn open(t: &Target, timeout: Option<Duration>) -> io::Result<Conn> {
        let addr = (t.host.as_str(), t.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut c = Conn { reader: BufReader::new(stream.try_clone()?), writer: stream };
        if let Some(p) = &t.password {
            let r = match &t.user {
                Some(u) => c.cmd(&[b"AUTH", u.as_bytes(), p.as_bytes()])?,
                None => c.cmd(&[b"AUTH", p.as_bytes()])?,
            };
            if let Reply::Error(e) = r {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, e));
            }
        }
        if t.db != 0 {
            if let Reply::Error(e) = c.cmd(&[b"SELECT", t.db.to_string().as_bytes()])? {
                return Err(io::Error::other(e));
            }
        }
        Ok(c)
    }

    pub fn send(&mut self, args: &[&[u8]]) -> io::Result<()> {
        let mut out = Vec::new();
        encode(args, &mut out);
        self.writer.write_all(&out)
    }

    pub fn cmd(&mut self, args: &[&[u8]]) -> io::Result<Reply> {
        self.send(args)?;
        self.read()
    }

    /// Several commands in one write; their replies in order.
    pub fn pipeline(&mut self, cmds: &[Vec<Vec<u8>>]) -> io::Result<Vec<Reply>> {
        let mut out = Vec::new();
        for c in cmds {
            let args: Vec<&[u8]> = c.iter().map(Vec::as_slice).collect();
            encode(&args, &mut out);
        }
        self.writer.write_all(&out)?;
        cmds.iter().map(|_| self.read()).collect()
    }

    pub fn read(&mut self) -> io::Result<Reply> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed by server."));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        let (kind, rest) = line.split_at(1.min(line.len()));
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid RESP reply");
        Ok(match kind {
            "+" => Reply::Ok(rest.to_owned()),
            "-" => Reply::Error(rest.to_owned()),
            ":" => Reply::Int(rest.parse().map_err(|_| bad())?),
            "$" => {
                let n: i64 = rest.parse().map_err(|_| bad())?;
                if n < 0 {
                    Reply::Nil
                } else {
                    let mut buf = vec![0u8; n as usize + 2];
                    self.reader.read_exact(&mut buf)?;
                    buf.truncate(n as usize);
                    Reply::Bulk(buf)
                }
            }
            "*" => {
                let n: i64 = rest.parse().map_err(|_| bad())?;
                if n < 0 {
                    Reply::Nil
                } else {
                    let mut items = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        items.push(self.read()?);
                    }
                    Reply::Array(items)
                }
            }
            _ => return Err(bad()),
        })
    }
}

/// A Redis error reply as an io error (redis-py raises ResponseError).
pub fn ok(r: Reply) -> io::Result<Reply> {
    match r {
        Reply::Error(e) => Err(io::Error::other(e)),
        other => Ok(other),
    }
}

/// One stream entry: its id and its field/value pairs.
pub type Entry = (String, Vec<(String, String)>);

pub fn entries(r: &Reply) -> Vec<Entry> {
    r.items()
        .iter()
        .filter_map(|e| {
            let parts = e.items();
            let id = parts.first()?.text()?;
            let kv = parts.get(1).map(|f| f.items()).unwrap_or(&[]);
            let fields = kv.chunks(2).filter_map(|p| Some((p.first()?.text()?, p.get(1)?.text()?))).collect();
            Some((id, fields))
        })
        .collect()
}

/// SHA-1 of a script (EVALSHA's name for it).
pub fn sha1_hex(data: &[u8]) -> String {
    vexa_native_kit::sha256::hex(&crate::ws::sha1(data))
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_urls_like_redis_py() {
        let t = super::parse_url("redis://:p%40ss@h:6380/2").unwrap();
        assert_eq!((t.host.as_str(), t.port, t.password.as_deref(), t.db), ("h", 6380, Some("p@ss"), 2));
        let t = super::parse_url("redis://localhost:6379").unwrap();
        assert_eq!((t.db, t.user), (0, None));
    }
}
