//! A small synchronous Redis client (RESP2) for the schedule.v1 store: one
//! connection, opened on first use and opened again after an error.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

use vexa_native_kit::http::decode;

#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Nil,
    Int(i64),
    Text(String),
    List(Vec<Reply>),
}

impl Reply {
    pub fn text(self) -> Option<String> {
        match self {
            Reply::Text(t) => Some(t),
            _ => None,
        }
    }
    pub fn int(&self) -> i64 {
        match self {
            Reply::Int(n) => *n,
            _ => 0,
        }
    }
    pub fn texts(self) -> Vec<String> {
        match self {
            Reply::List(items) => items.into_iter().filter_map(Reply::text).collect(),
            _ => Vec::new(),
        }
    }
}

/// Where and how to connect: `redis://[:password@]host:port[/db]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub address: String,
    pub password: Option<String>,
    pub db: u32,
}

pub fn parse_url(url: &str) -> Result<Target, String> {
    let rest = url.strip_prefix("redis://").ok_or_else(|| "REDIS_URL must start with redis://".to_owned())?;
    let (auth, host) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, rest),
    };
    let (host, db) = match host.split_once('/') {
        Some((h, d)) if !d.is_empty() => (h, d.parse().map_err(|_| "invalid REDIS_URL database".to_owned())?),
        Some((h, _)) => (h, 0),
        None => (host, 0),
    };
    let password = auth.map(|a| decode(a.split_once(':').map_or(a, |(_, p)| p))).filter(|p| !p.is_empty());
    let address = if host.contains(':') { host.to_owned() } else { format!("{host}:6379") };
    Ok(Target { address, password, db })
}

pub struct Redis {
    target: Target,
    connection: Mutex<Option<BufReader<TcpStream>>>,
}

fn encode(args: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        out.extend(format!("${}\r\n", arg.len()).as_bytes());
        out.extend(arg.as_bytes());
        out.extend(b"\r\n");
    }
    out
}

/// A failed command: `transport` faults close the connection; an error
/// reply from Redis keeps it.
#[derive(Debug)]
struct Fault {
    transport: bool,
    text: String,
}

fn transport(text: impl std::fmt::Display) -> Fault {
    Fault { transport: true, text: format!("redis: {text}") }
}

fn read_reply(reader: &mut BufReader<TcpStream>) -> Result<Reply, Fault> {
    let mut line = String::new();
    if reader.read_line(&mut line).map_err(transport)? == 0 {
        return Err(transport("the connection closed"));
    }
    let line = line.trim_end_matches(['\r', '\n']);
    let (kind, rest) = line.split_at(1.min(line.len()));
    match kind {
        "+" => Ok(Reply::Text(rest.to_owned())),
        "-" => Err(Fault { transport: false, text: format!("redis: {rest}") }),
        ":" => rest.parse().map(Reply::Int).map_err(|_| transport(format!("bad integer {rest:?}"))),
        "$" => {
            let len: i64 = rest.parse().map_err(|_| transport(format!("bad length {rest:?}")))?;
            if len < 0 {
                return Ok(Reply::Nil);
            }
            let mut data = vec![0; len as usize + 2];
            reader.read_exact(&mut data).map_err(transport)?;
            data.truncate(len as usize);
            Ok(Reply::Text(String::from_utf8_lossy(&data).into_owned()))
        }
        "*" => {
            let count: i64 = rest.parse().map_err(|_| transport(format!("bad count {rest:?}")))?;
            if count < 0 {
                return Ok(Reply::Nil);
            }
            let mut items = Vec::with_capacity(count as usize);
            for _ in 0..count {
                items.push(read_reply(reader)?);
            }
            Ok(Reply::List(items))
        }
        _ => Err(transport(format!("bad reply {line:?}"))),
    }
}

impl Redis {
    pub fn new(target: Target) -> Self {
        Self { target, connection: Mutex::new(None) }
    }

    fn connect(&self) -> Result<BufReader<TcpStream>, Fault> {
        let address = self
            .target
            .address
            .to_socket_addrs()
            .map_err(transport)?
            .next()
            .ok_or_else(|| transport("no address"))?;
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5)).map_err(transport)?;
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
        let mut reader = BufReader::new(stream);
        if let Some(password) = &self.target.password {
            Self::exchange(&mut reader, &["AUTH", password])?;
        }
        if self.target.db != 0 {
            Self::exchange(&mut reader, &["SELECT", &self.target.db.to_string()])?;
        }
        Ok(reader)
    }

    fn exchange(reader: &mut BufReader<TcpStream>, args: &[&str]) -> Result<Reply, Fault> {
        reader.get_mut().write_all(&encode(args)).map_err(transport)?;
        read_reply(reader)
    }

    /// Run one command. A transport error drops the connection, so the next
    /// command connects again; a Redis error reply keeps it.
    pub fn cmd(&self, args: &[&str]) -> Result<Reply, String> {
        let mut slot = self.connection.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(self.connect().map_err(|f| f.text)?);
        }
        let reader = slot.as_mut().expect("connection");
        Self::exchange(reader, args).map_err(|fault| {
            if fault.transport {
                *slot = None;
            }
            fault.text
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redis_urls() {
        assert_eq!(
            parse_url("redis://:s%40cret@127.0.0.1:23379/0").unwrap(),
            Target { address: "127.0.0.1:23379".into(), password: Some("s@cret".into()), db: 0 }
        );
        assert_eq!(parse_url("redis://localhost").unwrap(), Target { address: "localhost:6379".into(), password: None, db: 0 });
        assert_eq!(parse_url("redis://user:pw@h:1/3").unwrap().db, 3);
        assert!(parse_url("http://x").is_err());
    }

    #[test]
    fn encodes_commands() {
        assert_eq!(encode(&["GET", "k"]), b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n");
    }
}
