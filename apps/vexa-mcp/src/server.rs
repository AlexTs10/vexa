//! The listening socket: one thread per connection, one request per connection (`Connection: close`),
//! the answer written whole — or, for the session's event stream, kept open and chunked.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use crate::edge::App;
use crate::wire::{parse_qsl, Req, Resp};

const MAX_BODY: usize = 500 * 1024 * 1024;

/// The request path as Starlette routes it: percent-decoded (a `+` stays a `+`).
fn decode_path(p: &str) -> String {
    let b = p.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
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

fn read(stream: &mut TcpStream) -> Result<Req, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("empty request")?.to_owned();
    let target = parts.next().ok_or("no request target")?.to_owned();
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        let t = line.trim_end_matches(['\r', '\n']);
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
        }
    }
    let get = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v): &(String, String)| v.clone())
    };
    if get("expect").is_some_and(|e| e.eq_ignore_ascii_case("100-continue")) {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|e| e.to_string())?;
    }
    let mut body = Vec::new();
    if get("transfer-encoding").is_some_and(|t| t.to_ascii_lowercase().contains("chunked")) {
        loop {
            line.clear();
            reader.read_line(&mut line).map_err(|e| e.to_string())?;
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| "bad chunk")?;
            if size == 0 {
                loop {
                    line.clear();
                    if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0
                        || line.trim().is_empty()
                    {
                        break;
                    }
                }
                break;
            }
            if body.len() + size > MAX_BODY {
                return Err("body too large".into());
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader
                .read_exact(&mut body[start..])
                .map_err(|e| e.to_string())?;
            line.clear();
            reader.read_line(&mut line).map_err(|e| e.to_string())?;
        }
    } else if let Some(n) = get("content-length") {
        let n: usize = n.parse().map_err(|_| "bad content-length")?;
        if n > MAX_BODY {
            return Err("body too large".into());
        }
        body.resize(n, 0);
        reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    }
    let (path, raw_query) = target
        .split_once('?')
        .map_or((target.as_str(), ""), |(p, q)| (p, q));
    Ok(Req {
        method,
        path: decode_path(path),
        raw_query: raw_query.to_owned(),
        query: parse_qsl(raw_query),
        headers,
        body,
    })
}

fn write(stream: &mut TcpStream, resp: Resp) -> std::io::Result<()> {
    let reason = vexa_native_kit::reason::phrase(resp.status);
    let mut head = format!("HTTP/1.1 {} {reason}\r\n", resp.status);
    for (k, v) in &resp.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    match resp.stream {
        Some(run) => {
            head.push_str("transfer-encoding: chunked\r\n\r\n");
            stream.write_all(head.as_bytes())?;
            stream.flush()?;
            run(stream);
            Ok(())
        }
        None => {
            head.push_str(&format!(
                "content-length: {}\r\nconnection: close\r\n\r\n",
                resp.body.len()
            ));
            stream.write_all(head.as_bytes())?;
            stream.write_all(&resp.body)?;
            stream.flush()
        }
    }
}

fn serve_one(app: &'static App, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let resp = match read(&mut stream) {
        Ok(req) => crate::edge::handle(app, req),
        Err(_) => Resp::bare(400, "Bad Request"),
    };
    let _ = write(&mut stream, resp);
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

pub fn serve(app: &'static App, listener: TcpListener) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        std::thread::spawn(move || serve_one(app, stream));
    }
}
