//! PostgreSQL for the native processes: a small pool of blocking clients (the \`postgres\`
//! crate), transactions opened and closed explicitly, and rows read as JSON maps
//! (text, integers, booleans and JSON/JSONB as \`serde_json\` values, NULL as null).
//!
//! A connection is checked before it is handed out (SQLAlchemy's \`pool_pre_ping\`), at most
//! \`max\` are open at once, and a caller waits up to 30 s for one (SQLAlchemy's QueuePool).

use std::error::Error as _;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub use postgres::types::ToSql;
use postgres::types::{to_sql_checked, IsNull, Type};
use postgres::{Client, NoTls, Row};
use serde_json::{Map, Value};

/// A database error: its SQLSTATE when the server sent one, and its text.
#[derive(Debug, Clone)]
pub struct PgError {
    pub code: Option<String>,
    pub message: String,
}

impl PgError {
    fn of(e: postgres::Error) -> Self {
        let code = e.code().map(|c| c.code().to_owned());
        let message = match e.as_db_error() {
            Some(db) => db.message().to_owned(),
            None => e.source().map(|s| s.to_string()).unwrap_or_else(|| e.to_string()),
        };
        PgError { code, message }
    }
    fn text(message: &str) -> Self {
        PgError { code: None, message: message.to_owned() }
    }
    /// 23505: a unique or primary key constraint refused the row.
    pub fn is_unique_violation(&self) -> bool {
        self.code.as_deref() == Some("23505")
    }
    /// Class 23: an integrity constraint (SQLAlchemy's IntegrityError).
    pub fn is_integrity(&self) -> bool {
        self.code.as_deref().is_some_and(|c| c.starts_with("23"))
    }
}

impl std::fmt::Display for PgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub type Result<T> = std::result::Result<T, PgError>;

/// An integer parameter for an INT2, INT4 or INT8 column (the \`postgres\` crate binds an
/// \`i64\` to INT8 only).
#[derive(Debug, Clone, Copy)]
pub struct Int(pub i64);

impl ToSql for Int {
    fn to_sql(&self, ty: &Type, out: &mut postgres::types::private::BytesMut) -> std::result::Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match *ty {
            Type::INT2 => i16::try_from(self.0)?.to_sql(ty, out),
            Type::INT4 => i32::try_from(self.0)?.to_sql(ty, out),
            _ => self.0.to_sql(ty, out),
        }
    }
    fn accepts(ty: &Type) -> bool {
        matches!(*ty, Type::INT2 | Type::INT4 | Type::INT8)
    }
    to_sql_checked!();
}

/// The parts of a database URL: \`postgresql://\`, \`postgres://\` or a SQLAlchemy
/// \`postgresql+<driver>://\` URL, the user and password percent-decoded.
pub fn config(url: &str) -> Result<postgres::Config> {
    let rest = url
        .split_once("://")
        .filter(|(scheme, _)| *scheme == "postgres" || *scheme == "postgresql" || scheme.starts_with("postgresql+"))
        .map(|(_, rest)| rest)
        .ok_or_else(|| PgError::text("not a PostgreSQL URL"))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (userinfo, hostport) = authority.rsplit_once('@').unwrap_or(("", authority));
    let (user, password) = userinfo.split_once(':').map(|(u, p)| (u, Some(p))).unwrap_or((userinfo, None));
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || hostport.starts_with('[') => (h, p.parse::<u16>().map_err(|_| PgError::text("bad port"))?),
        _ => (hostport, 5432),
    };
    let (db, _query) = path.split_once('?').unwrap_or((path, ""));
    let mut c = postgres::Config::new();
    c.host(if host.is_empty() { "localhost" } else { host.trim_start_matches('[').trim_end_matches(']') });
    c.port(port);
    if !user.is_empty() {
        c.user(&unquote(user));
    }
    if let Some(p) = password {
        c.password(unquote(p));
    }
    if !db.is_empty() {
        c.dbname(&unquote(db));
    }
    c.connect_timeout(Duration::from_secs(10));
    Ok(c)
}

/// Percent-decoding as `urllib.parse.unquote` (a `+` stays a `+`).
fn unquote(text: &str) -> String {
    let b = text.as_bytes();
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

struct Slots {
    idle: Vec<Client>,
    open: usize,
}

/// At most \`max\` connections, opened on demand and reused.
pub struct Pool {
    config: postgres::Config,
    max: usize,
    wait: Duration,
    slots: Mutex<Slots>,
    freed: Condvar,
}

impl Pool {
    pub fn new(url: &str, max: usize) -> Result<Arc<Pool>> {
        Ok(Arc::new(Pool {
            config: config(url)?,
            max: max.max(1),
            wait: Duration::from_secs(30),
            slots: Mutex::new(Slots { idle: Vec::new(), open: 0 }),
            freed: Condvar::new(),
        }))
    }

    /// A checked connection, waiting for one when \`max\` are in use.
    pub fn get(self: &Arc<Self>) -> Result<Conn> {
        let deadline = Instant::now() + self.wait;
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            while let Some(mut client) = slots.idle.pop() {
                drop(slots);
                if !client.is_closed() && client.is_valid(Duration::from_secs(5)).is_ok() {
                    return Ok(Conn { pool: Arc::clone(self), client: Some(client) });
                }
                slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
                slots.open -= 1;
            }
            if slots.open < self.max {
                slots.open += 1;
                drop(slots);
                return match self.config.connect(NoTls) {
                    Ok(client) => Ok(Conn { pool: Arc::clone(self), client: Some(client) }),
                    Err(e) => {
                        let mut s = self.slots.lock().unwrap_or_else(|e| e.into_inner());
                        s.open -= 1;
                        self.freed.notify_one();
                        Err(PgError::of(e))
                    }
                };
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(PgError::text("QueuePool limit reached, connection timed out"));
            }
            slots = self.freed.wait_timeout(slots, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
        }
    }

    /// A new transaction on a pooled connection.
    pub fn begin(self: &Arc<Self>) -> Result<Tx> {
        let mut conn = self.get()?;
        conn.client().batch_execute("BEGIN").map_err(PgError::of)?;
        Ok(Tx { conn, open: true, savepoints: 0 })
    }
}

/// A pooled connection; it goes back to the pool when dropped.
pub struct Conn {
    pool: Arc<Pool>,
    client: Option<Client>,
}

impl Conn {
    pub fn client(&mut self) -> &mut Client {
        self.client.as_mut().expect("a pooled connection holds a client")
    }
    fn discard(&mut self) {
        self.client = None;
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let mut slots = self.pool.slots.lock().unwrap_or_else(|e| e.into_inner());
        match self.client.take() {
            Some(c) if !c.is_closed() => slots.idle.push(c),
            _ => slots.open -= 1,
        }
        self.pool.freed.notify_one();
    }
}

/// One transaction: BEGIN at the start, COMMIT or ROLLBACK at the end (ROLLBACK when dropped).
pub struct Tx {
    conn: Conn,
    open: bool,
    savepoints: u32,
}

/// A value of one column, as JSON.
fn cell(row: &Row, i: usize) -> Value {
    let ty = row.columns()[i].type_().clone();
    macro_rules! get {
        ($t:ty) => {
            row.try_get::<_, Option<$t>>(i).ok().flatten()
        };
    }
    match ty {
        Type::BOOL => get!(bool).map(Value::Bool),
        Type::INT2 => get!(i16).map(|v| Value::from(v as i64)),
        Type::INT4 => get!(i32).map(|v| Value::from(v as i64)),
        Type::INT8 => get!(i64).map(Value::from),
        Type::OID => get!(u32).map(|v| Value::from(v as u64)),
        Type::FLOAT4 => get!(f32).map(|v| Value::from(v as f64)),
        Type::FLOAT8 => get!(f64).map(Value::from),
        Type::JSON | Type::JSONB => get!(Value),
        Type::TEXT_ARRAY | Type::VARCHAR_ARRAY => get!(Vec<String>).map(|v| Value::Array(v.into_iter().map(Value::String).collect())),
        _ => get!(String).map(Value::String),
    }
    .unwrap_or(Value::Null)
}

/// A row as a map of column name to value, in column order.
pub fn row_map(row: &Row) -> Map<String, Value> {
    let mut m = Map::new();
    for (i, c) in row.columns().iter().enumerate() {
        m.insert(c.name().to_owned(), cell(row, i));
    }
    m
}

/// A row as its values, in column order.
pub fn row_values(row: &Row) -> Vec<Value> {
    (0..row.len()).map(|i| cell(row, i)).collect()
}

impl Tx {
    fn client(&mut self) -> &mut Client {
        self.conn.client()
    }

    pub fn query(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>> {
        self.client().query(sql, params).map_err(PgError::of)
    }

    /// Every row as a map.
    pub fn maps(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Map<String, Value>>> {
        Ok(self.query(sql, params)?.iter().map(row_map).collect())
    }

    /// The first row as a map.
    pub fn map(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Option<Map<String, Value>>> {
        Ok(self.query(sql, params)?.first().map(row_map))
    }

    /// Every row as its values.
    pub fn tuples(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Vec<Value>>> {
        Ok(self.query(sql, params)?.iter().map(row_values).collect())
    }

    /// The first column of every row.
    pub fn column(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Value>> {
        Ok(self.query(sql, params)?.iter().map(|r| cell(r, 0)).collect())
    }

    /// The first column of the first row; None when there is no row. More than one row is
    /// an error, as SQLAlchemy's \`scalar_one_or_none\`.
    pub fn scalar(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Option<Value>> {
        let rows = self.query(sql, params)?;
        if rows.len() > 1 {
            return Err(PgError::text("Multiple rows were found when one or none was required"));
        }
        Ok(rows.first().map(|r| cell(r, 0)))
    }

    /// The first column of the first row, whatever follows (SQLAlchemy's \`scalar\`/\`first\`).
    pub fn first(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Option<Value>> {
        Ok(self.query(sql, params)?.first().map(|r| cell(r, 0)))
    }

    /// A statement's row count.
    pub fn exec(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<u64> {
        self.client().execute(sql, params).map_err(PgError::of)
    }

    /// Run \`f\` inside a SAVEPOINT: released when it returns Ok, rolled back to when it returns
    /// Err (SQLAlchemy's \`begin_nested\`), so the transaction goes on after a refused statement.
    pub fn savepoint<T, E: From<PgError>>(&mut self, f: impl FnOnce(&mut Tx) -> std::result::Result<T, E>) -> std::result::Result<T, E> {
        self.savepoints += 1;
        let name = format!("sp_{}", self.savepoints);
        self.client().batch_execute(&format!("SAVEPOINT {name}")).map_err(PgError::of)?;
        match f(self) {
            Ok(v) => {
                self.client().batch_execute(&format!("RELEASE SAVEPOINT {name}")).map_err(PgError::of)?;
                Ok(v)
            }
            Err(e) => {
                self.client().batch_execute(&format!("ROLLBACK TO SAVEPOINT {name}")).map_err(PgError::of)?;
                Err(e)
            }
        }
    }

    pub fn commit(mut self) -> Result<()> {
        self.open = false;
        let r = self.client().batch_execute("COMMIT").map_err(PgError::of);
        if r.is_err() {
            self.conn.discard();
        }
        r
    }

    pub fn rollback(mut self) {
        self.end();
    }

    fn end(&mut self) {
        if self.open {
            self.open = false;
            if self.client().batch_execute("ROLLBACK").is_err() {
                self.conn.discard();
            }
        }
    }
}

impl Drop for Tx {
    fn drop(&mut self) {
        self.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_sqlalchemy_urls() {
        let c = config("postgresql+pg8000://vexa_crm:p%40s+s@127.0.0.1:5433/vexa").unwrap();
        assert_eq!(c.get_user(), Some("vexa_crm"));
        assert_eq!(c.get_password(), Some(&b"p@s+s"[..]));
        assert_eq!(c.get_dbname(), Some("vexa"));
        assert_eq!(c.get_ports(), &[5433]);
        assert!(config("mysql://x").is_err());
    }

    /// Against a real server only when VEXA_TEST_PG_URL names one.
    #[test]
    fn round_trip_when_a_server_is_named() {
        let Ok(url) = std::env::var("VEXA_TEST_PG_URL") else { return };
        let pool = Pool::new(&url, 2).unwrap();
        let mut tx = pool.begin().unwrap();
        let row = tx
            .map("SELECT 1::int4 AS a, 'x'::varchar AS b, true AS c, '{\"k\": [1, 2.5]}'::jsonb AS d, NULL::text AS e, $1::int4 AS f", &[&Int(7)])
            .unwrap()
            .unwrap();
        assert_eq!(Value::Object(row), serde_json::json!({"a": 1, "b": "x", "c": true, "d": {"k": [1, 2.5]}, "e": null, "f": 7}));
        let n: std::result::Result<u64, PgError> = tx.savepoint(|t| t.exec("SELECT 1/0", &[]));
        assert_eq!(n.unwrap_err().code.as_deref(), Some("22012"));
        assert_eq!(tx.scalar("SELECT 2", &[]).unwrap(), Some(Value::from(2)));
        tx.rollback();
    }
}
