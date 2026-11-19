//! The broker's state directory: the metadata database's schema, its additive
//! migration, and the broker-private HMAC key. The schema is the Python
//! service's, unchanged, so either implementation opens the other's files.

use std::path::Path;

use rusqlite::Connection;

use crate::util;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, actor TEXT, session TEXT, label TEXT, status TEXT, version INTEGER DEFAULT 0, created REAL);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, actor TEXT, session TEXT, operation_id TEXT, connection TEXT, action TEXT, outcome TEXT, vault_request_id TEXT, version INTEGER, receipt TEXT);
CREATE TABLE IF NOT EXISTS oauth_states (state_hash TEXT PRIMARY KEY, actor TEXT, session TEXT, connection TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS draft_requests (id TEXT PRIMARY KEY, actor TEXT, connection TEXT, fingerprint TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS assertion_nonces (nonce TEXT PRIMARY KEY, expires REAL);
CREATE TABLE IF NOT EXISTS broker_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS drafts (draft_id TEXT PRIMARY KEY, actor TEXT NOT NULL, connection TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS preferences (actor TEXT PRIMARY KEY, value TEXT NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sensor_grants (id TEXT PRIMARY KEY, actor TEXT NOT NULL, connection TEXT NOT NULL, scope TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, revoked REAL NOT NULL DEFAULT 0, issued_via TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS sensor_grants_by_person ON sensor_grants(actor, connection);
";

/// Columns the connections table gained after its first release.
const COLUMNS: [(&str, &str); 8] = [
    ("provider", "TEXT NOT NULL DEFAULT 'custom_secret'"),
    ("setup_request", "TEXT NOT NULL DEFAULT ''"),
    ("account", "TEXT NOT NULL DEFAULT ''"),
    ("setup_spec", "TEXT NOT NULL DEFAULT ''"),
    ("oauth_app_version", "INTEGER NOT NULL DEFAULT 0"),
    ("approved_host", "TEXT NOT NULL DEFAULT ''"),
    ("grants", "TEXT NOT NULL DEFAULT ''"),
    ("touched", "REAL NOT NULL DEFAULT 0"),
];
const OTHER_COLUMNS: [(&str, &str, &str); 1] = [("oauth_states", "grant_name", "TEXT NOT NULL DEFAULT ''")];

fn columns(c: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut s = c.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = s.query_map([], |r| r.get::<_, String>(1))?.collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

/// Create every table, then add each column an older database lacks.
pub fn open_schema(c: &mut Connection) -> rusqlite::Result<()> {
    let tx = c.transaction()?;
    tx.execute_batch(SCHEMA)?;
    let present = columns(&tx, "connections")?;
    for (name, decl) in COLUMNS {
        if !present.iter().any(|p| p == name) {
            tx.execute(&format!("ALTER TABLE connections ADD COLUMN {name} {decl}"), [])?;
        }
    }
    for (table, name, decl) in OTHER_COLUMNS {
        if !columns(&tx, table)?.iter().any(|p| p == name) {
            tx.execute(&format!("ALTER TABLE {table} ADD COLUMN {name} {decl}"), [])?;
        }
    }
    // Drafts recorded only in the idempotency rows are this broker's too.
    tx.execute(
        "INSERT OR IGNORE INTO drafts(draft_id, actor, connection, created) SELECT json_extract(result, '$.draft_id'), actor, connection, 0 FROM draft_requests WHERE result != '' AND json_valid(result) AND json_extract(result, '$.draft_id') IS NOT NULL",
        [],
    )?;
    tx.commit()
}

/// A broker-private HMAC key, generated once into the state directory (0600).
/// It derives PKCE verifiers and the draft idempotency fingerprint.
pub fn state_key(path: &Path) -> std::io::Result<Vec<u8>> {
    if let Ok(key) = std::fs::read(path) {
        if key.len() >= 32 {
            return Ok(key);
        }
    }
    let key = util::random_bytes(32);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &key)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(key)
}
