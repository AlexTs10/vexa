//! Sensor grants: a person lets flows' sensors read ONE calendar connection of
//! theirs, for a while. The sensors key is one key for the deployment, so a
//! grant, which only the person issues, decides whose calendar is read.

use serde_json::{json, Value};

use crate::broker::{row_f64, row_text, Broker, Row};
use crate::fail::R;
use crate::util;

pub const SCOPE: &str = "calendar.read";
pub const MAX_DAYS: i64 = 90;
pub const DAY_S: f64 = 86400.0;
pub const ADOPT_WINDOW_S: f64 = 14.0 * DAY_S;
pub const ADOPT_DAYS: i64 = 30;
const ADOPTED: &str = "sensor_grants_adopted";

pub fn status(row: &Row, now: f64) -> &'static str {
    if util::truthy(row.get("revoked")) {
        "revoked"
    } else if row_f64(row, "expires") <= now {
        "expired"
    } else {
        "active"
    }
}

/// credential-broker.v1 SensorGrant.
pub fn view(row: &Row, now: f64) -> Value {
    let via = row_text(row, "issued_via");
    json!({
        "grant_id": row["id"], "connection_id": row["connection"], "scope": row["scope"],
        "created": row["created"], "expires": row["expires"], "status": status(row, now),
        "issued_via": if via.is_empty() { "person" } else { via },
    })
}

/// A new live grant on connection; an earlier live one on it is revoked.
pub fn issue(b: &Broker, actor: &str, connection: &str, days: i64, via: &str, now: f64) -> R<Row> {
    let days = days.clamp(1, MAX_DAYS);
    let gid = util::uuid_hex();
    {
        let _g = b.lock.lock();
        b.exec("UPDATE sensor_grants SET revoked=? WHERE actor=? AND connection=? AND revoked=0", &[&now, &actor, &connection])?;
        b.exec(
            "INSERT INTO sensor_grants(id,actor,connection,scope,created,expires,revoked,issued_via) VALUES (?,?,?,?,?,?,0,?)",
            &[&gid, &actor, &connection, &SCOPE, &now, &(now + days as f64 * DAY_S), &via],
        )?;
    }
    b.one("SELECT * FROM sensor_grants WHERE id=?", &[&gid])?.ok_or(crate::fail::Fail::Internal)
}

/// The newest grant this person gave on this connection, live or not.
pub fn latest(b: &Broker, actor: &str, connection: &str) -> R<Option<Row>> {
    b.one("SELECT * FROM sensor_grants WHERE actor=? AND connection=? AND scope=? ORDER BY created DESC", &[&actor, &connection, &SCOPE])
}

/// The ready calendar connection with this person's newest live grant.
pub fn granted_connection(b: &Broker, actor: &str, now: f64) -> R<Option<String>> {
    let row = b.one(
        "SELECT g.connection FROM sensor_grants g JOIN connections c ON c.id=g.connection WHERE g.actor=? AND c.actor=? AND g.scope=? AND g.revoked=0 AND g.expires>? AND c.status='ready' AND c.provider='google_calendar' ORDER BY g.created DESC",
        &[&actor, &actor, &SCOPE, &now],
    )?;
    Ok(row.map(|r| row_text(&r, "connection").to_owned()))
}

/// The upgrade step: once per state directory, a calendar the broker's own
/// audit shows a sensor read successfully in the last 14 days gets a 30-day grant.
pub fn adopt(b: &Broker, now: f64) -> R<usize> {
    let _g = b.lock.lock();
    if b.one("SELECT 1 FROM broker_meta WHERE key=?", &[&ADOPTED])?.is_some() {
        return Ok(0);
    }
    let pairs = b.rows(
        "SELECT DISTINCT a.actor AS actor, a.connection AS connection FROM audit a JOIN connections c ON c.id=a.connection AND c.actor=a.actor WHERE a.action='calendar.changes' AND a.outcome='success' AND a.at>=? AND c.status='ready' AND c.provider='google_calendar'",
        &[&(now - ADOPT_WINDOW_S)],
    )?;
    let mut issued = 0;
    for p in pairs {
        let (actor, connection) = (row_text(&p, "actor"), row_text(&p, "connection"));
        if latest(b, actor, connection)?.is_none() {
            issue(b, actor, connection, ADOPT_DAYS, "upgrade", now)?;
            issued += 1;
        }
    }
    b.exec("INSERT OR REPLACE INTO broker_meta(key, value) VALUES (?, ?)", &[&ADOPTED, &util::py_float(now)])?;
    Ok(issued)
}
