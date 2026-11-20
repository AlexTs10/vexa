//! crm-api's boot check, as its own role: not a superuser, and the schema version this code knows.
//! Creating and upgrading the schema is the migrations path's (`python -m crm.migrate init|migrate`).

use std::sync::Arc;

use serde_json::Value;
use vexa_native_kit::pg::{PgError, Pool};

pub const SCHEMA_VERSION: i64 = crate::schema::SCHEMA_VERSION;

/// The driver exception's class name: a server error is pg8000's ProgrammingError, a failure
/// with no server answer its InterfaceError.
fn class_of(e: &PgError) -> &'static str {
    if e.code.is_some() { "ProgrammingError" } else { "InterfaceError" }
}

/// crm-api's boot check. Err (SchemaNotReady): a superuser login, no schema yet, or another version.
pub fn check(pool: &Arc<Pool>) -> Result<(), String> {
    let not_there = |e: PgError| format!("the CRM's schema is not there yet ({})", class_of(&e));
    let got = {
        let mut c = pool.begin().map_err(not_there)?;
        let row = c.first("SELECT rolsuper FROM pg_roles WHERE rolname = current_user", &[]).map_err(not_there)?;
        if row.is_none() || row.is_some_and(|v| crate::val::truthy(&v)) {
            return Err("crm-api refuses a superuser login; give it its own role (CRM_DB_USER, created by \
                        `python -m crm.migrate init`)".into());
        }
        c.first("SELECT version FROM crm_schema", &[]).map_err(not_there)?
    };
    match got {
        Some(Value::Number(n)) if n.as_i64() == Some(SCHEMA_VERSION) => Ok(()),
        Some(v) => Err(format!("the CRM's schema version is {}, this crm-api knows {SCHEMA_VERSION}", vexa_native_kit::pyjson::py_str(&v))),
        None => Err(format!("the CRM's schema version is unset, this crm-api knows {SCHEMA_VERSION}")),
    }
}
