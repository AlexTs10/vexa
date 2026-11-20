//! The audit expires on schedule: `crm_purge_audit()` once an hour (retention.py).

use std::sync::Arc;
use std::time::Duration;

use crate::store::Store;

pub const PURGE_EVERY_S: u64 = 3600;

pub fn purge_audit(store: &Store) -> crate::err::R<i64> {
    store.engine_begin(|c| Ok(c.scalar("SELECT crm_purge_audit()", &[])?.and_then(|v| v.as_i64()).unwrap_or(0)))
}

pub fn start(store: Arc<Store>) {
    std::thread::Builder::new()
        .name("crm-audit-retention".into())
        .spawn(move || loop {
            match purge_audit(&store) {
                Ok(n) if n > 0 => eprintln!("INFO:crm.retention:audit retention: {n} row(s) past the period removed"),
                Ok(_) => {}
                Err(e) => eprintln!("ERROR:crm.retention:audit retention pass failed ({})", e.class),
            }
            std::thread::sleep(Duration::from_secs(PURGE_EVERY_S));
        })
        .expect("spawn the retention thread");
}
