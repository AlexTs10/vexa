//! Durable RuntimeEvent callback delivery: each event is posted at once to
//! its workload's `callbackUrl`, signed (`X-Runtime-Signature`); a delivery
//! the receiver does not acknowledge stays pending and a later sweep retries it.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use vexa_native_kit::http;
use vexa_native_kit::json::{self, Value};
use vexa_native_kit::sha256;

use super::Log;

pub const SIGNATURE_HEADER: &str = "X-Runtime-Signature";
const CALLBACK_LABEL: &[u8] = b"vexa-runtime-callback.v2";

/// What a callback signature covers: the signing time, the delivery URL and
/// the canonical event.
pub fn callback_message(timestamp: i64, url: &str, event: &Value) -> Vec<u8> {
    let mut message = format!("{timestamp}\n{url}\n").into_bytes();
    message.extend(json::canonical(event).as_bytes());
    message
}

/// `t=<unix seconds>,v2=<hex>`: an HMAC keyed from the caller token, so the
/// token itself never travels to a callback URL.
pub fn sign_callback(token: &str, event: &Value, url: &str, timestamp: i64) -> String {
    let key = sha256::hmac(token.as_bytes(), CALLBACK_LABEL);
    let digest = sha256::hmac(&key, &callback_message(timestamp, url, event));
    format!("t={timestamp},v2={}", sha256::hex(&digest))
}

struct Pending {
    url: String,
    event: Value,
    attempts: u32,
}

pub struct CallbackQueue {
    token: String,
    pending: Mutex<BTreeMap<u64, Pending>>,
    seq: Mutex<u64>,
}

impl CallbackQueue {
    pub fn new(token: String) -> Self {
        Self { token, pending: Mutex::new(BTreeMap::new()), seq: Mutex::new(0) }
    }

    /// Record a delivery and try it once now.
    pub fn enqueue(&self, url: &str, event: Value, log: &Log) {
        let key = {
            let mut seq = self.seq.lock().unwrap_or_else(|e| e.into_inner());
            *seq += 1;
            *seq
        };
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, Pending { url: url.to_owned(), event, attempts: 0 });
        self.attempt(key, log);
    }

    fn attempt(&self, key: u64, log: &Log) {
        let (url, event, attempts) = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            let Some(record) = pending.get_mut(&key) else { return };
            record.attempts += 1;
            (record.url.clone(), record.event.clone(), record.attempts)
        };
        // Signed when it is sent, so a retry carries a fresh time.
        let timestamp = super::clock::now() as i64;
        let headers = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            (SIGNATURE_HEADER.to_owned(), sign_callback(&self.token, &event, &url, timestamp)),
        ];
        let body = json::write(&event);
        match http::send("POST", &url, &headers, body.as_bytes(), Duration::from_secs(10)) {
            Ok(answer) if answer.status < 400 => {
                self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
                log.line(&format!("callback cb-{key} delivered (attempt {attempts}) -> {}", answer.status));
            }
            Ok(answer) => log.line(&format!("callback cb-{key} got {} (attempt {attempts})", answer.status)),
            Err(error) => log.line(&format!("callback cb-{key} delivery failed (attempt {attempts}): {error}")),
        }
    }

    /// Try every pending delivery once. Returns how many stay pending.
    pub fn sweep(&self, log: &Log) -> usize {
        let keys: Vec<u64> = self.pending.lock().unwrap_or_else(|e| e.into_inner()).keys().copied().collect();
        for key in keys {
            self.attempt(key, log);
        }
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_the_contract_golden() {
        let golden = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../core/runtime/contracts/runtime.v1/golden/signed-event-stopped.json"
        ))
        .unwrap();
        let golden = json::parse(&golden).unwrap();
        let text = |k: &str| golden.get(k).unwrap().as_str().unwrap().to_owned();
        let signature = sign_callback(
            &text("token"),
            golden.get("event").unwrap(),
            &text("url"),
            golden.get("timestamp").unwrap().as_i64().unwrap(),
        );
        assert_eq!(signature, text("signature"));
    }
}
