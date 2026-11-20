//! Shared building blocks of the native Vexa Mac processes (`vexa-daemon`,
//! `vexa-stt`, `vexa-credential-broker`, `vexa-mcp`). The default build has no
//! external crates; the `py` feature adds the serde_json-based modules.

pub mod b64;
pub mod binary;
pub mod client;
pub mod http;
pub mod httpd;
pub mod ids;
pub mod json;
pub mod reason;
pub mod sha256;

#[cfg(feature = "py")]
pub mod logevent;
#[cfg(feature = "py")]
pub mod pyjson;
