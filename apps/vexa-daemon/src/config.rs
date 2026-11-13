//! The native stack configuration: `config/native.env` in the Vexa folder.
//!
//! The file holds the ports, the generated secrets and any operator setting
//! (for example a model API key). The daemon creates it with mode 0600 and
//! mints every missing secret on start. It never prints a secret.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Hex secrets of 32 random bytes, minted when missing or empty.
pub const HEX_SECRETS: [&str; 20] = [
    "ADMIN_TOKEN",
    "INTERNAL_API_SECRET",
    "RUNTIME_API_TOKEN",
    "DB_PASSWORD",
    "REDIS_PASSWORD",
    "VEXA_MCP_DELEGATION_SECRET",
    "VEXA_MODEL_PROXY_SECRET",
    "VEXA_DISPATCH_SIGNING_KEY",
    "VEXA_FLOWS_API_KEY",
    "VEXA_FLOWS_SERVICE_KEY",
    "VEXA_FLOWS_TIMELINE_KEY",
    "VEXA_FLOWS_CRM_PUBLISH_KEY",
    "NEXTAUTH_SECRET",
    "VEXA_TERMINAL_SESSION_SECRET",
    "VEXA_SESSIONS_DB_PASSWORD",
    "VEXA_SESSIONS_S3_SECRET_KEY",
    "VEXA_PHOTOS_S3_SECRET_KEY",
    "MINIO_SECRET_KEY",
    "CRM_DB_PASSWORD",
    "TRANSCRIPTION_SERVICE_TOKEN",
];

/// Access-key style identifiers: a prefix plus 12 random bytes in hex.
pub const PREFIXED_IDS: [(&str, &str); 3] = [
    ("MINIO_ACCESS_KEY", "vexa-"),
    ("VEXA_SESSIONS_S3_ACCESS_KEY", "vexa-sessions-"),
    ("VEXA_PHOTOS_S3_ACCESS_KEY", "vexa-photos-"),
];

/// Non-secret defaults. The native ports use the 23xxx range so the native
/// stack can run beside the Compose stack (18xxx/13xxx) during migration.
pub const DEFAULTS: [(&str, &str); 31] = [
    ("VEXA_PG_PORT", "23432"),
    ("VEXA_REDIS_PORT", "23379"),
    ("VEXA_STORAGE_PORT", "23900"),
    ("VEXA_STT_PORT", "23083"),
    ("VEXA_ADMIN_API_PORT", "23001"),
    ("VEXA_MEETING_API_PORT", "23080"),
    ("VEXA_RUNTIME_PORT", "23090"),
    ("VEXA_AGENT_API_PORT", "23100"),
    ("VEXA_MODEL_PROXY_PORT", "23102"),
    ("VEXA_GATEWAY_PORT", "23056"),
    ("VEXA_GATEWAY_SERVICE_DOOR_PORT", "23002"),
    ("VEXA_MCP_PORT", "23010"),
    ("VEXA_FLOWS_PORT", "23200"),
    ("VEXA_CRM_PORT", "23300"),
    ("VEXA_CREDENTIAL_BROKER_PORT", "23110"),
    ("VEXA_SIGNALS_PORT", "23310"),
    ("VEXA_TERMINAL_PORT", "23000"),
    ("DB_NAME", "vexa"),
    ("DB_USER", "postgres"),
    ("MINIO_BUCKET", "vexa"),
    ("VEXA_SESSIONS_S3_BUCKET", "vexa-sessions"),
    ("CRM_DB_USER", "vexa_crm"),
    ("CRM_ORG_ID", "local"),
    ("CRM_ORG_NAME", "Vexa Local"),
    ("LOG_LEVEL", "info"),
    ("VEXA_ENV", "development"),
    ("VEXA_CONNECTIONS_STORE", "local"),
    ("VEXA_PERSON_GRAVATAR", "true"),
    ("VOICE_NOTE_MAX_DURATION_SEC", "1800"),
    ("VOICE_NOTE_IDLE_TIMEOUT_SEC", "120"),
    ("TRANSCRIPTION_MODEL", "whisper-1"),
];

#[derive(Clone, Debug, Default)]
pub struct NativeEnv {
    pub values: BTreeMap<String, String>,
}

impl NativeEnv {
    pub fn get(&self, key: &str) -> String {
        self.values.get(key).cloned().unwrap_or_default()
    }

    pub fn port(&self, key: &str) -> u16 {
        self.get(key)
            .parse()
            .unwrap_or_else(|_| panic!("{key} in native.env is not a port number"))
    }
}

pub fn parse(text: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            values.insert(key.trim().to_owned(), value.to_owned());
        }
    }
    values
}

pub fn random_hex(bytes: usize) -> Result<String, String> {
    let mut buffer = vec![0_u8; bytes];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buffer))
        .map_err(|error| format!("cannot read random bytes: {error}"))?;
    Ok(buffer.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Fill every missing default and secret. Returns the keys that were added.
pub fn complete(values: &mut BTreeMap<String, String>) -> Result<Vec<String>, String> {
    let mut added = Vec::new();
    for (key, value) in DEFAULTS {
        if values.get(key).map_or(true, |v| v.is_empty()) {
            values.insert(key.to_owned(), value.to_owned());
            added.push(key.to_owned());
        }
    }
    for key in HEX_SECRETS {
        if values.get(key).map_or(true, |v| v.is_empty()) {
            values.insert(key.to_owned(), random_hex(32)?);
            added.push(key.to_owned());
        }
    }
    for (key, prefix) in PREFIXED_IDS {
        if values.get(key).map_or(true, |v| v.is_empty()) {
            values.insert(key.to_owned(), format!("{prefix}{}", random_hex(12)?));
            added.push(key.to_owned());
        }
    }
    Ok(added)
}

fn render(values: &BTreeMap<String, String>) -> String {
    let mut text = String::from(
        "# Vexa native stack settings. The daemon mints missing secrets on start.\n\
         # Keep this file private (mode 0600). Add operator settings here, for\n\
         # example ANTHROPIC_API_KEY=... or VEXA_ADMIN_EMAILS=you@example.com.\n",
    );
    for (key, value) in values {
        // Quote a value with spaces, so a shell can also read the file.
        if value.contains(char::is_whitespace) && !value.starts_with('"') {
            text.push_str(&format!("{key}=\"{value}\"\n"));
        } else {
            text.push_str(&format!("{key}={value}\n"));
        }
    }
    text
}

pub fn path(config_dir: &Path) -> PathBuf {
    config_dir.join("native.env")
}

/// Load `native.env`, add missing values, and write it back when it changed.
pub fn load_or_create(config_dir: &Path) -> Result<NativeEnv, String> {
    fs::create_dir_all(config_dir).map_err(|error| error.to_string())?;
    let file = path(config_dir);
    let mut values = match fs::read_to_string(&file) {
        Ok(text) => parse(&text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(format!("cannot read {}: {error}", file.display())),
    };
    let added = complete(&mut values)?;
    if !added.is_empty() || !file.exists() {
        write_private(&file, render(&values).as_bytes())?;
        println!(
            "vexa-daemon: {} has {} new value(s): {}",
            file.display(),
            added.len(),
            added.join(", ")
        );
    }
    Ok(NativeEnv { values })
}

/// Write a file that only the current user can read.
pub fn write_private(file: &Path, contents: &[u8]) -> Result<(), String> {
    let mut handle = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(file)
        .map_err(|error| format!("cannot write {}: {error}", file.display()))?;
    fs::set_permissions(file, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    handle
        .write_all(contents)
        .map_err(|error| format!("cannot write {}: {error}", file.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comments_quotes_and_blank_lines() {
        let values = parse("# c\n\nA=1\nB=\"two\"\n C = 3 \n");
        assert_eq!(values["A"], "1");
        assert_eq!(values["B"], "two");
        assert_eq!(values["C"], "3");
    }

    #[test]
    fn mints_only_missing_values() {
        let mut values = BTreeMap::new();
        values.insert("DB_PASSWORD".to_owned(), "kept".to_owned());
        values.insert("REDIS_PASSWORD".to_owned(), String::new());
        let added = complete(&mut values).unwrap();
        assert_eq!(values["DB_PASSWORD"], "kept");
        assert_eq!(values["REDIS_PASSWORD"].len(), 64);
        assert!(values["MINIO_ACCESS_KEY"].starts_with("vexa-"));
        assert!(added.contains(&"REDIS_PASSWORD".to_owned()));
        assert!(!added.contains(&"DB_PASSWORD".to_owned()));
        assert!(complete(&mut values).unwrap().is_empty());
    }

    #[test]
    fn writes_a_private_file_and_keeps_values_across_loads() {
        let dir = std::env::temp_dir().join(format!("vexa-config-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = load_or_create(&dir).unwrap();
        let mode = fs::metadata(path(&dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let second = load_or_create(&dir).unwrap();
        assert_eq!(first.get("DB_PASSWORD"), second.get("DB_PASSWORD"));
        assert_eq!(second.port("VEXA_PG_PORT"), 23432);
        let text = fs::read_to_string(path(&dir)).unwrap();
        assert!(text.contains("CRM_ORG_NAME=\"Vexa Local\""));
        assert_eq!(second.get("CRM_ORG_NAME"), "Vexa Local");
    }
}
