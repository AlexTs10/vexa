//! One logevent.v1 line: the envelope every Python service's `obs.py` prints,
//! in its key order, as compact ASCII JSON on stdout.

use std::io::Write;
use std::sync::Mutex;

use serde_json::{Map, Value};

static OUT: Mutex<()> = Mutex::new(());

pub struct Line<'a> {
    pub service: &'a str,
    pub level: &'a str,
    pub event: &'a str,
    /// The request's trace id; a fresh one is minted when None.
    pub trace_id: Option<&'a str>,
    pub audience: &'a str,
    pub user_id: Option<&'a str>,
    pub session: Option<&'a str>,
    /// Left out when None or an empty object.
    pub fields: Option<Value>,
}

impl Line<'_> {
    pub fn text(self) -> String {
        let mut line = Map::new();
        line.insert("ts".into(), Value::String(crate::ids::utc_stamp(crate::ids::now())));
        line.insert("level".into(), self.level.into());
        line.insert("service".into(), self.service.into());
        line.insert("trace_id".into(), self.trace_id.map(str::to_owned).unwrap_or_else(crate::ids::uuid_hex).into());
        line.insert("audience".into(), self.audience.into());
        line.insert("event".into(), self.event.into());
        if let Some(user) = self.user_id {
            line.insert("user_id".into(), user.into());
        }
        if let Some(session) = self.session {
            line.insert("session".into(), session.into());
        }
        if let Some(fields) = self.fields.filter(|f| f.as_object().is_some_and(|o| !o.is_empty())) {
            line.insert("fields".into(), fields);
        }
        crate::pyjson::py_dumps_compact(&Value::Object(line))
    }

    /// Print the line on stdout, whole (one writer at a time).
    pub fn emit(self) {
        let text = self.text();
        let _guard = OUT.lock();
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{text}");
        let _ = out.flush();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn envelope_order() {
        let text = super::Line { service: "s", level: "info", event: "e", trace_id: Some("t"), audience: "system",
                                 user_id: None, session: Some("x"), fields: Some(serde_json::json!({})) }.text();
        let rest = text.split_once(",\"level\"").unwrap().1;
        assert_eq!(rest, r#":"info","service":"s","trace_id":"t","audience":"system","event":"e","session":"x"}"#);
    }
}
