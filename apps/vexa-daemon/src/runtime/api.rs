//! The runtime.v1 and schedule.v1 HTTP surface. Every route except
//! `/health` needs the caller token as a bearer credential. Errors keep the
//! FastAPI shapes: `{"detail": "..."}`, and a list of issues for a 422.

use std::collections::BTreeMap;

use vexa_native_kit::http::{decode, Request, Response};
use vexa_native_kit::json::{self, object, Value};
use vexa_native_kit::sha256::constant_time_eq;

use super::kernel::{CreateError, Spec, StopReason};
use super::scheduler::ScheduleError;
use super::Runtime;

const MAX_AVOID_NODES: usize = 10;

fn detail(status: u16, text: &str) -> Response {
    Response::json(status, json::write(&object(vec![("detail", text.into())])))
}

fn issue(kind: &str, loc: &[&str], msg: &str, input: Value) -> Value {
    object(vec![
        ("type", kind.into()),
        ("loc", Value::Array(loc.iter().map(|l| (*l).into()).collect())),
        ("msg", msg.into()),
        ("input", input),
    ])
}

fn unprocessable(issues: Vec<Value>) -> Response {
    Response::json(422, json::write(&object(vec![("detail", Value::Array(issues))])))
}

fn body_json(request: &Request) -> Result<Option<Value>, Response> {
    if request.body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&request.body);
    json::parse(&text)
        .map(Some)
        .map_err(|e| unprocessable(vec![issue("json_invalid", &["body", "0"], "JSON decode error", object(vec![("error", e.into())]))]))
}

fn dns1123_subdomain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
                && bytes[0] != b'-'
                && bytes[bytes.len() - 1] != b'-'
        })
}

fn optional_int(body: &Value, key: &str, issues: &mut Vec<Value>) {
    match body.get(key) {
        None | Some(Value::Null) => {}
        Some(v) if v.as_i64().is_some() => {}
        Some(Value::String(s)) if s.trim().parse::<i64>().is_ok() => {}
        Some(v) => issues.push(issue("int_type", &["body", key], "Input should be a valid integer", v.clone())),
    }
}

/// Validate a runtime.v1 WorkloadSpec (`extra="forbid"`).
fn parse_spec(body: Option<Value>) -> Result<Spec, Vec<Value>> {
    let body = match body {
        Some(b @ Value::Object(_)) => b,
        Some(other) => return Err(vec![issue("model_attributes_type", &["body"], "Input should be a valid dictionary or object to extract fields from", other)]),
        None => return Err(vec![issue("missing", &["body"], "Field required", Value::Null)]),
    };
    const FIELDS: [&str; 9] =
        ["workloadId", "profile", "env", "callbackUrl", "resources", "idleTimeoutSec", "maxLifetimeSec", "backend", "avoidNodes"];
    let mut issues = Vec::new();
    for (key, value) in body.as_object().unwrap_or(&[]) {
        if !FIELDS.contains(&key.as_str()) {
            issues.push(issue("extra_forbidden", &["body", key], "Extra inputs are not permitted", value.clone()));
        }
    }
    let text = |key: &str, issues: &mut Vec<Value>| match body.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => {
            issues.push(issue("string_type", &["body", key], "Input should be a valid string", other.clone()));
            None
        }
        None => {
            issues.push(issue("missing", &["body", key], "Field required", body.clone()));
            None
        }
    };
    let workload_id = text("workloadId", &mut issues);
    let profile = text("profile", &mut issues);
    let mut env = BTreeMap::new();
    match body.get("env") {
        Some(Value::Object(items)) => {
            for (k, v) in items {
                match v.as_str() {
                    Some(s) => {
                        env.insert(k.clone(), s.to_owned());
                    }
                    None => issues.push(issue("string_type", &["body", "env", k], "Input should be a valid string", v.clone())),
                }
            }
        }
        Some(other) => issues.push(issue("dict_type", &["body", "env"], "Input should be a valid dictionary", other.clone())),
        None => issues.push(issue("missing", &["body", "env"], "Field required", body.clone())),
    }
    let callback_url = match body.get("callbackUrl") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => {
            issues.push(issue("string_type", &["body", "callbackUrl"], "Input should be a valid string", other.clone()));
            None
        }
    };
    match body.get("resources") {
        None | Some(Value::Null) => {}
        Some(Value::Object(items)) => {
            for (k, v) in items {
                let ok = match k.as_str() {
                    "cpu" => v.is_null() || v.as_f64().is_some_and(|n| n >= 0.0),
                    "memoryMb" | "gpu" => v.is_null() || v.as_i64().is_some_and(|n| n >= 0),
                    _ => {
                        issues.push(issue("extra_forbidden", &["body", "resources", k], "Extra inputs are not permitted", v.clone()));
                        true
                    }
                };
                if !ok {
                    issues.push(issue("greater_than_equal", &["body", "resources", k], "Input should be a non-negative number", v.clone()));
                }
            }
        }
        Some(other) => issues.push(issue("model_type", &["body", "resources"], "Input should be a valid dictionary", other.clone())),
    }
    optional_int(&body, "idleTimeoutSec", &mut issues);
    optional_int(&body, "maxLifetimeSec", &mut issues);
    match body.get("backend") {
        None | Some(Value::Null) => {}
        Some(v) if matches!(v.as_str(), Some("docker" | "k8s" | "process")) => {}
        Some(v) => issues.push(issue("enum", &["body", "backend"], "Input should be 'docker', 'k8s' or 'process'", v.clone())),
    }
    match body.get("avoidNodes") {
        None | Some(Value::Null) => {}
        Some(Value::Array(nodes)) => {
            if nodes.len() > MAX_AVOID_NODES {
                let msg = format!("Value error, avoidNodes names {} nodes; at most {MAX_AVOID_NODES} are allowed", nodes.len());
                issues.push(issue("value_error", &["body", "avoidNodes"], &msg, Value::Array(nodes.clone())));
            } else if let Some(bad) = nodes.iter().find(|n| !n.as_str().is_some_and(dns1123_subdomain)) {
                let msg = format!(
                    "Value error, avoidNodes: {} is not a Kubernetes node name (a lowercase DNS-1123 subdomain of at most 253 characters)",
                    json::write(bad).replace('"', "'")
                );
                issues.push(issue("value_error", &["body", "avoidNodes"], &msg, Value::Array(nodes.clone())));
            }
        }
        Some(other) => issues.push(issue("list_type", &["body", "avoidNodes"], "Input should be a valid list", other.clone())),
    }
    match (workload_id, profile) {
        (Some(workload_id), Some(profile)) if issues.is_empty() => Ok(Spec { workload_id, profile, env, callback_url }),
        _ => Err(issues),
    }
}

fn status_json(status: Option<super::kernel::Status>) -> Response {
    match status {
        Some(s) => Response::json(200, json::write(&s.to_json())),
        None => detail(404, "unknown workload"),
    }
}

fn authorized(request: &Request, token: &str) -> bool {
    let header = request.header("authorization").unwrap_or("");
    let (scheme, presented) = header.split_once(' ').unwrap_or((header, ""));
    scheme.eq_ignore_ascii_case("bearer") && constant_time_eq(presented.trim().as_bytes(), token.as_bytes())
}

/// One request → one response.
pub fn handle(runtime: &Runtime, request: &Request) -> Response {
    let segments: Vec<String> = request.path.trim_start_matches('/').split('/').map(decode).collect();
    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
    let method = request.method.as_str();
    let allowed: &[&str] = match segments.as_slice() {
        ["health"] => &["GET"],
        ["workloads"] => &["GET", "POST"],
        ["workloads", _] => &["GET", "DELETE"],
        ["workloads", _, "stop"] => &["POST"],
        ["schedule"] => &["GET", "POST"],
        ["schedule", _] => &["DELETE"],
        _ => return detail(404, "Not Found"),
    };
    if !allowed.contains(&method) {
        return detail(405, "Method Not Allowed").with_header("Allow", &allowed.join(", "));
    }
    if segments != ["health"] && !authorized(request, &runtime.token) {
        return detail(401, "runtime caller credential required").with_header("WWW-Authenticate", "Bearer");
    }
    let body = if method == "POST" {
        match body_json(request) {
            Ok(body) => body,
            Err(response) => return response,
        }
    } else {
        None
    };
    let kernel = &runtime.kernel;
    match (method, segments.as_slice()) {
        ("GET", ["health"]) => health(runtime),
        ("POST", ["workloads"]) => {
            let spec = match parse_spec(body) {
                Ok(spec) => spec,
                Err(issues) => return unprocessable(issues),
            };
            let (id, profile) = (spec.workload_id.clone(), spec.profile.clone());
            let fields = |error: Option<&str>| {
                let mut f = object(vec![("workload_id", id.clone().into()), ("profile", profile.clone().into())]);
                if let Some(e) = error {
                    f.set("error", e.into());
                }
                f
            };
            match kernel.create(spec) {
                Ok(status) => {
                    runtime.log.event("workload_spawned", "system", "info", "workloads.create", fields(None));
                    Response::json(201, json::write(&status.to_json()))
                }
                Err(CreateError::StartFailed(error)) => {
                    runtime.log.event("workload_spawn_failed", "system", "error", "workloads.create", fields(Some(&error)));
                    detail(502, &error)
                }
                Err(CreateError::Invalid(error)) => detail(400, &error),
            }
        }
        ("GET", ["workloads"]) => {
            let all: Vec<Value> = kernel.list().iter().map(|s| s.to_json()).collect();
            Response::json(200, json::write(&Value::Array(all)))
        }
        ("GET", ["workloads", id]) => status_json(kernel.get(id)),
        ("POST", ["workloads", id, "stop"]) => {
            let reason = match body.as_ref().and_then(|b| b.get("reason")) {
                None | Some(Value::Null) => StopReason::Stopped,
                Some(v) => match v.as_str().and_then(StopReason::parse) {
                    Some(reason) => reason,
                    None => {
                        let names: Vec<String> = StopReason::ALL.iter().map(|r| format!("'{}'", r.as_str())).collect();
                        let msg = format!("Input should be {}", names.join(", "));
                        return unprocessable(vec![issue("enum", &["body", "reason"], &msg, v.clone())]);
                    }
                },
            };
            status_json(kernel.stop(id, reason))
        }
        ("DELETE", ["workloads", id]) => status_json(kernel.destroy(id)),
        (_, ["schedule", ..]) => schedule(runtime, method, &segments, body, request),
        _ => detail(404, "Not Found"),
    }
}

fn health(runtime: &Runtime) -> Response {
    let mut checks: Vec<(&str, Value)> = vec![("backend", true.into()), ("store", true.into())];
    if let Some(scheduler) = &runtime.scheduler {
        checks.push(("scheduler", scheduler.list(None, 1).is_ok().into()));
    }
    let healthy = checks.iter().all(|(_, ok)| ok.as_bool() == Some(true));
    let body = object(vec![
        ("status", if healthy { "ok" } else { "degraded" }.into()),
        ("checks", object(checks)),
        ("capabilities", runtime.declaration.capability_health(&runtime.kernel.parent_env)),
    ]);
    Response::json(if healthy { 200 } else { 503 }, json::write(&body))
}

fn schedule(runtime: &Runtime, method: &str, segments: &[&str], body: Option<Value>, request: &Request) -> Response {
    let Some(scheduler) = &runtime.scheduler else {
        return detail(503, "scheduler not wired");
    };
    let store_error = |e: String| detail(500, &format!("schedule store: {e}"));
    match (method, segments) {
        ("POST", ["schedule"]) => {
            let spec = match body {
                Some(spec @ Value::Object(_)) => spec,
                Some(other) => return unprocessable(vec![issue("dict_type", &["body"], "Input should be a valid dictionary", other)]),
                None => return unprocessable(vec![issue("missing", &["body"], "Field required", Value::Null)]),
            };
            match scheduler.schedule(&spec) {
                Ok(job) => Response::json(201, json::write(&job)),
                Err(ScheduleError::Invalid(e)) => detail(400, &e),
                Err(ScheduleError::Store(e)) => store_error(e),
            }
        }
        ("GET", ["schedule"]) => {
            let status = request.query_param("status");
            let limit = match request.query_param("limit") {
                None => 50,
                Some(raw) => match raw.trim().parse::<i64>() {
                    Ok(n) => n.max(0) as usize,
                    Err(_) => {
                        return unprocessable(vec![issue(
                            "int_parsing",
                            &["query", "limit"],
                            "Input should be a valid integer, unable to parse string as an integer",
                            raw.into(),
                        )])
                    }
                },
            };
            match scheduler.list(status.as_deref(), limit) {
                Ok(jobs) => Response::json(200, json::write(&Value::Array(jobs))),
                Err(e) => store_error(e),
            }
        }
        ("DELETE", ["schedule", job_id]) => match scheduler.cancel(job_id) {
            Ok(Some(job)) => Response::json(200, json::write(&job)),
            Ok(None) => detail(404, "unknown job"),
            Err(e) => store_error(e),
        },
        _ => detail(404, "Not Found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_specs_like_the_python_model() {
        let ok = json::parse(r#"{"workloadId":"w","profile":"agent","env":{"A":"b"},"avoidNodes":["node-1.x"],"resources":{"cpu":0.5}}"#).unwrap();
        let spec = parse_spec(Some(ok)).unwrap();
        assert_eq!((spec.workload_id.as_str(), spec.env.get("A").map(String::as_str)), ("w", Some("b")));
        let types = |text: &str| -> Vec<String> {
            parse_spec(Some(json::parse(text).unwrap()))
                .err()
                .unwrap_or_default()
                .iter()
                .map(|i| i.get("type").and_then(Value::as_str).unwrap_or("").to_owned())
                .collect()
        };
        assert_eq!(types(r#"{"profile":"a","env":{}}"#), ["missing"]);
        assert_eq!(types(r#"{"workloadId":"w","profile":"a","env":{"A":1}}"#), ["string_type"]);
        assert_eq!(types(r#"{"workloadId":"w","profile":"a","env":{},"x":1}"#), ["extra_forbidden"]);
        assert_eq!(types(r#"{"workloadId":"w","profile":"a","env":{},"resources":{"cpu":-1}}"#), ["greater_than_equal"]);
        assert_eq!(types(r#"{"workloadId":"w","profile":"a","env":{},"avoidNodes":["Bad_Node"]}"#), ["value_error"]);
        assert_eq!(types(r#"{"workloadId":"w","profile":"a","env":{},"backend":"vm"}"#), ["enum"]);
        assert!(parse_spec(None).is_err());
    }

    #[test]
    fn checks_node_names() {
        assert!(dns1123_subdomain("worker-3.eu-west"));
        assert!(!dns1123_subdomain("-x") && !dns1123_subdomain("A") && !dns1123_subdomain("a..b"));
    }
}
