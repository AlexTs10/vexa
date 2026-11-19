//! A person's custom service: the human-configured HTTPS credential use
//! (secret_service) and its declarative OAuth authorization-code adapter
//! (service_oauth). DNS is resolved, checked and pinned per request. A refusal
//! the person can act on is Fail::Service; a service that cannot be reached or
//! answers unreadably is Fail::Upstream with source "service".

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::fail::{Fail, R};
use crate::net::{self, NetError, Request};
use crate::{ssrf, util};

pub const USER_AGENT: &str = "vexa-credential-broker";
pub const SERVICE_DEADLINE_S: f64 = 12.0;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_PAUSE_S: f64 = 0.5;
const MIN_ATTEMPT_S: f64 = 2.0;
const RESPONSE_MAX: usize = 262_144;

fn svc(s: &str) -> Fail {
    Fail::service(s)
}

pub fn validate_endpoint(endpoint: &str) -> R<util::Split> {
    let refused = || svc("Use an exact public HTTPS endpoint without query, fragment, or credentials");
    let u = util::urlsplit(endpoint).map_err(|_| refused())?;
    let port = u.port().map_err(|_| refused())?;
    let nonempty = |o: Option<String>| o.is_some_and(|s| !s.is_empty());
    if u.scheme != "https" || u.hostname().is_none() || !matches!(port, None | Some(443)) || nonempty(u.username()) || nonempty(u.password()) || !u.fragment.is_empty() || !u.query.is_empty() {
        return Err(refused());
    }
    if !u.path.starts_with('/') || u.path.contains("..") || u.path.contains('%') || endpoint.contains('\\') {
        return Err(refused());
    }
    Ok(u)
}

fn is_prefix(p: &str) -> bool {
    (1..=32).contains(&p.chars().count()) && p.chars().all(|c| c.is_ascii_alphanumeric() || "!#$&'*+.^_~|~-".contains(c) || c == '\u{60}')
}

fn is_header(h: &str) -> bool {
    let mut cs = h.chars();
    cs.next().is_some_and(|c| c.is_ascii_alphabetic()) && h.len() <= 64 && cs.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn is_telegram_token(s: &str) -> bool {
    match s.split_once(':') {
        Some((id, rest)) => !id.is_empty() && id.bytes().all(|c| c.is_ascii_digit()) && !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
        None => false,
    }
}

const TELEGRAM: [&str; 3] = [
    "https://api.telegram.org/bot{secret}/sendMessage",
    "https://api.telegram.org/bot{secret}/getMe",
    "https://api.telegram.org/bot{secret}/getUpdates",
];

/// The stored configuration of a custom secret, or the refusal.
pub fn configure(secret: &str, endpoint: &str, header: &str, scheme: &str, method: &str, prefix: &str) -> R<Value> {
    if !prefix.is_empty() && scheme != "prefix" {
        return Err(svc("An authentication prefix needs scheme prefix"));
    }
    if scheme == "prefix" && !is_prefix(prefix) {
        return Err(svc("Use an authentication prefix of letters, digits or dashes, such as Bot or Token"));
    }
    if secret.is_empty() || secret.chars().count() > 65536 {
        return Err(svc("Enter a secret value"));
    }
    if !endpoint.is_empty() {
        validate_endpoint(endpoint)?;
        let lower = header.to_lowercase();
        if !is_header(header) || ["host", "cookie", "content-length", "connection", "transfer-encoding", "proxy-authorization"].contains(&lower.as_str()) {
            return Err(svc("Use an authentication header such as Authorization or X-API-Key"));
        }
        if scheme == "telegram" {
            if !TELEGRAM.contains(&endpoint) || !is_telegram_token(secret) {
                return Err(svc("Invalid Telegram bot token or endpoint"));
            }
            if method != if endpoint.ends_with("/sendMessage") { "POST" } else { "GET" } {
                return Err(svc("Invalid Telegram method"));
            }
        }
        if !["bearer", "raw", "telegram", "prefix"].contains(&scheme) || !["GET", "POST"].contains(&method) {
            return Err(svc("Unsupported authentication or method"));
        }
        if secret.chars().any(|c| (c as u32) < 32 || (c as u32) > 126) {
            return Err(svc("HTTP authentication needs a single-line ASCII credential; omit the endpoint to store other secret types"));
        }
    }
    let mut out = json!({"value": secret, "endpoint": endpoint, "header": header, "scheme": scheme, "method": method});
    if scheme == "prefix" {
        out["prefix"] = json!(prefix);
    }
    Ok(out)
}

fn authorization(c: &Value) -> String {
    let value = util::text(c, "value");
    match util::text(c, "scheme") {
        "bearer" => format!("Bearer {value}"),
        "prefix" => format!("{} {value}", util::text(c, "prefix")),
        _ => value.to_owned(),
    }
}

/// Every address host resolves to, each one public.
pub fn public_addresses(host: &str) -> R<Vec<IpAddr>> {
    match net::resolve(host, 443) {
        Ok(ips) if !ips.is_empty() && !ips.iter().any(ssrf::is_blocked_ip) => Ok(ips),
        Ok(_) => Err(svc("Service must resolve only to public addresses")),
        Err(NetError::NoName) => Err(svc("Service host name does not resolve; check the configured endpoint")),
        Err(_) => Err(Fail::upstream("service", "unreachable", "Service address could not be resolved; retry later")),
    }
}

fn late() -> String {
    format!("Service did not answer within {} s; do not automatically retry a POST", SERVICE_DEADLINE_S as i64)
}

fn str_of(v: Option<&Value>, default: &str) -> String {
    v.and_then(Value::as_str).unwrap_or(default).to_owned()
}

fn pairs(v: Option<&Value>) -> Vec<(String, Value)> {
    v.and_then(Value::as_object).map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default()
}

/// One call to a connected service, retry included, within SERVICE_DEADLINE_S.
pub fn execute(config: &Value, parameters: &[(String, String)], body: Option<&Map<String, Value>>) -> R<Value> {
    let c = configure(
        util::text(config, "value"),
        &str_of(config.get("endpoint"), ""),
        &str_of(config.get("header"), "Authorization"),
        &str_of(config.get("scheme"), "bearer"),
        &str_of(config.get("method"), "GET"),
        &str_of(config.get("prefix"), ""),
    )?;
    let endpoint = util::text(&c, "endpoint").to_owned();
    if endpoint.is_empty() {
        return Err(svc("Configure an HTTPS endpoint in the secure panel before use"));
    }
    let u = validate_endpoint(&endpoint)?;
    let host = u.hostname().unwrap_or_default();
    let ips = public_addresses(&host)?;
    if parameters.len() > 30 || parameters.iter().any(|(k, v)| k.chars().count() > 100 || v.chars().count() > 2000) {
        return Err(svc("Invalid query parameters"));
    }
    let method = util::text(&c, "method").to_owned();
    if method == "GET" && body.is_some() {
        return Err(svc("This connection allows GET only"));
    }
    let fixed_body = pairs(config.get("fixed_body"));
    let fixed_query = pairs(config.get("fixed_query"));
    if fixed_body.iter().any(|(k, _)| parameters.iter().any(|(p, _)| p == k)) {
        return Err(svc("Saved body fields cannot be supplied as query parameters"));
    }
    if fixed_query.iter().any(|(k, _)| body.is_some_and(|b| b.contains_key(k))) {
        return Err(svc("Saved query fields cannot be supplied in the body"));
    }
    let mut params: Vec<(String, String)> = parameters.to_vec();
    for (k, v) in &fixed_query {
        let v = util::py_str(v);
        match params.iter_mut().find(|(p, _)| p == k) {
            Some((_, existing)) if *existing != v => return Err(svc("A saved connection field cannot be overridden; update it in Connections")),
            Some(_) => {}
            None => params.push((k.clone(), v)),
        }
    }
    let mut body: Option<Map<String, Value>> = body.cloned();
    if !fixed_body.is_empty() {
        let b = body.get_or_insert_with(Map::new);
        for (k, v) in &fixed_body {
            if b.get(k).is_some_and(|x| x != v) {
                return Err(svc("A saved connection field cannot be overridden; update it in Connections"));
            }
            b.insert(k.clone(), v.clone());
        }
    }
    let raw = body.map(|b| util::py_dumps(&Value::Object(b)).into_bytes());
    if raw.as_ref().is_some_and(|r| r.len() > 65536) {
        return Err(svc("Request body too large"));
    }
    let value = util::text(&c, "value").to_owned();
    let header = util::text(&c, "header").to_owned();
    let telegram = util::text(&c, "scheme") == "telegram";
    let mut path = u.path.clone();
    if telegram {
        path = path.replace("{secret}", &value);
    }
    let query: Vec<(&str, String)> = params.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    let url = format!("https://{host}{path}{}", if params.is_empty() { String::new() } else { format!("?{}", util::urlencode(&query)) });
    let start = Instant::now();
    let left = || SERVICE_DEADLINE_S - start.elapsed().as_secs_f64();
    let attempt = || -> Result<net::Answer, NetError> {
        let remaining = left();
        if remaining <= 0.0 {
            return Err(NetError::Timeout);
        }
        let mut req = Request::new(&method, &url, Duration::from_secs_f64(remaining));
        req.connect_timeout = CONNECT_TIMEOUT.min(Duration::from_secs_f64(remaining));
        req.pin = Some(ips[0]);
        req.limit = RESPONSE_MAX;
        req = req.header("User-Agent", USER_AGENT);
        if !telegram {
            req = req.header(&header, &authorization(&c));
        }
        req = req.header("Accept", "application/json").header("Content-Type", "application/json");
        if let Some(r) = &raw {
            req.body = r.clone();
        }
        net::send(&req)
    };
    let mut tries = 0;
    let answer = loop {
        let (failure, safe) = match attempt() {
            Ok(a) => break a,
            Err(NetError::Connect) => ("unreachable", true),
            Err(NetError::Timeout) => ("late", method == "GET"),
            Err(NetError::Protocol) => ("bad_answer", method == "GET"),
            Err(_) => ("unreachable", method == "GET"),
        };
        if safe && tries == 0 && left() - RETRY_PAUSE_S >= MIN_ATTEMPT_S {
            tries += 1;
            std::thread::sleep(Duration::from_secs_f64(RETRY_PAUSE_S));
            continue;
        }
        return Err(match failure {
            "late" => Fail::upstream("service", "unreachable", &late()),
            "bad_answer" => Fail::upstream("service", "bad_answer", "Service answered with an unreadable response; do not automatically retry a POST"),
            _ => Fail::upstream("service", "unreachable", "Service could not be reached; do not automatically retry a POST"),
        });
    };
    if (300..400).contains(&answer.status) {
        return Err(svc("Redirect refused; configure the final service endpoint"));
    }
    if answer.over_limit || answer.body.len() > RESPONSE_MAX {
        return Err(svc("Response too large"));
    }
    let mut text = String::from_utf8_lossy(&answer.body).into_owned();
    let quoted = util::py_dumps(&json!(value));
    for sensitive in [quoted[1..quoted.len() - 1].to_owned(), value.clone(), util::quote(&value, ""), util::b64(value.as_bytes())] {
        if !sensitive.is_empty() {
            text = text.replace(&sensitive, "[credential redacted]");
        }
    }
    let content = serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text));
    Ok(json!({"http_status": answer.status, "content": content, "untrusted_content": true}))
}

// ── OAuth ──────────────────────────────────────────────────────────────────

/// The authorization-code (with PKCE) or refresh exchange at the setup's token endpoint.
pub fn exchange(spec: &Value, app: &Value, code: &str, verifier: &str, redirect: &str, refresh: Option<&str>) -> R<Value> {
    let oauth = &spec["oauth"];
    let token_url = util::text(oauth, "token_url");
    let u = validate_endpoint(token_url)?;
    let host = u.hostname().unwrap_or_default();
    let ips = public_addresses(&host)?;
    let mut form: Vec<(&str, String)> = vec![("grant_type", if refresh.is_some() { "refresh_token" } else { "authorization_code" }.to_owned())];
    match refresh {
        Some(r) => form.push(("refresh_token", r.to_owned())),
        None => form.extend([("code", code.to_owned()), ("code_verifier", verifier.to_owned()), ("redirect_uri", redirect.to_owned())]),
    }
    let (client_id, client_secret) = (util::text(app, "client_id"), util::text(app, "client_secret"));
    let basic = oauth.get("token_auth").and_then(Value::as_str).unwrap_or("client_secret_post") == "client_secret_basic";
    if !basic {
        form.push(("client_id", client_id.to_owned()));
        form.push(("client_secret", client_secret.to_owned()));
    }
    let url = format!("https://{host}{}", u.path);
    let mut req = Request::new("POST", &url, CONNECT_TIMEOUT);
    req.pin = Some(ips[0]);
    req.limit = 65536;
    req = req
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .header("User-Agent", USER_AGENT);
    if basic {
        let pair = format!("{}:{}", util::quote(client_id, ""), util::quote(client_secret, ""));
        req = req.header("Authorization", &format!("Basic {}", util::b64(pair.as_bytes())));
    }
    req.body = util::urlencode(&form).into_bytes();
    let unusable = || Fail::upstream("service", "bad_answer", "OAuth token endpoint answered with an unusable response; try again later");
    let answer = net::send(&req).map_err(|e| match e {
        NetError::Protocol | NetError::Url => unusable(),
        _ => Fail::upstream("service", "unreachable", "OAuth token endpoint could not be reached; try again later"),
    })?;
    if answer.status == 429 || answer.status >= 500 {
        return Err(Fail::upstream("service", if answer.status == 429 { "rate_limited" } else { "bad_answer" }, "OAuth token endpoint is unavailable; try again later"));
    }
    if answer.status != 200 {
        return Err(svc("OAuth exchange failed; check application credentials, registered redirect and consent"));
    }
    if answer.over_limit {
        return Err(svc("OAuth response too large"));
    }
    let result = answer.json().filter(Value::is_object).ok_or_else(unusable)?;
    let access = result.get("access_token").and_then(Value::as_str).unwrap_or("");
    let token_type = match result.get("token_type") {
        None => String::new(),
        Some(Value::String(s)) => s.to_lowercase(),
        Some(_) => return Err(unusable()),
    };
    if access.is_empty() || token_type != "bearer" {
        return Err(unusable());
    }
    let scope = result.get("scope").cloned().unwrap_or(Value::Null);
    if let Some(granted) = scope.as_str() {
        let granted: Vec<&str> = granted.split_whitespace().collect();
        let wanted = oauth["scopes"].as_array().cloned().unwrap_or_default();
        if !wanted.iter().all(|s| granted.contains(&s.as_str().unwrap_or(""))) {
            return Err(svc("Required permissions were not granted; reconnect"));
        }
    } else if !scope.is_null() {
        return Err(unusable());
    }
    let expires_at = match result.get("expires_in") {
        None => Value::Null,
        Some(v) => {
            let n = match v {
                Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
                Value::String(s) => s.trim().parse().ok(),
                Value::Bool(b) => Some(*b as i64),
                _ => None,
            }
            .ok_or_else(unusable)?;
            json!(util::now() + n.max(0) as f64)
        }
    };
    let refresh_token = match result.get("refresh_token") {
        Some(v) if util::truthy(Some(v)) => v.clone(),
        _ => refresh.map_or(Value::Null, |r| json!(r)),
    };
    Ok(json!({"access_token": access, "refresh_token": refresh_token, "expires_at": expires_at, "granted_scope": scope}))
}

pub fn authorize(spec: &Value, app: &Value, redirect: &str, state: &str, challenge: &str) -> R<String> {
    let oauth = &spec["oauth"];
    let url = util::text(oauth, "authorization_url");
    let u = validate_endpoint(url)?;
    public_addresses(&u.hostname().unwrap_or_default())?;
    let scopes: Vec<&str> = oauth["scopes"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let args = [
        ("response_type", "code".to_owned()),
        ("client_id", util::text(app, "client_id").to_owned()),
        ("redirect_uri", redirect.to_owned()),
        ("scope", scopes.join(" ")),
        ("state", state.to_owned()),
        ("code_challenge", challenge.to_owned()),
        ("code_challenge_method", "S256".to_owned()),
    ];
    Ok(format!("{url}?{}", util::urlencode(&args)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_and_configuration_rules() {
        assert!(validate_endpoint("https://api.example.com/v1").is_ok());
        for bad in ["http://api.example.com/v1", "https://api.example.com:8443/x", "https://u:p@api.example.com/x", "https://api.example.com/x?q=1", "https://api.example.com/a/../b", "https://api.example.com"] {
            assert!(validate_endpoint(bad).is_err(), "{bad}");
        }
        let c = configure("tok", "https://api.example.com/v1", "X-API-Key", "prefix", "GET", "Token").unwrap();
        assert_eq!(authorization(&c), "Token tok");
        assert_eq!(c["prefix"], "Token");
        assert!(matches!(configure("tok", "https://api.example.com/v1", "Host", "bearer", "GET", ""), Err(Fail::Service(_))));
        assert!(matches!(configure("t\nk", "https://api.example.com/v1", "Authorization", "bearer", "GET", ""), Err(Fail::Service(_))));
        assert!(configure("t\nk", "", "Authorization", "bearer", "GET", "").is_ok());
        assert!(configure("123:abc", "https://api.telegram.org/bot{secret}/getMe", "Authorization", "telegram", "GET", "").is_ok());
        assert!(matches!(configure("123:abc", "https://api.telegram.org/bot{secret}/getMe", "Authorization", "telegram", "POST", ""), Err(Fail::Service(s)) if s == "Invalid Telegram method"));
    }

    #[test]
    fn loopback_is_not_public() {
        assert!(matches!(public_addresses("localhost"), Err(Fail::Service(s)) if s == "Service must resolve only to public addresses"));
    }
}
