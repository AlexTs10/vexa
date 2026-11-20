//! The edge's three admission limits: the per-IP guard in front of every HTTP request (fastapi-guard
//! as `edge_guard.py` configures it: IP allow and deny lists, a sliding-window rate limit kept in
//! Redis or in memory), its opt-in twin on the /ws upgrade, and the per-user token bucket spent by
//! each authorized request.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use crate::redis::{self, Reply};

pub fn env_truthy(raw: Option<&str>) -> bool {
    raw.is_some_and(|r| matches!(r.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => env_truthy(Some(&v)),
        Err(_) => default,
    }
}

fn env_int(name: &str, default: i64) -> i64 {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v.trim().parse().unwrap_or(default),
        _ => default,
    }
}

fn csv(name: &str) -> Vec<String> {
    std::env::var(name).unwrap_or_default().split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect()
}

/// `ipaddress.ip_network(entry, strict=False)` containment; a malformed entry matches nothing.
pub fn ip_matches(ip: &str, entries: &[String]) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else { return false };
    entries.iter().any(|e| {
        let (net, bits) = match e.trim().split_once('/') {
            Some((n, b)) => (n, b.parse::<u32>().ok()),
            None => (e.trim(), None),
        };
        let Ok(net) = net.parse::<IpAddr>() else { return false };
        match (addr, net) {
            (IpAddr::V4(a), IpAddr::V4(n)) => {
                let b = bits.unwrap_or(32);
                b <= 32 && (b == 0 || (u32::from(a) ^ u32::from(n)) >> (32 - b) == 0)
            }
            (IpAddr::V6(a), IpAddr::V6(n)) => {
                let b = bits.unwrap_or(128);
                b <= 128 && (b == 0 || (u128::from(a) ^ u128::from(n)) >> (128 - b) == 0)
            }
            _ => false,
        }
    })
}

const RATE_SCRIPT: &str = "local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_start = now - window
redis.call('ZADD', key, now, now)
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
local count = redis.call('ZCARD', key)
redis.call('EXPIRE', key, window * 2)
return count
";

pub struct Guard {
    pub enabled: bool,
    redis: Option<redis::Target>,
    prefix: String,
    rpm: i64,
    window: i64,
    whitelist: Vec<String>,
    blacklist: Vec<String>,
    trusted: Vec<String>,
    memory: Mutex<HashMap<String, VecDeque<f64>>>,
    conn: Mutex<Option<redis::Conn>>,
    ws_enabled: bool,
    ws: Mutex<WsState>,
    ban_threshold: i64,
    ban_duration: i64,
}

#[derive(Default)]
struct WsState {
    rl: HashMap<String, VecDeque<Instant>>,
    bans: HashMap<String, Instant>,
    counts: HashMap<String, i64>,
}

/// The guard's refusal: status, headers, body (a plain Starlette Response: no content type).
pub type Refusal = (u16, Vec<(String, String)>, Vec<u8>);

impl Guard {
    pub fn from_env() -> Result<Guard, String> {
        for name in ["GUARD_BLOCKED_COUNTRIES", "GUARD_BLOCK_CLOUD_PROVIDERS"] {
            if !csv(name).is_empty() {
                return Err(format!("gateway refuses to boot: {name} needs the country and cloud-range lookups, which this edge does not carry; unset it"));
            }
        }
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379/0".into());
        let redis = if env_bool("GUARD_ENABLE_REDIS", true) { Some(redis::parse_url(&url)?) } else { None };
        Ok(Guard {
            enabled: env_bool("GUARD_ENABLED", true),
            redis,
            prefix: std::env::var("GUARD_REDIS_PREFIX").unwrap_or_else(|_| "vexa:guard:".into()),
            rpm: env_int("GUARD_RATE_LIMIT_RPM", 600),
            window: env_int("GUARD_RATE_LIMIT_WINDOW", 60),
            whitelist: csv("GUARD_IP_WHITELIST"),
            blacklist: csv("GUARD_IP_BLACKLIST"),
            trusted: csv("GUARD_TRUSTED_PROXIES"),
            memory: Mutex::new(HashMap::new()),
            conn: Mutex::new(None),
            ws_enabled: env_truthy(std::env::var("GUARD_WS_ENABLED").ok().as_deref()),
            ws: Mutex::new(WsState::default()),
            ban_threshold: env_int("GUARD_AUTO_BAN_THRESHOLD", 10),
            ban_duration: env_int("GUARD_AUTO_BAN_DURATION", 3600),
        })
    }

    /// The client address: the peer, or the X-Forwarded-For entry one hop back from a trusted peer.
    pub fn client_ip(&self, peer: &str, xff: Option<&str>) -> String {
        if self.trusted.is_empty() || !ip_matches(peer, &self.trusted) {
            return peer.to_owned();
        }
        match xff {
            Some(x) if !x.is_empty() => {
                let ips: Vec<&str> = x.split(',').map(str::trim).collect();
                match ips.last() {
                    Some(ip) if !ip.is_empty() => ip.to_string(),
                    _ => peer.to_owned(),
                }
            }
            _ => peer.to_owned(),
        }
    }

    fn redis_count(&self, ip: &str, now: f64) -> Option<i64> {
        let target = self.redis.as_ref()?;
        let mut slot = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        for _ in 0..2 {
            if slot.is_none() {
                *slot = redis::Conn::open(target, Some(std::time::Duration::from_secs(10))).ok();
            }
            let conn = slot.as_mut()?;
            let key = format!("{}rate_limit:rate:{ip}", self.prefix);
            let sha = redis::sha1_hex(RATE_SCRIPT.as_bytes());
            let args = [now.to_string(), self.window.to_string(), self.rpm.to_string()];
            let run = |c: &mut redis::Conn, cmd: &[u8], first: &[u8]| {
                c.cmd(&[cmd, first, b"1", key.as_bytes(), args[0].as_bytes(), args[1].as_bytes(), args[2].as_bytes()])
            };
            match run(conn, b"EVALSHA", sha.as_bytes()) {
                Ok(Reply::Int(n)) => return Some(n),
                Ok(Reply::Error(e)) if e.starts_with("NOSCRIPT") => match run(conn, b"EVAL", RATE_SCRIPT.as_bytes()) {
                    Ok(Reply::Int(n)) => return Some(n),
                    _ => return None,
                },
                Ok(_) => return None,
                Err(_) => *slot = None,
            }
        }
        None
    }

    /// The HTTP pipeline's verdict on one request; None lets it through.
    pub fn check(&self, ip: &str) -> Option<Refusal> {
        if !self.enabled {
            return None;
        }
        let forbidden = || (403, vec![], b"Forbidden".to_vec());
        if ip_matches(ip, &self.blacklist) {
            return Some(forbidden());
        }
        if !self.whitelist.is_empty() {
            if !ip_matches(ip, &self.whitelist) {
                return Some(forbidden());
            }
            return None;
        }
        if self.rpm <= 0 {
            return None;
        }
        let too_many = || (429, vec![("retry-after".to_owned(), self.window.to_string())], b"Too many requests".to_vec());
        let now = vexa_native_kit::ids::now();
        if self.redis.is_some() {
            // A Redis that cannot be reached skips the check (fail_secure=False).
            return match self.redis_count(ip, now) {
                Some(n) if n > self.rpm => Some(too_many()),
                _ => None,
            };
        }
        let mut mem = self.memory.lock().unwrap_or_else(|p| p.into_inner());
        let stamps = mem.entry(ip.to_owned()).or_default();
        let start = now - self.window as f64;
        while stamps.front().is_some_and(|t| *t <= start) {
            stamps.pop_front();
        }
        let count = stamps.len() as i64;
        stamps.push_back(now);
        (count >= self.rpm).then(too_many)
    }

    /// The /ws upgrade's opt-in limit (`GUARD_WS_ENABLED`): false refuses the upgrade.
    pub fn ws_admits(&self, ip: &str) -> bool {
        if !self.ws_enabled {
            return true;
        }
        if !self.whitelist.is_empty() && ip_matches(ip, &self.whitelist) {
            return true;
        }
        if ip_matches(ip, &self.blacklist) {
            return false;
        }
        let now = Instant::now();
        let mut st = self.ws.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(unban) = st.bans.get(ip).copied() {
            if now < unban {
                return false;
            }
            st.bans.remove(ip);
        }
        if self.rpm > 0 {
            let window = std::time::Duration::from_secs(self.window.max(0) as u64);
            let bucket = st.rl.entry(ip.to_owned()).or_default();
            while bucket.front().is_some_and(|t| now.duration_since(*t) >= window) {
                bucket.pop_front();
            }
            if bucket.len() as i64 >= self.rpm {
                let n = { let c = st.counts.entry(ip.to_owned()).or_default(); *c += 1; *c };
                if n >= self.ban_threshold {
                    st.bans.insert(ip.to_owned(), now + std::time::Duration::from_secs(self.ban_duration.max(0) as u64));
                    st.counts.insert(ip.to_owned(), 0);
                    if let Some(b) = st.rl.get_mut(ip) {
                        b.clear();
                    }
                }
                return false;
            }
            bucket.push_back(now);
        }
        true
    }
}

/// The per-user token bucket (`ratelimit.py`): `GATEWAY_RATE_LIMIT_BURST` tokens refilled at
/// `GATEWAY_RATE_LIMIT_RPS` per second; None when `GATEWAY_RATE_LIMIT_DISABLED` is truthy.
pub struct UserLimiter {
    capacity: f64,
    refill: f64,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl UserLimiter {
    pub fn from_env() -> Result<Option<UserLimiter>, String> {
        if env_truthy(std::env::var("GATEWAY_RATE_LIMIT_DISABLED").ok().as_deref()) {
            return Ok(None);
        }
        let num = |k: &str, d: &str| -> Result<f64, String> {
            let v = std::env::var(k).unwrap_or_else(|_| d.into());
            v.trim().parse::<f64>().map_err(|_| format!("could not convert string to float: '{v}'"))
        };
        let (capacity, refill) = (num("GATEWAY_RATE_LIMIT_BURST", "120")?, num("GATEWAY_RATE_LIMIT_RPS", "40")?);
        if capacity <= 0.0 || refill < 0.0 {
            return Err("capacity must be > 0 and refill_per_sec >= 0".into());
        }
        Ok(Some(UserLimiter { capacity, refill, buckets: Mutex::new(HashMap::new()) }))
    }

    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut b = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let entry = b.entry(key.to_owned()).or_insert((self.capacity, now));
        entry.0 = self.capacity.min(entry.0 + now.duration_since(entry.1).as_secs_f64() * self.refill);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// `VEXA_AGENT_ALLOW`: who the agent tier is enabled for.
pub struct AgentAllow {
    unrestricted: bool,
    ids: Vec<String>,
    emails: Vec<String>,
    domains: Vec<String>,
}

impl AgentAllow {
    pub fn from_env() -> AgentAllow {
        let raw = std::env::var("VEXA_AGENT_ALLOW").unwrap_or_default();
        let entries: Vec<String> = raw.split(',').map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()).collect();
        AgentAllow {
            unrestricted: entries.is_empty() || entries.iter().any(|e| e == "*"),
            ids: entries.iter().filter(|e| !e.contains('@')).cloned().collect(),
            emails: entries.iter().filter(|e| e.contains('@') && !e.starts_with('@')).cloned().collect(),
            domains: entries.iter().filter(|e| e.starts_with('@') && e.len() > 1).map(|e| e[1..].to_owned()).collect(),
        }
    }

    pub fn admits(&self, user: &serde_json::Value) -> bool {
        if self.unrestricted {
            return true;
        }
        let text = |k: &str| match user.get(k) {
            Some(v) if vexa_native_kit::pyjson::truthy(Some(v)) => vexa_native_kit::pyjson::py_str(v).trim().to_lowercase(),
            _ => String::new(),
        };
        let uid = text("user_id");
        if !uid.is_empty() && self.ids.contains(&uid) {
            return true;
        }
        let email = text("email");
        if email.is_empty() || !email.contains('@') {
            return false;
        }
        self.emails.contains(&email) || email.rsplit_once('@').is_some_and(|(_, d)| self.domains.iter().any(|x| x == d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_and_bucket() {
        assert!(ip_matches("10.1.2.3", &["10.0.0.0/8".into()]));
        assert!(!ip_matches("11.1.2.3", &["10.0.0.0/8".into(), "bad".into()]));
        assert!(ip_matches("::1", &["::1".into()]));
        let l = UserLimiter { capacity: 2.0, refill: 0.0, buckets: Mutex::new(HashMap::new()) };
        assert!(l.allow("7") && l.allow("7") && !l.allow("7") && l.allow("8"));
    }
}
