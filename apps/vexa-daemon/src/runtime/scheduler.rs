//! The durable schedule.v1 cron: jobs in a Redis sorted set keyed by
//! `execute_at`, fired as HTTP calls when due, retried with backoff, and
//! re-armed when they carry a `cron`. The Redis keys are the ones the Python
//! runtime used, so jobs survive the change of implementation.

use std::time::Duration;

use vexa_native_kit::http;
use vexa_native_kit::json::{self, object, Value};

use super::clock::{now, parse_iso, Cron};
use super::redis::Redis;
use super::Log;

const JOBS_KEY: &str = "scheduler:jobs";
const EXECUTING_KEY: &str = "scheduler:executing";
const HISTORY_KEY: &str = "scheduler:history";
const IDEMPOTENCY_PREFIX: &str = "scheduler:idem:";
const HISTORY_TTL: u64 = 86_400 * 7;

pub enum ScheduleError {
    /// The job spec is invalid (400).
    Invalid(String),
    /// Redis failed (500).
    Store(String),
}

impl From<String> for ScheduleError {
    fn from(error: String) -> Self {
        ScheduleError::Store(error)
    }
}

pub struct Scheduler {
    redis: Redis,
}

fn number(n: f64) -> String {
    json::write(&Value::Number(n))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    vexa_native_kit::sha256::hex(&buf)
}

fn get_or<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get(key).filter(|v| !v.is_null())
}

impl Scheduler {
    pub fn new(redis: Redis) -> Self {
        Self { redis }
    }

    fn make_job(&self, spec: &Value) -> Result<Value, ScheduleError> {
        let created = now();
        let cron = get_or(spec, "cron").and_then(Value::as_str).filter(|c| !c.is_empty()).map(str::to_owned);
        let execute_at = match get_or(spec, "execute_at") {
            Some(Value::String(text)) => Value::Number(parse_iso(text).map_err(ScheduleError::Invalid)?),
            Some(n @ Value::Number(_)) => n.clone(),
            Some(_) => return Err(ScheduleError::Invalid("execute_at must be a number or an ISO 8601 time".into())),
            None => match &cron {
                Some(expr) => {
                    let next = Cron::parse(expr).map_err(ScheduleError::Invalid)?.next_after(created);
                    Value::Number(next.ok_or_else(|| ScheduleError::Invalid(format!("cron {expr:?} never fires")))?)
                }
                None => return Err(ScheduleError::Invalid("execute_at or cron is required".into())),
            },
        };
        if let Some(expr) = &cron {
            Cron::parse(expr).map_err(ScheduleError::Invalid)?;
        }
        let request = get_or(spec, "request").filter(|r| r.as_object().is_some_and(|o| !o.is_empty()));
        let url = request.and_then(|r| get_or(r, "url")).and_then(Value::as_str).filter(|u| !u.is_empty());
        let (Some(request), Some(url)) = (request, url) else {
            return Err(ScheduleError::Invalid("request.url is required".into()));
        };
        let mut retry = object(vec![
            ("max_attempts", 3i64.into()),
            ("backoff", Value::Array(vec![30i64.into(), 120i64.into(), 300i64.into()])),
            ("attempt", 0i64.into()),
        ]);
        if let Some(Value::Object(items)) = get_or(spec, "retry") {
            for (k, v) in items {
                retry.set(k, v.clone());
            }
        }
        Ok(object(vec![
            ("job_id", format!("job_{}", random_hex(8)).into()),
            ("execute_at", execute_at),
            ("created_at", Value::Number(created)),
            ("status", "pending".into()),
            (
                "request",
                object(vec![
                    ("method", request.get("method").cloned().unwrap_or_else(|| "POST".into())),
                    ("url", url.into()),
                    ("headers", request.get("headers").cloned().unwrap_or(Value::Object(vec![]))),
                    ("body", request.get("body").cloned().unwrap_or(Value::Null)),
                    ("timeout", request.get("timeout").cloned().unwrap_or(30i64.into())),
                ]),
            ),
            ("retry", retry),
            ("metadata", spec.get("metadata").cloned().unwrap_or(Value::Object(vec![]))),
            ("cron", cron.map(Value::from).unwrap_or(Value::Null)),
            ("idempotency_key", spec.get("idempotency_key").cloned().unwrap_or(Value::Null)),
        ]))
    }

    pub fn schedule(&self, spec: &Value) -> Result<Value, ScheduleError> {
        let job = self.make_job(spec)?;
        if let Some(key) = job.get("idempotency_key").filter(|k| !k.is_null()) {
            let key = match key.as_str() {
                Some(text) => text.to_owned(),
                None => json::write(key),
            };
            if !key.is_empty() {
                let redis_key = format!("{IDEMPOTENCY_PREFIX}{key}");
                if let Some(existing) = self.redis.cmd(&["GET", &redis_key])?.text() {
                    return json::parse(&existing).map_err(ScheduleError::Store);
                }
                self.redis.cmd(&["SET", &redis_key, &json::write(&job), "EX", &HISTORY_TTL.to_string()])?;
            }
        }
        let score = job.get("execute_at").and_then(Value::as_f64).unwrap_or(0.0);
        self.redis.cmd(&["ZADD", JOBS_KEY, &number(score), &json::write(&job)])?;
        Ok(job)
    }

    pub fn cancel(&self, job_id: &str) -> Result<Option<Value>, String> {
        for raw in self.redis.cmd(&["ZRANGE", JOBS_KEY, "0", "-1"])?.texts() {
            let Ok(mut job) = json::parse(&raw) else { continue };
            if job.get("job_id").and_then(Value::as_str) == Some(job_id) && self.redis.cmd(&["ZREM", JOBS_KEY, &raw])?.int() > 0 {
                job.set("status", "cancelled".into());
                self.redis.cmd(&["HSET", HISTORY_KEY, job_id, &json::write(&job)])?;
                return Ok(Some(job));
            }
        }
        Ok(None)
    }

    pub fn list(&self, status: Option<&str>, limit: usize) -> Result<Vec<Value>, String> {
        let mut jobs = Vec::new();
        if matches!(status, None | Some("pending")) {
            jobs.extend(self.redis.cmd(&["ZRANGE", JOBS_KEY, "0", "-1"])?.texts().iter().filter_map(|r| json::parse(r).ok()));
        }
        if matches!(status, None | Some("executing")) {
            let pairs = self.redis.cmd(&["HGETALL", EXECUTING_KEY])?.texts();
            jobs.extend(pairs.iter().skip(1).step_by(2).filter_map(|r| json::parse(r).ok()));
        }
        jobs.sort_by(|a, b| {
            let at = |j: &Value| j.get("execute_at").and_then(Value::as_f64).unwrap_or(0.0);
            at(a).total_cmp(&at(b))
        });
        jobs.truncate(limit);
        Ok(jobs)
    }

    /// Re-queue the jobs that were executing when the runtime stopped.
    pub fn recover_orphans(&self, log: &Log) -> Result<usize, String> {
        let pairs = self.redis.cmd(&["HGETALL", EXECUTING_KEY])?.texts();
        let mut recovered = 0;
        for pair in pairs.chunks(2) {
            let [job_id, raw] = pair else { continue };
            let Ok(mut job) = json::parse(raw) else { continue };
            job.set("status", "pending".into());
            self.redis.cmd(&["ZADD", JOBS_KEY, &number(now()), &json::write(&job)])?;
            self.redis.cmd(&["HDEL", EXECUTING_KEY, job_id])?;
            log.line(&format!("WARNING recovered orphaned job {job_id}"));
            recovered += 1;
        }
        Ok(recovered)
    }

    /// Fire every job that is due now. Returns how many ran.
    pub fn tick(&self, log: &Log) -> Result<usize, String> {
        let due = self.redis.cmd(&["ZRANGEBYSCORE", JOBS_KEY, "-inf", &number(now())])?.texts();
        for raw in &due {
            self.process(raw, log)?;
        }
        Ok(due.len())
    }

    fn process(&self, raw: &str, log: &Log) -> Result<(), String> {
        let mut job = json::parse(raw).map_err(|e| format!("bad job in {JOBS_KEY}: {e}"))?;
        let job_id = job.get("job_id").and_then(Value::as_str).unwrap_or("").to_owned();
        // The claim: whoever removes the member runs the job.
        if self.redis.cmd(&["ZREM", JOBS_KEY, raw])?.int() == 0 {
            return Ok(());
        }
        job.set("status", "executing".into());
        self.redis.cmd(&["HSET", EXECUTING_KEY, &job_id, &json::write(&job)])?;
        let request = job.get("request").cloned().unwrap_or(Value::Null);
        match dispatch(&request) {
            Ok(result) => {
                job.set("status", "completed".into());
                job.set("result", result);
                job.set("completed_at", Value::Number(now()));
            }
            Err(error) => {
                let retry = job.get("retry").cloned().unwrap_or(Value::Object(vec![]));
                let attempt = retry.get("attempt").and_then(Value::as_i64).unwrap_or(0) + 1;
                let max_attempts = retry.get("max_attempts").and_then(Value::as_i64).unwrap_or(3);
                if attempt < max_attempts {
                    let backoff: Vec<f64> = retry
                        .get("backoff")
                        .and_then(Value::as_array)
                        .map(|b| b.iter().filter_map(Value::as_f64).collect())
                        .filter(|b: &Vec<f64>| !b.is_empty())
                        .unwrap_or_else(|| vec![30.0, 120.0, 300.0]);
                    let delay = backoff[((attempt - 1) as usize).min(backoff.len() - 1)];
                    let mut retry = retry;
                    retry.set("attempt", attempt.into());
                    job.set("retry", retry);
                    job.set("status", "pending".into());
                    self.redis.cmd(&["HDEL", EXECUTING_KEY, &job_id])?;
                    self.redis.cmd(&["ZADD", JOBS_KEY, &number(now() + delay), &json::write(&job)])?;
                    log.line(&format!("WARNING job {job_id} attempt {attempt}/{max_attempts} failed ({error}), retry in {delay}s"));
                    return Ok(());
                }
                job.set("status", "failed".into());
                job.set("error", error.clone().into());
                job.set("failed_at", Value::Number(now()));
                log.line(&format!("ERROR job {job_id} permanently failed after {max_attempts} attempts: {error}"));
            }
        }
        self.redis.cmd(&["HDEL", EXECUTING_KEY, &job_id])?;
        self.redis.cmd(&["HSET", HISTORY_KEY, &job_id, &json::write(&job)])?;
        if job.get("status").and_then(Value::as_str) == Some("completed") {
            if let Some(cron) = job.get("cron").and_then(Value::as_str) {
                let next = Cron::parse(cron).ok().and_then(|c| c.next_after(now()));
                if let Some(next) = next {
                    let spec = object(vec![
                        ("execute_at", Value::Number(next)),
                        ("request", request),
                        ("metadata", job.get("metadata").cloned().unwrap_or(Value::Object(vec![]))),
                        ("cron", cron.into()),
                    ]);
                    if let Err(ScheduleError::Invalid(e) | ScheduleError::Store(e)) = self.schedule(&spec) {
                        log.line(&format!("ERROR job {job_id}: cannot re-arm its cron: {e}"));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Fire a job's HTTP call. 2xx/3xx completes the job; 4xx completes it
/// without a retry (a bad body does not fix itself); 5xx and transport
/// failures are retried.
fn dispatch(request: &Value) -> Result<Value, String> {
    let url = request.get("url").and_then(Value::as_str).ok_or("job request has no url")?;
    let method = request.get("method").and_then(Value::as_str).unwrap_or("POST");
    let body = match request.get("body") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(text)) => text.clone().into_bytes(),
        Some(other) => json::write(other).into_bytes(),
    };
    let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
    if let Some(Value::Object(items)) = request.get("headers") {
        for (k, v) in items {
            let value = v.as_str().map(str::to_owned).unwrap_or_else(|| json::write(v));
            match headers.iter_mut().find(|(name, _)| name.eq_ignore_ascii_case(k)) {
                Some(slot) => slot.1 = value,
                None => headers.push((k.clone(), value)),
            }
        }
    }
    let timeout = Duration::from_secs_f64(request.get("timeout").and_then(Value::as_f64).filter(|t| *t > 0.0).unwrap_or(30.0));
    let answer = http::send(method, url, &headers, &body, timeout).map_err(|e| format!("{url} unreachable: {e}"))?;
    if answer.status >= 500 {
        return Err(format!("{url} -> {}", answer.status));
    }
    if answer.status >= 400 {
        return Ok(object(vec![("status_code", i64::from(answer.status).into()), ("error", answer.reason.into())]));
    }
    Ok(object(vec![("status_code", i64::from(answer.status).into())]))
}
