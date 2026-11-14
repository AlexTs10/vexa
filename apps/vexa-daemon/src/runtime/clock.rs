//! Time for the runtime: UTC timestamps in the Python service's text form,
//! ISO 8601 parsing for `execute_at`, and cron (`croniter` semantics).

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, with the fraction (Python `time.time()`).
pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The date of a day number from [`days_from_civil`].
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// `datetime.fromtimestamp(t, timezone.utc).isoformat()`: microseconds are
/// shown unless they are zero, and the offset is `+00:00`.
pub fn iso(timestamp: f64) -> String {
    let micros_total = (timestamp * 1_000_000.0).round() as i64;
    let secs = micros_total.div_euclid(1_000_000);
    let micros = micros_total.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let base = format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60);
    if micros == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{micros:06}+00:00")
    }
}

/// The current time as [`iso`] text.
pub fn now_iso() -> String {
    iso(now())
}

/// Parse `datetime.fromisoformat` text to a Unix timestamp. A value without
/// an offset is UTC (the native stack runs with `TZ=UTC`).
pub fn parse_iso(text: &str) -> Result<f64, String> {
    let bad = || format!("Invalid isoformat string: {text:?}");
    let text = text.trim();
    let (date, rest) = match text.find(['T', ' ']) {
        Some(i) => (&text[..i], &text[i + 1..]),
        None => (text, ""),
    };
    let mut parts = date.split('-');
    let year: i64 = parts.next().and_then(|p| (p.len() == 4).then(|| p.parse().ok()).flatten()).ok_or_else(bad)?;
    let month: u32 = parts.next().and_then(|p| p.parse().ok()).filter(|m| (1..=12).contains(m)).ok_or_else(bad)?;
    let day: u32 = parts.next().and_then(|p| p.parse().ok()).filter(|d| (1..=31).contains(d)).ok_or_else(bad)?;
    if parts.next().is_some() {
        return Err(bad());
    }
    let (time, offset) = split_offset(rest).ok_or_else(bad)?;
    let mut seconds = 0.0;
    if !time.is_empty() {
        let fields: Vec<&str> = time.split(':').collect();
        if fields.len() < 2 || fields.len() > 3 {
            return Err(bad());
        }
        let hour: u32 = fields[0].parse().ok().filter(|h| *h < 24).ok_or_else(bad)?;
        let minute: u32 = fields[1].parse().ok().filter(|m| *m < 60).ok_or_else(bad)?;
        let second: f64 = match fields.get(2) {
            Some(s) => s.parse().ok().filter(|s: &f64| (0.0..60.0).contains(s)).ok_or_else(bad)?,
            None => 0.0,
        };
        seconds = (hour * 3600 + minute * 60) as f64 + second;
    }
    Ok(days_from_civil(year, month, day) as f64 * 86_400.0 + seconds - offset)
}

/// Split `HH:MM[:SS[.f]]` from a trailing `Z` or `±HH:MM` offset (seconds east).
fn split_offset(rest: &str) -> Option<(&str, f64)> {
    if let Some(time) = rest.strip_suffix('Z') {
        return Some((time, 0.0));
    }
    match rest.rfind(['+', '-']) {
        Some(i) => {
            let sign = if &rest[i..i + 1] == "-" { -1.0 } else { 1.0 };
            let (h, m) = rest[i + 1..].split_once(':').unwrap_or((&rest[i + 1..], "0"));
            let hours: f64 = h.parse().ok()?;
            let minutes: f64 = m.parse().ok()?;
            Some((&rest[..i], sign * (hours * 3600.0 + minutes * 60.0)))
        }
        None => Some((rest, 0.0)),
    }
}

/// A parsed cron expression (minute, hour, day of month, month, day of week).
#[derive(Debug, Clone)]
pub struct Cron {
    minutes: [bool; 60],
    hours: [bool; 24],
    days: [bool; 32],
    months: [bool; 13],
    weekdays: [bool; 7],
    days_restricted: bool,
    weekdays_restricted: bool,
}

const MONTH_NAMES: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const DAY_NAMES: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

fn field_value(text: &str, names: &[&str], offset: u32) -> Option<u32> {
    if let Ok(n) = text.parse() {
        return Some(n);
    }
    let lower = text.to_ascii_lowercase();
    names.iter().position(|n| *n == lower).map(|i| i as u32 + offset)
}

/// Parse one field into the set of allowed values in `min..=max`.
fn field(text: &str, min: u32, max: u32, names: &[&str], name_offset: u32, what: &str) -> Result<Vec<u32>, String> {
    let bad = || format!("invalid cron {what} field: {text:?}");
    let mut out = Vec::new();
    for part in text.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().ok().filter(|s| *s > 0).ok_or_else(bad)?),
            None => (part, 1),
        };
        let (start, end) = if range == "*" || range == "?" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (field_value(a, names, name_offset).ok_or_else(bad)?, field_value(b, names, name_offset).ok_or_else(bad)?)
        } else {
            let a = field_value(range, names, name_offset).ok_or_else(bad)?;
            // croniter reads `a/n` as `a-max/n`.
            (a, if part.contains('/') { max } else { a })
        };
        if start < min || end > max || start > end {
            return Err(bad());
        }
        out.extend((start..=end).step_by(step as usize));
    }
    Ok(out)
}

impl Cron {
    pub fn parse(expression: &str) -> Result<Self, String> {
        let expanded = match expression.trim().to_ascii_lowercase().as_str() {
            "@yearly" | "@annually" => "0 0 1 1 *".to_owned(),
            "@monthly" => "0 0 1 * *".to_owned(),
            "@weekly" => "0 0 * * 0".to_owned(),
            "@daily" | "@midnight" => "0 0 * * *".to_owned(),
            "@hourly" => "0 * * * *".to_owned(),
            _ => expression.trim().to_owned(),
        };
        let fields: Vec<&str> = expanded.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(format!("Exactly 5 columns has to be specified for iterator expression: {expression:?}"));
        }
        let mut cron = Cron {
            minutes: [false; 60],
            hours: [false; 24],
            days: [false; 32],
            months: [false; 13],
            weekdays: [false; 7],
            days_restricted: !matches!(fields[2], "*" | "?"),
            weekdays_restricted: !matches!(fields[4], "*" | "?"),
        };
        for v in field(fields[0], 0, 59, &[], 0, "minute")? {
            cron.minutes[v as usize] = true;
        }
        for v in field(fields[1], 0, 23, &[], 0, "hour")? {
            cron.hours[v as usize] = true;
        }
        for v in field(fields[2], 1, 31, &[], 0, "day-of-month")? {
            cron.days[v as usize] = true;
        }
        for v in field(fields[3], 1, 12, &MONTH_NAMES, 1, "month")? {
            cron.months[v as usize] = true;
        }
        for v in field(fields[4], 0, 7, &DAY_NAMES, 0, "day-of-week")? {
            cron.weekdays[(v % 7) as usize] = true;
        }
        Ok(cron)
    }

    fn day_matches(&self, month: u32, day: u32, weekday: usize) -> bool {
        if !self.months[month as usize] {
            return false;
        }
        let by_day = self.days[day as usize];
        let by_weekday = self.weekdays[weekday];
        // croniter (day_or=True): when both fields are restricted, either one matches.
        if self.days_restricted && self.weekdays_restricted {
            by_day || by_weekday
        } else {
            by_day && by_weekday
        }
    }

    /// The first matching minute strictly after `after` (Unix seconds), as
    /// `croniter(expr, after).get_next(float)` gives it.
    pub fn next_after(&self, after: f64) -> Option<f64> {
        let start = (after / 60.0).floor() as i64 * 60 + 60;
        let mut day = start.div_euclid(86_400);
        let mut minute_of_day = start.rem_euclid(86_400) / 60;
        // Five years covers every valid expression (29 February is at most 8 years apart, and
        // February 29 alone with a weekday restriction still matches by the OR rule).
        for _ in 0..(366 * 9) {
            let (_, month, dom) = civil_from_days(day);
            let weekday = (day + 4).rem_euclid(7) as usize; // 1970-01-01 was a Thursday.
            if self.day_matches(month, dom, weekday) {
                for m in minute_of_day..1440 {
                    if self.hours[(m / 60) as usize] && self.minutes[(m % 60) as usize] {
                        return Some((day * 86_400 + m * 60) as f64);
                    }
                }
            }
            day += 1;
            minute_of_day = 0;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> f64 {
        parse_iso(text).unwrap()
    }

    #[test]
    fn formats_and_parses_iso_times() {
        assert_eq!(iso(0.0), "1970-01-01T00:00:00+00:00");
        assert_eq!(iso(1_791_504_000.25), "2026-10-09T00:00:00.250000+00:00");
        assert_eq!(at("2026-10-09T00:00:00+00:00"), 1_791_504_000.0);
        assert_eq!(at("2026-10-09T02:00:00+02:00"), 1_791_504_000.0);
        assert_eq!(at("2026-10-09T00:00:00Z"), 1_791_504_000.0);
        assert_eq!(at("2026-10-09"), 1_791_504_000.0);
        assert_eq!(at("2026-10-09 00:00:01.5"), 1_791_504_001.5);
        assert!(parse_iso("tomorrow").is_err());
    }

    #[test]
    fn finds_the_next_cron_time() {
        let monday_nine = Cron::parse("0 9 * * 1").unwrap();
        // 2026-10-09 is a Friday; the next Monday is 2026-10-12.
        assert_eq!(monday_nine.next_after(at("2026-10-09T10:00:00Z")), Some(at("2026-10-12T09:00:00Z")));
        // A time on a match gives the next one, not itself.
        assert_eq!(monday_nine.next_after(at("2026-10-12T09:00:00Z")), Some(at("2026-10-19T09:00:00Z")));
        let every_15 = Cron::parse("*/15 * * * *").unwrap();
        assert_eq!(every_15.next_after(at("2026-10-09T10:07:30Z")), Some(at("2026-10-09T10:15:00Z")));
        let names = Cron::parse("30 8 * jan,jul mon-fri").unwrap();
        assert_eq!(names.next_after(at("2026-10-09T00:00:00Z")), Some(at("2027-01-01T08:30:00Z")));
        // Day of month OR day of week when both are restricted: the 13th, or a Friday.
        let either = Cron::parse("0 0 13 * fri").unwrap();
        assert_eq!(either.next_after(at("2026-10-09T01:00:00Z")), Some(at("2026-10-13T00:00:00Z")));
        let sunday_seven = Cron::parse("0 0 * * 7").unwrap();
        assert_eq!(sunday_seven.next_after(at("2026-10-09T00:00:00Z")), Some(at("2026-10-11T00:00:00Z")));
        let leap = Cron::parse("0 0 29 2 *").unwrap();
        assert_eq!(leap.next_after(at("2026-10-09T00:00:00Z")), Some(at("2028-02-29T00:00:00Z")));
        assert_eq!(Cron::parse("@hourly").unwrap().next_after(at("2026-10-09T00:59:59Z")), Some(at("2026-10-09T01:00:00Z")));
        assert!(Cron::parse("0 9 * *").is_err());
        assert!(Cron::parse("61 * * * *").is_err());
        assert!(Cron::parse("0 0 L * *").is_err());
    }
}
