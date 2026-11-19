//! ISO 8601 date-times the way Python's datetime.fromisoformat reads and
//! isoformat writes them, and IANA time zones from the system's TZif files
//! (what zoneinfo.ZoneInfo reads).

use crate::util;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DateTime {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub micro: u32,
    /// Seconds east of UTC; None for a naive time.
    pub offset: Option<i32>,
}

fn digits(s: &str, n: usize) -> Option<u32> {
    (s.len() == n && s.bytes().all(|c| c.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// YYYY-MM-DD or YYYYMMDD.
pub fn parse_date(s: &str) -> Option<(i64, u32, u32)> {
    let (y, m, d) = if s.len() == 10 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-' {
        (digits(&s[..4], 4)?, digits(&s[5..7], 2)?, digits(&s[8..], 2)?)
    } else if s.len() == 8 {
        (digits(&s[..4], 4)?, digits(&s[4..6], 2)?, digits(&s[6..], 2)?)
    } else {
        return None;
    };
    let y = y as i64;
    (y >= 1 && (1..=12).contains(&m) && d >= 1 && d <= days_in_month(y, m)).then_some((y, m, d))
}

/// HH[:MM[:SS[.ffffff]]] or HHMM[SS]; a fraction of any length.
fn parse_time(s: &str) -> Option<(u32, u32, u32, u32)> {
    let (clock, frac) = match s.find(['.', ',']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let fields: Vec<u32> = if clock.contains(':') {
        clock.split(':').map(|p| digits(p, 2)).collect::<Option<Vec<_>>>()?
    } else {
        if clock.len() % 2 != 0 || clock.is_empty() || clock.len() > 6 {
            return None;
        }
        (0..clock.len() / 2).map(|i| digits(&clock[2 * i..2 * i + 2], 2)).collect::<Option<Vec<_>>>()?
    };
    if fields.is_empty() || fields.len() > 3 || (frac.is_some() && fields.len() != 3) {
        return None;
    }
    let (h, m, sec) = (fields[0], *fields.get(1).unwrap_or(&0), *fields.get(2).unwrap_or(&0));
    let micro = match frac {
        None => 0,
        Some(f) if !f.is_empty() && f.bytes().all(|c| c.is_ascii_digit()) => {
            let mut six: String = f.chars().take(6).collect();
            while six.len() < 6 {
                six.push('0');
            }
            six.parse().ok()?
        }
        Some(_) => return None,
    };
    (h < 24 && m < 60 && sec < 60).then_some((h, m, sec, micro))
}

fn parse_offset(sign: i32, s: &str) -> Option<i32> {
    let (h, m, sec, micro) = parse_time(s)?;
    if micro != 0 {
        return None;
    }
    Some(sign * (h as i32 * 3600 + m as i32 * 60 + sec as i32))
}

/// datetime.fromisoformat(text).
pub fn fromisoformat(text: &str) -> Option<DateTime> {
    let date_len = if text.len() >= 10 && text.as_bytes().get(4) == Some(&b'-') { 10 } else { 8 };
    if text.len() < date_len {
        return None;
    }
    let (y, mo, d) = parse_date(text.get(..date_len)?)?;
    let mut dt = DateTime { year: y, month: mo, day: d, hour: 0, minute: 0, second: 0, micro: 0, offset: None };
    let rest = &text[date_len..];
    if rest.is_empty() {
        return Some(dt);
    }
    let mut chars = rest.chars();
    chars.next()?;
    let rest = chars.as_str();
    let (time, tz) = match rest.find(['Z', '+', '-']) {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    let (h, mi, s, us) = parse_time(time)?;
    dt.hour = h;
    dt.minute = mi;
    dt.second = s;
    dt.micro = us;
    if let Some(tz) = tz {
        dt.offset = Some(match tz {
            "Z" => 0,
            _ if tz.starts_with('+') => parse_offset(1, &tz[1..])?,
            _ if tz.starts_with('-') => parse_offset(-1, &tz[1..])?,
            _ => return None,
        });
    }
    Some(dt)
}

impl DateTime {
    /// Seconds since the epoch of the wall clock as if it were UTC.
    pub fn wall_seconds(&self) -> i64 {
        util::days_from_civil(self.year, self.month, self.day) * 86400 + (self.hour * 3600 + self.minute * 60 + self.second) as i64
    }

    /// Microseconds since the epoch (aware times only).
    pub fn utc_micros(&self) -> Option<i128> {
        let off = self.offset? as i64;
        Some(((self.wall_seconds() - off) as i128) * 1_000_000 + self.micro as i128)
    }

    pub fn isoformat(&self) -> String {
        let mut out = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        );
        if self.micro != 0 {
            out.push_str(&format!(".{:06}", self.micro));
        }
        if let Some(off) = self.offset {
            let sign = if off < 0 { '-' } else { '+' };
            let a = off.unsigned_abs();
            out.push_str(&format!("{sign}{:02}:{:02}", a / 3600, a % 3600 / 60));
            if a % 60 != 0 {
                out.push_str(&format!(":{:02}", a % 60));
            }
        }
        out
    }

    pub fn from_unix(t: f64, offset: i32) -> Self {
        let secs = t.floor() as i64 + offset as i64;
        let micro = ((t - t.floor()) * 1e6).floor() as u32;
        let (year, month, day, hour, minute, second) = util::civil(secs);
        DateTime { year, month, day, hour, minute, second, micro, offset: Some(offset) }
    }
}

// ── zones ──────────────────────────────────────────────────────────────────

const ZONE_DIRS: [&str; 3] = ["/usr/share/zoneinfo", "/usr/lib/zoneinfo", "/usr/share/lib/zoneinfo"];

pub struct Zone {
    transitions: Vec<(i64, i32)>,
    initial: i32,
    rule: Option<Rule>,
}

/// The zone named key, as ZoneInfo(key) finds it, or None.
pub fn zone(key: &str) -> Option<Zone> {
    if key.is_empty() || key.starts_with('/') || key.split('/').any(|p| p == ".." || p == "." || p.is_empty()) {
        return None;
    }
    for dir in ZONE_DIRS {
        if let Ok(data) = std::fs::read(std::path::Path::new(dir).join(key)) {
            if let Some(z) = parse_tzif(&data) {
                return Some(z);
            }
        }
    }
    None
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn parse_tzif(data: &[u8]) -> Option<Zone> {
    if data.get(..4)? != b"TZif" {
        return None;
    }
    let version = *data.get(4)?;
    let counts = |at: usize| -> Option<[usize; 6]> {
        let mut c = [0usize; 6];
        for (k, slot) in c.iter_mut().enumerate() {
            *slot = be32(data, at + 20 + 4 * k)? as usize;
        }
        Some(c)
    };
    let [isut, isstd, leap, time, typ, chars] = counts(0)?;
    let v1_len = time * 5 + typ * 6 + chars + leap * 8 + isstd + isut;
    let (base, tsize, [_, _, leap2, time2, typ2, chars2]) = if version >= b'2' {
        let at = 44 + v1_len;
        if data.get(at..at + 4)? != b"TZif" {
            return None;
        }
        (at + 44, 8usize, counts(at)?)
    } else {
        (44, 4usize, [isut, isstd, leap, time, typ, chars])
    };
    let read_time = |i: usize| -> Option<i64> {
        let s = data.get(base + i * tsize..base + (i + 1) * tsize)?;
        Some(if tsize == 8 { i64::from_be_bytes(s.try_into().ok()?) } else { i32::from_be_bytes(s.try_into().ok()?) as i64 })
    };
    let idx_at = base + time2 * tsize;
    let types_at = idx_at + time2;
    let mut types = Vec::new();
    for k in 0..typ2 {
        let off = be32(data, types_at + 6 * k)? as i32;
        let isdst = *data.get(types_at + 6 * k + 4)?;
        types.push((off, isdst));
    }
    let mut transitions = Vec::new();
    for i in 0..time2 {
        let t = read_time(i)?;
        let idx = *data.get(idx_at + i)? as usize;
        transitions.push((t, types.get(idx)?.0));
    }
    let initial = types.iter().find(|t| t.1 == 0).or(types.first()).map(|t| t.0).unwrap_or(0);
    let mut rule = None;
    if version >= b'2' {
        let footer_at = types_at + typ2 * 6 + chars2 + leap2 * 12 + typ2 * 2;
        let _ = footer_at;
        if let Some(text) = data.iter().rposition(|&c| c == b'\n').and_then(|end| {
            let start = data[..end].iter().rposition(|&c| c == b'\n')? + 1;
            std::str::from_utf8(&data[start..end]).ok()
        }) {
            rule = parse_rule(text);
        }
    }
    Some(Zone { transitions, initial, rule })
}

/// A POSIX TZ rule: std offset, and optionally dst with its two changes.
struct Rule {
    std: i32,
    dst: Option<(i32, Change, i64, Change, i64)>,
}

#[derive(Clone, Copy)]
enum Change {
    Month(u32, u32, u32),
    Julian(u32),
    Day(u32),
}

fn parse_rule(s: &str) -> Option<Rule> {
    let mut p = s;
    let name = |p: &mut &str| -> Option<()> {
        if let Some(rest) = p.strip_prefix('<') {
            let end = rest.find('>')?;
            *p = &rest[end + 1..];
        } else {
            let n = p.chars().take_while(|c| c.is_ascii_alphabetic()).count();
            if n < 3 {
                return None;
            }
            *p = &p[n..];
        }
        Some(())
    };
    let offset = |p: &mut &str| -> Option<i64> {
        let n = p.chars().take_while(|c| c.is_ascii_digit() || matches!(c, ':' | '+' | '-')).count();
        let text = &p[..n];
        *p = &p[n..];
        let (sign, body) = match text.as_bytes().first() {
            Some(b'-') => (-1, &text[1..]),
            Some(b'+') => (1, &text[1..]),
            _ => (1, text),
        };
        let mut parts = body.split(':').map(|x| x.parse::<i64>());
        let h = parts.next()?.ok()?;
        let m = parts.next().transpose().ok()?.unwrap_or(0);
        let sec = parts.next().transpose().ok()?.unwrap_or(0);
        Some(sign * (h * 3600 + m * 60 + sec))
    };
    name(&mut p)?;
    let std = -offset(&mut p)? as i32;
    if p.is_empty() {
        return Some(Rule { std, dst: None });
    }
    name(&mut p)?;
    let dst_off = if p.starts_with(',') { std + 3600 } else { -offset(&mut p)? as i32 };
    let change = |text: &str| -> Option<(Change, i64)> {
        let (date, time) = match text.split_once('/') {
            Some((d, t)) => {
                let mut tt = t;
                (d, offset(&mut tt)?)
            }
            None => (text, 7200),
        };
        let c = if let Some(m) = date.strip_prefix('M') {
            let v: Vec<u32> = m.split('.').map(|x| x.parse().ok()).collect::<Option<_>>()?;
            if v.len() != 3 {
                return None;
            }
            Change::Month(v[0], v[1], v[2])
        } else if let Some(j) = date.strip_prefix('J') {
            Change::Julian(j.parse().ok()?)
        } else {
            Change::Day(date.parse().ok()?)
        };
        Some((c, time))
    };
    let rest = p.strip_prefix(',')?;
    let (a, b) = rest.split_once(',')?;
    let (start, start_t) = change(a)?;
    let (end, end_t) = change(b)?;
    Some(Rule { std, dst: Some((dst_off, start, start_t, end, end_t)) })
}

fn change_day(year: i64, c: Change) -> i64 {
    let jan1 = util::days_from_civil(year, 1, 1);
    match c {
        Change::Julian(n) => {
            let leap = days_in_month(year, 2) == 29;
            jan1 + n as i64 - 1 + i64::from(leap && n >= 60)
        }
        Change::Day(n) => jan1 + n as i64,
        Change::Month(m, w, d) => {
            let first = util::days_from_civil(year, m, 1);
            let weekday = (first + 4).rem_euclid(7);
            let mut day = first + (d as i64 - weekday).rem_euclid(7) + (w as i64 - 1) * 7;
            let last = first + days_in_month(year, m) as i64 - 1;
            while day > last {
                day -= 7;
            }
            day
        }
    }
}

impl Rule {
    /// The UTC instants of the changes of year, with the offsets around them.
    fn changes(&self, year: i64) -> Vec<(i64, i32, i32)> {
        let Some((dst, start, start_t, end, end_t)) = self.dst else { return vec![] };
        let s = change_day(year, start) * 86400 + start_t - self.std as i64;
        let e = change_day(year, end) * 86400 + end_t - dst as i64;
        let mut out = vec![(s, self.std, dst), (e, dst, self.std)];
        out.sort_by_key(|c| c.0);
        out
    }
}

impl Zone {
    fn all_transitions(&self, around: i64) -> Vec<(i64, i32, i32)> {
        let mut out = Vec::new();
        let mut before = self.initial;
        for &(t, off) in &self.transitions {
            out.push((t, before, off));
            before = off;
        }
        let last = self.transitions.last().map(|t| t.0).unwrap_or(i64::MIN);
        if let Some(rule) = &self.rule {
            let (year, ..) = util::civil(around);
            for y in [year - 1, year, year + 1] {
                for c in rule.changes(y) {
                    if c.0 > last {
                        out.push(c);
                    }
                }
            }
            if out.is_empty() || (self.transitions.is_empty() && rule.dst.is_none()) {
                return vec![(i64::MIN, rule.std, rule.std)];
            }
        }
        out.sort_by_key(|c| c.0);
        out
    }

    /// The offset of a local wall time, as zoneinfo resolves it with fold=0:
    /// a change takes effect at its UTC instant plus the larger of the two offsets.
    pub fn offset_of_local(&self, wall: i64) -> i32 {
        let list = self.all_transitions(wall);
        let mut off = list.first().map(|c| c.1).unwrap_or(self.initial);
        if list.first().is_some_and(|c| c.0 == i64::MIN) {
            off = list[0].2;
        }
        for (t, before, after) in list {
            if t == i64::MIN {
                continue;
            }
            if t + before.max(after) as i64 <= wall {
                off = after;
            } else {
                break;
            }
        }
        off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_like_python() {
        let d = fromisoformat("2026-11-20T10:00:00+00:00").unwrap();
        assert_eq!(d.isoformat(), "2026-11-20T10:00:00+00:00");
        assert_eq!(fromisoformat("2026-11-20").unwrap().isoformat(), "2026-11-20T00:00:00");
        assert_eq!(fromisoformat("2026-11-20T10:00:00.5-05:30").unwrap().isoformat(), "2026-11-20T10:00:00.500000-05:30");
        assert_eq!(fromisoformat("2026-11-20 10:00").unwrap().isoformat(), "2026-11-20T10:00:00");
        assert!(fromisoformat("2026-02-30T10:00:00").is_none());
        assert!(fromisoformat("tomorrow").is_none());
        assert!(fromisoformat("2026-11-20T25:00").is_none());
    }

    #[test]
    fn resolves_iana_zones() {
        let lisbon = zone("Europe/Lisbon").expect("system tzdata");
        let summer = fromisoformat("2026-07-01T12:00:00").unwrap().wall_seconds();
        let winter = fromisoformat("2026-01-01T12:00:00").unwrap().wall_seconds();
        assert_eq!(lisbon.offset_of_local(summer), 3600);
        assert_eq!(lisbon.offset_of_local(winter), 0);
        let ny = zone("America/New_York").unwrap();
        assert_eq!(ny.offset_of_local(fromisoformat("2040-07-01T12:00:00").unwrap().wall_seconds()), -4 * 3600);
        assert_eq!(ny.offset_of_local(fromisoformat("2040-01-01T12:00:00").unwrap().wall_seconds()), -5 * 3600);
        assert!(zone("UTC").is_some());
        assert!(zone("Mars/Base").is_none() && zone("../etc/passwd").is_none() && zone("").is_none());
    }
}
