//! Clock and random ids the way the Python services write them.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the epoch, as Python's time.time().
pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Random bytes from the operating system.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut out))
        .expect("the operating system's random source is readable");
    out
}

/// uuid4().hex
pub fn uuid_hex() -> String {
    let mut b = random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    crate::sha256::hex(&b)
}

/// The UTC calendar date and time of a Unix second.
pub fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, (rem / 3600) as u32, (rem % 3600 / 60) as u32, (rem % 60) as u32)
}

fn parts(t: f64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let secs = t.floor() as i64;
    let micros = ((t - t.floor()) * 1e6).floor().min(999_999.0) as u32;
    let (y, mo, d, h, mi, s) = civil(secs);
    (y, mo, d, h, mi, s, micros)
}

/// datetime.now(timezone.utc).isoformat() with "+00:00" written as "Z", always
/// with six fraction digits.
pub fn utc_stamp(t: f64) -> String {
    let (y, mo, d, h, mi, s, micros) = parts(t);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{micros:06}Z")
}

/// datetime.now(timezone.utc).isoformat() exactly: "+00:00", and no fraction
/// when the microseconds are zero.
pub fn utc_isoformat(t: f64) -> String {
    let (y, mo, d, h, mi, s, micros) = parts(t);
    let fraction = if micros == 0 { String::new() } else { format!(".{micros:06}") };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{fraction}+00:00")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_and_ids() {
        assert_eq!(utc_stamp(0.5), "1970-01-01T00:00:00.500000Z");
        assert_eq!(utc_isoformat(0.0), "1970-01-01T00:00:00+00:00");
        assert_eq!(utc_isoformat(1.25), "1970-01-01T00:00:01.250000+00:00");
        let id = uuid_hex();
        assert_eq!(id.len(), 32);
        assert_eq!(&id[12..13], "4");
    }
}
