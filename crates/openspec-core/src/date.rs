//! Dependency-free civil-date formatting (`YYYY-MM-DD`).
//!
//! Uses Howard Hinnant's `civil_from_days` algorithm so archive naming and
//! change metadata need no external date crate — keeping the binary encased.

use std::time::{SystemTime, UNIX_EPOCH};

/// Today's date in UTC as `YYYY-MM-DD`. Falls back to the epoch if the system
/// clock predates 1970 (it won't in practice).
pub fn today_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    from_unix_secs(secs)
}

/// Format a Unix timestamp (seconds) as a UTC `YYYY-MM-DD` string.
pub fn from_unix_secs(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert days since 1970-01-01 to a `(year, month, day)` civil date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (y + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_epochs() {
        assert_eq!(from_unix_secs(0), "1970-01-01");
        assert_eq!(from_unix_secs(1_000_000_000), "2001-09-09");
        // 2026-06-29 00:00:00 UTC
        assert_eq!(from_unix_secs(1_782_691_200), "2026-06-29");
        // A leap day: 2020-02-29 00:00:00 UTC.
        assert_eq!(from_unix_secs(1_582_934_400), "2020-02-29");
    }
}
