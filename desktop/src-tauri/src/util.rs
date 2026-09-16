//! Small helpers. Deliberately dependency-free: a datetime crate would cost
//! more binary than the entire crypto stack, and GitHub only ever emits one
//! timestamp format.

/// Parse the UTC timestamps GitHub returns (`2026-09-16T12:34:56Z`) into Unix
/// seconds.
///
/// Fractional seconds and non-`Z` offsets are tolerated by ignoring anything
/// after the seconds field, because GitHub has historically emitted both
/// `...:56Z` and `...:56.000Z`. Anything that does not at least look like the
/// expected shape returns `None` rather than guessing -- a wrong countdown is
/// worse than no countdown.
pub fn rfc3339_to_unix(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }

    let total = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(total).ok()
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
///
/// Howard Hinnant's `days_from_civil`, which is exact for the whole Gregorian
/// range and needs no lookup tables.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = y - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `HH:MM:SS` for a duration, for the countdown display.
pub fn format_hms(total_secs: u64) -> String {
    let h = total_secs / 3_600;
    let m = (total_secs % 3_600) / 60;
    let s = total_secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// A short, non-reversible description of a secret, for the UI.
///
/// Returns the length and a truncated SHA-256 prefix. Neither reveals the
/// secret, and together they let a user confirm that the value they just pasted
/// is the one stored -- which is the actual question the UI needs to answer.
pub fn secret_fingerprint(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let prefix: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
    format!("{} chars, sha256:{}...", value.chars().count(), prefix)
}

/// Truncate a value for a log line. Never used on secret material -- only on
/// repository names, run ids and other non-secret identifiers.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}...")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_github_timestamps() {
        // Cross-checked against `date -u -d ... +%s`.
        assert_eq!(rfc3339_to_unix("2026-09-16T12:34:56Z"), Some(1_789_562_096));
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_to_unix("1970-01-02T00:00:00Z"), Some(86_400));
        // Leap day.
        assert_eq!(rfc3339_to_unix("2024-02-29T00:00:00Z"), Some(1_709_164_800));
    }

    #[test]
    fn tolerates_fractional_seconds_and_rejects_junk() {
        // Compared against the whole-second parse of the same instant rather than
        // unwrapped: this crate denies `unwrap_used` deliberately, and a test is
        // not a reason to carve an exception into a panic-free rule.
        let whole = rfc3339_to_unix("2026-09-16T12:34:56Z");
        assert_eq!(rfc3339_to_unix("2026-09-16T12:34:56.000Z"), whole);
        assert_eq!(rfc3339_to_unix(""), None);
        assert_eq!(rfc3339_to_unix("not-a-date"), None);
        assert_eq!(rfc3339_to_unix("2026-13-16T12:34:56Z"), None);
        assert_eq!(rfc3339_to_unix("2026-09-16T25:34:56Z"), None);
        assert_eq!(rfc3339_to_unix("1969-01-01T00:00:00Z"), None, "pre-epoch");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_hms(0), "00:00:00");
        assert_eq!(format_hms(340 * 60), "05:40:00");
        assert_eq!(format_hms(3_661), "01:01:01");
    }

    #[test]
    fn fingerprint_describes_without_revealing() {
        let value = "ghp_averysecretgithubtokenvalue";
        let fp = secret_fingerprint(value);
        assert!(fp.contains("31 chars"));
        assert!(!fp.contains("ghp_"));
        assert!(!fp.contains("secret"));
    }
}
