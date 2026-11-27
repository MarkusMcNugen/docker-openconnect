//! Wall-clock time as Unix seconds, and its RFC 3339 form for the audit log.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds in a day.
const DAY: u64 = 86_400;

/// The current time in whole seconds since the Unix epoch.
pub fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| format!("the system clock is set before the Unix epoch: {error}"))
}

/// Formats Unix seconds as an RFC 3339 UTC timestamp,
/// `YYYY-MM-DDThh:mm:ssZ`.
pub fn rfc3339(seconds: u64) -> String {
    let (year, month, day) = civil_from_days(seconds / DAY);
    let time = seconds % DAY;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        time % 3600 / 60,
        time % 60
    )
}

/// The UTC year and month, 1 to 12, of Unix seconds.
pub fn year_month(seconds: u64) -> (u64, u64) {
    let (year, month, _day) = civil_from_days(seconds / DAY);
    (year, month)
}

/// The month before a (year, month).
pub fn month_before((year, month): (u64, u64)) -> (u64, u64) {
    match month {
        1 => (year - 1, 12),
        month => (year, month - 1),
    }
}

/// The Unix seconds at the start of a UTC date written YYYY-MM-DD, as a
/// browser's date field sends it, from 1970 on.
pub fn date_start(text: &str) -> Result<u64, String> {
    let malformed = || format!("'{text}' is not a date written YYYY-MM-DD");
    let mut parts = text.split('-');
    let (Some(year), Some(month), Some(day), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed());
    };
    let number = |part: &str, digits: usize| -> Result<u64, String> {
        if part.len() != digits || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(malformed());
        }
        part.parse()
            .map_err(|error| format!("{}: {error}", malformed()))
    };
    let (year, month, day) = (number(year, 4)?, number(month, 2)?, number(day, 2)?);
    if year < 1970 || !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return Err(format!("{text} is not a day of the calendar from 1970 on"));
    }
    Ok(days_from_civil(year, month, day) * DAY)
}

/// The days of a month of the proleptic Gregorian calendar.
fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _other => 31,
    }
}

/// Converts a proleptic Gregorian (year, month, day) from 1970 on to days
/// since the Unix epoch, by Howard Hinnant's days_from_civil algorithm, the
/// inverse of civil_from_days.
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Converts days since the Unix epoch to a proleptic Gregorian (year,
/// month, day), by Howard Hinnant's civil_from_days algorithm.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        for (seconds, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (951_868_800, "2000-03-01T00:00:00Z"),
            (1_700_000_000, "2023-11-14T22:13:20Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
            (253_402_300_799, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(rfc3339(seconds), text, "for {seconds}");
        }
    }

    #[test]
    fn every_day_follows_the_one_before() {
        let mut previous = civil_from_days(0);
        for days in 1..200_000 {
            let current = civil_from_days(days);
            let (year, month, day) = previous;
            let next_day = (year, month, day + 1);
            let next_month = (year, month + 1, 1);
            let next_year = (year + 1, 1, 1);
            assert!(
                current == next_day || current == next_month || current == next_year,
                "{previous:?} then {current:?}"
            );
            previous = current;
        }
    }

    #[test]
    fn dates_turn_back_into_their_days() {
        for days in (0..200_000).step_by(7) {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(
                days_from_civil(year, month, day),
                days,
                "{year}-{month}-{day}"
            );
            let text = format!("{year:04}-{month:02}-{day:02}");
            assert_eq!(date_start(&text), Ok(days * DAY), "{text}");
        }
    }

    #[test]
    fn only_calendar_dates_written_in_full_are_read() {
        assert_eq!(date_start("2000-02-29"), Ok(951_782_400));
        for text in [
            "",
            "2026-11",
            "2026-11-27-1",
            "26-11-27",
            "2026-1-27",
            "2026-11-7",
            "2026-13-01",
            "2026-00-10",
            "2026-02-29",
            "2026-04-31",
            "1969-12-31",
            "2026-11-2a",
            "+026-11-27",
        ] {
            assert!(date_start(text).is_err(), "{text}");
        }
    }

    #[test]
    fn now_is_after_2020() {
        assert!(now().unwrap() > 1_577_836_800);
    }
}
