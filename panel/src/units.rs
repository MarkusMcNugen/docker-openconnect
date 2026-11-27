//! Numbers as pages and messages write them: byte amounts with their unit
//! symbols, and counts with their thousands marked.

/// A byte count with its decimal unit symbol, with one decimal below ten:
/// "912 MB", "3.1 MB", "512 B".
pub fn amount(bytes: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1_000_000_000_000, "TB"),
        (1_000_000_000, "GB"),
        (1_000_000, "MB"),
        (1_000, "kB"),
    ];
    for (size, unit) in UNITS {
        if bytes >= size {
            let tenths = u128::from(bytes) * 10 / u128::from(size);
            return if tenths < 100 {
                format!("{}.{} {unit}", tenths / 10, tenths % 10)
            } else {
                format!("{} {unit}", tenths / 10)
            };
        }
    }
    format!("{bytes} B")
}

/// A count with a comma between each group of three digits: "1,234,567".
pub fn count(number: u64) -> String {
    let digits = number.to_string();
    let mut text = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push(',');
        }
        text.push(digit);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_carry_their_unit() {
        assert_eq!(amount(0), "0 B");
        assert_eq!(amount(1), "1 B");
        assert_eq!(amount(512), "512 B");
        assert_eq!(amount(3_120_554), "3.1 MB");
        assert_eq!(amount(48_211_337), "48 MB");
        assert_eq!(amount(912_004_113), "912 MB");
        assert_eq!(amount(1_500_000_000_000), "1.5 TB");
        assert_eq!(amount(u64::MAX), "18446744 TB");
    }

    #[test]
    fn counts_mark_their_thousands() {
        for (number, text) in [
            (0, "0"),
            (7, "7"),
            (999, "999"),
            (1_000, "1,000"),
            (12_345, "12,345"),
            (1_234_567, "1,234,567"),
            (u64::MAX, "18,446,744,073,709,551,615"),
        ] {
            assert_eq!(count(number), text);
        }
    }
}
