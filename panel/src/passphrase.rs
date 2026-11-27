//! Generated VPN passwords: five words from the EFF large word list and a
//! two-digit number at a random place among them, joined by hyphens, as in
//! `tuba-lantern-orbit-57-quill-mango`. Five words of 7,776, one number of
//! 90 and one place of six give about 74 bits.
//!
//! The word list is the Electronic Frontier Foundation's large word list,
//! <https://www.eff.org/dice>, under CC BY 3.0.

use crate::secret;

/// The EFF large word list: one `dice-digits<TAB>word` line per word.
const WORD_LIST: &str = include_str!("../data/eff_large_wordlist.txt");

/// Words in a generated password.
const WORDS: usize = 5;

/// The words of the list, in order.
fn words() -> Vec<&'static str> {
    WORD_LIST
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(_, word)| word)
        .collect()
}

/// A uniformly random number below `bound`, which must be at most 65,536,
/// from the system's random number generator.
fn below(bound: u32) -> Result<u32, String> {
    let range = 1u32 << 16;
    let limit = range - range % bound;
    loop {
        let candidate = u32::from(u16::from_be_bytes(secret::random_bytes::<2>()?));
        if candidate < limit {
            return Ok(candidate % bound);
        }
    }
}

/// A new generated password.
pub fn generate() -> Result<String, String> {
    let list = words();
    let count =
        u32::try_from(list.len()).map_err(|error| format!("the word list is too long: {error}"))?;
    let mut parts = Vec::with_capacity(WORDS + 1);
    for _ in 0..WORDS {
        let index = usize::try_from(below(count)?)
            .map_err(|error| format!("a word index does not fit: {error}"))?;
        parts.push(list[index].to_owned());
    }
    let number = (10 + below(90)?).to_string();
    let place =
        usize::try_from(below(u32::try_from(WORDS + 1).map_err(|error| {
            format!("the number of places does not fit: {error}")
        })?)?)
        .map_err(|error| format!("a place does not fit: {error}"))?;
    parts.insert(place, number);
    Ok(parts.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_list_is_the_whole_eff_large_list() {
        let list = words();
        assert_eq!(list.len(), 7776);
        assert_eq!(list[0], "abacus");
        assert_eq!(list[7775], "zoom");
        assert!(list.iter().all(|word| (3..=9).contains(&word.len())));
    }

    #[test]
    fn a_password_is_five_words_and_a_number() {
        let list = words();
        for _ in 0..50 {
            let password = generate().unwrap();
            let numbers: Vec<&str> = password
                .split('-')
                .filter(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
                .collect();
            assert_eq!(numbers.len(), 1, "{password}");
            let number: u32 = numbers[0].parse().unwrap();
            assert!((10..100).contains(&number), "{password}");
            let without = password.replacen(&format!("{number}"), "", 1);
            let rejoined: String = without.split('-').filter(|part| !part.is_empty()).collect();
            assert!(
                rejoined.chars().all(|c| c.is_ascii_lowercase()),
                "{password}"
            );
            assert!(password.split('-').count() >= 6, "{password}");
            assert!(
                list.iter().any(|word| password.contains(word)),
                "{password}"
            );
        }
        assert_ne!(generate().unwrap(), generate().unwrap());
    }

    #[test]
    fn below_stays_in_range() {
        for bound in [1, 2, 6, 90, 7776] {
            for _ in 0..200 {
                assert!(below(bound).unwrap() < bound);
            }
        }
    }
}
