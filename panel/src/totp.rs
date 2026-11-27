//! Time-based one-time passwords, RFC 6238: HMAC-SHA1, six digits,
//! 30-second steps, the defaults every authenticator app uses.

use data_encoding::{BASE32_NOPAD, HEXLOWER};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::secret;

/// Seconds per step.
pub const STEP: u64 = 30;

/// Digits in a code.
const DIGITS: u32 = 6;

/// Secret length in bytes: 160 bits, the size RFC 4226 recommends.
const SECRET_BYTES: usize = 20;

/// A new random secret, as unpadded base32.
pub fn new_secret() -> Result<String, String> {
    Ok(BASE32_NOPAD.encode(&secret::random_bytes::<SECRET_BYTES>()?))
}

/// A base32 secret in lowercase hex, as liboath's users file holds it.
pub fn hex_of(secret_base32: &str) -> Result<String, String> {
    let key = Zeroizing::new(
        BASE32_NOPAD
            .decode(secret_base32.as_bytes())
            .map_err(|error| format!("a TOTP secret is not base32: {error}"))?,
    );
    Ok(HEXLOWER.encode(&key))
}

/// The code for `step`, from a base32 secret.
pub fn code(secret_base32: &str, step: u64) -> Result<u32, String> {
    let key = Zeroizing::new(
        BASE32_NOPAD
            .decode(secret_base32.as_bytes())
            .map_err(|error| format!("a TOTP secret is not base32: {error}"))?,
    );
    code_of(&key, step, DIGITS)
}

/// The `digits`-digit code for `step` from a key's bytes, RFC 4226.
pub fn code_of(key: &[u8], step: u64, digits: u32) -> Result<u32, String> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key)
        .map_err(|error| format!("a TOTP secret cannot key HMAC: {error}"))?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    Ok(value % 10u32.pow(digits))
}

/// Checks `given`, six digits, against the step of `now` and the steps on
/// either side of it, and returns the step it matched. Steps at or before
/// `last_used` never match, so a code works once.
pub fn verify(
    secret_base32: &str,
    given: &str,
    now: u64,
    last_used: Option<u64>,
) -> Result<Option<u64>, String> {
    if given.len() != DIGITS as usize || !given.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let current = now / STEP;
    let mut matched = None;
    for step in [
        current.saturating_sub(1),
        current,
        current.saturating_add(1),
    ] {
        if last_used.is_some_and(|last| step <= last) {
            continue;
        }
        let expected = format!(
            "{:0width$}",
            code(secret_base32, step)?,
            width = DIGITS as usize
        );
        if secret::equal(expected.as_bytes(), given.as_bytes()) && matched.is_none() {
            matched = Some(step);
        }
    }
    Ok(matched)
}

/// The `otpauth://` URI an authenticator app reads from a QR code.
pub fn uri(secret_base32: &str, account: &str, issuer: &str) -> String {
    let issuer = percent_encode(issuer);
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_base32}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP}",
        account = percent_encode(account),
    )
}

/// Percent-encodes everything but unreserved URI characters.
fn percent_encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "12345678901234567890", the RFC 6238 SHA-1 test secret.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors() {
        for (time, expected) in [
            (59, 287_082),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
        ] {
            assert_eq!(
                code(RFC_SECRET, time / STEP).unwrap(),
                expected,
                "at {time}"
            );
        }
    }

    #[test]
    fn codes_match_their_step_and_one_either_side() {
        let now = 1_234_567_890;
        let step = now / STEP;
        assert_eq!(verify(RFC_SECRET, "005924", now, None).unwrap(), Some(step));
        let early = format!("{:06}", code(RFC_SECRET, step - 1).unwrap());
        let late = format!("{:06}", code(RFC_SECRET, step + 1).unwrap());
        let stale = format!("{:06}", code(RFC_SECRET, step - 2).unwrap());
        assert_eq!(
            verify(RFC_SECRET, &early, now, None).unwrap(),
            Some(step - 1)
        );
        assert_eq!(
            verify(RFC_SECRET, &late, now, None).unwrap(),
            Some(step + 1)
        );
        assert_eq!(verify(RFC_SECRET, &stale, now, None).unwrap(), None);
    }

    #[test]
    fn a_code_works_once() {
        let now = 1_234_567_890;
        let step = verify(RFC_SECRET, "005924", now, None).unwrap();
        assert_eq!(verify(RFC_SECRET, "005924", now, step).unwrap(), None);
        let early = format!("{:06}", code(RFC_SECRET, now / STEP - 1).unwrap());
        assert_eq!(verify(RFC_SECRET, &early, now, step).unwrap(), None);
    }

    #[test]
    fn malformed_codes_never_match() {
        for given in ["", "12345", "1234567", "12345a", "+12345", "005 24"] {
            assert_eq!(
                verify(RFC_SECRET, given, 1_234_567_890, None).unwrap(),
                None,
                "{given:?}"
            );
        }
    }

    #[test]
    fn secrets_convert_to_the_hex_liboath_reads() {
        assert_eq!(
            hex_of(RFC_SECRET).unwrap(),
            "3132333435363738393031323334353637383930"
        );
        assert!(hex_of("not base32!").is_err());
    }

    #[test]
    fn new_secrets_are_160_bits_of_base32() {
        let secret = new_secret().unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(BASE32_NOPAD.decode(secret.as_bytes()).unwrap().len(), 20);
        assert_ne!(secret, new_secret().unwrap());
    }

    #[test]
    fn uris_are_what_authenticators_read() {
        assert_eq!(
            uri("JBSWY3DPEHPK3PXP", "alex@vpn", "OpenConnect admin"),
            "otpauth://totp/OpenConnect%20admin:alex%40vpn?secret=JBSWY3DPEHPK3PXP\
             &issuer=OpenConnect%20admin&algorithm=SHA1&digits=6&period=30"
        );
    }
}
