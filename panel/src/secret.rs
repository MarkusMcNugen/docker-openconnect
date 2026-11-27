//! Random tokens, the digests they are kept under, and constant-time
//! comparison.

use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Random bytes in a session, CSRF or pending sign-in token: 256 bits.
const TOKEN_BYTES: usize = 32;

/// Random bytes in a one-time password: 120 bits.
const ONE_TIME_PASSWORD_BYTES: usize = 15;

/// Characters between the hyphens of a one-time password.
const ONE_TIME_PASSWORD_GROUP: usize = 4;

/// Bytes from the operating system's random number generator.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| format!("the system random number generator failed: {error}"))?;
    Ok(bytes)
}

/// A new random token, as unpadded base64url.
pub fn token() -> Result<String, String> {
    Ok(BASE64URL_NOPAD.encode(&random_bytes::<TOKEN_BYTES>()?))
}

/// The SHA-256 digest a token is kept under, so that what the helper holds in
/// memory cannot itself be presented as a token.
pub fn digest(token: &str) -> [u8; 32] {
    let output = Sha256::digest(token.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&output);
    bytes
}

/// Whether two byte strings are equal, in time that depends only on their
/// lengths.
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// A one-time password: 120 random bits as lower-case base32 in groups of
/// four, `abcd-efgh-ijkl-mnop-qrst-uvwx`.
pub fn one_time_password() -> Result<String, String> {
    let encoded = BASE32_NOPAD
        .encode(&random_bytes::<ONE_TIME_PASSWORD_BYTES>()?)
        .to_ascii_lowercase();
    let mut password =
        String::with_capacity(encoded.len() + encoded.len() / ONE_TIME_PASSWORD_GROUP);
    for (index, character) in encoded.chars().enumerate() {
        if index > 0 && index % ONE_TIME_PASSWORD_GROUP == 0 {
            password.push('-');
        }
        password.push(character);
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_256_bits_of_base64url() {
        let one = token().unwrap();
        let two = token().unwrap();
        assert_eq!(one.len(), 43);
        assert_ne!(one, two);
        assert!(
            one.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
    }

    #[test]
    fn digests_are_sha256() {
        assert_eq!(
            data_encoding::HEXLOWER.encode(&digest("abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn equality() {
        assert!(equal(b"same", b"same"));
        assert!(!equal(b"same", b"Same"));
        assert!(!equal(b"same", b"same "));
        assert!(equal(b"", b""));
    }

    #[test]
    fn one_time_passwords_are_six_groups_of_four() {
        let password = one_time_password().unwrap();
        let groups: Vec<&str> = password.split('-').collect();
        assert_eq!(groups.len(), 6, "{password}");
        for group in groups {
            assert_eq!(group.len(), 4, "{password}");
            assert!(
                group
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
            );
        }
        assert_ne!(password, one_time_password().unwrap());
    }
}
