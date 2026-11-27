//! Argon2id password hashes in PHC string form.

use argon2::password_hash::{
    Error as HashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::secret;

/// Random bytes in each salt.
const SALT_BYTES: usize = 16;

/// Argon2id with the configured memory cost and passes, in one lane.
pub struct Hasher {
    argon2: Argon2<'static>,
    /// A hash of a random password, checked instead of a real one when the
    /// named admin does not exist, so that the answer takes as long as a real
    /// check and its timing does not tell which names exist.
    decoy: String,
}

impl Hasher {
    /// A hasher that writes new hashes with `memory_kib` KiB and `passes`
    /// passes. Verification always follows the parameters stored in the hash
    /// being checked.
    pub fn new(memory_kib: u32, passes: u32) -> Result<Hasher, String> {
        let params = Params::new(memory_kib, passes, 1, None)
            .map_err(|error| format!("invalid Argon2 parameters: {error}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let decoy = hash_with(&argon2, &secret::token()?)?;
        Ok(Hasher { argon2, decoy })
    }

    /// Hashes a password with a new random salt.
    pub fn hash(&self, password: &str) -> Result<String, String> {
        hash_with(&self.argon2, password)
    }

    /// Whether `password` matches the stored hash `phc`. A malformed stored
    /// hash, one without its salt or digest, or one of another algorithm
    /// than Argon2id is an error, never a mismatch.
    pub fn verify(&self, password: &str, phc: &str) -> Result<bool, String> {
        let parsed = PasswordHash::new(phc)
            .map_err(|error| format!("a stored password hash is malformed: {error}"))?;
        if parsed.algorithm.as_str() != "argon2id" {
            return Err(format!(
                "a stored password hash uses {}, not argon2id",
                parsed.algorithm
            ));
        }
        if parsed.salt.is_none() || parsed.hash.is_none() {
            return Err("a stored password hash has no salt or no digest".to_owned());
        }
        match self.argon2.verify_password(password.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(HashError::Password) => Ok(false),
            Err(error) => Err(format!("a password could not be checked: {error}")),
        }
    }

    /// Checks `password` against the decoy hash: the cost of a real check,
    /// and always false.
    pub fn verify_decoy(&self, password: &str) -> Result<bool, String> {
        self.verify(password, &self.decoy)
    }
}

fn hash_with(argon2: &Argon2<'static>, password: &str) -> Result<String, String> {
    let salt = SaltString::encode_b64(&secret::random_bytes::<SALT_BYTES>()?)
        .map_err(|error| format!("a salt could not be encoded: {error}"))?;
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| format!("a password could not be hashed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small parameters keep the tests fast; the floor for real use is
    /// enforced where the settings are read.
    fn hasher() -> Hasher {
        Hasher::new(64, 1).unwrap()
    }

    #[test]
    fn hashes_verify() {
        let hasher = hasher();
        let phc = hasher.hash("correct horse battery staple").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=64,t=1,p=1$"), "{phc}");
        assert!(hasher.verify("correct horse battery staple", &phc).unwrap());
        assert!(
            !hasher
                .verify("correct horse battery stapler", &phc)
                .unwrap()
        );
    }

    #[test]
    fn salts_differ() {
        let hasher = hasher();
        assert_ne!(hasher.hash("same").unwrap(), hasher.hash("same").unwrap());
    }

    #[test]
    fn verification_follows_the_stored_parameters() {
        let old = Hasher::new(128, 2).unwrap().hash("password one").unwrap();
        assert!(hasher().verify("password one", &old).unwrap());
    }

    #[test]
    fn a_malformed_hash_is_an_error() {
        assert!(hasher().verify("anything", "not a hash").is_err());
        assert!(hasher().verify("anything", "$argon2id$v=19$m=64").is_err());
        let weaker = hasher()
            .hash("anything")
            .unwrap()
            .replacen("argon2id", "argon2i", 1);
        assert!(hasher().verify("anything", &weaker).is_err());
    }

    #[test]
    fn the_decoy_never_matches() {
        assert!(!hasher().verify_decoy("").unwrap());
        assert!(!hasher().verify_decoy("password").unwrap());
    }

    #[test]
    fn parameters_below_argon2s_minimum_are_refused() {
        assert!(Hasher::new(1, 1).is_err());
        assert!(Hasher::new(64, 0).is_err());
    }
}
