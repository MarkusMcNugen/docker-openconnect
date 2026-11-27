//! The admin accounts, kept in admins.json in the panel's data directory.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::files;

/// The version of admins.json this program reads and writes.
const FORMAT_VERSION: u32 = 1;

/// The longest admin name, in characters.
pub const MAX_NAME_LEN: usize = 64;

/// What an admin may do in the panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Everything, including settings, certificates, admins and the audit log.
    Owner,
    /// VPN users, groups, sessions and bans.
    Operator,
    /// Reads the dashboard, sessions, users and events.
    Viewer,
}

/// One admin account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    /// The sign-in name, in lower case.
    pub name: String,
    pub role: Role,
    /// An Argon2id hash in PHC string form.
    pub password_hash: String,
    /// Set for a one-time password, which must be replaced at the next
    /// sign-in.
    pub must_change_password: bool,
    /// The base32 TOTP secret, once one is enrolled.
    pub totp_secret: Option<String>,
    /// The TOTP step of the last code accepted; that code and earlier ones
    /// are refused.
    pub last_totp_step: Option<u64>,
    /// Set when the account is created and cleared when its first second
    /// factor is enrolled. While it is set, sign-in from outside the LAN
    /// without a second factor opens an enrollment-only session.
    pub enrollment_open: bool,
    /// Consecutive wrong passwords since the last sign-in or lockout.
    pub failed_logins: u32,
    /// Unix time until which sign-in is refused.
    pub locked_until: Option<u64>,
    /// Unix time the account was created.
    pub created: u64,
    /// Unix time of the last successful sign-in.
    pub last_login: Option<u64>,
    /// The passkeys the admin registered, each a second factor beside the
    /// authenticator app; left out of the file while there are none, so the
    /// file stays as an older panel wrote it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<StoredPasskey>,
    /// The random user handle, a UUID, that the admin's passkeys carry,
    /// made at their first passkey and left out of the file until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_user: Option<String>,
}

/// A passkey an admin registered: the name they gave it, when it was added
/// and last used, and the credential a sign-in is checked against, as
/// webauthn-rs serializes it: a public key, never a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPasskey {
    pub name: String,
    pub created: u64,
    pub last_used: Option<u64>,
    pub credential: String,
}

impl Admin {
    /// Whether the admin has a second factor: an authenticator app, a
    /// passkey, or both.
    pub fn has_second_factor(&self) -> bool {
        self.totp_secret.is_some() || !self.passkeys.is_empty()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    version: u32,
    admins: Vec<Admin>,
}

/// The admin accounts, loaded from and saved to one file.
pub struct Store {
    path: PathBuf,
    admins: Vec<Admin>,
}

impl Store {
    /// Loads `path`, or starts empty when it does not exist. A file of
    /// another format version, with unknown fields, invalid names or two
    /// accounts of one name is refused, never repaired.
    pub fn open(path: &Path) -> Result<Store, String> {
        let admins = match fs::read(path) {
            Ok(bytes) => {
                let file: StoreFile = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                if file.version != FORMAT_VERSION {
                    return Err(format!(
                        "{}: format version {} is not the version {FORMAT_VERSION} this panel reads",
                        path.display(),
                        file.version
                    ));
                }
                file.admins
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        for (index, admin) in admins.iter().enumerate() {
            let canonical = canonical_name(&admin.name)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if canonical != admin.name {
                return Err(format!(
                    "{}: the name '{}' is not in lower case",
                    path.display(),
                    admin.name
                ));
            }
            if admins[..index].iter().any(|other| other.name == admin.name) {
                return Err(format!(
                    "{}: the name '{}' appears twice",
                    path.display(),
                    admin.name
                ));
            }
        }
        Ok(Store {
            path: path.to_owned(),
            admins,
        })
    }

    /// Writes the accounts to the file, atomically and readable by root only.
    pub fn save(&self) -> Result<(), String> {
        let file = StoreFile {
            version: FORMAT_VERSION,
            admins: self.admins.clone(),
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|error| format!("{}: {error}", self.path.display()))?;
        files::write_private(&self.path, &json)
    }

    pub fn is_empty(&self) -> bool {
        self.admins.is_empty()
    }

    /// The admin of the given name, compared in lower case.
    pub fn get(&self, name: &str) -> Option<&Admin> {
        let wanted = name.to_ascii_lowercase();
        self.admins.iter().find(|admin| admin.name == wanted)
    }

    /// Every admin, in the order they were added.
    pub fn list(&self) -> &[Admin] {
        &self.admins
    }

    /// Removes the admin of the given name, compared in lower case; false
    /// when there was none.
    pub fn remove(&mut self, name: &str) -> bool {
        let wanted = name.to_ascii_lowercase();
        let before = self.admins.len();
        self.admins.retain(|admin| admin.name != wanted);
        self.admins.len() != before
    }

    /// The admin of the given name, compared in lower case.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Admin> {
        let wanted = name.to_ascii_lowercase();
        self.admins.iter_mut().find(|admin| admin.name == wanted)
    }

    /// Adds an account whose name is already canonical and not taken.
    pub fn add(&mut self, admin: Admin) -> Result<(), String> {
        let canonical = canonical_name(&admin.name)?;
        if canonical != admin.name {
            return Err(format!("the name '{}' is not in lower case", admin.name));
        }
        if self.get(&admin.name).is_some() {
            return Err(format!("an admin named '{}' already exists", admin.name));
        }
        self.admins.push(admin);
        Ok(())
    }
}

/// Validates an admin name and returns it in lower case: 1 to 64 letters,
/// digits, dots, hyphens, underscores and at signs.
pub fn canonical_name(name: &str) -> Result<String, String> {
    match name_problem(name) {
        Some(problem) => Err(format!("'{name}' is not an admin name: {problem}")),
        None => Ok(name.to_ascii_lowercase()),
    }
}

/// The rule `name` breaks as an admin name, without the name itself, or
/// none when it is a valid one.
pub fn name_problem(name: &str) -> Option<String> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Some(format!("it must be 1 to {MAX_NAME_LEN} characters long"));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'@'))
    {
        return Some("only letters, digits, '.', '-', '_' and '@' are allowed".to_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    fn admin(name: &str) -> Admin {
        Admin {
            name: name.to_owned(),
            role: Role::Owner,
            password_hash: "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaA".to_owned(),
            must_change_password: true,
            totp_secret: None,
            last_totp_step: None,
            enrollment_open: true,
            failed_logins: 0,
            locked_until: None,
            created: 1,
            last_login: None,
            passkeys: Vec::new(),
            passkey_user: None,
        }
    }

    #[test]
    fn a_missing_file_is_an_empty_store() {
        let dir = TestDir::new();
        let store = Store::open(&dir.path().join("admins.json")).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn accounts_survive_a_save_and_a_reload() {
        let dir = TestDir::new();
        let path = dir.path().join("admins.json");
        let mut store = Store::open(&path).unwrap();
        store.add(admin("alex")).unwrap();
        store.save().unwrap();
        let reloaded = Store::open(&path).unwrap();
        assert_eq!(reloaded.get("alex"), Some(&admin("alex")));
        assert_eq!(reloaded.get("ALEX"), Some(&admin("alex")));
        assert_eq!(reloaded.get("kai"), None);
    }

    #[test]
    fn passkeys_are_kept_and_an_empty_list_is_left_out() {
        let dir = TestDir::new();
        let path = dir.path().join("admins.json");
        let mut store = Store::open(&path).unwrap();
        store.add(admin("alex")).unwrap();
        store.save().unwrap();
        assert!(!fs::read_to_string(&path).unwrap().contains("passkeys"));
        store.get_mut("alex").unwrap().passkeys.push(StoredPasskey {
            name: "Work laptop".to_owned(),
            created: 5,
            last_used: None,
            credential: "{}".to_owned(),
        });
        store.save().unwrap();
        let reloaded = Store::open(&path).unwrap();
        assert_eq!(
            reloaded.get("alex").unwrap().passkeys[0].name,
            "Work laptop"
        );
    }

    #[test]
    fn names_are_unique_and_lower_case() {
        let dir = TestDir::new();
        let mut store = Store::open(&dir.path().join("admins.json")).unwrap();
        store.add(admin("alex")).unwrap();
        assert!(store.add(admin("alex")).is_err());
        assert!(store.add(admin("Kai")).is_err());
    }

    #[test]
    fn name_rules() {
        assert_eq!(canonical_name("Alex.Ops-1_a@b").unwrap(), "alex.ops-1_a@b");
        for bad in ["", "a b", "a:b", "a/b", "\u{e9}", &"a".repeat(65)] {
            assert!(canonical_name(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn other_versions_and_unknown_fields_are_refused() {
        let dir = TestDir::new();
        let path = dir.path().join("admins.json");
        fs::write(&path, br#"{"version":2,"admins":[]}"#).unwrap();
        assert!(Store::open(&path).is_err());
        fs::write(&path, br#"{"version":1,"admins":[],"extra":true}"#).unwrap();
        assert!(Store::open(&path).is_err());
        fs::write(&path, b"not json").unwrap();
        assert!(Store::open(&path).is_err());
    }

    #[test]
    fn duplicate_or_upper_case_names_in_the_file_are_refused() {
        let dir = TestDir::new();
        let path = dir.path().join("admins.json");
        let twice = StoreFile {
            version: FORMAT_VERSION,
            admins: vec![admin("alex"), admin("alex")],
        };
        fs::write(&path, serde_json::to_vec(&twice).unwrap()).unwrap();
        assert!(Store::open(&path).is_err());
        let upper = StoreFile {
            version: FORMAT_VERSION,
            admins: vec![admin("Alex")],
        };
        fs::write(&path, serde_json::to_vec(&upper).unwrap()).unwrap();
        assert!(Store::open(&path).is_err());
    }
}
