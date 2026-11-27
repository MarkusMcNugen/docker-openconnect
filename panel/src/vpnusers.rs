//! The VPN users in ocserv's password file, and changes to them. Writes go
//! through ocpasswd, which keeps the file's format and its lock: the file
//! named after it with .tmp added, which exists while one writer works. A
//! change of groups alone, which ocpasswd makes only with the password, is
//! written here under the same lock.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha_crypt::{PasswordVerifier, ShaCrypt};
use zeroize::Zeroizing;

use crate::otpfile::{self, CodeCheck};
use crate::{command, files, secret};

/// The longest VPN user password accepted, in characters. VPN passwords have
/// no minimum length, as with ocpasswd.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// The longest user or group name accepted, in bytes.
const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnUser {
    pub name: String,
    /// The user's groups; empty when the file names none.
    pub groups: Vec<String>,
    /// A locked user's password is kept but refused at sign-in.
    pub locked: bool,
    /// Whether the one-time password file has an entry for the user.
    pub otp: bool,
}

/// The users in a password file's text: one `name:groups:hash` line each,
/// groups comma-separated or `*` for none, and a locked user's hash starting
/// with `!`.
pub fn parse_passwd(text: &str, otp_users: &[String]) -> Result<Vec<VpnUser>, String> {
    let mut users = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.splitn(3, ':');
        let (Some(name), Some(groups), Some(hash)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(format!(
                "line {} of the password file is not name:groups:hash",
                index + 1
            ));
        };
        users.push(VpnUser {
            name: name.to_owned(),
            groups: match groups {
                "*" | "" => Vec::new(),
                listed => listed.split(',').map(str::to_owned).collect(),
            },
            locked: hash.starts_with('!'),
            otp: otp_users.iter().any(|user| user == name),
        });
    }
    Ok(users)
}

/// The user names in a one-time password file, liboath's users file: one
/// `type user pin secret ...` line each, and `#` starting a comment.
pub fn parse_otp_users(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(str::to_owned)
        .collect()
}

/// What checking a VPN user's password found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordCheck {
    /// The password is right and the user is not locked.
    Accepted,
    Wrong,
    /// The password file has no such user.
    Unknown,
    Locked,
    /// The user's hash is of a kind the panel cannot check, for this reason.
    Unsupported(String),
}

/// Hashes checked for an unknown user, of the kind the password file's
/// first user has, so that a check takes as long whether or not the user
/// exists: MD5-crypt, and SHA-256-crypt for the other kinds.
const DUMMY_MD5_HASH: &str = "$1$Ab3dE6gH$7/xcPT/9QbfnE8Si6wjl6.";
const DUMMY_HASH: &str = "$5$Ab3dE6gH9jK2mN5p$aJqvosbo9w1hzXE/qpdfhNWRyjaJ4TBceGiHz88eqjD";

/// The alphabet crypt(3) writes salts and hashes in.
const CRYPT_ALPHABET: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Checks `password` against `hash` from the password file: SHA-256-crypt,
/// which ocpasswd writes when built with glibc or with this image's patch,
/// MD5-crypt, which it writes when built with musl otherwise, or
/// SHA-512-crypt, with any rounds.
pub fn check_hash(hash: &str, password: &str) -> PasswordCheck {
    if let Some(rest) = hash.strip_prefix("$1$") {
        return check_md5_crypt(hash, rest, password);
    }
    match ShaCrypt::default().verify_password(password.as_bytes(), hash) {
        Ok(()) => PasswordCheck::Accepted,
        Err(sha_crypt::password_hash::Error::PasswordInvalid) => PasswordCheck::Wrong,
        Err(error) => PasswordCheck::Unsupported(format!(
            "the password file holds a hash the panel cannot check: {error}"
        )),
    }
}

/// Checks `password` against the MD5-crypt hash `hash`, whose `rest` follows
/// `$1$`: a salt of up to 8 characters, `$`, and the encoded digest.
fn check_md5_crypt(hash: &str, rest: &str, password: &str) -> PasswordCheck {
    let salt = rest.split_once('$').map(|(salt, _digest)| salt);
    match salt {
        Some(salt)
            if salt.len() <= 8 && salt.bytes().all(|byte| CRYPT_ALPHABET.contains(&byte)) =>
        {
            let computed = md5_crypt(password.as_bytes(), salt.as_bytes());
            if secret::equal(computed.as_bytes(), hash.as_bytes()) {
                PasswordCheck::Accepted
            } else {
                PasswordCheck::Wrong
            }
        }
        Some(_) | None => PasswordCheck::Unsupported(
            "the password file holds an MD5-crypt hash without a valid salt".to_owned(),
        ),
    }
}

/// MD5-crypt, `$1$`, as crypt(3) computes it, for a salt of up to 8
/// characters of `CRYPT_ALPHABET`.
fn md5_crypt(password: &[u8], salt: &[u8]) -> String {
    let mut alternate = md5::Context::new();
    alternate.consume(password);
    alternate.consume(salt);
    alternate.consume(password);
    let alternate = alternate.finalize();
    let mut context = md5::Context::new();
    context.consume(password);
    context.consume(b"$1$");
    context.consume(salt);
    let mut left = password.len();
    while left > 0 {
        let take = left.min(alternate.len());
        context.consume(&alternate[..take]);
        left -= take;
    }
    let mut bits = password.len();
    while bits > 0 {
        if bits & 1 == 1 {
            context.consume([0u8]);
        } else {
            context.consume(&password[..1]);
        }
        bits >>= 1;
    }
    let mut digest = context.finalize();
    for round in 0..1000 {
        let mut step = md5::Context::new();
        if round % 2 == 1 {
            step.consume(password);
        } else {
            step.consume(*digest);
        }
        if round % 3 != 0 {
            step.consume(salt);
        }
        if round % 7 != 0 {
            step.consume(password);
        }
        if round % 2 == 1 {
            step.consume(*digest);
        } else {
            step.consume(password);
        }
        digest = step.finalize();
    }
    let byte = |index: usize| u32::from(digest[index]);
    let mut encoded = format!("$1${}$", String::from_utf8_lossy(salt));
    let groups = [(0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)];
    for (high, middle, low) in groups {
        push_crypt64(
            &mut encoded,
            (byte(high) << 16) | (byte(middle) << 8) | byte(low),
            4,
        );
    }
    push_crypt64(&mut encoded, byte(11), 2);
    encoded
}

/// Appends the low `count` six-bit groups of `value` to `text`, lowest first,
/// in `CRYPT_ALPHABET`.
fn push_crypt64(text: &mut String, value: u32, count: u32) {
    for shift in 0..count {
        let index = (value >> (6 * shift)) & 0x3f;
        text.push(char::from(CRYPT_ALPHABET[index as usize]));
    }
}

/// Checks the password of `name` against the password file's text, as
/// ocserv does at sign-in. A locked user's hash is checked too, so that no
/// answer comes sooner than another.
pub fn check_in(text: &str, name: &str, password: &str) -> PasswordCheck {
    let hash = text.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let user = fields.next()?;
        let hash = fields.nth(1)?;
        (user == name).then_some(hash)
    });
    match hash {
        None => {
            let md5 = text
                .lines()
                .find_map(|line| line.splitn(3, ':').nth(2))
                .is_some_and(|first| first.trim_start_matches('!').starts_with("$1$"));
            let dummy = if md5 { DUMMY_MD5_HASH } else { DUMMY_HASH };
            std::hint::black_box(check_hash(dummy, password));
            PasswordCheck::Unknown
        }
        Some(hash) => match hash.strip_prefix('!') {
            Some(locked) => {
                std::hint::black_box(check_hash(locked, password));
                PasswordCheck::Locked
            }
            None => check_hash(hash, password),
        },
    }
}

/// A user or group name the password file can hold and ocpasswd takes as an
/// argument: 1 to 64 letters, digits, dots, underscores, at signs, plus
/// signs and hyphens, not starting with a hyphen.
pub fn check_name(name: &str, what: &str) -> Result<(), String> {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"._@+-".contains(&byte);
    if name.is_empty()
        || name.len() > MAX_NAME_LEN
        || name.starts_with('-')
        || !name.bytes().all(allowed)
    {
        return Err(format!(
            "a {what} has 1 to {MAX_NAME_LEN} letters, digits, dots, underscores, at signs, \
             plus signs and hyphens, and does not start with a hyphen"
        ));
    }
    Ok(())
}

/// Groups typed as a comma-separated list; none when the list is empty.
pub fn parse_groups(text: &str) -> Result<Vec<String>, String> {
    let mut groups = Vec::new();
    for group in text.split(',').map(str::trim) {
        if group.is_empty() {
            continue;
        }
        check_name(group, "group name")?;
        if !groups.iter().any(|known| known == group) {
            groups.push(group.to_owned());
        }
    }
    Ok(groups)
}

/// The password file's text with the groups of `name` set to `groups`, `*`
/// for none, and every other field and line kept as it was, the hash and
/// with it the lock included.
pub fn with_groups(text: &str, name: &str, groups: &[String]) -> Result<String, String> {
    let field = match groups {
        [] => "*".to_owned(),
        groups => groups.join(","),
    };
    let mut found = false;
    let mut changed = String::with_capacity(text.len() + field.len());
    for line in text.split_inclusive('\n') {
        let mut fields = line.splitn(3, ':');
        if let (Some(user), Some(_groups), Some(rest)) =
            (fields.next(), fields.next(), fields.next())
            && user == name
        {
            found = true;
            changed.push_str(user);
            changed.push(':');
            changed.push_str(&field);
            changed.push(':');
            changed.push_str(rest);
            continue;
        }
        changed.push_str(line);
    }
    if !found {
        return Err(format!("there is no user named {name}"));
    }
    Ok(changed)
}

/// A VPN password the panel may set: at least `min` characters, and one
/// that ocpasswd can take on one line of standard input.
pub fn check_password(password: &str, min: usize) -> Result<(), String> {
    if password.is_empty() {
        return Err("the password cannot be empty".to_owned());
    }
    if password.contains(['\n', '\r', '\0']) {
        return Err("the password cannot contain line breaks".to_owned());
    }
    let length = password.chars().count();
    if length < min {
        return Err(format!(
            "the password must be at least {min} characters long"
        ));
    }
    if length > MAX_PASSWORD_LEN {
        return Err(format!(
            "the password must be at most {MAX_PASSWORD_LEN} characters long"
        ));
    }
    Ok(())
}

/// The VPN users' password file.
pub trait UserFile: Send {
    fn list(&mut self) -> Result<Vec<VpnUser>, String>;
    /// Sets the password and groups of `name`, adding the user when new; a
    /// locked user stays locked.
    fn set_password(&mut self, name: &str, groups: &[String], password: &str)
    -> Result<(), String>;
    /// Sets the groups of `name`, none when `groups` is empty, keeping their
    /// password and whether they are locked.
    fn set_groups(&mut self, name: &str, groups: &[String]) -> Result<(), String>;
    fn lock(&mut self, name: &str) -> Result<(), String>;
    fn unlock(&mut self, name: &str) -> Result<(), String>;
    fn remove(&mut self, name: &str) -> Result<(), String>;
    /// Gives `name` the time-based secret `secret_hex` in the one-time
    /// password file, replacing the one they had, whether or not the
    /// password file has them yet. The file must exist: ocserv asks for codes
    /// only when it existed as ocserv started.
    fn set_otp(&mut self, name: &str, secret_hex: &str) -> Result<(), String>;
    /// Removes `name`'s secret from the one-time password file; true when
    /// they had one. A missing file has none.
    fn remove_otp(&mut self, name: &str) -> Result<bool, String>;
    /// Checks `name`'s password as ocserv does at sign-in.
    fn check_password(&mut self, name: &str, password: &str) -> Result<PasswordCheck, String>;
    /// Checks `name`'s code at Unix time `now` as ocserv's liboath does, and
    /// records an accepted one so that it is not accepted again.
    fn check_code(&mut self, name: &str, code: &str, now: u64) -> Result<CodeCheck, String>;
}

/// The password file, read directly and changed with ocpasswd.
pub struct Ocpasswd {
    pub passwd_file: PathBuf,
    pub otp_file: PathBuf,
}

impl Ocpasswd {
    fn ocpasswd(&self, args: &[&str], input: &[u8]) -> Result<(), String> {
        let file = self.passwd_file.to_str().ok_or_else(|| {
            format!(
                "the password file's path is not UTF-8: {}",
                self.passwd_file.display()
            )
        })?;
        let mut all = vec!["-c", file];
        all.extend_from_slice(args);
        let ran = command::run("ocpasswd", &all, input)?;
        if ran.status.success() {
            Ok(())
        } else {
            Err(ran.failed("ocpasswd could not change the password file"))
        }
    }
}

impl UserFile for Ocpasswd {
    fn list(&mut self) -> Result<Vec<VpnUser>, String> {
        let otp_users = parse_otp_users(&read_if_present(&self.otp_file)?);
        parse_passwd(&read_if_present(&self.passwd_file)?, &otp_users)
    }

    fn set_password(
        &mut self,
        name: &str,
        groups: &[String],
        password: &str,
    ) -> Result<(), String> {
        let was_locked = self
            .list()?
            .iter()
            .any(|user| user.name == name && user.locked);
        let groups = if groups.is_empty() {
            "*".to_owned()
        } else {
            groups.join(",")
        };
        let input = Zeroizing::new(format!("{password}\n"));
        self.ocpasswd(&["-g", &groups, "--", name], input.as_bytes())?;
        if was_locked {
            self.lock(name)?;
        }
        Ok(())
    }

    /// ocpasswd cannot set groups without a password, so the file is
    /// rewritten here under ocpasswd's own lock, the file named after it with
    /// .tmp added.
    fn set_groups(&mut self, name: &str, groups: &[String]) -> Result<(), String> {
        let mut lock = self.passwd_file.as_os_str().to_owned();
        lock.push(".tmp");
        files::replace_under_lock(&self.passwd_file, Path::new(&lock), |text| {
            with_groups(text, name, groups)
        })
    }

    fn lock(&mut self, name: &str) -> Result<(), String> {
        self.ocpasswd(&["-l", "--", name], &[])
    }

    fn unlock(&mut self, name: &str) -> Result<(), String> {
        self.ocpasswd(&["-u", "--", name], &[])
    }

    fn remove(&mut self, name: &str) -> Result<(), String> {
        self.ocpasswd(&["-d", "--", name], &[])
    }

    fn set_otp(&mut self, name: &str, secret_hex: &str) -> Result<(), String> {
        let line = Zeroizing::new(otpfile::totp_line(name, secret_hex));
        otpfile::set(&self.otp_file, name, Some(line.as_str()))?;
        Ok(())
    }

    fn remove_otp(&mut self, name: &str) -> Result<bool, String> {
        match fs::metadata(&self.otp_file) {
            Ok(_) => otpfile::set(&self.otp_file, name, None),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("{}: {error}", self.otp_file.display())),
        }
    }

    fn check_password(&mut self, name: &str, password: &str) -> Result<PasswordCheck, String> {
        Ok(check_in(
            &read_if_present(&self.passwd_file)?,
            name,
            password,
        ))
    }

    fn check_code(&mut self, name: &str, code: &str, now: u64) -> Result<CodeCheck, String> {
        otpfile::check_code(&self.otp_file, name, code, now)
    }
}

/// A file's text; empty when the file does not exist yet.
fn read_if_present(path: &Path) -> Result<String, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// A password file and a one-time password file in memory, for the tests and
/// the development server.
#[cfg(any(test, debug_assertions))]
pub struct FakeUsers {
    /// The password file's users; `list` sets their `otp` from `otp_names`.
    pub users: Vec<VpnUser>,
    /// The names the one-time password file has a secret for.
    pub otp_names: Vec<String>,
}

#[cfg(any(test, debug_assertions))]
impl FakeUsers {
    /// alex, with an authenticator app; sam in the staff group; and riley,
    /// locked.
    pub fn sample() -> FakeUsers {
        let user = |name: &str, groups: &[&str], locked| VpnUser {
            name: name.to_owned(),
            groups: groups.iter().map(|group| (*group).to_owned()).collect(),
            locked,
            otp: false,
        };
        FakeUsers {
            users: vec![
                user("alex", &[], false),
                user("sam", &["staff"], false),
                user("riley", &["contractors"], true),
            ],
            otp_names: vec!["alex".to_owned()],
        }
    }

    fn find(&mut self, name: &str) -> Result<&mut VpnUser, String> {
        self.users
            .iter_mut()
            .find(|user| user.name == name)
            .ok_or_else(|| format!("there is no user named {name}"))
    }
}

#[cfg(any(test, debug_assertions))]
impl UserFile for FakeUsers {
    fn list(&mut self) -> Result<Vec<VpnUser>, String> {
        Ok(self
            .users
            .iter()
            .map(|user| VpnUser {
                otp: self.otp_names.contains(&user.name),
                ..user.clone()
            })
            .collect())
    }

    fn set_password(
        &mut self,
        name: &str,
        groups: &[String],
        _password: &str,
    ) -> Result<(), String> {
        match self.users.iter_mut().find(|user| user.name == name) {
            Some(user) => user.groups = groups.to_vec(),
            None => self.users.push(VpnUser {
                name: name.to_owned(),
                groups: groups.to_vec(),
                locked: false,
                otp: false,
            }),
        }
        Ok(())
    }

    fn set_groups(&mut self, name: &str, groups: &[String]) -> Result<(), String> {
        self.find(name)?.groups = groups.to_vec();
        Ok(())
    }

    fn lock(&mut self, name: &str) -> Result<(), String> {
        self.find(name)?.locked = true;
        Ok(())
    }

    fn unlock(&mut self, name: &str) -> Result<(), String> {
        self.find(name)?.locked = false;
        Ok(())
    }

    fn remove(&mut self, name: &str) -> Result<(), String> {
        self.find(name)?;
        self.users.retain(|user| user.name != name);
        Ok(())
    }

    fn set_otp(&mut self, name: &str, _secret_hex: &str) -> Result<(), String> {
        if !self.otp_names.iter().any(|known| known == name) {
            self.otp_names.push(name.to_owned());
        }
        Ok(())
    }

    fn remove_otp(&mut self, name: &str) -> Result<bool, String> {
        let had = self.otp_names.iter().any(|known| known == name);
        self.otp_names.retain(|known| known != name);
        Ok(had)
    }

    /// Every sample user's password is their name followed by "-password".
    fn check_password(&mut self, name: &str, password: &str) -> Result<PasswordCheck, String> {
        Ok(match self.users.iter().find(|user| user.name == name) {
            None => PasswordCheck::Unknown,
            Some(user) if user.locked => PasswordCheck::Locked,
            Some(_) if password == format!("{name}-password") => PasswordCheck::Accepted,
            Some(_) => PasswordCheck::Wrong,
        })
    }

    /// A user with a secret has the code 123456 at every moment.
    fn check_code(&mut self, name: &str, code: &str, _now: u64) -> Result<CodeCheck, String> {
        Ok(
            match (self.otp_names.iter().any(|known| known == name), code) {
                (false, _) => CodeCheck::NoSecret,
                (true, "123456") => CodeCheck::Accepted,
                (true, _) => CodeCheck::Wrong,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_of_groups_keeps_the_hash_the_lock_and_the_other_lines() {
        let text = "alex:*:$5$salt$hash\r\nsam:staff:!$5$salt$locked\nriley:contractors:$1$ab$md5";
        let groups = |names: &[&str]| -> Vec<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        assert_eq!(
            with_groups(text, "alex", &groups(&["staff", "lab"])).unwrap(),
            "alex:staff,lab:$5$salt$hash\r\nsam:staff:!$5$salt$locked\nriley:contractors:$1$ab$md5"
        );
        assert_eq!(
            with_groups(text, "sam", &[]).unwrap(),
            "alex:*:$5$salt$hash\r\nsam:*:!$5$salt$locked\nriley:contractors:$1$ab$md5"
        );
        assert_eq!(
            with_groups(text, "riley", &groups(&["lab"])).unwrap(),
            "alex:*:$5$salt$hash\r\nsam:staff:!$5$salt$locked\nriley:lab:$1$ab$md5"
        );
        assert_eq!(
            with_groups(text, "al", &[]).unwrap_err(),
            "there is no user named al"
        );
        let users = parse_passwd(&with_groups(text, "sam", &[]).unwrap(), &[]).unwrap();
        assert!(users[1].groups.is_empty() && users[1].locked);
    }

    #[test]
    fn users_are_read_from_ocpasswd_lines() {
        let text = "alex:*:$5$salt$hash\nsam:staff,admins:$5$s$h\n\nriley:contractors:!$5$s$h\n";
        let users = parse_passwd(text, &["alex".to_owned()]).unwrap();
        assert_eq!(
            users,
            [
                VpnUser {
                    name: "alex".to_owned(),
                    groups: Vec::new(),
                    locked: false,
                    otp: true,
                },
                VpnUser {
                    name: "sam".to_owned(),
                    groups: vec!["staff".to_owned(), "admins".to_owned()],
                    locked: false,
                    otp: false,
                },
                VpnUser {
                    name: "riley".to_owned(),
                    groups: vec!["contractors".to_owned()],
                    locked: true,
                    otp: false,
                },
            ]
        );
    }

    #[test]
    fn a_line_without_three_fields_is_an_error() {
        let error = parse_passwd("alex:*:hash\nbroken\n", &[]).unwrap_err();
        assert!(error.contains("line 2"), "{error}");
    }

    #[test]
    fn otp_users_are_the_second_field_of_each_line() {
        let text =
            "# users\nHOTP/T30 alex - 3132\n\nHOTP/T30/6 sam 1234 abcd 7 2026-11-26T05:00:00L\n";
        assert_eq!(parse_otp_users(text), ["alex", "sam"]);
    }

    #[test]
    fn names_are_checked_before_ocpasswd_sees_them() {
        for good in ["alex", "a.b_c-d", "first.last@example.com", "x+y"] {
            assert!(check_name(good, "user name").is_ok(), "{good}");
        }
        for bad in ["", "-l", "a:b", "a b", "a\nb", "é", &"a".repeat(65)] {
            assert!(check_name(bad, "user name").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn groups_are_a_comma_separated_list() {
        assert_eq!(parse_groups("").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_groups(" staff, admins ,staff,").unwrap(),
            ["staff", "admins"]
        );
        assert!(parse_groups("staff,a:b").is_err());
    }

    /// Hashes made with `openssl passwd -5` and `-6`.
    const SALT10: &str = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5";
    const SHA256: &str = "$5$Ab3dE6gH9jK2mN5p$aJqvosbo9w1hzXE/qpdfhNWRyjaJ4TBceGiHz88eqjD";
    const SHA512: &str = "$6$Ab3dE6gH9jK2mN5p$FGkare3xB5CB85s8CgdV83milqENY2wBWthf9PpF05GuA6aWCS68TFSWPv0w/Xbr8NTYIb81e/TlIkLVLg783.";
    const ROUNDS: &str = "$5$rounds=12000$Ab3dE6gH$B0ZYYiv7ig3FqB4pKjcxdwzXXmB0AHGGjTkeuELIdNA";

    #[test]
    fn hashes_check_as_openssl_made_them() {
        assert_eq!(check_hash(SALT10, "Hello world!"), PasswordCheck::Accepted);
        for hash in [SHA256, SHA512, ROUNDS] {
            assert_eq!(
                check_hash(hash, "correct horse battery staple"),
                PasswordCheck::Accepted,
                "{hash}"
            );
            assert_eq!(
                check_hash(hash, "Correct horse battery staple"),
                PasswordCheck::Wrong
            );
        }
        for hash in ["", "x", "$1$", "$1$bad salt$x", "$1$saltsalty$x", "!$5$x"] {
            assert!(
                matches!(check_hash(hash, "pw"), PasswordCheck::Unsupported(_)),
                "{hash:?}"
            );
        }
    }

    /// MD5-crypt hashes from `openssl passwd -1 -salt <salt> <password>`, as
    /// ocpasswd writes them when built with musl: a password longer than a
    /// digest, a short one and an empty one, and a salt cut to 8 characters.
    #[test]
    fn md5_crypt_hashes_check_as_openssl_made_them() {
        for (hash, password) in [
            ("$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1", "Hello world!"),
            (DUMMY_MD5_HASH, "correct horse battery staple"),
            ("$1$x1Y2z3W4$i1uvZgQa9tCklGboRVKVJ.", ""),
            ("$1$0123abcd$O6qewVyTBz0ro80b9Pa5j.", "a"),
        ] {
            assert_eq!(
                check_hash(hash, password),
                PasswordCheck::Accepted,
                "{hash}"
            );
            assert_eq!(check_hash(hash, "x"), PasswordCheck::Wrong, "{hash}");
        }
    }

    #[test]
    fn a_user_is_checked_by_name_and_a_locked_one_is_refused() {
        let text = format!("alex:*:{SHA256}\nriley:contractors:!{SHA256}\n");
        let password = "correct horse battery staple";
        assert_eq!(check_in(&text, "alex", password), PasswordCheck::Accepted);
        assert_eq!(check_in(&text, "alex", "wrong"), PasswordCheck::Wrong);
        assert_eq!(check_in(&text, "riley", password), PasswordCheck::Locked);
        assert_eq!(check_in(&text, "sam", password), PasswordCheck::Unknown);
        assert_eq!(check_in(&text, "ale", password), PasswordCheck::Unknown);
        let musl = format!("jo:*:{DUMMY_MD5_HASH}\n");
        assert_eq!(check_in(&musl, "jo", password), PasswordCheck::Accepted);
        assert_eq!(check_in(&musl, "sam", password), PasswordCheck::Unknown);
    }

    #[test]
    fn passwords_are_long_enough_and_fit_on_one_line() {
        assert!(check_password("x", 1).is_ok());
        assert!(check_password("", 0).is_err());
        assert!(check_password("a\nb", 1).is_err());
        assert!(check_password(&"a".repeat(MAX_PASSWORD_LEN + 1), 1).is_err());
        let short = check_password("eleven-char", 12).unwrap_err();
        assert!(short.contains("at least 12"), "{short}");
        assert!(check_password("twelve-chars", 12).is_ok());
        assert!(check_password("wörter-zwölf", 12).is_ok());
    }
}
