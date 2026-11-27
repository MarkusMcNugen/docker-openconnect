//! The VPN users' one-time password file, liboath's users file: one
//! `HOTP/T30 user - hex-secret` line per user, which ocserv rewrites after
//! each sign-in. A change follows liboath's protocol: create `<file>.lock`
//! exclusively and hold a write lock on it, write `<file>.new`, rename that
//! over the file with the file's owner kept, and remove the lock. A lock file
//! that no process holds for a whole wait was left by a writer that stopped,
//! and is removed. liboath reads the file before it locks, so each change is
//! checked after a pause and made again when a sign-in put the old file back.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::{clock, secret, totp};

/// How long a change waits for a lock that a sign-in holds.
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// How often the lock is tested while a change waits.
const LOCK_RETRY: Duration = Duration::from_millis(25);

/// How long after a change the file is checked: a sign-in that read the file
/// before the change has taken the lock by then.
const SETTLE: Duration = Duration::from_millis(200);

/// Times a change is made while sign-ins keep putting the old file back.
const ATTEMPTS: u32 = 3;

/// The line liboath reads for a time-based secret: 30-second steps, six
/// digits and no PIN.
pub fn totp_line(name: &str, secret_hex: &str) -> String {
    format!("HOTP/T30 {name} - {secret_hex}")
}

/// Gives `name` the line `line`, replacing the one they had, or removes
/// their line when `line` is none; the file must exist. True when they had a
/// line.
pub fn set(path: &Path, name: &str, line: Option<&str>) -> Result<bool, String> {
    let mut had = None;
    for _ in 0..ATTEMPTS {
        let found = rewrite(path, name, line)?;
        had.get_or_insert(found);
        thread::sleep(SETTLE);
        wait_unlocked(path)?;
        if holds(path, name, line)? {
            return Ok(had == Some(true));
        }
    }
    Err(format!(
        "{} kept being rewritten by sign-ins while the panel changed it; try again",
        path.display()
    ))
}

/// Whether `line` is the line of `name`: the user is the second field.
fn is_line_of(line: &str, name: &str) -> bool {
    let line = line.trim();
    !line.starts_with('#') && line.split_whitespace().nth(1) == Some(name)
}

/// The fields liboath never rewrites: type, user, PIN and secret.
fn fixed_fields(line: &str) -> Vec<&str> {
    line.split_whitespace().take(4).collect()
}

/// Whether the file holds the change: `name` has exactly `line`, give or
/// take the counter and last code liboath appends, or has no line.
fn holds(path: &Path, name: &str, line: Option<&str>) -> Result<bool, String> {
    let text = read(path)?;
    let found: Vec<&str> = text
        .lines()
        .filter(|existing| is_line_of(existing, name))
        .collect();
    Ok(match line {
        None => found.is_empty(),
        Some(line) => found.len() == 1 && fixed_fields(found[0]) == fixed_fields(line),
    })
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// `path` with `suffix` added to its name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The refusal when a sign-in holds the lock for the whole wait.
fn locked(file: &Path) -> String {
    format!(
        "{} is locked by a sign-in in progress; try again",
        file.display()
    )
}

#[cfg(unix)]
fn create_new(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_new(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Gives the new file the old file's owner, as liboath does.
#[cfg(unix)]
fn keep_owner(file: &File, original: &Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    std::os::unix::fs::fchown(file, Some(original.uid()), Some(original.gid())).map_err(|error| {
        format!("the new one-time password file's owner could not be set: {error}")
    })
}

#[cfg(not(unix))]
fn keep_owner(_file: &File, _original: &Metadata) -> Result<(), String> {
    Ok(())
}

/// A file's device and inode, which tell one lock file from the next.
type FileId = (u64, u64);

/// What a test of the lock file found.
enum Probe {
    /// There is no lock file.
    Gone,
    /// A live process holds its write lock.
    Held,
    /// No process holds it.
    Unheld(FileId),
}

/// What the tests of the lock file during one wait found.
#[derive(Debug, Clone, Copy)]
enum Seen {
    Nothing,
    /// The same lock file, held by no process, at every test.
    Unheld(FileId),
    /// A live writer, or lock files that came and went.
    Live,
}

impl Seen {
    fn and(self, probe: &Probe) -> Seen {
        match (self, probe) {
            (Seen::Nothing, Probe::Unheld(id)) => Seen::Unheld(*id),
            (Seen::Unheld(seen), Probe::Unheld(id)) if seen == *id => Seen::Unheld(seen),
            (
                Seen::Nothing | Seen::Unheld(_) | Seen::Live,
                Probe::Gone | Probe::Held | Probe::Unheld(_),
            ) => Seen::Live,
        }
    }
}

/// The lock on the file, held while its lock file is open.
struct Lock {
    path: PathBuf,
    file: Option<File>,
}

impl Lock {
    /// Takes the lock on `file`, waiting while a live writer holds it, and
    /// removing a lock file that no process held for the whole wait.
    fn take(file: &Path) -> Result<Lock, String> {
        let path = with_suffix(file, ".lock");
        let mut started = Instant::now();
        let mut seen = Seen::Nothing;
        loop {
            match create_new(&path) {
                Ok(lock_file) => {
                    hold(&lock_file, &path)?;
                    return Ok(Lock {
                        path,
                        file: Some(lock_file),
                    });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
            let probe = probe(&path)?;
            seen = seen.and(&probe);
            if matches!(probe, Probe::Gone) {
                continue;
            }
            if started.elapsed() >= LOCK_WAIT {
                match seen {
                    Seen::Unheld(id) => {
                        remove_dead(&path, id)?;
                        started = Instant::now();
                        seen = Seen::Nothing;
                        continue;
                    }
                    Seen::Nothing | Seen::Live => return Err(locked(file)),
                }
            }
            thread::sleep(LOCK_RETRY);
        }
    }

    /// Removes the lock file, then closes it, so the file is never seen
    /// without its lock.
    fn release(mut self) -> Result<(), String> {
        let removed = fs::remove_file(&self.path)
            .map_err(|error| format!("{}: {error}", self.path.display()));
        self.file = None;
        removed
    }
}

impl Drop for Lock {
    /// Removes a lock that an error left held, since every sign-in with a
    /// code is refused while it exists.
    fn drop(&mut self) {
        if self.file.is_some()
            && let Err(error) = fs::remove_file(&self.path)
        {
            eprintln!(
                "ocpanel: the lock {} could not be removed: {error}",
                self.path.display()
            );
        }
    }
}

/// Waits while a live writer holds the lock on `file`, so that its rename
/// has landed when the file is read.
fn wait_unlocked(file: &Path) -> Result<(), String> {
    let path = with_suffix(file, ".lock");
    let started = Instant::now();
    loop {
        match probe(&path)? {
            Probe::Gone | Probe::Unheld(_) => return Ok(()),
            Probe::Held => {}
        }
        if started.elapsed() >= LOCK_WAIT {
            return Err(locked(file));
        }
        thread::sleep(LOCK_RETRY);
    }
}

/// Open file description locks over a whole file. They meet the traditional
/// record locks liboath takes, even within one process, and closing another
/// descriptor of the file does not release them.
#[cfg(target_os = "linux")]
mod kernel {
    use std::fs::File;

    use nix::errno::Errno;
    use nix::fcntl::{FcntlArg, fcntl};
    use nix::libc;

    pub fn write_lock() -> libc::flock {
        libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        }
    }

    /// Whether a lock that a write lock on `file` would meet is held: one of
    /// another open file description, or any process's traditional one.
    pub fn is_held(file: &File) -> Result<bool, Errno> {
        let mut lock = write_lock();
        fcntl(file, FcntlArg::F_OFD_GETLK(&mut lock))?;
        Ok(lock.l_type != libc::F_UNLCK as libc::c_short)
    }

    /// Takes a write lock on `file` without waiting; false when another
    /// holds one.
    pub fn try_hold(file: &File) -> Result<bool, Errno> {
        match fcntl(file, FcntlArg::F_OFD_SETLK(&write_lock())) {
            Ok(_) => Ok(true),
            Err(Errno::EAGAIN | Errno::EACCES) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// Holds a write lock on the lock file just made, so that a test of it finds
/// a live writer.
#[cfg(target_os = "linux")]
fn hold(file: &File, path: &Path) -> Result<(), String> {
    match kernel::try_hold(file) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "{}: another writer locked it as it was made",
            path.display()
        )),
        Err(error) => Err(format!(
            "{}: it could not be locked: {error}",
            path.display()
        )),
    }
}

#[cfg(not(target_os = "linux"))]
fn hold(_file: &File, _path: &Path) -> Result<(), String> {
    Ok(())
}

/// The file at `path`, open to read and write; none when there is none.
#[cfg(target_os = "linux")]
fn open_existing(path: &Path) -> Result<Option<File>, String> {
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

#[cfg(target_os = "linux")]
fn id_of(metadata: &Metadata) -> FileId {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(target_os = "linux")]
fn file_id(file: &File, path: &Path) -> Result<FileId, String> {
    file.metadata()
        .map(|metadata| id_of(&metadata))
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Tests the lock file at `path`.
#[cfg(target_os = "linux")]
fn probe(path: &Path) -> Result<Probe, String> {
    let Some(file) = open_existing(path)? else {
        return Ok(Probe::Gone);
    };
    match kernel::is_held(&file) {
        Ok(true) => Ok(Probe::Held),
        Ok(false) => Ok(Probe::Unheld(file_id(&file, path)?)),
        Err(error) => Err(format!(
            "{}: its lock could not be tested: {error}",
            path.display()
        )),
    }
}

/// Elsewhere only the tests run, and a lock file counts as held.
#[cfg(not(target_os = "linux"))]
fn probe(path: &Path) -> Result<Probe, String> {
    match fs::metadata(path) {
        Ok(_) => Ok(Probe::Held),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Probe::Gone),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Removes the lock file `id` at `path`, which no process held for a whole
/// wait, after taking its lock so that no writer can take it meanwhile; it
/// stays when it changed or a writer took it first.
#[cfg(target_os = "linux")]
fn remove_dead(path: &Path, id: FileId) -> Result<(), String> {
    let Some(file) = open_existing(path)? else {
        return Ok(());
    };
    let taken = kernel::try_hold(&file)
        .map_err(|error| format!("{}: it could not be locked: {error}", path.display()))?;
    if !taken || file_id(&file, path)? != id {
        return Ok(());
    }
    let current = match fs::metadata(path) {
        Ok(metadata) => id_of(&metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if current != id {
        return Ok(());
    }
    fs::remove_file(path).map_err(|error| format!("{}: {error}", path.display()))?;
    eprintln!(
        "ocpanel: removed {}, a lock no process held, left by a writer that stopped",
        path.display()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn remove_dead(_path: &Path, _id: FileId) -> Result<(), String> {
    Ok(())
}

/// One change under the lock; true when `name` had a line.
fn rewrite(path: &Path, name: &str, line: Option<&str>) -> Result<bool, String> {
    let lock = Lock::take(path)?;
    let changed = rewrite_locked(path, name, line);
    let released = lock.release();
    let had = changed?;
    released?;
    Ok(had)
}

fn rewrite_locked(path: &Path, name: &str, line: Option<&str>) -> Result<bool, String> {
    let original = fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let text = read(path)?;
    let mut had = false;
    let mut lines = Vec::new();
    for existing in text.lines() {
        if is_line_of(existing, name) {
            if !had && let Some(line) = line {
                lines.push(line.to_owned());
            }
            had = true;
            continue;
        }
        lines.push(existing.to_owned());
    }
    if !had && let Some(line) = line {
        lines.push(line.to_owned());
    }
    let mut new_text = lines.join("\n");
    if !new_text.is_empty() {
        new_text.push('\n');
    }
    let new_path = with_suffix(path, ".new");
    let mut file = match create_new(&new_path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            fs::remove_file(&new_path)
                .map_err(|error| format!("{}: {error}", new_path.display()))?;
            eprintln!(
                "ocpanel: removed {}, left by a writer that stopped",
                new_path.display()
            );
            create_new(&new_path).map_err(|error| format!("{}: {error}", new_path.display()))?
        }
        Err(error) => return Err(format!("{}: {error}", new_path.display())),
    };
    file.write_all(new_text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", new_path.display()))?;
    keep_owner(&file, &original)?;
    drop(file);
    fs::rename(&new_path, path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(had)
}

/// What checking a code against the one-time password file found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeCheck {
    /// The code matches, and is recorded as the last one used.
    Accepted,
    /// The code matches no step in ocserv's window.
    Wrong,
    /// The code, or one from a later step, was used already.
    Used,
    /// The file has no secret for the user.
    NoSecret,
}

/// Steps on either side of now in which ocserv accepts a code.
const WINDOW: u64 = 20;

/// The digits and step seconds of a time-based token type, such as
/// `HOTP/T30` or `HOTP/T30/8`.
fn token_type(kind: &str) -> Result<(u32, u64), String> {
    let unsupported = || format!("'{kind}' is not a time-based token type, such as HOTP/T30");
    let mut parts = kind.split('/');
    if parts.next() != Some("HOTP") {
        return Err(unsupported());
    }
    let Some(seconds) = parts.next().and_then(|timing| timing.strip_prefix('T')) else {
        return Err(unsupported());
    };
    let seconds: u64 = seconds
        .parse()
        .map_err(|error| format!("{}: {error}", unsupported()))?;
    let digits: u32 = match parts.next() {
        None => 6,
        Some(digits) => digits
            .parse()
            .map_err(|error| format!("{}: {error}", unsupported()))?,
    };
    if seconds == 0 || !(6..=8).contains(&digits) || parts.next().is_some() {
        return Err(unsupported());
    }
    Ok((digits, seconds))
}

/// A user's line: type, user, PIN and secret, then what liboath records
/// after a sign-in: a counter and the last code used.
struct Token<'a> {
    kind: &'a str,
    user: &'a str,
    pin: &'a str,
    secret: &'a str,
    counter: u64,
    last: Option<&'a str>,
}

impl<'a> Token<'a> {
    fn parse(line: &'a str) -> Result<Token<'a>, String> {
        let mut fields = line.split_whitespace();
        let missing =
            || "a line of the one-time password file has fewer than four fields".to_owned();
        let kind = fields.next().ok_or_else(missing)?;
        let user = fields.next().ok_or_else(missing)?;
        let pin = fields.next().ok_or_else(missing)?;
        let secret = fields.next().ok_or_else(missing)?;
        let counter = match fields.next() {
            None => 0,
            Some(value) => value.parse().map_err(|error| {
                format!("the counter in {user}'s one-time password line is not a number: {error}")
            })?,
        };
        Ok(Token {
            kind,
            user,
            pin,
            secret,
            counter,
            last: fields.next(),
        })
    }

    /// The step whose code is `code`, searched outward from the step of
    /// `now` as liboath searches; none when no step in the window matches.
    fn step_of(&self, code: &str, now: u64) -> Result<Option<u64>, String> {
        let (digits, seconds) = token_type(self.kind)?;
        let key = Zeroizing::new(
            data_encoding::HEXLOWER_PERMISSIVE
                .decode(self.secret.as_bytes())
                .map_err(|error| format!("{}'s secret is not hex: {error}", self.user))?,
        );
        let width = usize::try_from(digits)
            .map_err(|error| format!("a code width does not fit: {error}"))?;
        let current = now / seconds;
        for distance in 0..=WINDOW {
            let mut steps = vec![current.saturating_add(distance)];
            if distance > 0
                && let Some(before) = current.checked_sub(distance)
            {
                steps.push(before);
            }
            for step in steps {
                let expected = format!("{:0width$}", totp::code_of(&key, step, digits)?);
                if secret::equal(expected.as_bytes(), code.as_bytes()) {
                    return Ok(Some(step));
                }
            }
        }
        Ok(None)
    }

    /// The line that records `code`, from `step`, as the last one used at
    /// `now`, in liboath's tab-separated form.
    fn recording(&self, code: &str, step: u64, now: u64) -> Result<String, String> {
        let (_, seconds) = token_type(self.kind)?;
        Ok(format!(
            "{}\t{}\t{}\t{}\t{}\t{code}\t{}",
            self.kind,
            self.user,
            self.pin,
            self.secret,
            self.counter.saturating_add((now / seconds).abs_diff(step)),
            clock::rfc3339(now).replace('Z', "L")
        ))
    }

    /// Whether the line records `code`, or a code from a later step, as
    /// the last one used.
    fn records(&self, code: &str, step: u64, now: u64) -> Result<bool, String> {
        Ok(match self.last {
            None => false,
            Some(last) if last == code => true,
            Some(last) => self
                .step_of(last, now)?
                .is_some_and(|recorded| recorded >= step),
        })
    }
}

/// `name`'s line in the file at `path`, if any.
fn line_of(path: &Path, name: &str) -> Result<Option<String>, String> {
    Ok(read(path)?
        .lines()
        .find(|line| is_line_of(line, name))
        .map(str::to_owned))
}

/// Judges `code` against `name`'s line, held under the lock, and records an
/// accepted code; the step it matched comes back with it.
fn judge_locked(
    path: &Path,
    name: &str,
    code: &str,
    now: u64,
) -> Result<(CodeCheck, Option<u64>), String> {
    let Some(line) = line_of(path, name)? else {
        return Ok((CodeCheck::NoSecret, None));
    };
    let token = Token::parse(&line)?;
    if token.last == Some(code) {
        return Ok((CodeCheck::Used, None));
    }
    let Some(step) = token.step_of(code, now)? else {
        return Ok((CodeCheck::Wrong, None));
    };
    if let Some(last) = token.last
        && token
            .step_of(last, now)?
            .is_some_and(|previous| previous >= step)
    {
        return Ok((CodeCheck::Used, None));
    }
    rewrite_locked(path, name, Some(&token.recording(code, step, now)?))?;
    Ok((CodeCheck::Accepted, Some(step)))
}

/// Records `code` from `step` again, under the lock, unless the line
/// already records it or a later code.
fn record_again_locked(
    path: &Path,
    name: &str,
    code: &str,
    step: u64,
    now: u64,
) -> Result<(), String> {
    let Some(line) = line_of(path, name)? else {
        return Err(format!(
            "{name}'s one-time password line went away while a code was recorded"
        ));
    };
    let token = Token::parse(&line)?;
    if !token.records(code, step, now)? {
        rewrite_locked(path, name, Some(&token.recording(code, step, now)?))?;
    }
    Ok(())
}

/// Checks `code` for `name` at Unix time `now` as ocserv's liboath does,
/// within the same window, refusing the last code used and earlier ones,
/// and records an accepted code in the user's line as liboath does, so
/// that neither the portal nor the VPN accepts it again.
pub fn check_code(path: &Path, name: &str, code: &str, now: u64) -> Result<CodeCheck, String> {
    let lock = Lock::take(path)?;
    let judged = judge_locked(path, name, code, now);
    let released = lock.release();
    let (check, step) = judged?;
    released?;
    let Some(step) = step else {
        return Ok(check);
    };
    for _ in 0..ATTEMPTS {
        thread::sleep(SETTLE);
        wait_unlocked(path)?;
        let recorded = match line_of(path, name)? {
            Some(line) => Token::parse(&line)?.records(code, step, now)?,
            None => false,
        };
        if recorded {
            return Ok(check);
        }
        let lock = Lock::take(path)?;
        let again = record_again_locked(path, name, code, step, now);
        let released = lock.release();
        again?;
        released?;
    }
    Err(format!(
        "{} kept being rewritten by sign-ins while the panel recorded a code; try again",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    /// "12345678901234567890" in hex, the RFC 6238 test secret, whose
    /// six-digit code at 59 seconds is 287082 and eight-digit one 94287082.
    const RFC_HEX: &str = "3132333435363738393031323334353637383930";

    #[test]
    fn a_code_is_accepted_once_and_recorded_as_liboath_records_it() {
        let dir = TestDir::new();
        let path = file(&dir, &format!("HOTP/T30 sam - {RFC_HEX}\n"));
        assert_eq!(
            check_code(&path, "jo", "287082", 59).unwrap(),
            CodeCheck::NoSecret
        );
        assert_eq!(
            check_code(&path, "sam", "000000", 59).unwrap(),
            CodeCheck::Wrong
        );
        assert_eq!(
            check_code(&path, "sam", "287082", 59).unwrap(),
            CodeCheck::Accepted
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("HOTP/T30\tsam\t-\t{RFC_HEX}\t0\t287082\t1970-01-01T00:00:59L\n")
        );
        assert_eq!(
            check_code(&path, "sam", "287082", 61).unwrap(),
            CodeCheck::Used
        );
        assert!(!dir.path().join("users.oath.lock").exists());
    }

    #[test]
    fn a_code_from_an_earlier_step_than_the_last_one_used_is_refused() {
        let dir = TestDir::new();
        let path = file(&dir, &format!("HOTP/T30 sam - {RFC_HEX}\n"));
        let key = data_encoding::HEXLOWER.decode(RFC_HEX.as_bytes()).unwrap();
        let at = |step: u64| format!("{:06}", totp::code_of(&key, step, 6).unwrap());
        let now = 3000;
        assert_eq!(
            check_code(&path, "sam", &at(101), now).unwrap(),
            CodeCheck::Accepted
        );
        assert_eq!(
            check_code(&path, "sam", &at(99), now).unwrap(),
            CodeCheck::Used
        );
        assert_eq!(
            check_code(&path, "sam", &at(102), now).unwrap(),
            CodeCheck::Accepted
        );
        assert_eq!(
            check_code(&path, "sam", &at(100 + 21), now).unwrap(),
            CodeCheck::Wrong
        );
        assert_eq!(
            check_code(&path, "sam", &at(100 + 20), now).unwrap(),
            CodeCheck::Accepted
        );
    }

    #[test]
    fn eight_digit_tokens_and_other_types_are_read_as_liboath_reads_them() {
        let dir = TestDir::new();
        let path = file(
            &dir,
            &format!("HOTP/T30/8 sam - {RFC_HEX}\nHOTP alex - {RFC_HEX}\n"),
        );
        assert_eq!(
            check_code(&path, "sam", "94287082", 59).unwrap(),
            CodeCheck::Accepted
        );
        assert!(check_code(&path, "alex", "287082", 59).is_err());
        assert_eq!(token_type("HOTP/T60").unwrap(), (6, 60));
        for bad in [
            "TOTP/T30",
            "HOTP/T0",
            "HOTP/T30/5",
            "HOTP/T30/6/x",
            "HOTP/E",
        ] {
            assert!(token_type(bad).is_err(), "{bad}");
        }
    }

    fn file(dir: &TestDir, text: &str) -> PathBuf {
        let path = dir.path().join("users.oath");
        fs::write(&path, text).unwrap();
        path
    }

    /// A lock file held the way a live writer holds it.
    fn held_lock(dir: &TestDir) -> File {
        let lock = File::create(dir.path().join("users.oath.lock")).unwrap();
        #[cfg(target_os = "linux")]
        assert!(kernel::try_hold(&lock).unwrap());
        lock
    }

    #[test]
    fn a_line_is_added_replaced_and_removed_with_the_rest_kept() {
        let dir = TestDir::new();
        let path = file(
            &dir,
            "# users\nHOTP/T30 alex - 3132 1 123456 2026-11-26T05:00:00L\nHOTP/T30 sam - 3334\n",
        );
        assert!(!set(&path, "jo", Some(&totp_line("jo", "aabb"))).unwrap());
        assert!(set(&path, "sam", Some(&totp_line("sam", "ccdd"))).unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# users\nHOTP/T30 alex - 3132 1 123456 2026-11-26T05:00:00L\nHOTP/T30 sam - ccdd\n\
             HOTP/T30 jo - aabb\n"
        );
        assert!(set(&path, "alex", None).unwrap());
        assert!(!set(&path, "alex", None).unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# users\nHOTP/T30 sam - ccdd\nHOTP/T30 jo - aabb\n"
        );
        assert!(!dir.path().join("users.oath.lock").exists());
        assert!(!dir.path().join("users.oath.new").exists());
    }

    #[test]
    fn a_leftover_new_file_is_replaced() {
        let dir = TestDir::new();
        let path = file(&dir, "HOTP/T30 sam - 3334\n");
        fs::write(dir.path().join("users.oath.new"), "half").unwrap();
        assert!(set(&path, "sam", None).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        assert!(!dir.path().join("users.oath.new").exists());
    }

    #[test]
    fn a_held_lock_is_waited_for_and_then_refused() {
        let dir = TestDir::new();
        let path = file(&dir, "HOTP/T30 sam - 3334\n");
        let holder = held_lock(&dir);
        let started = Instant::now();
        let error = set(&path, "sam", None).unwrap_err();
        assert!(error.contains("locked by a sign-in"), "{error}");
        assert!(started.elapsed() >= LOCK_WAIT);
        assert_eq!(fs::read_to_string(&path).unwrap(), "HOTP/T30 sam - 3334\n");
        assert!(dir.path().join("users.oath.lock").exists());
        drop(holder);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_lock_no_process_holds_is_removed_after_the_wait() {
        let dir = TestDir::new();
        let path = file(&dir, "HOTP/T30 sam - 3334\n");
        File::create(dir.path().join("users.oath.lock")).unwrap();
        let started = Instant::now();
        assert!(set(&path, "sam", None).unwrap());
        assert!(started.elapsed() >= LOCK_WAIT);
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        assert!(!dir.path().join("users.oath.lock").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_traditional_lock_like_liboaths_counts_as_held() {
        use nix::fcntl::{FcntlArg, fcntl};
        let dir = TestDir::new();
        let lock = dir.path().join("users.oath.lock");
        let holder = File::create(&lock).unwrap();
        fcntl(&holder, FcntlArg::F_SETLK(&kernel::write_lock())).unwrap();
        assert!(matches!(probe(&lock).unwrap(), Probe::Held));
        drop(holder);
        assert!(matches!(probe(&lock).unwrap(), Probe::Unheld(_)));
    }
}
