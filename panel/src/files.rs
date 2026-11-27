//! Files only root may read: written whole and atomically, or appended to.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;

/// Replaces `path` with `bytes` atomically: a crash leaves either the old file
/// or the new one, never a mixture. The file is created with mode 0600.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = Path::new(&temporary);
    match fs::remove_file(temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", temporary.display())),
    }
    let mut file = private_options()
        .write(true)
        .create_new(true)
        .open(temporary)
        .map_err(|error| format!("{}: {error}", temporary.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", temporary.display()))?;
    fs::rename(temporary, path).map_err(|error| format!("{}: {error}", path.display()))?;
    sync_parent(path)
}

/// Rewrites `path` with what `change` makes of its text, under a lock that
/// another program shares: `lock` is created exclusively with mode 0600, the
/// text is read and written to it, and it is renamed over `path` with
/// `path`'s owner kept. A `lock` that exists already belongs to another
/// writer at work, so the change is refused and the lock left alone.
pub fn replace_under_lock(
    path: &Path,
    lock: &Path,
    change: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(), String> {
    let mut file = match private_options().write(true).create_new(true).open(lock) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            return Err(format!(
                "{} exists, so another program is changing {}; try again once it is done",
                lock.display(),
                path.display()
            ));
        }
        Err(error) => return Err(format!("{}: {error}", lock.display())),
    };
    let replaced = fs::metadata(path)
        .and_then(|original| fs::read_to_string(path).map(|text| (original, text)))
        .map_err(|error| format!("{}: {error}", path.display()))
        .and_then(|(original, text)| Ok((original, change(&text)?)))
        .and_then(|(original, changed)| {
            file.write_all(changed.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("{}: {error}", lock.display()))?;
            keep_owner(&file, &original, lock)?;
            fs::rename(lock, path).map_err(|error| format!("{}: {error}", path.display()))
        });
    match replaced {
        Ok(()) => sync_parent(path),
        Err(error) => Err(match fs::remove_file(lock) {
            Ok(()) => error,
            Err(undo) => format!(
                "{error}; {} could not be removed either: {undo}",
                lock.display()
            ),
        }),
    }
}

/// Gives `file`, written at `path`, the owner of the file it replaces.
#[cfg(unix)]
fn keep_owner(file: &File, original: &fs::Metadata, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    std::os::unix::fs::fchown(file, Some(original.uid()), Some(original.gid())).map_err(|error| {
        format!(
            "{}: the replaced file's owner could not be kept: {error}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn keep_owner(_file: &File, _original: &fs::Metadata, _path: &Path) -> Result<(), String> {
    Ok(())
}

/// Opens `path` for appending, creating it with mode 0600.
pub fn open_private_append(path: &Path) -> Result<File, String> {
    private_options()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Creates `path` and any missing parents, and sets the last one's mode to
/// 0700.
pub fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("{}: {error}", path.display()))?;
    restrict_dir(path)
}

#[cfg(unix)]
fn private_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.mode(0o600);
    options
}

#[cfg(not(unix))]
fn private_options() -> OpenOptions {
    OpenOptions::new()
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Makes a rename in `path`'s directory durable.
#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        Some(_) | None => Path::new("."),
    };
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("{}: {error}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    #[test]
    fn writes_replace_whole_files() {
        let dir = TestDir::new();
        let path = dir.path().join("admins.json");
        write_private(&path, b"first").unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(".tmp");
        assert!(!Path::new(&temporary).exists());
    }

    #[test]
    fn a_leftover_temporary_file_is_replaced() {
        let dir = TestDir::new();
        let path = dir.path().join("admins.json");
        fs::write(dir.path().join("admins.json.tmp"), b"crashed").unwrap();
        write_private(&path, b"fresh").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"fresh");
    }

    #[test]
    fn a_change_under_the_lock_rewrites_the_file_and_releases_the_lock() {
        let dir = TestDir::new();
        let path = dir.path().join("ocpasswd");
        let lock = dir.path().join("ocpasswd.tmp");
        fs::write(&path, b"alex:*:$5$hash\n").unwrap();
        replace_under_lock(&path, &lock, |text| Ok(text.replace('*', "staff"))).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"alex:staff:$5$hash\n");
        assert!(!lock.exists());
        let error =
            replace_under_lock(&path, &lock, |_text| Err("no such user".to_owned())).unwrap_err();
        assert_eq!(error, "no such user");
        assert!(!lock.exists());
        assert_eq!(fs::read(&path).unwrap(), b"alex:staff:$5$hash\n");
    }

    #[test]
    fn another_writers_lock_refuses_the_change_and_stays() {
        let dir = TestDir::new();
        let path = dir.path().join("ocpasswd");
        let lock = dir.path().join("ocpasswd.tmp");
        fs::write(&path, b"alex:*:$5$hash\n").unwrap();
        fs::write(&lock, b"ocpasswd at work").unwrap();
        let error = replace_under_lock(&path, &lock, |text| Ok(text.to_owned())).unwrap_err();
        assert!(error.contains("another program is changing"), "{error}");
        assert_eq!(fs::read(&lock).unwrap(), b"ocpasswd at work");
        assert_eq!(fs::read(&path).unwrap(), b"alex:*:$5$hash\n");
    }

    #[test]
    fn appends_add_to_the_end() {
        let dir = TestDir::new();
        let path = dir.path().join("audit.log");
        open_private_append(&path)
            .unwrap()
            .write_all(b"one\n")
            .unwrap();
        open_private_append(&path)
            .unwrap()
            .write_all(b"two\n")
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one\ntwo\n");
    }

    #[cfg(unix)]
    #[test]
    fn files_and_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let panel = dir.path().join("config").join("panel");
        create_private_dir(&panel).unwrap();
        let file = panel.join("admins.json");
        write_private(&file, b"{}").unwrap();
        let log = panel.join("audit.log");
        open_private_append(&log).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&panel), 0o700);
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&log), 0o600);
    }
}
