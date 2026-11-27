//! MaxMind GeoLite2 Country, as docker-sftp keeps it: the account ID and
//! license key, from the container's environment or the admin panel, and
//! the download that puts GeoLite2 in place of DB-IP Lite while a key is
//! set. The panel's helper keeps the copy current; at start, `ocpanel
//! geoip-update` fetches one that is missing or due.

use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::countries::Countries;
use crate::files;

/// MaxMind's download of GeoLite2 Country, a gzipped tar archive.
#[cfg(unix)]
const URL: &str =
    "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz";

/// MaxMind publishes GeoLite2 twice a week; a copy this old is fetched
/// again.
pub const MAX_AGE: Duration = Duration::from_secs(3 * 86_400);

/// MaxMind's terms let a copy be used for 30 days after a newer one is out.
pub const STALE: Duration = Duration::from_secs(30 * 86_400);

/// The largest download accepted; DB-IP City Lite, the largest database the
/// panel fetches, is about half of it.
#[cfg(unix)]
const MAX_DOWNLOAD: u64 = 128 * 1024 * 1024;

/// The largest database a download may unpack to; DB-IP City Lite is about
/// half of it.
const MAX_DATABASE: u64 = 256 * 1024 * 1024;

/// A MaxMind account ID and license key. Its `Debug` leaves the license
/// key out.
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    pub account: String,
    pub license: String,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Key")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// Where the key the panel saved lives, readable by root only.
pub fn key_file(config_dir: &Path) -> PathBuf {
    config_dir.join("geoip").join("maxmind.conf")
}

/// Where the GeoLite2 copy lives, readable by root only.
pub fn database_file(config_dir: &Path) -> PathBuf {
    config_dir.join("geoip").join("GeoLite2-Country.mmdb")
}

/// An account ID is a number; a license key is letters, digits and
/// underscores.
pub fn check_key(key: &Key) -> Result<(), String> {
    let account = &key.account;
    if account.is_empty() || account.len() > 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return Err("a MaxMind account ID is a number, such as 123456".to_owned());
    }
    let license = &key.license;
    if license.len() < 6
        || license.len() > 128
        || !license
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("a MaxMind license key is letters, digits and underscores".to_owned());
    }
    Ok(())
}

/// The key MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY give, which wins
/// over the panel's; neither or both must be set.
pub fn environment_key<F>(get: &F) -> Result<Option<Key>, String>
where
    F: Fn(&str) -> Option<OsString>,
{
    let text = |name: &'static str| {
        crate::config::text(get, name)
            .map_err(|error| error.to_string())
            .map(|value| value.map(|value| value.trim().to_owned()))
    };
    let key = match (text("MAXMIND_ACCOUNT_ID")?, text("MAXMIND_LICENSE_KEY")?) {
        (Some(account), Some(license)) => Key { account, license },
        (None, None) => return Ok(None),
        (Some(_account), None) => {
            return Err("MAXMIND_ACCOUNT_ID is set without MAXMIND_LICENSE_KEY".to_owned());
        }
        (None, Some(_license)) => {
            return Err("MAXMIND_LICENSE_KEY is set without MAXMIND_ACCOUNT_ID".to_owned());
        }
    };
    check_key(&key)
        .map_err(|error| format!("MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY: {error}"))?;
    Ok(Some(key))
}

/// The key the panel saved at `path`; none without the file.
pub fn saved_key(path: &Path) -> Result<Option<Key>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .map(|value| value.trim().to_owned())
    };
    let (Some(account), Some(license)) =
        (field("MAXMIND_ACCOUNT_ID"), field("MAXMIND_LICENSE_KEY"))
    else {
        return Err(format!(
            "{} lacks MAXMIND_ACCOUNT_ID or MAXMIND_LICENSE_KEY",
            path.display()
        ));
    };
    let key = Key { account, license };
    check_key(&key).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(Some(key))
}

/// Saves `key` for the panel at `path`, readable by root only.
pub fn save_key(path: &Path, key: &Key) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        files::create_private_dir(dir)?;
    }
    let text = format!(
        "# Saved by the admin panel; root only.\nMAXMIND_ACCOUNT_ID={}\nMAXMIND_LICENSE_KEY={}\n",
        key.account, key.license
    );
    files::write_private(path, text.as_bytes())
}

/// Removes the file at `path`; a missing one is removed already.
pub fn remove(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// The text of a NUL-padded tar header field.
fn field_text(field: &[u8]) -> String {
    let end = match field.iter().position(|&byte| byte == 0) {
        Some(end) => end,
        None => field.len(),
    };
    String::from_utf8_lossy(&field[..end]).trim().to_owned()
}

/// The database `file`, such as GeoLite2-Country.mmdb, from the tar.gz
/// MaxMind serves, read in memory: no name in the archive ever becomes a
/// path.
pub fn mmdb_from_tar_gz(archive: &[u8], file: &str) -> Result<Vec<u8>, String> {
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(archive)
        .take(MAX_DATABASE + 1)
        .read_to_end(&mut tar)
        .map_err(|error| format!("the download cannot be unpacked: {error}"))?;
    if tar.len() as u64 > MAX_DATABASE {
        return Err(format!(
            "the download unpacks to more than {MAX_DATABASE} B"
        ));
    }
    let mut at = 0;
    while at + 512 <= tar.len() {
        let header = &tar[at..at + 512];
        if header.iter().all(|&byte| byte == 0) {
            break;
        }
        let name = field_text(&header[0..100]);
        let size_text = field_text(&header[124..136]);
        if size_text.is_empty() || !size_text.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
            return Err(format!("the entry {name} has no size"));
        }
        let size = usize::from_str_radix(&size_text, 8)
            .map_err(|error| format!("the entry {name} is too large: {error}"))?;
        let start = at + 512;
        let Some(end) = start.checked_add(size) else {
            return Err(format!("the entry {name} is too large"));
        };
        if end > tar.len() {
            return Err(format!("the download ends inside {name}"));
        }
        let regular = header[156] == b'0' || header[156] == 0;
        if regular && (name == file || name.ends_with(&format!("/{file}"))) {
            return Ok(tar[start..end].to_vec());
        }
        at = start + size.div_ceil(512) * 512;
    }
    Err(format!("the download holds no {file}"))
}

/// Checks that downloaded bytes are a country database that places a
/// public address in a country.
pub fn check_download(bytes: Vec<u8>) -> Result<(), String> {
    let database = Countries::from_bytes(bytes)?;
    if !database.kind().contains("Country") {
        return Err(format!(
            "the download is a {} database, not a country database",
            database.kind()
        ));
    }
    let probe = std::net::IpAddr::from([8, 8, 8, 8]);
    if database.lookup(probe)?.is_none() {
        return Err("the download places 8.8.8.8 in no country".to_owned());
    }
    Ok(())
}

/// GeoLite2 Country downloaded with `key` and checked. The key goes only
/// to MaxMind: ureq does not send it on to the storage host MaxMind
/// redirects the download to.
#[cfg(unix)]
pub fn download(key: &Key) -> Result<Vec<u8>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(Duration::from_secs(100)))
        .build()
        .into();
    let token = data_encoding::BASE64.encode(format!("{}:{}", key.account, key.license).as_bytes());
    let mut response = match agent
        .get(URL)
        .header("Authorization", format!("Basic {token}"))
        .call()
    {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(401)) => {
            return Err("MaxMind refused the account ID and license key".to_owned());
        }
        Err(ureq::Error::StatusCode(403)) => {
            return Err("MaxMind does not allow GeoLite2 downloads with this key".to_owned());
        }
        Err(ureq::Error::StatusCode(code)) => {
            return Err(format!("MaxMind answered with status {code}"));
        }
        Err(error) => return Err(format!("MaxMind cannot be reached: {error}")),
    };
    let archive = response
        .body_mut()
        .with_config()
        .limit(MAX_DOWNLOAD)
        .read_to_vec()
        .map_err(|error| format!("MaxMind's download cannot be read: {error}"))?;
    let bytes = mmdb_from_tar_gz(&archive, "GeoLite2-Country.mmdb")?;
    check_download(bytes.clone())?;
    Ok(bytes)
}

/// Puts a checked download in place of the GeoLite2 copy at `path`.
pub fn install(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        files::create_private_dir(dir)?;
    }
    files::write_private(path, bytes)
}

/// How long ago the copy at `path` was written; none without one.
pub fn copy_age(path: &Path) -> Result<Option<Duration>, String> {
    let modified = match fs::metadata(path) {
        Ok(metadata) => metadata
            .modified()
            .map_err(|error| format!("{}: {error}", path.display()))?,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    modified
        .elapsed()
        .map(Some)
        .map_err(|ahead| format!("{} is dated in the future: {ahead}", path.display()))
}

/// A database the location checks look addresses up in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locator {
    City,
    Network,
}

impl Locator {
    /// MaxMind's GeoLite2 edition of it.
    pub fn edition(self) -> &'static str {
        match self {
            Locator::City => "GeoLite2-City",
            Locator::Network => "GeoLite2-ASN",
        }
    }

    /// The name of DB-IP's free edition of it, before the month.
    pub fn lite(self) -> &'static str {
        match self {
            Locator::City => "dbip-city-lite",
            Locator::Network => "dbip-asn-lite",
        }
    }

    /// Checks that downloaded bytes are this database and that it knows a
    /// public address.
    pub fn check(self, bytes: Vec<u8>) -> Result<(), String> {
        match self {
            Locator::City => crate::location::check_city(bytes),
            Locator::Network => crate::location::check_networks(bytes),
        }
    }
}

/// How long one download of a location database may take in all, and how
/// long connecting may take; the owner's choice for 60 MB on slow lines.
#[cfg(unix)]
const LOCATOR_TIMEOUT: Duration = Duration::from_secs(10 * 60);
#[cfg(unix)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Where MaxMind's copy of `locator` lives, readable by root only.
pub fn maxmind_file(config_dir: &Path, locator: Locator) -> PathBuf {
    config_dir
        .join("geoip")
        .join(format!("{}.mmdb", locator.edition()))
}

/// Where DB-IP's copy of `locator` for a month lives: the month is in the
/// name, which is how the helper knows when a newer one is due.
pub fn lite_file(config_dir: &Path, locator: Locator, (year, month): (u64, u64)) -> PathBuf {
    config_dir
        .join("geoip")
        .join(format!("{}-{year:04}-{month:02}.mmdb", locator.lite()))
}

/// A year and a month, 1 to 12.
pub type Month = (u64, u64);

/// The newest DB-IP copy of `locator` in /config, with its month; none when
/// there is none. A file named as a copy whose month cannot be read is an
/// error.
pub fn installed_lite(
    config_dir: &Path,
    locator: Locator,
) -> Result<Option<(PathBuf, Month)>, String> {
    let dir = config_dir.join("geoip");
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", dir.display())),
    };
    let prefix = format!("{}-", locator.lite());
    let mut newest: Option<(PathBuf, (u64, u64))> = None;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let path = entry.path();
        let Some(rest) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|rest| rest.strip_suffix(".mmdb"))
        else {
            continue;
        };
        let month =
            parse_month(rest).map_err(|problem| format!("{}: {problem}", path.display()))?;
        if newest.as_ref().is_none_or(|(_path, best)| month > *best) {
            newest = Some((path.clone(), month));
        }
    }
    Ok(newest)
}

/// A month written `YYYY-MM`.
fn parse_month(text: &str) -> Result<(u64, u64), String> {
    let malformed = || format!("'{text}' is not a month written YYYY-MM");
    let (year, month) = text.split_once('-').ok_or_else(malformed)?;
    if year.len() != 4 || month.len() != 2 {
        return Err(malformed());
    }
    let year: u64 = year
        .parse()
        .map_err(|error| format!("{}: {error}", malformed()))?;
    let month: u64 = month
        .parse()
        .map_err(|error| format!("{}: {error}", malformed()))?;
    if (1..=12).contains(&month) {
        Ok((year, month))
    } else {
        Err(malformed())
    }
}

/// The database inside a `.mmdb.gz` as DB-IP serves it, read in memory.
pub fn mmdb_from_gz(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(MAX_DATABASE + 1)
        .read_to_end(&mut out)
        .map_err(|error| format!("the download cannot be unpacked: {error}"))?;
    if out.len() as u64 > MAX_DATABASE {
        return Err(format!(
            "the download unpacks to more than {MAX_DATABASE} B"
        ));
    }
    Ok(out)
}

/// MaxMind's GeoLite2 copy of `locator`, downloaded with `key` and checked.
#[cfg(unix)]
pub fn download_maxmind(key: &Key, locator: Locator) -> Result<Vec<u8>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(LOCATOR_TIMEOUT))
        .build()
        .into();
    let url = format!(
        "https://download.maxmind.com/geoip/databases/{}/download?suffix=tar.gz",
        locator.edition()
    );
    let token = data_encoding::BASE64.encode(format!("{}:{}", key.account, key.license).as_bytes());
    let mut response = match agent
        .get(&url)
        .header("Authorization", format!("Basic {token}"))
        .call()
    {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(401)) => {
            return Err("MaxMind refused the account ID and license key".to_owned());
        }
        Err(ureq::Error::StatusCode(403)) => {
            return Err(format!(
                "MaxMind does not allow {} downloads with this key",
                locator.edition()
            ));
        }
        Err(ureq::Error::StatusCode(code)) => {
            return Err(format!("MaxMind answered with status {code}"));
        }
        Err(error) => return Err(format!("MaxMind cannot be reached: {error}")),
    };
    let archive = response
        .body_mut()
        .with_config()
        .limit(MAX_DOWNLOAD)
        .read_to_vec()
        .map_err(|error| format!("MaxMind's download cannot be read: {error}"))?;
    let bytes = mmdb_from_tar_gz(&archive, &format!("{}.mmdb", locator.edition()))?;
    locator.check(bytes.clone())?;
    Ok(bytes)
}

/// The copy of `locator` the location checks read: MaxMind's while a key is
/// set and its copy exists, else the newest DB-IP copy; none before any
/// download.
pub fn locator_copy(
    config_dir: &Path,
    locator: Locator,
    key_set: bool,
) -> Result<Option<PathBuf>, String> {
    let maxmind = maxmind_file(config_dir, locator);
    if key_set && copy_age(&maxmind)?.is_some() {
        return Ok(Some(maxmind));
    }
    Ok(installed_lite(config_dir, locator)?.map(|(path, _month)| path))
}

/// What the updater is to fetch for `locator` at `now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Due {
    Nothing,
    /// MaxMind's copy, missing or MAX_AGE old, with the key set.
    Maxmind,
    /// DB-IP's copy for these months, the first tried first: the current
    /// month, and the month before when there is no copy at all, since DB-IP
    /// publishes each month's copy some days into it.
    Lite(Vec<(u64, u64)>),
}

/// What is due for `locator`: with a MaxMind key, GeoLite2 once its copy is
/// missing or 3 days old; without one, DB-IP once a newer month than the
/// copy's has begun.
pub fn locator_due(
    config_dir: &Path,
    locator: Locator,
    key_set: bool,
    now: u64,
) -> Result<Due, String> {
    if key_set {
        let age = copy_age(&maxmind_file(config_dir, locator))?;
        return Ok(match age {
            Some(age) if age < MAX_AGE => Due::Nothing,
            Some(_old) => Due::Maxmind,
            None => Due::Maxmind,
        });
    }
    let current = crate::clock::year_month(now);
    Ok(match installed_lite(config_dir, locator)? {
        Some((_path, month)) if month >= current => Due::Nothing,
        Some(_older) => Due::Lite(vec![current]),
        None => Due::Lite(vec![current, crate::clock::month_before(current)]),
    })
}

/// Installs DB-IP's copy of `locator` for `month` and removes the older
/// months' copies, which nothing reads once a newer one is in place.
pub fn install_lite(
    config_dir: &Path,
    locator: Locator,
    month: (u64, u64),
    bytes: &[u8],
) -> Result<(), String> {
    install(&lite_file(config_dir, locator, month), bytes)?;
    let dir = config_dir.join("geoip");
    let prefix = format!("{}-", locator.lite());
    let entries = fs::read_dir(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let path = entry.path();
        let Some(rest) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|rest| rest.strip_suffix(".mmdb"))
        else {
            continue;
        };
        let older =
            parse_month(rest).map_err(|problem| format!("{}: {problem}", path.display()))?;
        if older < month {
            fs::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        }
    }
    Ok(())
}

/// Fetches and installs whatever `locator_due` says is due for each
/// database, and names each copy it installed, as "DB-IP
/// dbip-city-lite-2026-11"; the first failure ends the pass.
#[cfg(unix)]
pub fn update_locators(
    config_dir: &Path,
    key: Option<&Key>,
    now: u64,
) -> Result<Vec<String>, String> {
    let mut done = Vec::new();
    for locator in [Locator::City, Locator::Network] {
        match (locator_due(config_dir, locator, key.is_some(), now)?, key) {
            (Due::Nothing, _key) => {}
            (Due::Maxmind, Some(key)) => {
                let bytes = download_maxmind(key, locator)?;
                install(&maxmind_file(config_dir, locator), &bytes)?;
                done.push(format!("MaxMind {}", locator.edition()));
            }
            (Due::Maxmind, None) => {
                return Err(format!(
                    "{} is due from MaxMind without a key",
                    locator.edition()
                ));
            }
            (Due::Lite(months), _key) => {
                for month in months {
                    match download_lite(locator, month)? {
                        Lite::Database(bytes) => {
                            install_lite(config_dir, locator, month, &bytes)?;
                            done.push(format!(
                                "DB-IP {}-{:04}-{:02}",
                                locator.lite(),
                                month.0,
                                month.1
                            ));
                            break;
                        }
                        Lite::NotOut => {}
                    }
                }
            }
        }
    }
    Ok(done)
}

/// What DB-IP gave for a month's copy of a database.
#[cfg(unix)]
pub enum Lite {
    /// The checked database.
    Database(Vec<u8>),
    /// DB-IP has not published that month yet.
    NotOut,
}

/// DB-IP's free copy of `locator` for a month, downloaded and checked.
#[cfg(unix)]
pub fn download_lite(locator: Locator, (year, month): (u64, u64)) -> Result<Lite, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(LOCATOR_TIMEOUT))
        .build()
        .into();
    let url = format!(
        "https://download.db-ip.com/free/{}-{year:04}-{month:02}.mmdb.gz",
        locator.lite()
    );
    let mut response = match agent.get(&url).call() {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(404)) => return Ok(Lite::NotOut),
        Err(ureq::Error::StatusCode(code)) => {
            return Err(format!("DB-IP answered with status {code}"));
        }
        Err(error) => return Err(format!("DB-IP cannot be reached: {error}")),
    };
    let packed = response
        .body_mut()
        .with_config()
        .limit(MAX_DOWNLOAD)
        .read_to_vec()
        .map_err(|error| format!("DB-IP's download cannot be read: {error}"))?;
    let bytes = mmdb_from_gz(&packed)?;
    locator.check(bytes.clone())?;
    Ok(Lite::Database(bytes))
}

/// When the panel's helper first checks whether GeoLite2 is due, after it
/// starts, and how often it checks after that, as docker-sftp does.
pub const FIRST_CHECK: Duration = Duration::from_secs(5 * 60);
pub const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);

/// MaxMind GeoLite2 as the panel's helper keeps it.
pub struct Maxmind {
    /// The key the environment gives, which the panel cannot change.
    pub environment: Option<Key>,
    /// Where the panel's own key and the GeoLite2 copy live.
    pub key_file: PathBuf,
    pub database_file: PathBuf,
    /// A key an admin saved, which is kept once a download with it works.
    pub candidate: Option<Key>,
    /// Whether the database is to be read again without a download, as
    /// after a key was removed.
    pub reread: bool,
    /// Whether the download thread is at work.
    pub busy: bool,
    /// The last thing the download thread did, and when, in Unix seconds:
    /// what it did, or why it failed.
    pub last: Option<(u64, Result<String, String>)>,
    /// Wakes the download thread; none where there is no such thread.
    pub wake: Option<std::sync::mpsc::Sender<()>>,
}

impl Maxmind {
    /// The key in force: the environment's, else the one the panel saved.
    pub fn key(&self) -> Result<Option<Key>, String> {
        match &self.environment {
            Some(key) => Ok(Some(key.clone())),
            None => saved_key(&self.key_file),
        }
    }

    /// Takes the next thing the download thread is to do: try the key an
    /// admin saved; read the database again; or download with the key in
    /// force when the copy is missing or MAX_AGE old.
    pub fn take_job(&mut self) -> Result<Job, String> {
        if let Some(key) = self.candidate.take() {
            return Ok(Job::Download { key, save: true });
        }
        if self.reread {
            self.reread = false;
            return Ok(Job::Reread);
        }
        let Some(key) = self.key()? else {
            return Ok(Job::Idle);
        };
        if copy_age(&self.database_file)?.is_some_and(|age| age < MAX_AGE) {
            return Ok(Job::Idle);
        }
        self.busy = true;
        Ok(Job::Download { key, save: false })
    }

    /// Wakes the download thread.
    pub fn wake(&self) -> Result<(), String> {
        match &self.wake {
            Some(wake) => wake
                .send(())
                .map_err(|error| format!("the GeoLite2 download thread has stopped: {error}")),
            None => Ok(()),
        }
    }
}

/// What the download thread is to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Job {
    Idle,
    /// Download GeoLite2 with `key`, and keep the key when `save`.
    Download {
        key: Key,
        save: bool,
    },
    /// Read the database again.
    Reread,
}

/// What `ocpanel geoip-update` did.
pub enum Said {
    Nothing,
    Done(String),
    Warning(String),
}

/// At start: with a key, fetches GeoLite2 when there is no copy or the copy
/// is MAX_AGE old. Without one, warns about a copy over 30 days old, which
/// nothing keeps current.
#[cfg(unix)]
pub fn update(config_dir: &Path, environment: Option<Key>) -> Result<Said, String> {
    let path = database_file(config_dir);
    let age = copy_age(&path)?;
    let key = match environment {
        Some(key) => Some(key),
        None => saved_key(&key_file(config_dir))?,
    };
    let Some(key) = key else {
        return Ok(match age {
            Some(age) if age > STALE => Said::Warning(format!(
                "{} is over 30 days old and no MaxMind key keeps it current; remove it to use \
                 DB-IP Lite",
                path.display()
            )),
            Some(_fresh) => Said::Nothing,
            None => Said::Nothing,
        });
    };
    if age.is_some_and(|age| age < MAX_AGE) {
        return Ok(Said::Nothing);
    }
    let bytes = download(&key)?;
    install(&path, &bytes)?;
    Ok(Said::Done("downloaded MaxMind GeoLite2 Country".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tar header for a regular file `name` of `size` bytes.
    fn header(name: &str, size: usize) -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{size:011o}");
        header[124..135].copy_from_slice(size.as_bytes());
        header[156] = b'0';
        header
    }

    fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut tar = Vec::new();
        for (name, data) in entries {
            tar.extend(header(name, data.len()));
            tar.extend_from_slice(data);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.extend([0u8; 1024]);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn the_database_is_taken_from_maxminds_archive() {
        let archive = tar_gz(&[
            ("GeoLite2-Country_build/COPYRIGHT.txt", b"notice"),
            ("GeoLite2-Country_build/GeoLite2-Country.mmdb", b"database"),
        ]);
        let file = "GeoLite2-Country.mmdb";
        assert_eq!(mmdb_from_tar_gz(&archive, file).unwrap(), b"database");
        assert!(
            mmdb_from_tar_gz(&archive, "GeoLite2-City.mmdb")
                .unwrap_err()
                .contains("no GeoLite2-City.mmdb")
        );
        let without = tar_gz(&[("GeoLite2-Country_build/LICENSE.txt", b"terms")]);
        assert!(
            mmdb_from_tar_gz(&without, file)
                .unwrap_err()
                .contains("no GeoLite2")
        );
        assert!(mmdb_from_tar_gz(b"not gzip", file).is_err());
    }

    #[test]
    fn the_newest_dbip_copy_is_found_by_its_month() {
        let dir = crate::testdir::TestDir::new();
        assert!(installed_lite(dir.path(), Locator::City).unwrap().is_none());
        fs::create_dir_all(dir.path().join("geoip")).unwrap();
        for month in [(2026, 9), (2026, 11), (2025, 12)] {
            fs::write(lite_file(dir.path(), Locator::City, month), b"city").unwrap();
        }
        fs::write(
            lite_file(dir.path(), Locator::Network, (2027, 1)),
            b"network",
        )
        .unwrap();
        let (path, month) = installed_lite(dir.path(), Locator::City).unwrap().unwrap();
        assert_eq!(month, (2026, 11));
        assert!(path.ends_with("dbip-city-lite-2026-11.mmdb"));
        assert_eq!(
            installed_lite(dir.path(), Locator::Network)
                .unwrap()
                .unwrap()
                .1,
            (2027, 1)
        );
        fs::write(dir.path().join("geoip/dbip-city-lite-2026-13.mmdb"), b"x").unwrap();
        assert!(
            installed_lite(dir.path(), Locator::City)
                .unwrap_err()
                .contains("not a month")
        );
    }

    #[test]
    fn the_updater_fetches_what_is_missing_or_old_from_the_right_source() {
        let dir = crate::testdir::TestDir::new();
        let config = dir.path();
        let now = 1_795_780_800;
        assert_eq!(crate::clock::year_month(now), (2026, 11));
        let due = |key_set| locator_due(config, Locator::City, key_set, now).unwrap();
        assert_eq!(due(false), Due::Lite(vec![(2026, 11), (2026, 10)]));
        assert_eq!(due(true), Due::Maxmind);
        assert_eq!(locator_copy(config, Locator::City, false).unwrap(), None);
        install_lite(config, Locator::City, (2026, 9), b"september").unwrap();
        assert_eq!(due(false), Due::Lite(vec![(2026, 11)]));
        install_lite(config, Locator::City, (2026, 11), b"november").unwrap();
        assert_eq!(due(false), Due::Nothing);
        assert!(!lite_file(config, Locator::City, (2026, 9)).exists());
        let november = lite_file(config, Locator::City, (2026, 11));
        assert_eq!(
            locator_copy(config, Locator::City, true).unwrap(),
            Some(november.clone())
        );
        install(&maxmind_file(config, Locator::City), b"geolite").unwrap();
        assert_eq!(due(true), Due::Nothing);
        assert_eq!(
            locator_copy(config, Locator::City, true).unwrap(),
            Some(maxmind_file(config, Locator::City))
        );
        assert_eq!(
            locator_copy(config, Locator::City, false).unwrap(),
            Some(november)
        );
        assert_eq!(
            locator_due(config, Locator::Network, false, now).unwrap(),
            Due::Lite(vec![(2026, 11), (2026, 10)])
        );
    }

    #[test]
    fn dbip_downloads_are_unpacked_and_each_database_is_checked_for_its_kind() {
        use crate::countries::sample::{database_of, double, map, string, uint32};
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"database").unwrap();
        assert_eq!(
            mmdb_from_gz(&encoder.finish().unwrap()).unwrap(),
            b"database"
        );
        assert!(mmdb_from_gz(b"not gzip").is_err());
        let city = database_of(
            "Test-City",
            &[(
                "8.8.8.0/24",
                map(&[
                    ("country", map(&[("iso_code", string("US"))])),
                    (
                        "location",
                        map(&[("latitude", double(37.75)), ("longitude", double(-97.82))]),
                    ),
                ]),
            )],
        );
        let networks = database_of(
            "Test-ASN",
            &[(
                "8.8.8.0/24",
                map(&[("autonomous_system_number", uint32(15_169))]),
            )],
        );
        Locator::City.check(city.clone()).unwrap();
        Locator::Network.check(networks.clone()).unwrap();
        assert!(
            Locator::City
                .check(networks)
                .unwrap_err()
                .contains("8.8.8.8")
        );
        assert!(
            Locator::Network
                .check(city)
                .unwrap_err()
                .contains("8.8.8.8")
        );
        assert!(Locator::City.check(b"nonsense".to_vec()).is_err());
    }

    #[test]
    fn a_download_must_be_a_country_database_that_places_addresses() {
        let placed = crate::countries::sample::database(&[("8.8.8.0/24", "US", "United States")]);
        check_download(placed).unwrap();
        let empty = crate::countries::sample::database(&[("192.0.2.0/24", "CN", "China")]);
        assert!(check_download(empty).unwrap_err().contains("8.8.8.8"));
        assert!(check_download(b"nonsense".to_vec()).is_err());
    }

    #[test]
    fn keys_are_checked_and_saved_for_root_only() {
        let key = |account: &str, license: &str| Key {
            account: account.to_owned(),
            license: license.to_owned(),
        };
        check_key(&key("123456", "abc_DEF_123")).unwrap();
        assert!(check_key(&key("12a456", "abc_DEF_123")).is_err());
        assert!(check_key(&key("123456", "short")).is_err());
        assert!(check_key(&key("123456", "has space here")).is_err());
        assert!(!format!("{:?}", key("123456", "secret_license")).contains("secret"));

        let dir = crate::testdir::TestDir::new();
        let path = key_file(dir.path());
        assert_eq!(saved_key(&path).unwrap(), None);
        save_key(&path, &key("123456", "abc_DEF_123")).unwrap();
        assert_eq!(
            saved_key(&path).unwrap(),
            Some(key("123456", "abc_DEF_123"))
        );
        remove(&path).unwrap();
        remove(&path).unwrap();
        assert_eq!(saved_key(&path).unwrap(), None);

        let get = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(variable, _)| *variable == name)
                    .map(|(_, value)| OsString::from(value))
            }
        };
        assert_eq!(environment_key(&get(&[])).unwrap(), None);
        assert_eq!(
            environment_key(&get(&[
                ("MAXMIND_ACCOUNT_ID", " 123456 "),
                ("MAXMIND_LICENSE_KEY", "abc_DEF_123")
            ]))
            .unwrap(),
            Some(key("123456", "abc_DEF_123"))
        );
        assert!(
            environment_key(&get(&[("MAXMIND_ACCOUNT_ID", "123456")]))
                .unwrap_err()
                .contains("without MAXMIND_LICENSE_KEY")
        );
    }
}
