//! Location checks: what a sign-in shows about where it comes from, what an
//! account has shown before, and the 0 to 100 score that flags a sign-in that
//! does not fit, or refuses it once the account's habits are learned.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::{Reader, geoip2};
use serde::{Deserialize, Serialize};

use crate::files;

/// The version of the learning file this program reads and writes.
const FORMAT_VERSION: u32 = 1;

/// The file in the panel's data directory that holds an owner's setting.
pub const STORED_FILE: &str = "location-checks.json";

/// How often the databases are checked for a newer copy, in hours: the
/// default, and the shortest and longest schedule an owner may set.
pub const DEFAULT_REFRESH_HOURS: u64 = 6;
pub const MIN_REFRESH_HOURS: u64 = 1;
pub const MAX_REFRESH_HOURS: u64 = 168;

/// How long ocserv's session script waits for the helper's answer to a VPN
/// sign-in's check, in seconds, before it lets the client in unchecked.
pub const VPN_CHECK_WAIT_SECONDS: u64 = 5;

/// The furthest ahead a vacation may end, in days from today.
pub const MAX_VACATION_DAYS: u64 = 60;

/// The score at which a sign-in raises an alert.
pub const ALERT_AT: u32 = 50;

/// The score at which a sign-in is refused, once the account is learned and
/// not on vacation.
pub const REFUSE_AT: u32 = 80;

/// What an impossible jump, or a session open far away, scores alone.
const JUMP_POINTS: u32 = 80;
/// What a place far from every learned area adds.
const FAR_POINTS: u32 = 40;
/// What a network or a country the account never used adds, each.
const NEW_NETWORK_POINTS: u32 = 20;
const NEW_COUNTRY_POINTS: u32 = 20;
/// What a sign-in at an hour the account does not use adds.
const HOUR_POINTS: u32 = 10;
/// What a device, platform or client version the account never used adds.
const DEVICE_POINTS: u32 = 10;

/// Moves shorter than this, in kilometers, never count as a jump, and
/// places within it of a learned area are usual.
const FAR_KM: f64 = 500.0;
/// The speed above which a move between two sign-ins cannot be travel.
const JUMP_KMH: f64 = 1000.0;

/// Places closer than this, in kilometers, are one learned area.
const AREA_KM: f64 = 50.0;
/// How long a learned area stays usual after the account was last seen
/// there, in seconds.
const FORGET_AFTER: u64 = 180 * 86_400;
/// The most learned areas one account keeps.
const MAX_AREAS: usize = 50;

/// The learning an account needs before a sign-in can be refused: this long
/// since its first sign-in, and this many sign-ins.
const LEARNING_SECONDS: u64 = 30 * 86_400;
const LEARNING_SIGN_INS: u32 = 10;

/// How far back the sign-in hours reach, and how close to one of them a
/// sign-in's time of day must be to count as usual, in seconds.
const HOURS_KEPT: u64 = 30 * 86_400;
const HOUR_WINDOW: u64 = 2 * 3600;

const EARTH_RADIUS_KM: f64 = 6371.0;
const DAY: u64 = 86_400;

/// Where an address is, as a database gives it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Place {
    pub lat: f64,
    pub lon: f64,
    /// The ISO 3166-1 alpha-2 code, when the database knows it.
    pub country: Option<String>,
    /// The network's autonomous system number, when the database knows it.
    pub asn: Option<u32>,
}

/// A database as the panel names it: what it calls itself, as
/// DBIP-City-Lite, and when it was built, in Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edition {
    pub kind: String,
    pub built: u64,
}

/// The databases a sign-in's address is looked up in: a city database, DB-IP
/// City Lite or MaxMind GeoLite2 City, and a network database, DB-IP ASN Lite
/// or GeoLite2 ASN, when one is installed.
pub struct Atlas {
    city: Reader<Vec<u8>>,
    networks: Option<Reader<Vec<u8>>>,
}

impl Atlas {
    pub fn open(city: &Path, networks: Option<&Path>) -> Result<Atlas, String> {
        let read = |path: &Path| {
            Reader::open_readfile(path)
                .map_err(|error| format!("the database {} cannot be read: {error}", path.display()))
        };
        Ok(Atlas {
            city: read(city)?,
            networks: networks.map(read).transpose()?,
        })
    }

    /// Databases held in memory, as downloads before they are installed.
    pub fn from_bytes(city: Vec<u8>, networks: Option<Vec<u8>>) -> Result<Atlas, String> {
        let read = |bytes: Vec<u8>| {
            Reader::from_source(bytes)
                .map_err(|error| format!("the data is not a database: {error}"))
        };
        Ok(Atlas {
            city: read(city)?,
            networks: networks.map(read).transpose()?,
        })
    }

    /// What the city database and the network database, when there is one,
    /// call themselves, as DBIP-City-Lite or GeoLite2-ASN, and when each was
    /// built, in Unix seconds.
    pub fn editions(&self) -> (Edition, Option<Edition>) {
        let edition = |reader: &Reader<Vec<u8>>| Edition {
            kind: reader.metadata().database_type.clone(),
            built: reader.metadata().build_epoch,
        };
        (edition(&self.city), self.networks.as_ref().map(edition))
    }

    /// Where `address` is; none for an address the city database places
    /// nowhere, as a private one.
    pub fn place(&self, address: IpAddr) -> Result<Option<Place>, String> {
        let address = address.to_canonical();
        let record: Option<geoip2::City> = self
            .city
            .lookup(address)
            .map_err(|error| format!("{address} cannot be looked up: {error}"))?
            .decode()
            .map_err(|error| format!("the city record of {address} cannot be read: {error}"))?;
        let Some(record) = record else {
            return Ok(None);
        };
        let (Some(lat), Some(lon)) = (record.location.latitude, record.location.longitude) else {
            return Ok(None);
        };
        let asn = match &self.networks {
            Some(reader) => {
                let network: Option<geoip2::Asn> = reader
                    .lookup(address)
                    .map_err(|error| format!("{address} cannot be looked up: {error}"))?
                    .decode()
                    .map_err(|error| {
                        format!("the network record of {address} cannot be read: {error}")
                    })?;
                network.and_then(|network| network.autonomous_system_number)
            }
            None => None,
        };
        Ok(Some(Place {
            lat,
            lon,
            country: record.country.iso_code.map(str::to_ascii_uppercase),
            asn,
        }))
    }
}

/// The databases in `config_dir` the checks read: MaxMind's copies while a
/// key is set and they exist, else DB-IP's newest; none before the first
/// city database is downloaded.
pub fn load_atlas(config_dir: &Path, key_set: bool) -> Result<Option<Atlas>, String> {
    use crate::geoip::{Locator, locator_copy};
    let Some(city) = locator_copy(config_dir, Locator::City, key_set)? else {
        return Ok(None);
    };
    let networks = locator_copy(config_dir, Locator::Network, key_set)?;
    Atlas::open(&city, networks.as_deref()).map(Some)
}

/// Checks that downloaded bytes are a city database that places a public
/// address.
pub fn check_city(bytes: Vec<u8>) -> Result<(), String> {
    let atlas = Atlas::from_bytes(bytes, None)?;
    match atlas.place(IpAddr::from([8, 8, 8, 8]))? {
        Some(_place) => Ok(()),
        None => Err("the download places 8.8.8.8 nowhere".to_owned()),
    }
}

/// Checks that downloaded bytes are a network database that knows a public
/// address's network.
pub fn check_networks(bytes: Vec<u8>) -> Result<(), String> {
    let reader = Reader::from_source(bytes)
        .map_err(|error| format!("the data is not a database: {error}"))?;
    let probe = IpAddr::from([8, 8, 8, 8]);
    let record: Option<geoip2::Asn> = reader
        .lookup(probe)
        .map_err(|error| format!("{probe} cannot be looked up: {error}"))?
        .decode()
        .map_err(|error| format!("the network record of {probe} cannot be read: {error}"))?;
    match record.and_then(|record| record.autonomous_system_number) {
        Some(_number) => Ok(()),
        None => Err("the download gives 8.8.8.8 no network".to_owned()),
    }
}

/// What one sign-in shows.
#[derive(Debug, Clone, PartialEq)]
pub struct Sighting {
    /// Unix time of the sign-in.
    pub time: u64,
    /// Where its address is, when a database names a place for it.
    pub place: Option<Place>,
    /// The device's type and platform, and the client's version, as ocserv
    /// reports them; empty for an admin's browser.
    pub devices: Vec<String>,
}

/// A session the account has open now, and where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenSession {
    pub lat: f64,
    pub lon: f64,
}

/// An area an account has signed in from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Area {
    pub lat: f64,
    pub lon: f64,
    pub country: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub sign_ins: u32,
}

/// Where and when the account last signed in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Visit {
    pub lat: f64,
    pub lon: f64,
    pub time: u64,
}

/// What an account has shown before.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    /// Unix time of the first sign-in learned, 0 before any.
    pub first_seen: u64,
    pub sign_ins: u32,
    pub areas: Vec<Area>,
    /// Autonomous system numbers, countries and devices, each with when it
    /// was last seen.
    pub networks: BTreeMap<u32, u64>,
    pub countries: BTreeMap<String, u64>,
    pub devices: BTreeMap<String, u64>,
    /// Unix times of the sign-ins of the last 30 days.
    pub times: Vec<u64>,
    pub last: Option<Visit>,
    /// Unix time until which implausible sign-ins alert but are not refused.
    pub vacation_until: Option<u64>,
}

/// One reason a sign-in scored, with what it adds.
#[derive(Debug, Clone, PartialEq)]
pub enum Reason {
    /// The move from the last sign-in needs more than 1,000 km/h.
    Jump {
        km: u32,
        kmh: u32,
    },
    /// A session is open more than 500 km away.
    OpenElsewhere {
        km: u32,
    },
    /// More than 500 km from every learned area.
    Far {
        km: u32,
    },
    NewNetwork {
        asn: u32,
    },
    NewCountry {
        country: String,
    },
    /// No sign-in within 2 hours of this time of day in the last 30 days.
    UnusualHour,
    NewDevice {
        device: String,
    },
}

impl Reason {
    pub fn points(&self) -> u32 {
        match self {
            Reason::Jump { .. } | Reason::OpenElsewhere { .. } => JUMP_POINTS,
            Reason::Far { .. } => FAR_POINTS,
            Reason::NewNetwork { .. } => NEW_NETWORK_POINTS,
            Reason::NewCountry { .. } => NEW_COUNTRY_POINTS,
            Reason::UnusualHour => HOUR_POINTS,
            Reason::NewDevice { .. } => DEVICE_POINTS,
        }
    }

    /// The reason in words, for the event log and the alerts.
    pub fn words(&self) -> String {
        match self {
            Reason::Jump { km, kmh } => {
                format!("{km} km from the last sign-in, which needs {kmh} km/h")
            }
            Reason::OpenElsewhere { km } => format!("a session is open {km} km away"),
            Reason::Far { km } => format!("{km} km from every usual place"),
            Reason::NewNetwork { asn } => format!("a network not used before (AS{asn})"),
            Reason::NewCountry { country } => format!("a country not used before ({country})"),
            Reason::UnusualHour => "an hour of the day not used in the last 30 days".to_owned(),
            Reason::NewDevice { device } => format!("a device not used before ({device})"),
        }
    }
}

/// What a sign-in scored and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    /// 0 to 100.
    pub points: u32,
    pub reasons: Vec<Reason>,
}

/// What the check does with a sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Let in, and alert.
    Flag,
    /// Refused, and alert.
    Refuse,
}

/// What the container's environment says about location checks:
/// LOCATION_CHECKS and LOCATION_REFRESH_HOURS, each when set. Either wins
/// over what an owner stored on the panel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    pub on: Option<bool>,
    pub refresh_hours: Option<u64>,
}

impl Environment {
    /// Reads the environment through `get`, which returns a variable's value
    /// or none when it is unset; an empty value counts as unset.
    pub fn from_env<F>(get: &F) -> Result<Environment, String>
    where
        F: Fn(&str) -> Option<std::ffi::OsString>,
    {
        let text =
            |name: &'static str| crate::config::text(get, name).map_err(|error| error.to_string());
        let on = match text("LOCATION_CHECKS")? {
            Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                "true" => Some(true),
                "false" => Some(false),
                other => {
                    return Err(format!(
                        "LOCATION_CHECKS must be true or false, not {other}"
                    ));
                }
            },
            None => None,
        };
        let refresh_hours = match text("LOCATION_REFRESH_HOURS")? {
            Some(value) => Some(
                refresh_hours(&value)
                    .map_err(|problem| format!("LOCATION_REFRESH_HOURS: {problem}"))?,
            ),
            None => None,
        };
        Ok(Environment { on, refresh_hours })
    }
}

/// A refresh schedule, in whole hours from 1 to 168.
pub fn refresh_hours(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let hours: u64 = text
        .parse()
        .map_err(|error| format!("'{text}' is not a whole number of hours: {error}"))?;
    if (MIN_REFRESH_HOURS..=MAX_REFRESH_HOURS).contains(&hours) {
        Ok(hours)
    } else {
        Err(format!(
            "{hours} is not from {MIN_REFRESH_HOURS} to {MAX_REFRESH_HOURS} hours"
        ))
    }
}

/// What an owner stored on the panel: whether location checks are on, and
/// how often the databases are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stored {
    pub on: bool,
    pub refresh_hours: u64,
}

impl Default for Stored {
    fn default() -> Stored {
        Stored {
            on: false,
            refresh_hours: DEFAULT_REFRESH_HOURS,
        }
    }
}

impl Stored {
    /// Loads `path`; the defaults when it does not exist.
    pub fn open(path: &Path) -> Result<Stored, String> {
        let stored: Stored = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| format!("{}: {error}", path.display()))?,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Stored::default()),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        refresh_hours(&stored.refresh_hours.to_string())
            .map_err(|problem| format!("{}: {problem}", path.display()))?;
        Ok(stored)
    }

    /// Writes the setting to `path`, atomically and readable by root only.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        files::write_private(path, &json)
    }

    /// What is in force: each value the environment sets, else this one.
    pub fn in_force(&self, environment: &Environment) -> Stored {
        Stored {
            on: environment.on.unwrap_or(self.on),
            refresh_hours: environment.refresh_hours.unwrap_or(self.refresh_hours),
        }
    }
}

/// Whose sign-ins a history learns: a VPN user's or a panel admin's, which
/// may share a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Vpn,
    Admin,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    kind: Kind,
    name: String,
    history: History,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LearningFile {
    version: u32,
    accounts: Vec<Entry>,
}

/// Every account's history, loaded from and saved to one file in the
/// panel's data directory, readable by root only.
pub struct Learning {
    path: PathBuf,
    accounts: BTreeMap<(Kind, String), History>,
}

impl Learning {
    /// Loads `path`, or starts empty when it does not exist. A file of
    /// another format version or with unknown fields is refused.
    pub fn open(path: &Path) -> Result<Learning, String> {
        let accounts = match fs::read(path) {
            Ok(bytes) => {
                let file: LearningFile = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                if file.version != FORMAT_VERSION {
                    return Err(format!(
                        "{}: format version {} is not the version {FORMAT_VERSION} this panel reads",
                        path.display(),
                        file.version
                    ));
                }
                file.accounts
                    .into_iter()
                    .map(|entry| ((entry.kind, entry.name), entry.history))
                    .collect()
            }
            Err(error) if error.kind() == ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        Ok(Learning {
            path: path.to_owned(),
            accounts,
        })
    }

    /// Writes every history to the file, atomically.
    pub fn save(&self) -> Result<(), String> {
        let file = LearningFile {
            version: FORMAT_VERSION,
            accounts: self
                .accounts
                .iter()
                .map(|((kind, name), history)| Entry {
                    kind: *kind,
                    name: name.clone(),
                    history: history.clone(),
                })
                .collect(),
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|error| format!("{}: {error}", self.path.display()))?;
        files::write_private(&self.path, &json)
    }

    /// The history of the account; none before its first sign-in.
    pub fn history(&self, kind: Kind, name: &str) -> Option<&History> {
        self.accounts.get(&(kind, name.to_owned()))
    }

    /// The account's history to change, made empty when it has none.
    pub fn history_mut(&mut self, kind: Kind, name: &str) -> &mut History {
        self.accounts.entry((kind, name.to_owned())).or_default()
    }

    /// Forgets everything learned about a removed account; whether there
    /// was anything.
    pub fn forget_account(&mut self, kind: Kind, name: &str) -> bool {
        self.accounts.remove(&(kind, name.to_owned())).is_some()
    }
}

/// When a vacation whose last day is `date`, written YYYY-MM-DD, ends: the
/// end of that day, UTC. The day may be today and at most
/// MAX_VACATION_DAYS ahead.
pub fn vacation_end(date: &str, now: u64) -> Result<u64, String> {
    let start = crate::clock::date_start(date)?;
    let today = now - now % DAY;
    if start < today {
        return Err(format!("{date} has passed"));
    }
    if start > today + MAX_VACATION_DAYS * DAY {
        return Err(format!(
            "a vacation ends at most {MAX_VACATION_DAYS} days ahead, and {date} is further"
        ));
    }
    Ok(start + DAY)
}

/// The distance between two points on the earth, in kilometers.
pub fn km_between(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (phi1, phi2) = (lat1.to_radians(), lat2.to_radians());
    let dphi = (lat2 - lat1).to_radians();
    let dlambda = (lon2 - lon1).to_radians();
    let a = (dphi / 2.0).sin().powi(2) + phi1.cos() * phi2.cos() * (dlambda / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_KM * a.sqrt().min(1.0).asin()
}

/// Whole kilometers or km/h, for the reasons' words.
fn whole(value: f64) -> u32 {
    if value.is_finite() && value > 0.0 {
        value.round().min(f64::from(u32::MAX)) as u32
    } else {
        0
    }
}

/// How far apart two times of day are, in seconds, around midnight too.
fn apart_in_day(a: u64, b: u64) -> u64 {
    let (a, b) = (a % DAY, b % DAY);
    let gap = a.abs_diff(b);
    gap.min(DAY - gap)
}

impl History {
    /// Whether the account has signed in long and often enough for a
    /// sign-in to be refused.
    pub fn learned(&self, now: u64) -> bool {
        self.sign_ins >= LEARNING_SIGN_INS
            && self.first_seen > 0
            && now >= self.first_seen.saturating_add(LEARNING_SECONDS)
    }

    /// Whether the account is on vacation at `now`.
    pub fn on_vacation(&self, now: u64) -> bool {
        self.vacation_until.is_some_and(|until| now < until)
    }

    /// Scores `seen` against what the account showed before and the
    /// sessions it has open now.
    pub fn score(&self, seen: &Sighting, open: &[OpenSession]) -> Score {
        let mut reasons = Vec::new();
        if let Some(place) = &seen.place {
            let far_open = open
                .iter()
                .map(|session| km_between(session.lat, session.lon, place.lat, place.lon))
                .filter(|km| *km > FAR_KM)
                .fold(None, |most: Option<f64>, km| {
                    Some(most.map_or(km, |most| most.max(km)))
                });
            if let Some(km) = far_open {
                reasons.push(Reason::OpenElsewhere { km: whole(km) });
            } else if let Some(last) = &self.last {
                let km = km_between(last.lat, last.lon, place.lat, place.lon);
                let hours = seen.time.saturating_sub(last.time) as f64 / 3600.0;
                let kmh = if hours > 0.0 {
                    km / hours
                } else {
                    f64::INFINITY
                };
                if km > FAR_KM && kmh > JUMP_KMH {
                    reasons.push(Reason::Jump {
                        km: whole(km),
                        kmh: whole(kmh.min(f64::from(u32::MAX))),
                    });
                }
            }
            let nearest = self
                .areas
                .iter()
                .map(|area| km_between(area.lat, area.lon, place.lat, place.lon))
                .fold(None, |least: Option<f64>, km| {
                    Some(least.map_or(km, |least| least.min(km)))
                });
            if let Some(km) = nearest
                && km > FAR_KM
            {
                reasons.push(Reason::Far { km: whole(km) });
            }
            if self.sign_ins > 0 {
                if let Some(asn) = place.asn
                    && !self.networks.contains_key(&asn)
                {
                    reasons.push(Reason::NewNetwork { asn });
                }
                if let Some(country) = &place.country
                    && !self.countries.contains_key(country)
                {
                    reasons.push(Reason::NewCountry {
                        country: country.clone(),
                    });
                }
            }
        }
        if self.sign_ins >= LEARNING_SIGN_INS
            && !self
                .times
                .iter()
                .any(|time| apart_in_day(*time, seen.time) <= HOUR_WINDOW)
        {
            reasons.push(Reason::UnusualHour);
        }
        if self.sign_ins > 0
            && let Some(device) = seen
                .devices
                .iter()
                .find(|device| !self.devices.contains_key(*device))
        {
            reasons.push(Reason::NewDevice {
                device: device.clone(),
            });
        }
        let points = reasons.iter().map(Reason::points).sum::<u32>().min(100);
        Score { points, reasons }
    }

    /// What the check does with a sign-in that scored `score` at `now`.
    pub fn verdict(&self, score: &Score, now: u64) -> Verdict {
        if score.points >= REFUSE_AT && self.learned(now) && !self.on_vacation(now) {
            Verdict::Refuse
        } else if score.points >= ALERT_AT {
            Verdict::Flag
        } else {
            Verdict::Allow
        }
    }

    /// Learns a sign-in the account was let in with.
    pub fn learn(&mut self, seen: &Sighting) {
        let now = seen.time;
        if self.first_seen == 0 {
            self.first_seen = now;
        }
        self.sign_ins = self.sign_ins.saturating_add(1);
        if let Some(place) = &seen.place {
            self.learn_place(place, now);
            if let Some(asn) = place.asn {
                self.networks.insert(asn, now);
            }
            if let Some(country) = &place.country {
                self.countries.insert(country.clone(), now);
            }
            self.last = Some(Visit {
                lat: place.lat,
                lon: place.lon,
                time: now,
            });
        }
        for device in &seen.devices {
            self.devices.insert(device.clone(), now);
        }
        self.times.push(now);
        self.forget(now);
    }

    /// Makes `place` usual for the account, as an admin's Allow this place
    /// does: its area, network and country become known, and it counts as
    /// where the account is now, so a sign-in from it is no jump.
    pub fn allow(&mut self, place: &Place, now: u64) {
        self.learn_place(place, now);
        if let Some(asn) = place.asn {
            self.networks.insert(asn, now);
        }
        if let Some(country) = &place.country {
            self.countries.insert(country.clone(), now);
        }
        self.last = Some(Visit {
            lat: place.lat,
            lon: place.lon,
            time: now,
        });
    }

    /// Whether `place` lies in one of the account's learned areas.
    pub fn knows(&self, place: &Place) -> bool {
        self.areas
            .iter()
            .any(|area| km_between(area.lat, area.lon, place.lat, place.lon) <= AREA_KM)
    }

    /// Adds `place` to the account's learned areas, or counts it in the area
    /// it falls in.
    pub fn learn_place(&mut self, place: &Place, now: u64) {
        let nearest = self
            .areas
            .iter_mut()
            .map(|area| (km_between(area.lat, area.lon, place.lat, place.lon), area))
            .filter(|(km, _area)| *km <= AREA_KM)
            .min_by(|(a, _), (b, _)| a.total_cmp(b));
        match nearest {
            Some((_km, area)) => {
                area.last_seen = now;
                area.sign_ins = area.sign_ins.saturating_add(1);
            }
            None => self.areas.push(Area {
                lat: place.lat,
                lon: place.lon,
                country: place.country.clone(),
                first_seen: now,
                last_seen: now,
                sign_ins: 1,
            }),
        }
        self.forget(now);
    }

    /// Drops what is too old to count: areas not seen for 180 days, beyond
    /// the 50 most recently seen, and sign-in times older than 30 days.
    pub fn forget(&mut self, now: u64) {
        self.areas
            .retain(|area| now < area.last_seen.saturating_add(FORGET_AFTER));
        if self.areas.len() > MAX_AREAS {
            self.areas
                .sort_by_key(|area| std::cmp::Reverse(area.last_seen));
            self.areas.truncate(MAX_AREAS);
        }
        self.times
            .retain(|time| now < time.saturating_add(HOURS_KEPT));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: u64 = 1_700_000_000;
    const HOUR: u64 = 3600;

    /// Places for the tests, with real coordinates.
    fn denver() -> Place {
        Place {
            lat: 39.74,
            lon: -104.99,
            country: Some("US".to_owned()),
            asn: Some(7922),
        }
    }

    fn boulder() -> Place {
        Place {
            lat: 40.01,
            lon: -105.27,
            country: Some("US".to_owned()),
            asn: Some(7922),
        }
    }

    fn chicago() -> Place {
        Place {
            lat: 41.88,
            lon: -87.63,
            country: Some("US".to_owned()),
            asn: Some(7922),
        }
    }

    fn moscow() -> Place {
        Place {
            lat: 55.76,
            lon: 37.62,
            country: Some("RU".to_owned()),
            asn: Some(8359),
        }
    }

    fn at(place: Place, time: u64) -> Sighting {
        Sighting {
            time,
            place: Some(place),
            devices: vec!["windows desktop".to_owned()],
        }
    }

    /// An account that signed in from Denver every day for `days` days at
    /// 09:00 UTC.
    fn learned_in_denver(days: u64) -> History {
        let mut history = History::default();
        for day in 0..days {
            history.learn(&at(denver(), START + day * DAY + 9 * HOUR));
        }
        history
    }

    /// A city database with Denver at 203.0.113.0/24 and a network database
    /// giving that network AS7922, as the downloads would.
    fn atlas(with_networks: bool) -> Atlas {
        use crate::countries::sample::{database_of, double, map, string, uint32};
        let city = database_of(
            "Test-City",
            &[(
                "203.0.113.0/24",
                map(&[
                    ("country", map(&[("iso_code", string("us"))])),
                    (
                        "location",
                        map(&[("latitude", double(39.74)), ("longitude", double(-104.99))]),
                    ),
                ]),
            )],
        );
        let networks = database_of(
            "Test-ASN",
            &[(
                "203.0.113.0/24",
                map(&[("autonomous_system_number", uint32(7922))]),
            )],
        );
        Atlas::from_bytes(city, with_networks.then_some(networks)).unwrap()
    }

    #[test]
    fn addresses_are_placed_with_their_network() {
        let found = atlas(true).place("203.0.113.9".parse().unwrap()).unwrap();
        assert_eq!(found, Some(denver()));
        let mapped = atlas(true)
            .place("::ffff:203.0.113.9".parse().unwrap())
            .unwrap();
        assert_eq!(mapped, Some(denver()));
        assert_eq!(
            atlas(true).place("198.51.100.1".parse().unwrap()).unwrap(),
            None
        );
        let without = atlas(false).place("203.0.113.9".parse().unwrap()).unwrap();
        assert_eq!(without.map(|place| place.asn), Some(None));
    }

    #[test]
    fn distances_are_great_circle_kilometers() {
        let denver = denver();
        let chicago = chicago();
        let km = km_between(denver.lat, denver.lon, chicago.lat, chicago.lon);
        assert!((1400.0..1500.0).contains(&km), "{km}");
        assert_eq!(km_between(1.0, 2.0, 1.0, 2.0), 0.0);
    }

    #[test]
    fn a_first_sign_in_scores_nothing_new() {
        let history = History::default();
        let score = history.score(&at(moscow(), START), &[]);
        assert_eq!(score.points, 0, "{:?}", score.reasons);
    }

    #[test]
    fn a_usual_sign_in_scores_nothing() {
        let history = learned_in_denver(40);
        let score = history.score(&at(boulder(), START + 41 * DAY + 9 * HOUR), &[]);
        assert_eq!(score.points, 0, "{:?}", score.reasons);
        assert_eq!(history.verdict(&score, START + 41 * DAY), Verdict::Allow);
    }

    #[test]
    fn an_impossible_jump_is_refused_once_learned_and_only_flagged_before() {
        let history = learned_in_denver(40);
        let now = START + 39 * DAY + 10 * HOUR;
        let score = history.score(&at(moscow(), now), &[]);
        assert!(score.points >= REFUSE_AT, "{:?}", score.reasons);
        assert!(matches!(score.reasons[0], Reason::Jump { .. }));
        assert_eq!(history.verdict(&score, now), Verdict::Refuse);
        let young = learned_in_denver(5);
        let now = START + 4 * DAY + 10 * HOUR;
        let score = young.score(&at(moscow(), now), &[]);
        assert_eq!(young.verdict(&score, now), Verdict::Flag);
    }

    #[test]
    fn a_long_flight_is_no_jump() {
        let history = learned_in_denver(40);
        let now = START + 39 * DAY + 9 * HOUR + 15 * HOUR;
        let score = history.score(&at(chicago(), now), &[]);
        assert!(
            !score
                .reasons
                .iter()
                .any(|reason| matches!(reason, Reason::Jump { .. })),
            "{:?}",
            score.reasons
        );
        assert!(
            score
                .reasons
                .iter()
                .any(|reason| matches!(reason, Reason::Far { km } if *km > 1400)),
            "{:?}",
            score.reasons
        );
    }

    #[test]
    fn a_session_open_far_away_scores_like_a_jump() {
        let history = learned_in_denver(40);
        let open = [OpenSession {
            lat: denver().lat,
            lon: denver().lon,
        }];
        let now = START + 45 * DAY + 9 * HOUR;
        let score = history.score(&at(chicago(), now), &open);
        assert!(matches!(score.reasons[0], Reason::OpenElsewhere { .. }));
        assert!(score.points >= REFUSE_AT);
        let near = history.score(&at(boulder(), now), &open);
        assert_eq!(near.points, 0, "{:?}", near.reasons);
    }

    #[test]
    fn vacation_turns_a_refusal_into_an_alert() {
        let mut history = learned_in_denver(40);
        let now = START + 39 * DAY + 10 * HOUR;
        history.vacation_until = Some(now + DAY);
        let score = history.score(&at(moscow(), now), &[]);
        assert_eq!(history.verdict(&score, now), Verdict::Flag);
        assert_eq!(history.verdict(&score, now + 2 * DAY), Verdict::Refuse);
    }

    #[test]
    fn new_networks_countries_hours_and_devices_add_up() {
        let history = learned_in_denver(40);
        let mut seen = at(
            Place {
                asn: Some(64_500),
                ..boulder()
            },
            START + 40 * DAY + 21 * HOUR,
        );
        seen.devices = vec!["android phone".to_owned()];
        let score = history.score(&seen, &[]);
        assert_eq!(
            score.reasons,
            [
                Reason::NewNetwork { asn: 64_500 },
                Reason::UnusualHour,
                Reason::NewDevice {
                    device: "android phone".to_owned()
                }
            ]
        );
        assert_eq!(
            score.points,
            NEW_NETWORK_POINTS + HOUR_POINTS + DEVICE_POINTS
        );
        assert_eq!(history.verdict(&score, seen.time), Verdict::Allow);
    }

    #[test]
    fn the_score_stops_at_100() {
        let history = learned_in_denver(40);
        let mut seen = at(moscow(), START + 39 * DAY + 21 * HOUR);
        seen.devices = vec!["android phone".to_owned()];
        assert_eq!(history.score(&seen, &[]).points, 100);
    }

    #[test]
    fn an_allowed_place_is_usual_from_then_on() {
        let mut history = learned_in_denver(40);
        let now = START + 39 * DAY + 10 * HOUR;
        assert!(!history.knows(&moscow()));
        let refused = history.score(&at(moscow(), now), &[]);
        assert_eq!(history.verdict(&refused, now), Verdict::Refuse);
        history.allow(&moscow(), now + 300);
        assert!(history.knows(&moscow()));
        let again = history.score(&at(moscow(), now + 600), &[]);
        assert!(again.reasons.is_empty(), "{:?}", again.reasons);
        assert_eq!(history.sign_ins, 40);
    }

    #[test]
    fn nearby_places_share_an_area_and_old_ones_are_forgotten() {
        let mut history = History::default();
        history.learn(&at(denver(), START));
        history.learn(&at(boulder(), START + DAY));
        assert_eq!(history.areas.len(), 1);
        assert_eq!(history.areas[0].sign_ins, 2);
        history.learn(&at(chicago(), START + 2 * DAY));
        assert_eq!(history.areas.len(), 2);
        history.learn(&at(chicago(), START + 200 * DAY));
        assert_eq!(history.areas.len(), 1, "Denver was not forgotten");
        assert!(history.times.len() == 1, "times older than 30 days stayed");
    }

    #[test]
    fn an_account_keeps_its_50_newest_areas() {
        let mut history = History::default();
        for index in 0..60u64 {
            let place = Place {
                lat: -60.0 + index as f64 * 2.0,
                lon: 0.0,
                country: None,
                asn: None,
            };
            history.learn_place(&place, START + index);
        }
        assert_eq!(history.areas.len(), MAX_AREAS);
        assert!(
            history
                .areas
                .iter()
                .all(|area| area.last_seen >= START + 10)
        );
    }

    #[test]
    fn the_environment_is_checked_and_wins_value_by_value() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _value)| *key == name)
                    .map(|(_key, value)| std::ffi::OsString::from(value))
            }
        };
        let read = Environment::from_env(&env(&[
            ("LOCATION_CHECKS", "TRUE"),
            ("LOCATION_REFRESH_HOURS", " 12 "),
        ]))
        .unwrap();
        assert_eq!(
            read,
            Environment {
                on: Some(true),
                refresh_hours: Some(12)
            }
        );
        assert_eq!(
            Environment::from_env(&env(&[])).unwrap(),
            Environment::default()
        );
        assert!(Environment::from_env(&env(&[("LOCATION_CHECKS", "yes")])).is_err());
        for bad in ["0", "169", "six", "-1"] {
            assert!(refresh_hours(bad).is_err(), "accepted {bad}");
        }
        assert_eq!(refresh_hours("168"), Ok(168));
        let stored = Stored {
            on: false,
            refresh_hours: 24,
        };
        assert_eq!(
            stored.in_force(&Environment {
                on: Some(true),
                refresh_hours: None
            }),
            Stored {
                on: true,
                refresh_hours: 24
            }
        );
    }

    #[test]
    fn a_stored_setting_survives_a_save_and_starts_off() {
        let dir = crate::testdir::TestDir::new();
        let path = dir.path().join("location-checks.json");
        assert_eq!(Stored::open(&path).unwrap(), Stored::default());
        assert!(!Stored::default().on);
        let on = Stored {
            on: true,
            refresh_hours: 3,
        };
        on.save(&path).unwrap();
        assert_eq!(Stored::open(&path).unwrap(), on);
        fs::write(&path, br#"{"on":true,"refresh_hours":0}"#).unwrap();
        assert!(Stored::open(&path).is_err());
    }

    #[test]
    fn learning_survives_a_save_and_keeps_kinds_apart() {
        let dir = crate::testdir::TestDir::new();
        let path = dir.path().join("locations.json");
        let mut learning = Learning::open(&path).unwrap();
        assert!(learning.history(Kind::Vpn, "alex").is_none());
        learning
            .history_mut(Kind::Vpn, "alex")
            .learn(&at(denver(), START));
        learning.history_mut(Kind::Admin, "alex").vacation_until = Some(START + DAY);
        learning.save().unwrap();
        let mut reloaded = Learning::open(&path).unwrap();
        assert_eq!(reloaded.history(Kind::Vpn, "alex").unwrap().sign_ins, 1);
        let admin = reloaded.history(Kind::Admin, "alex").unwrap();
        assert_eq!(
            (admin.sign_ins, admin.vacation_until),
            (0, Some(START + DAY))
        );
        assert!(reloaded.forget_account(Kind::Vpn, "alex"));
        assert!(!reloaded.forget_account(Kind::Vpn, "alex"));
        fs::write(&path, br#"{"version":2,"accounts":[]}"#).unwrap();
        assert!(Learning::open(&path).is_err());
    }

    #[test]
    fn a_vacation_ends_with_its_last_day_from_today_to_60_days_ahead() {
        let today = START - START % DAY;
        assert_eq!(vacation_end("2023-11-14", START), Ok(today + DAY));
        assert_eq!(vacation_end("2024-01-13", START), Ok(today + 61 * DAY));
        for refused in ["2023-11-13", "2024-01-14", "2023-11-31", "14/11/2023"] {
            assert!(vacation_end(refused, START).is_err(), "{refused}");
        }
    }

    #[test]
    fn hours_wrap_around_midnight() {
        assert_eq!(apart_in_day(23 * HOUR, HOUR), 2 * HOUR);
        assert_eq!(apart_in_day(DAY + 5, 5), 0);
    }
}
