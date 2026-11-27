//! The Live events feed. Connects and disconnects come from ocserv's session
//! script, which runs `ocpanel record-event`; failed sign-ins and bans come
//! from ocserv's log, which reaches the container log through
//! `ocpanel log-relay`. Each producer writes every event as a small JSON file
//! of its own into the spool directory PANEL_EVENTS_DIR, which only root can
//! use. The helper reads the files in order, removes each, and keeps the
//! events in memory for PANEL_HISTORY_HOURS.

use std::collections::VecDeque;
use std::ffi::OsString;
#[cfg(any(unix, test))]
use std::fs;
#[cfg(any(unix, test))]
use std::io::ErrorKind;
use std::io::{BufRead, Write};
use std::net::IpAddr;
#[cfg(any(unix, test))]
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::files;

/// The variable that names the spool directory.
pub const SPOOL_VARIABLE: &str = "PANEL_EVENTS_DIR";

/// An event and when it happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Unix seconds.
    pub time: u64,
    pub what: What,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum What {
    /// A VPN session started.
    Connected {
        user: String,
        group: Option<String>,
        /// The session's ID, as occtl lists it.
        session: Option<u64>,
        /// The address the client connected from.
        from: Option<String>,
        vpn_ipv4: Option<String>,
        vpn_ipv6: Option<String>,
        /// The client's user agent.
        client: Option<String>,
    },
    /// A VPN session ended.
    Disconnected {
        user: String,
        session: Option<u64>,
        from: Option<String>,
        /// How long the session lasted, in seconds.
        seconds: Option<u64>,
        /// Bytes the server received from the client.
        received: Option<u64>,
        /// Bytes the server sent to the client.
        sent: Option<u64>,
    },
    /// ocserv refused a sign-in.
    SignInFailed { user: String, from: Option<String> },
    /// ocserv banned an address.
    Banned { address: String, score: u64 },
    /// The location checks refused a VPN sign-in.
    LocationRefused {
        user: String,
        from: String,
        /// What the sign-in scored, 0 to 100.
        score: u32,
        /// Why it scored, in words.
        reasons: Vec<String>,
    },
    /// The location checks let a VPN sign-in in and found it unusual.
    LocationFlagged {
        user: String,
        from: String,
        score: u32,
        reasons: Vec<String>,
    },
    /// The location check of a VPN sign-in could not run, so the client was
    /// let in.
    LocationUnchecked {
        user: String,
        from: Option<String>,
        /// Why it could not run.
        problem: String,
    },
}

impl What {
    /// The event ocserv's session script reports, from the variables ocserv
    /// sets for it; none for a REASON other than connect and disconnect.
    pub fn from_script(get: impl Fn(&str) -> Option<String>) -> Result<Option<What>, String> {
        let text = |name: &str| get(name).filter(|value| !value.is_empty());
        let number = |name: &str| -> Result<Option<u64>, String> {
            match text(name) {
                None => Ok(None),
                Some(value) => value
                    .parse()
                    .map(Some)
                    .map_err(|error| format!("{name} is not a whole number: '{value}': {error}")),
            }
        };
        let user = || text("USERNAME").ok_or_else(|| "USERNAME is not set".to_owned());
        match text("REASON").as_deref() {
            Some("connect") => Ok(Some(What::Connected {
                user: user()?,
                group: text("GROUPNAME"),
                session: number("ID")?,
                from: text("IP_REAL"),
                vpn_ipv4: text("IP_REMOTE").filter(|address| !address.contains(':')),
                vpn_ipv6: text("IPV6_REMOTE"),
                client: text("USER_AGENT"),
            })),
            Some("disconnect") => Ok(Some(What::Disconnected {
                user: user()?,
                session: number("ID")?,
                from: text("IP_REAL"),
                seconds: number("STATS_DURATION")?,
                received: number("STATS_BYTES_IN")?,
                sent: number("STATS_BYTES_OUT")?,
            })),
            Some(_) | None => Ok(None),
        }
    }

    /// The event a line of ocserv's log reports, if any: a refused sign-in,
    /// which a worker logs as `worker[NAME]: ADDRESS FILE:LINE: failed
    /// authentication for 'NAME'`, or a ban, which the main process logs as
    /// `main: added IP 'ADDRESS' (with score N) to ban list, ...`. A line that
    /// starts like one of them but does not finish like it is an error.
    pub fn from_log_line(line: &str) -> Result<Option<What>, String> {
        const FAILED: &str = "failed authentication for '";
        const BANNED: &str = "added IP '";
        const SCORE: &str = "' (with score ";
        let line = line.trim_end();
        if line.starts_with("worker")
            && let Some(at) = line.find(FAILED)
        {
            let user = line[at + FAILED.len()..]
                .strip_suffix('\'')
                .ok_or_else(|| format!("a failed sign-in line ends without its quote: {line}"))?;
            let from = line
                .split_once(": ")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .filter(|address| address.parse::<IpAddr>().is_ok())
                .map(str::to_owned);
            return Ok(Some(What::SignInFailed {
                user: user.to_owned(),
                from,
            }));
        }
        if line.starts_with("main")
            && let Some(at) = line.find(BANNED)
        {
            let malformed = || format!("a ban line is not in the form ocserv writes: {line}");
            let (address, rest) = line[at + BANNED.len()..]
                .split_once(SCORE)
                .ok_or_else(malformed)?;
            let (score, _) = rest.split_once(')').ok_or_else(malformed)?;
            let score = score
                .parse()
                .map_err(|error| format!("{}: {error}", malformed()))?;
            return Ok(Some(What::Banned {
                address: address.to_owned(),
                score,
            }));
        }
        Ok(None)
    }
}

/// The spool directory PANEL_EVENTS_DIR names, which must be absolute.
pub fn spool_dir(get: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf, String> {
    let value = get(SPOOL_VARIABLE).ok_or_else(|| format!("{SPOOL_VARIABLE} is not set"))?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!(
            "{SPOOL_VARIABLE} must be an absolute path, not {}",
            path.display()
        ));
    }
    Ok(path)
}

/// The spool directory, where producers leave events and the helper picks
/// them up.
pub struct Spool {
    dir: PathBuf,
}

/// What reading the spool found.
#[cfg(any(unix, test))]
#[derive(Debug, Default)]
pub struct Drained {
    /// The events, oldest first.
    pub events: Vec<Event>,
    /// Files that could not be read, parsed or removed, and why.
    pub problems: Vec<String>,
}

impl Spool {
    pub fn new(dir: PathBuf) -> Spool {
        Spool { dir }
    }

    /// Writes `event` as a file of its own, named so that the files sort in
    /// the order they were written: the event's time, the writing process,
    /// and `sequence`, which a process writing several events counts up.
    pub fn write(&self, event: &Event, sequence: u64) -> Result<(), String> {
        let json = serde_json::to_vec(event)
            .map_err(|error| format!("an event could not be encoded: {error}"))?;
        let name = format!(
            "{:020}-{:010}-{sequence:010}.json",
            event.time,
            std::process::id()
        );
        files::write_private(&self.dir.join(name), &json)
    }

    /// Reads every event file, oldest first, and removes it. A file that is
    /// not an event is removed too and named in the problems; a file still
    /// being written, whose name ends in `.tmp`, is left for the next time.
    #[cfg(any(unix, test))]
    pub fn drain(&self) -> Drained {
        let mut drained = Drained::default();
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) => {
                drained
                    .problems
                    .push(format!("{}: {error}", self.dir.display()));
                return drained;
            }
        };
        let mut names = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => names.push(entry.file_name()),
                Err(error) => drained
                    .problems
                    .push(format!("an entry of {}: {error}", self.dir.display())),
            }
        }
        names.retain(|name| Path::new(name).extension().is_some_and(|ext| ext == "json"));
        names.sort();
        for name in names {
            let path = self.dir.join(&name);
            match fs::read(&path) {
                Ok(bytes) => match serde_json::from_slice::<Event>(&bytes) {
                    Ok(event) => drained.events.push(event),
                    Err(error) => drained.problems.push(format!(
                        "{} is not an event and was removed: {error}",
                        path.display()
                    )),
                },
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => {
                    drained
                        .problems
                        .push(format!("{}: {error}", path.display()));
                    continue;
                }
            }
            if let Err(error) = fs::remove_file(&path) {
                drained
                    .problems
                    .push(format!("{} could not be removed: {error}", path.display()));
            }
        }
        drained
    }
}

/// Copies ocserv's log from `input` to `output` line by line, exactly as
/// written, and leaves each failed sign-in and ban it reports in `spool`,
/// stamped with `now`. Ends at the end of the input. An output that cannot
/// be written ends it with an error, since ocserv must not run without its
/// log; an event that cannot be recorded is reported on the output.
pub fn relay(
    input: &mut impl BufRead,
    output: &mut impl Write,
    spool: &Spool,
    now: impl Fn() -> Result<u64, String>,
) -> Result<(), String> {
    let mut line = Vec::new();
    let mut sequence = 0u64;
    loop {
        line.clear();
        let read = input
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("ocserv's log could not be read: {error}"))?;
        if read == 0 {
            return Ok(());
        }
        output
            .write_all(&line)
            .and_then(|()| output.flush())
            .map_err(|error| format!("the container log could not be written: {error}"))?;
        let recorded = match What::from_log_line(&String::from_utf8_lossy(&line)) {
            Ok(Some(what)) => now().and_then(|time| {
                sequence += 1;
                spool.write(&Event { time, what }, sequence)
            }),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        };
        if let Err(error) = recorded {
            output
                .write_all(
                    format!("ocpanel log-relay: an event was not recorded: {error}\n").as_bytes(),
                )
                .and_then(|()| output.flush())
                .map_err(|error| format!("the container log could not be written: {error}"))?;
        }
    }
}

/// An event as the helper keeps it: numbered in the order it arrived, and,
/// for a failed sign-in, why it failed when the user file tells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Logged {
    pub number: u64,
    pub event: Event,
    pub reason: Option<String>,
}

/// The events of the last `keep` seconds.
pub struct EventLog {
    keep: u64,
    events: VecDeque<Logged>,
    next: u64,
}

impl EventLog {
    /// A log keeping `hours` of events.
    pub fn new(hours: u64) -> EventLog {
        EventLog {
            keep: hours.saturating_mul(3600),
            events: VecDeque::new(),
            next: 1,
        }
    }

    /// The log's retention, in hours.
    pub fn hours(&self) -> u64 {
        self.keep / 3600
    }

    pub fn add(&mut self, event: Event, reason: Option<String>) {
        self.events.push_back(Logged {
            number: self.next,
            event,
            reason,
        });
        self.next += 1;
    }

    /// Drops the events older than the log keeps at `now`.
    pub fn prune(&mut self, now: u64) {
        let oldest = now.saturating_sub(self.keep);
        self.events.retain(|logged| logged.event.time >= oldest);
    }

    /// The events numbered after `after`, or all of them, oldest first.
    pub fn after(&self, after: Option<u64>) -> Vec<Logged> {
        self.events
            .iter()
            .filter(|logged| after.is_none_or(|number| logged.number > number))
            .cloned()
            .collect()
    }

    /// Every event kept, oldest first.
    pub fn kept(&self) -> impl Iterator<Item = &Logged> {
        self.events.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::collections::HashMap;
    use std::io::Cursor;

    fn script(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn a_connect_is_read_from_the_script_variables() {
        let what = What::from_script(script(&[
            ("REASON", "connect"),
            ("USERNAME", "alex"),
            ("GROUPNAME", ""),
            ("ID", "245"),
            ("IP_REAL", "203.0.113.20"),
            ("IP_REMOTE", "192.168.255.2"),
            ("USER_AGENT", "Open AnyConnect VPN Agent v9.12"),
        ]))
        .unwrap();
        assert_eq!(
            what,
            Some(What::Connected {
                user: "alex".to_owned(),
                group: None,
                session: Some(245),
                from: Some("203.0.113.20".to_owned()),
                vpn_ipv4: Some("192.168.255.2".to_owned()),
                vpn_ipv6: None,
                client: Some("Open AnyConnect VPN Agent v9.12".to_owned()),
            })
        );
    }

    #[test]
    fn a_disconnect_carries_its_statistics() {
        let what = What::from_script(script(&[
            ("REASON", "disconnect"),
            ("USERNAME", "sam"),
            ("ID", "246"),
            ("STATS_DURATION", "7380"),
            ("STATS_BYTES_IN", "3120554"),
            ("STATS_BYTES_OUT", "18220901"),
        ]))
        .unwrap();
        assert_eq!(
            what,
            Some(What::Disconnected {
                user: "sam".to_owned(),
                session: Some(246),
                from: None,
                seconds: Some(7380),
                received: Some(3_120_554),
                sent: Some(18_220_901),
            })
        );
    }

    #[test]
    fn other_script_reasons_are_not_events_and_bad_numbers_are_errors() {
        assert_eq!(
            What::from_script(script(&[("REASON", "host-update"), ("USERNAME", "a")])).unwrap(),
            None
        );
        assert!(
            What::from_script(script(&[
                ("REASON", "connect"),
                ("USERNAME", "a"),
                ("ID", "x")
            ]))
            .is_err()
        );
        assert!(What::from_script(script(&[("REASON", "connect")])).is_err());
    }

    #[test]
    fn failed_sign_ins_and_bans_are_read_from_the_log() {
        assert_eq!(
            What::from_log_line(
                "worker[jo]: 203.0.113.9 worker-auth.c:2251: failed authentication for 'jo'\n"
            )
            .unwrap(),
            Some(What::SignInFailed {
                user: "jo".to_owned(),
                from: Some("203.0.113.9".to_owned()),
            })
        );
        assert_eq!(
            What::from_log_line(
                "worker: 2001:db8::7 worker-auth.c:2251: failed authentication for ''"
            )
            .unwrap(),
            Some(What::SignInFailed {
                user: String::new(),
                from: Some("2001:db8::7".to_owned()),
            })
        );
        assert_eq!(
            What::from_log_line(
                "main: added IP '203.0.113.250' (with score 92) to ban list, will be reset at: \
                 Thu Nov 26 06:31:58 2026"
            )
            .unwrap(),
            Some(What::Banned {
                address: "203.0.113.250".to_owned(),
                score: 92,
            })
        );
    }

    #[test]
    fn other_log_lines_are_not_events_and_broken_ones_are_errors() {
        for line in [
            "main[jo]:203.0.113.9:51234 user logged in",
            "worker: 203.0.113.9 failed cookie authentication attempt",
            "note: the line mentions failed authentication for 'x' but is not a worker's",
            "",
        ] {
            assert_eq!(What::from_log_line(line).unwrap(), None, "{line}");
        }
        assert!(What::from_log_line("main: added IP '1.2.3.4' to ban list").is_err());
        assert!(What::from_log_line("main: added IP '1.2.3.4' (with score lots) ...").is_err());
        assert!(What::from_log_line("worker: 1.2.3.4 failed authentication for 'jo").is_err());
    }

    #[test]
    fn the_relay_copies_every_line_and_spools_the_events() {
        let dir = TestDir::new();
        let spool = Spool::new(dir.path().to_path_buf());
        let log = "ocserv started\n\
                   worker[jo]: 203.0.113.9 worker-auth.c:2251: failed authentication for 'jo'\n\
                   main: added IP 'broken (with score\n\
                   main: added IP '203.0.113.9' (with score 80) to ban list, will be reset at: x\n\
                   a last line without an end";
        let mut output = Vec::new();
        relay(&mut Cursor::new(log), &mut output, &spool, || {
            Ok(1_795_669_200)
        })
        .unwrap();
        let written = String::from_utf8(output).unwrap();
        let (warnings, copied): (Vec<&str>, Vec<&str>) = written
            .lines()
            .partition(|line| line.starts_with("ocpanel log-relay:"));
        assert_eq!(copied, log.lines().collect::<Vec<_>>());
        assert_eq!(warnings.len(), 1, "{written}");
        assert!(written.ends_with("a last line without an end"), "{written}");
        let drained = spool.drain();
        assert!(drained.problems.is_empty(), "{:?}", drained.problems);
        let kinds: Vec<&What> = drained.events.iter().map(|event| &event.what).collect();
        assert!(matches!(
            kinds[..],
            [What::SignInFailed { .. }, What::Banned { score: 80, .. }]
        ));
        assert!(spool.drain().events.is_empty());
    }

    #[test]
    fn the_spool_is_drained_in_order_and_bad_files_are_reported() {
        let dir = TestDir::new();
        let spool = Spool::new(dir.path().to_path_buf());
        let banned = |time, score| Event {
            time,
            what: What::Banned {
                address: "192.0.2.1".to_owned(),
                score,
            },
        };
        spool.write(&banned(20, 2), 1).unwrap();
        spool.write(&banned(10, 1), 2).unwrap();
        fs::write(dir.path().join("00000000000000000015-x.json"), b"not json").unwrap();
        fs::write(dir.path().join("00000000000000000016-x.json.tmp"), b"half").unwrap();
        let drained = spool.drain();
        assert_eq!(drained.events, [banned(10, 1), banned(20, 2)]);
        assert_eq!(drained.problems.len(), 1, "{:?}", drained.problems);
        assert!(dir.path().join("00000000000000000016-x.json.tmp").exists());
        assert!(spool.drain().events.is_empty());
    }

    #[test]
    fn the_log_keeps_its_hours_and_numbers_events_in_order() {
        let mut log = EventLog::new(1);
        let at = |time| Event {
            time,
            what: What::SignInFailed {
                user: "jo".to_owned(),
                from: None,
            },
        };
        log.add(at(100), None);
        log.add(at(4000), Some("the account is locked".to_owned()));
        log.prune(3800);
        let kept = log.after(None);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].number, 2);
        assert_eq!(kept[0].reason.as_deref(), Some("the account is locked"));
        log.add(at(4100), None);
        assert_eq!(log.after(Some(2)).len(), 1);
    }

    #[test]
    fn the_spool_directory_must_be_absolute() {
        let get = |value: &'static str| move |_: &str| Some(OsString::from(value));
        assert!(spool_dir(get("relative/events")).is_err());
        assert!(spool_dir(|_: &str| None).is_err());
        let absolute = if cfg!(windows) {
            r"C:\run\events"
        } else {
            "/run/events"
        };
        assert_eq!(spool_dir(get(absolute)).unwrap(), PathBuf::from(absolute));
    }
}
