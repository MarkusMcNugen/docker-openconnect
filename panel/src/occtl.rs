//! The VPN server's state and the actions on it, through ocserv's control
//! tool: `occtl --json show status`, `show users`, `show ip bans` and
//! `show ip ban points`, and `terminate` and `unban ip`.
//! The parsing follows occtl's own printers: integers bare, byte counts as
//! quoted decimals, and a string field whose value is empty left out
//! entirely. A field occtl always prints is required here; one it can leave
//! out is an Option.

use serde::{Deserialize, Serialize};
#[cfg(any(unix, test))]
use serde_json::{Map, Value};

/// The server, as `occtl show status` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Status {
    /// occtl could not reach the server.
    Offline,
    Online {
        /// When the server started, in Unix seconds.
        up_since: u64,
        active_sessions: u64,
        /// Sessions closed in the current statistics period.
        total_sessions: u64,
        auth_failures: u64,
        banned_addresses: u64,
    },
}

/// One connected VPN session, as `occtl show users` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id: u64,
    pub user: String,
    pub group: Option<String>,
    pub state: String,
    /// The address the client connected from.
    pub remote_ip: Option<String>,
    pub vpn_ipv4: Option<String>,
    pub vpn_ipv6: Option<String>,
    pub user_agent: Option<String>,
    pub hostname: Option<String>,
    /// When the client connected, in Unix seconds.
    pub connected_at: u64,
    /// Bytes the server received from the client through the tunnel; none
    /// when occtl could not read the tunnel device.
    pub received: Option<u64>,
    /// Bytes the server sent to the client through the tunnel.
    pub sent: Option<u64>,
    /// Whether the session carries its traffic over UDP (DTLS) as well as TCP.
    pub udp: bool,
}

/// An address ocserv has banned, as `occtl show ip bans` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ban {
    /// An IPv4 address, or the first address of a banned IPv6 /64.
    pub address: String,
    pub score: u64,
    /// Seconds until the ban lifts: exact below an hour, to the minute below
    /// two days, to the day beyond; none when occtl could not tell.
    pub lifts_in: Option<u64>,
}

/// An address with ban points, banned or not, as `occtl show ip ban points`
/// reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanPoints {
    pub address: String,
    pub score: u64,
}

/// What occtl prints for a session without a group.
#[cfg(any(unix, test))]
const NO_GROUP: &str = "(none)";

/// Reads `occtl --json show status`. A server occtl cannot reach prints only
/// `"Status": "offline"`.
#[cfg(any(unix, test))]
pub fn parse_status(json: &str) -> Result<Status, String> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| format!("occtl's status is not JSON: {error}"))?;
    let fields = object(&value, "status")?;
    match required_text(fields, "Status")?.as_str() {
        "online" => Ok(Status::Online {
            up_since: required_number(fields, "raw_up_since")?,
            active_sessions: required_number(fields, "Active sessions")?,
            total_sessions: required_number(fields, "Total sessions")?,
            auth_failures: required_number(fields, "Total authentication failures")?,
            banned_addresses: required_number(fields, "IPs in ban list")?,
        }),
        "offline" => Ok(Status::Offline),
        other => Err(format!("occtl reports an unknown server state '{other}'")),
    }
}

/// Reads `occtl --json show users`.
#[cfg(any(unix, test))]
pub fn parse_sessions(json: &str) -> Result<Vec<Session>, String> {
    records(json, "session list")?
        .iter()
        .map(|record| {
            let fields = object(record, "session")?;
            Ok(Session {
                id: required_number(fields, "ID")?,
                user: required_text(fields, "Username")?,
                group: text(fields, "Groupname")?.filter(|group| group != NO_GROUP),
                state: required_text(fields, "State")?,
                remote_ip: text(fields, "Remote IP")?,
                vpn_ipv4: text(fields, "IPv4")?,
                vpn_ipv6: text(fields, "IPv6")?,
                user_agent: text(fields, "User-Agent")?,
                hostname: text(fields, "Hostname")?,
                connected_at: required_number(fields, "raw_connected_at")?,
                received: number(fields, "RX")?,
                sent: number(fields, "TX")?,
                udp: text(fields, "DTLS cipher")?.is_some(),
            })
        })
        .collect()
}

/// Reads `occtl --json show ip bans`, which lists only the bans in force.
#[cfg(any(unix, test))]
pub fn parse_bans(json: &str) -> Result<Vec<Ban>, String> {
    records(json, "ban list")?
        .iter()
        .map(|record| {
            let fields = object(record, "ban")?;
            Ok(Ban {
                address: required_text(fields, "IP")?,
                score: required_number(fields, "Score")?,
                lifts_in: match text(fields, "_Since")? {
                    Some(left) => time_left(&left)?,
                    None => None,
                },
            })
        })
        .collect()
}

/// Reads `occtl --json show ip ban points`.
#[cfg(any(unix, test))]
pub fn parse_ban_points(json: &str) -> Result<Vec<BanPoints>, String> {
    records(json, "ban point list")?
        .iter()
        .map(|record| {
            let fields = object(record, "address with ban points")?;
            Ok(BanPoints {
                address: required_text(fields, "IP")?,
                score: required_number(fields, "Score")?,
            })
        })
        .collect()
}

/// The time left that occtl prints beside a ban's end, as print_time_ival7
/// writes it: "   42s", " 4m:12s", " 1h:05m" or " 3days". None for "?",
/// which it prints when the ban's end is already past.
#[cfg(any(unix, test))]
fn time_left(text: &str) -> Result<Option<u64>, String> {
    let text = text.trim();
    let bad = || format!("occtl printed a time left in a form it does not write: '{text}'");
    let count = |part: &str| {
        part.trim().parse::<u32>().map(u64::from).map_err(|error| {
            format!("occtl printed a time left that is not a count: '{text}': {error}")
        })
    };
    if text == "?" {
        return Ok(None);
    }
    if let Some(days) = text.strip_suffix("days") {
        return Ok(Some(count(days)? * 86_400));
    }
    if let Some((hours, minutes)) = text.split_once("h:") {
        let minutes = minutes.strip_suffix('m').ok_or_else(bad)?;
        return Ok(Some(count(hours)? * 3600 + count(minutes)? * 60));
    }
    if let Some((minutes, seconds)) = text.split_once("m:") {
        let seconds = seconds.strip_suffix('s').ok_or_else(bad)?;
        return Ok(Some(count(minutes)? * 60 + count(seconds)?));
    }
    match text.strip_suffix('s') {
        Some(seconds) => Ok(Some(count(seconds)?)),
        None => Err(bad()),
    }
}

/// The records of a JSON array occtl printed.
#[cfg(any(unix, test))]
fn records(json: &str, what: &str) -> Result<Vec<Value>, String> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| format!("occtl's {what} is not JSON: {error}"))?;
    let Value::Array(records) = value else {
        return Err(format!("occtl's {what} is not a JSON array"));
    };
    Ok(records)
}

#[cfg(any(unix, test))]
fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("occtl's {what} is not a JSON object: {value}"))
}

/// A string field; none when occtl left it out, which it does when empty.
#[cfg(any(unix, test))]
fn text(fields: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match fields.get(key) {
        None => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(format!("occtl's \"{key}\" is not a string: {other}")),
    }
}

#[cfg(any(unix, test))]
fn required_text(fields: &Map<String, Value>, key: &str) -> Result<String, String> {
    text(fields, key)?.ok_or_else(|| format!("occtl printed no \"{key}\""))
}

/// A whole number written bare or as a quoted decimal; none when occtl left
/// it out.
#[cfg(any(unix, test))]
fn number(fields: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    match fields.get(key) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("occtl's \"{key}\" is not a whole number: {value}")),
        Some(Value::String(value)) => value.parse().map(Some).map_err(|error| {
            format!("occtl's \"{key}\" is not a whole number: '{value}': {error}")
        }),
        Some(other) => Err(format!("occtl's \"{key}\" is not a number: {other}")),
    }
}

#[cfg(any(unix, test))]
fn required_number(fields: &Map<String, Value>, key: &str) -> Result<u64, String> {
    number(fields, key)?.ok_or_else(|| format!("occtl printed no \"{key}\""))
}

/// What the panel asks of the VPN server.
pub trait Control: Send {
    fn status(&mut self) -> Result<Status, String>;
    fn sessions(&mut self) -> Result<Vec<Session>, String>;
    /// Ends the session with `id` and invalidates its cookie, so the client
    /// must sign in again; false when no session has that ID.
    fn end_session(&mut self, id: u64) -> Result<bool, String>;
    /// Ends every session of `user` and invalidates their cookies; false
    /// when the user has none.
    fn end_user_sessions(&mut self, user: &str) -> Result<bool, String>;
    /// The bans in force.
    fn bans(&mut self) -> Result<Vec<Ban>, String>;
    /// Every address with ban points, banned or not.
    fn ban_points(&mut self) -> Result<Vec<BanPoints>, String>;
    /// Lifts the ban on `address` and clears its points; false when ocserv
    /// has no entry for it.
    fn unban(&mut self, address: &str) -> Result<bool, String>;
    /// Makes ocserv read its configuration file again; sessions stay.
    fn reload(&mut self) -> Result<(), String>;
}

/// A VPN server that answers from memory, for the tests and the
/// development server.
#[cfg(any(test, debug_assertions))]
pub struct Fake {
    pub up_since: u64,
    pub sessions: Vec<Session>,
    pub bans: Vec<Ban>,
    pub points: Vec<BanPoints>,
}

#[cfg(any(test, debug_assertions))]
impl Fake {
    /// A server up since `up_since` with two sessions, alex on a laptop over
    /// UDP and sam in the staff group over TCP only; two banned addresses,
    /// one of them an IPv6 network; and three more with ban points.
    pub fn sample(up_since: u64) -> Fake {
        let session = |id, user: &str, group: Option<&str>, remote: &str, vpn: &str| Session {
            id,
            user: user.to_owned(),
            group: group.map(str::to_owned),
            state: "connected".to_owned(),
            remote_ip: Some(remote.to_owned()),
            vpn_ipv4: Some(vpn.to_owned()),
            vpn_ipv6: None,
            user_agent: None,
            hostname: None,
            connected_at: up_since + 60,
            received: Some(0),
            sent: Some(0),
            udp: false,
        };
        let mut alex = session(245, "alex", None, "203.0.113.20", "192.168.255.2");
        alex.user_agent = Some("Open AnyConnect VPN Agent v9.12".to_owned());
        alex.hostname = Some("laptop".to_owned());
        alex.received = Some(48_211_337);
        alex.sent = Some(912_004_113);
        alex.udp = true;
        let mut sam = session(246, "sam", Some("staff"), "198.51.100.7", "192.168.255.3");
        sam.user_agent = Some("AnyConnect Windows 4.10.07073".to_owned());
        sam.connected_at = up_since + 7200;
        sam.received = Some(3_120_554);
        sam.sent = Some(18_220_901);
        let ban = |address: &str, score, lifts_in| Ban {
            address: address.to_owned(),
            score,
            lifts_in: Some(lifts_in),
        };
        let bans = vec![
            ban("203.0.113.250", 92, 4 * 60 + 12),
            ban("2001:db8:4:2::", 80, 8 * 60 + 40),
        ];
        let points = bans
            .iter()
            .map(|ban| (ban.address.as_str(), ban.score))
            .chain([
                ("192.0.2.77", 31),
                ("203.0.113.9", 22),
                ("198.51.100.23", 11),
            ])
            .map(|(address, score)| BanPoints {
                address: address.to_owned(),
                score,
            })
            .collect();
        Fake {
            up_since,
            sessions: vec![alex, sam],
            bans,
            points,
        }
    }
}

#[cfg(any(test, debug_assertions))]
impl Control for Fake {
    fn status(&mut self) -> Result<Status, String> {
        Ok(Status::Online {
            up_since: self.up_since,
            active_sessions: u64::try_from(self.sessions.len())
                .map_err(|error| format!("the session count does not fit: {error}"))?,
            total_sessions: 12,
            auth_failures: 1,
            banned_addresses: u64::try_from(self.bans.len())
                .map_err(|error| format!("the ban count does not fit: {error}"))?,
        })
    }

    fn sessions(&mut self) -> Result<Vec<Session>, String> {
        Ok(self.sessions.clone())
    }

    fn end_session(&mut self, id: u64) -> Result<bool, String> {
        let before = self.sessions.len();
        self.sessions.retain(|session| session.id != id);
        Ok(self.sessions.len() < before)
    }

    fn end_user_sessions(&mut self, user: &str) -> Result<bool, String> {
        let before = self.sessions.len();
        self.sessions.retain(|session| session.user != user);
        Ok(self.sessions.len() < before)
    }

    fn bans(&mut self) -> Result<Vec<Ban>, String> {
        Ok(self.bans.clone())
    }

    fn ban_points(&mut self) -> Result<Vec<BanPoints>, String> {
        Ok(self.points.clone())
    }

    /// Like ocserv, keeps the address's entry with no points.
    fn unban(&mut self, address: &str) -> Result<bool, String> {
        self.bans.retain(|ban| ban.address != address);
        match self
            .points
            .iter_mut()
            .find(|entry| entry.address == address)
        {
            Some(entry) => {
                entry.score = 0;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn reload(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(unix)]
pub use runner::Occtl;

#[cfg(unix)]
mod runner {
    use super::{
        Ban, BanPoints, Control, Session, Status, parse_ban_points, parse_bans, parse_sessions,
        parse_status,
    };
    use crate::command::{self, Ran};

    /// ocserv's control tool, run as the helper's own child.
    pub struct Occtl;

    fn occtl(args: &[&str]) -> Result<Ran, String> {
        command::run("occtl", args, &[])
    }

    /// The outcome of a terminate command: true when it ended something,
    /// false when occtl found nothing to end.
    fn terminated(ran: &Ran, what: &str) -> Result<bool, String> {
        if ran.status.success() {
            return Ok(true);
        }
        if ran.stdout.contains("could not terminate") {
            return Ok(false);
        }
        Err(ran.failed(what))
    }

    impl Control for Occtl {
        fn status(&mut self) -> Result<Status, String> {
            let ran = occtl(&["--json", "show", "status"])?;
            parse_status(&ran.stdout).map_err(|error| ran.failed(&error))
        }

        fn sessions(&mut self) -> Result<Vec<Session>, String> {
            let ran = occtl(&["--json", "show", "users"])?;
            if !ran.status.success() {
                return Err(ran.failed("occtl could not list the sessions"));
            }
            parse_sessions(&ran.stdout).map_err(|error| ran.failed(&error))
        }

        fn end_session(&mut self, id: u64) -> Result<bool, String> {
            let id = id.to_string();
            let ran = occtl(&["terminate", "id", &id])?;
            terminated(&ran, "occtl could not end the session")
        }

        fn end_user_sessions(&mut self, user: &str) -> Result<bool, String> {
            let ran = occtl(&["terminate", "user", user])?;
            terminated(&ran, "occtl could not end the user's sessions")
        }

        fn bans(&mut self) -> Result<Vec<Ban>, String> {
            let ran = occtl(&["--json", "show", "ip", "bans"])?;
            if !ran.status.success() {
                return Err(ran.failed("occtl could not list the bans"));
            }
            parse_bans(&ran.stdout).map_err(|error| ran.failed(&error))
        }

        fn ban_points(&mut self) -> Result<Vec<BanPoints>, String> {
            let ran = occtl(&["--json", "show", "ip", "ban", "points"])?;
            if !ran.status.success() {
                return Err(ran.failed("occtl could not list the addresses with ban points"));
            }
            parse_ban_points(&ran.stdout).map_err(|error| ran.failed(&error))
        }

        fn unban(&mut self, address: &str) -> Result<bool, String> {
            let ran = occtl(&["unban", "ip", address])?;
            if ran.status.success() {
                return Ok(true);
            }
            if ran.stdout.contains("could not unban") {
                return Ok(false);
            }
            Err(ran.failed("occtl could not lift the ban"))
        }

        fn reload(&mut self) -> Result<(), String> {
            let ran = occtl(&["reload"])?;
            if ran.status.success() {
                return Ok(());
            }
            Err(ran.failed("occtl could not reload the server"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Session records as occtl's common_info_cmd prints them: the first in
    /// full, with an empty route list followed by the "defaultroute" string
    /// under the same key; the second with the fields occtl leaves out when
    /// they are empty or the tunnel device cannot be read.
    const USERS: &str = r#"[
  {
    "ID":  245,
    "Username":  "alex",
    "Groupname":  "(none)",
    "State":  "connected",
    "vhost":  "default",
    "Device":  "vpns0",
    "MTU":  "1434",
    "Remote IP":  "203.0.113.20",
    "Location":  "unknown",
    "Local Device IP":  "172.17.0.2",
    "IPv4":  "192.168.255.2",
    "P-t-P IPv4":  "192.168.255.1",
    "User-Agent":  "Open AnyConnect VPN Agent v9.12",
    "RX":  "421337",
    "TX":  "9002313",
    "_RX":  "421.3 KB",
    "_TX":  "9.0 MB",
    "Average RX":  "1.4 KB/sec",
    "Average TX":  "30.0 KB/sec",
    "DPD":  "90",
    "KeepAlive":  "32400",
    "Hostname":  "laptop",
    "Last connected at":  "2026-11-26 05:00",
    "_Last connected at":  " 5m:01s",
    "Session started at":  "2026-11-26 05:00",
    "_Session started at":  " 5m:01s",
    "raw_connected_at":  1795669200,
    "raw_session_started_at":  1795669200,
    "Full session":  "4dBd3Rk1",
    "Session":  "4dBd3R",
    "TLS ciphersuite":  "(TLS1.3)-(ECDHE-SECP256R1)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)",
    "DTLS cipher":  "(DTLS1.2)-(ECDHE-RSA)-(AES-256-GCM)",
    "DNS":	["9.9.9.9", "1.1.1.1"],
    "NBNS":	[],
    "Split-DNS-Domains":	[],
    "Routes":	[],
    "Routes":  "defaultroute",
    "No-routes":	[],
    "iRoutes":	[],
    "Restricted to routes":  "False",
    "Restricted to ports":	[]
  },

  {
    "ID":  246,
    "Username":  "sam",
    "Groupname":  "staff",
    "State":  "connected",
    "IPv6":  "fd3e:7a0c:5b19::2",
    "P-t-P IPv6":  "fd3e:7a0c:5b19::1",
    "raw_connected_at":  1795669260,
    "Restricted to ports":	[]
  }
]
"#;

    #[test]
    fn sessions_are_read_from_occtl_records() {
        let sessions = parse_sessions(USERS).unwrap();
        assert_eq!(
            sessions[0],
            Session {
                id: 245,
                user: "alex".to_owned(),
                group: None,
                state: "connected".to_owned(),
                remote_ip: Some("203.0.113.20".to_owned()),
                vpn_ipv4: Some("192.168.255.2".to_owned()),
                vpn_ipv6: None,
                user_agent: Some("Open AnyConnect VPN Agent v9.12".to_owned()),
                hostname: Some("laptop".to_owned()),
                connected_at: 1_795_669_200,
                received: Some(421_337),
                sent: Some(9_002_313),
                udp: true,
            }
        );
        let sam = &sessions[1];
        assert_eq!(sam.group.as_deref(), Some("staff"));
        assert_eq!(sam.vpn_ipv6.as_deref(), Some("fd3e:7a0c:5b19::2"));
        assert_eq!(
            (sam.remote_ip.as_deref(), sam.received, sam.sent),
            (None, None, None)
        );
        assert!(!sam.udp);
    }

    #[test]
    fn no_sessions_is_an_empty_array() {
        assert_eq!(parse_sessions("[\n]\n").unwrap(), Vec::new());
    }

    #[test]
    fn a_session_missing_what_occtl_always_prints_is_an_error() {
        assert!(parse_sessions(r#"[{"Username": "alex", "State": "connected"}]"#).is_err());
        let malformed = r#"[{"ID": 1, "Username": "a", "State": "connected",
            "raw_connected_at": 1, "RX": "lots"}]"#;
        assert!(parse_sessions(malformed).is_err());
        assert!(parse_sessions(r#"{"ID": 1}"#).is_err());
        assert!(parse_sessions("[{").is_err());
    }

    #[test]
    fn the_status_of_a_running_server() {
        let json = r#"{
    "Status":  "online",
    "Server PID":  12,
    "Sec-mod PID":  13,
    "Sec-mod instance count":  1,
    "Up since":  "2026-11-26 04:50",
    "_Up since":  "15m:12s",
    "raw_up_since":  1795668600,
    "uptime":  912,
    "Active sessions":  2,
    "Total sessions":  7,
    "Total authentication failures":  3,
    "IPs in ban list":  1,
    "Sessions handled":  7,
    "RX":  "1.2 MB",
    "raw_rx":  1200000,
    "TX":  "9.0 MB",
    "raw_tx":  9000000
  }
"#;
        assert_eq!(
            parse_status(json).unwrap(),
            Status::Online {
                up_since: 1_795_668_600,
                active_sessions: 2,
                total_sessions: 7,
                auth_failures: 3,
                banned_addresses: 1,
            }
        );
    }

    #[test]
    fn a_server_occtl_cannot_reach_is_offline() {
        assert_eq!(
            parse_status("{\n    \"Status\":  \"offline\"\n  }\n").unwrap(),
            Status::Offline
        );
    }

    #[test]
    fn a_running_server_missing_a_count_is_an_error() {
        let json = r#"{"Status": "online", "raw_up_since": 1, "Active sessions": 2}"#;
        assert!(parse_status(json).is_err());
        assert!(parse_status(r#"{"Status": "starting"}"#).is_err());
    }

    /// Bans as handle_list_banned_cmd prints them: "Since" is the ban's end
    /// in local time, and "_Since" the time left.
    const BANS: &str = r#"[
  {
    "IP":  "203.0.113.250",
    "Since":  "2026-11-26 06:31",
    "_Since":  " 4m:12s",
    "Score":  92
  },
  {
    "IP":  "2001:db8:4:2::",
    "Since":  "2026-11-26 08:20",
    "_Since":  " 1h:53m",
    "Score":  80
  }
]
"#;

    #[test]
    fn bans_are_read_with_the_time_left() {
        assert_eq!(
            parse_bans(BANS).unwrap(),
            [
                Ban {
                    address: "203.0.113.250".to_owned(),
                    score: 92,
                    lifts_in: Some(252),
                },
                Ban {
                    address: "2001:db8:4:2::".to_owned(),
                    score: 80,
                    lifts_in: Some(3600 + 53 * 60),
                },
            ]
        );
        assert_eq!(parse_bans("[\n]\n").unwrap(), Vec::new());
    }

    #[test]
    fn ban_points_are_read() {
        let json = r#"[
  {
    "IP":  "192.0.2.77",
    "Score":  31
  }
]
"#;
        assert_eq!(
            parse_ban_points(json).unwrap(),
            [BanPoints {
                address: "192.0.2.77".to_owned(),
                score: 31,
            }]
        );
        assert!(parse_ban_points(r#"[{"IP": "192.0.2.77"}]"#).is_err());
    }

    #[test]
    fn the_time_left_is_read_in_every_form_occtl_writes() {
        assert_eq!(time_left("   42s").unwrap(), Some(42));
        assert_eq!(time_left(" 4m:07s").unwrap(), Some(247));
        assert_eq!(time_left(" 2h:05m").unwrap(), Some(2 * 3600 + 300));
        assert_eq!(time_left(" 3days").unwrap(), Some(3 * 86_400));
        assert_eq!(time_left("   ?   ").unwrap(), None);
        for bad in ["", "soon", "4m:07", "2h:05", "xs", "99999999999s"] {
            assert!(time_left(bad).is_err(), "{bad:?}");
        }
    }
}
