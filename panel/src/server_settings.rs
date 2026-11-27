//! The server settings an owner may change on the Settings page. The
//! entrypoint reads them from the panel's settings file beneath the
//! environment, so a setting the environment gives is never the panel's,
//! and at every start it records where each setting came from. The helper
//! checks a value with the rules the entrypoint applies before storing it.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::files;
use crate::net::Network;
use crate::serverconf::ServerConfig;

/// What a setting holds, which decides how its value is checked and how
/// the page asks for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `true` or `false`.
    Switch,
    /// A whole number of the unit named: a unit symbol for a measure, as
    /// "s", or a noun for a count, as "clients".
    Number(&'static str),
    /// A bandwidth limit, typed in Mbps and stored in bytes per second, the
    /// variable's own unit.
    Rate,
    /// One line of text without double quotes or backslashes.
    Text,
    /// IP addresses separated by commas; at least one.
    Addresses,
    /// Domain names separated by commas.
    Domains,
    /// Domain names separated by spaces.
    SearchDomains,
    /// Networks separated by commas, as `address/prefix` or
    /// `address/netmask`.
    Routes,
    /// One of the values listed.
    /// One of the values listed, each with the label the page shows.
    Choice(&'static [(&'static str, &'static str)]),
}

/// A setting the Settings page offers: the variable the entrypoint reads,
/// what it holds, the section of the page and its label there.
pub struct Spec {
    pub name: &'static str,
    pub kind: Kind,
    pub section: &'static str,
    pub label: &'static str,
}

const fn spec(name: &'static str, kind: Kind, section: &'static str, label: &'static str) -> Spec {
    Spec {
        name,
        kind,
        section,
        label,
    }
}

const SECONDS: Kind = Kind::Number("s");

/// The settings in the order the page shows them; the same variables as
/// PANEL_SETTINGS in the entrypoint's settings.sh.
pub const SPECS: &[Spec] = &[
    spec("DNS_SERVERS", Kind::Addresses, "DNS", "DNS servers"),
    spec(
        "SPLIT_DNS_DOMAINS",
        Kind::Domains,
        "DNS",
        "Domains resolved through the VPN only",
    ),
    spec(
        "DEFAULT_DOMAIN",
        Kind::SearchDomains,
        "DNS",
        "Search domains",
    ),
    spec(
        "TUNNEL_ALL_DNS",
        Kind::Switch,
        "DNS",
        "Send every DNS query through the tunnel",
    ),
    spec("BANNER", Kind::Text, "Messages", "Message after connecting"),
    spec(
        "PRE_LOGIN_BANNER",
        Kind::Text,
        "Messages",
        "Message before signing in",
    ),
    spec(
        "MAX_CLIENTS",
        Kind::Number("clients"),
        "Connections",
        "Most clients at once",
    ),
    spec(
        "MAX_SAME_CLIENTS",
        Kind::Number("sessions"),
        "Connections",
        "Most sessions per user",
    ),
    spec(
        "IDLE_TIMEOUT",
        SECONDS,
        "Connections",
        "Disconnect after idle",
    ),
    spec(
        "MOBILE_IDLE_TIMEOUT",
        SECONDS,
        "Connections",
        "Disconnect phones after idle",
    ),
    spec("SESSION_TIMEOUT", SECONDS, "Connections", "Longest session"),
    spec("AUTH_TIMEOUT", SECONDS, "Connections", "Time to sign in"),
    spec(
        "COOKIE_TIMEOUT",
        SECONDS,
        "Connections",
        "Time to reconnect without signing in",
    ),
    spec("KEEPALIVE", SECONDS, "Connections", "Keepalive"),
    spec("DPD", SECONDS, "Connections", "Dead peer detection"),
    spec(
        "MOBILE_DPD",
        SECONDS,
        "Connections",
        "Dead peer detection for phones",
    ),
    spec(
        "SWITCH_TO_TCP_TIMEOUT",
        SECONDS,
        "Connections",
        "Fall back to TCP after UDP is silent",
    ),
    spec("MTU", Kind::Number("B"), "Connections", "MTU"),
    spec(
        "RX_DATA_PER_SEC",
        Kind::Rate,
        "Connections",
        "Upload limit per user",
    ),
    spec(
        "TX_DATA_PER_SEC",
        Kind::Rate,
        "Connections",
        "Download limit per user",
    ),
    spec(
        "MAX_BAN_SCORE",
        Kind::Number("points"),
        "Bans",
        "Ban an address at",
    ),
    spec("BAN_TIME", SECONDS, "Bans", "Ban for"),
    spec("BAN_RESET_TIME", SECONDS, "Bans", "Forget points after"),
    spec(
        "BAN_POINTS_WRONG_PASSWORD",
        Kind::Number("points"),
        "Bans",
        "Points for a wrong password",
    ),
    spec(
        "RATE_LIMIT_MS",
        Kind::Number("ms"),
        "Bans",
        "Accept a new connection every",
    ),
    spec(
        "PROXY_PROTOCOL",
        Kind::Switch,
        "Load balancer",
        "PROXY protocol from a load balancer",
    ),
    spec(
        "SERVER_DRAIN_MS",
        Kind::Number("ms"),
        "Load balancer",
        "On stop, refuse new connections and wait",
    ),
    spec(
        "AUTH_MODE",
        Kind::Choice(&[
            ("password", "Password"),
            ("certificate", "Certificate"),
            ("both", "Password and certificate"),
            ("either", "Password or certificate"),
        ]),
        "Sign-in",
        "How VPN users sign in",
    ),
    spec(
        "DTLS",
        Kind::Switch,
        "Tunnel and firewall",
        "UDP channel (DTLS)",
    ),
    spec(
        "TUNNEL_MODE",
        Kind::Choice(&[
            ("all", "Every network"),
            ("split-include", "Only the listed networks"),
        ]),
        "Tunnel and firewall",
        "Tunnel mode",
    ),
    spec(
        "TUNNEL_ROUTES",
        Kind::Routes,
        "Tunnel and firewall",
        "Networks through the tunnel",
    ),
    spec(
        "NO_ROUTES",
        Kind::Routes,
        "Tunnel and firewall",
        "Networks kept out of the tunnel",
    ),
    spec(
        "RESTRICT_TO_ROUTES",
        Kind::Choice(&[
            ("auto", "Automatic"),
            ("true", "Always"),
            ("false", "Never"),
        ]),
        "Tunnel and firewall",
        "Hold clients to their routes",
    ),
    spec(
        "NAT",
        Kind::Switch,
        "Tunnel and firewall",
        "Translate client addresses (NAT)",
    ),
    spec(
        "CLIENT_TO_CLIENT",
        Kind::Switch,
        "Tunnel and firewall",
        "Let clients reach each other",
    ),
    spec(
        "CISCO_COMPAT",
        Kind::Switch,
        "Tunnel and firewall",
        "Cisco client compatibility",
    ),
    spec(
        "LOG_LEVEL",
        Kind::Choice(&[
            ("0", "Default"),
            ("1", "Basic"),
            ("2", "Information"),
            ("3", "Debugging"),
            ("4", "HTTP"),
            ("8", "Sensitive data"),
            ("9", "TLS"),
        ]),
        "Tunnel and firewall",
        "Log level",
    ),
];

/// The setting named `name`, if the page offers it.
pub fn spec_of(name: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.name == name)
}

/// When a change reaches ocserv.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Apply {
    /// With a reload, while sessions stay.
    Reload,
    /// At the next container start.
    Start,
}

/// Where the value a setting has came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "by", rename_all = "snake_case")]
pub enum Source {
    Environment,
    Panel,
    Default,
    /// The file or OCSERV_CONF_* variable that sets the ocserv option the
    /// setting becomes.
    Override(String),
}

impl Source {
    /// Whether the panel may change the setting.
    pub fn is_open(&self) -> bool {
        matches!(self, Source::Panel | Source::Default)
    }
}

/// A setting as the server uses it and as the panel stored it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setting {
    pub name: String,
    pub apply: Apply,
    pub source: Source,
    /// The value the server uses; empty when the setting is unset or
    /// overridden.
    pub running: String,
    /// The value the panel stored, which waits for the next start when it
    /// differs from `running` and `apply` is `Start`.
    pub stored: Option<String>,
}

impl Setting {
    /// Whether the stored value waits for the next start.
    pub fn pending(&self) -> bool {
        self.apply == Apply::Start
            && match &self.stored {
                Some(stored) => *stored != self.running,
                None => self.source == Source::Panel,
            }
    }
}

/// One line of the state the entrypoint writes at start.
pub type StateLine = (String, Apply, Source, String);

/// The state the entrypoint wrote at start: one line per setting with its
/// name, when a change applies, its source and its value, separated by
/// tabs. None when there is no file, as when the server runs an operator's
/// own configuration file.
pub fn read_state(path: &Path) -> Result<Option<Vec<StateLine>>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let mut state = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<&str> = line.splitn(4, '\t').collect();
        let [name, apply, source, value] = fields[..] else {
            return Err(format!("{}: '{line}' has too few fields", path.display()));
        };
        let apply = match apply {
            "reload" => Apply::Reload,
            "start" => Apply::Start,
            other => {
                return Err(format!(
                    "{}: '{other}' is not reload or start",
                    path.display()
                ));
            }
        };
        let source = match source {
            "environment" => Source::Environment,
            "panel" => Source::Panel,
            "default" => Source::Default,
            other => Source::Override(other.to_owned()),
        };
        state.push((name.to_owned(), apply, source, value.to_owned()));
    }
    Ok(Some(state))
}

/// The values the panel stored, by setting.
pub fn read_stored(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let mut stored = BTreeMap::new();
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!("{}: '{line}' has no equals sign", path.display()));
        };
        if spec_of(name).is_none() {
            return Err(format!(
                "{}: {name} is not a setting the panel manages",
                path.display()
            ));
        }
        stored.insert(name.to_owned(), value.to_owned());
    }
    Ok(stored)
}

/// Replaces the stored values, readable by root only.
pub fn write_stored(path: &Path, stored: &BTreeMap<String, String>) -> Result<(), String> {
    let mut text =
        String::from("# Written by the admin panel; the environment wins over every line.\n");
    for (name, value) in stored {
        text.push_str(&format!("{name}={value}\n"));
    }
    files::write_private(path, text.as_bytes())
}

/// The value to store for `value` typed into the field of the setting
/// `spec`, in the form the entrypoint reads, or none for an empty field,
/// which returns the setting to its default.
pub fn check(spec: &Spec, value: &str) -> Result<Option<String>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let name = spec.name;
    let items: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect();
    let checked = match spec.kind {
        Kind::Switch => match value.to_ascii_lowercase().as_str() {
            "true" => "true".to_owned(),
            "false" => "false".to_owned(),
            _ => return Err(format!("{name} must be true or false")),
        },
        Kind::Number(_) => {
            if !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("{name} must be a whole number"));
            }
            value
                .parse::<u64>()
                .map_err(|error| format!("{name} must be a whole number: {error}"))?;
            value.to_owned()
        }
        Kind::Rate => match crate::overrides::limit(value, name)? {
            Some(bytes) => bytes.to_string(),
            None => return Ok(None),
        },
        Kind::Text => {
            if value.contains(['"', '\\', '\n', '\r', '\t']) {
                return Err(format!(
                    "{name} must not contain double quotes, backslashes, tabs or line breaks"
                ));
            }
            value.to_owned()
        }
        Kind::Addresses => {
            for item in &items {
                item.parse::<IpAddr>()
                    .map_err(|error| format!("{name}: '{item}' is not an IP address: {error}"))?;
            }
            items.join(",")
        }
        Kind::Domains => {
            for item in &items {
                if !item
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
                {
                    return Err(format!("{name}: '{item}' is not a domain name"));
                }
            }
            items.join(",")
        }
        Kind::SearchDomains => {
            if !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".- ".contains(&byte))
            {
                return Err(format!("{name} must be domain names separated by spaces"));
            }
            value.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        Kind::Routes => {
            for item in &items {
                check_route(item).map_err(|reason| format!("{name}: {reason}"))?;
            }
            items.join(",")
        }
        Kind::Choice(choices) => {
            let lower = value.to_ascii_lowercase();
            if !choices.iter().any(|(choice, _)| *choice == lower) {
                let values: Vec<&str> = choices.iter().map(|(choice, _)| *choice).collect();
                return Err(format!("{name} must be one of {}", values.join(", ")));
            }
            lower
        }
    };
    Ok((!checked.is_empty()).then_some(checked))
}

/// Checks a route given as `address/prefix` or IPv4 `address/netmask`.
fn check_route(route: &str) -> Result<(), String> {
    let Some((address, mask)) = route.split_once('/') else {
        return Err(format!("'{route}' needs a prefix or a netmask"));
    };
    if !mask.contains('.') {
        return Network::parse(route).map(|_network| ());
    }
    address
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("'{route}' is not a route: {error}"))?;
    let bits = u32::from(
        mask.parse::<Ipv4Addr>()
            .map_err(|error| format!("'{route}' has no valid netmask: {error}"))?,
    );
    if bits.leading_ones() + bits.trailing_zeros() != 32 {
        return Err(format!(
            "'{route}' has no valid netmask: its ones are not contiguous"
        ));
    }
    Ok(())
}

/// Where the entrypoint's record of the settings and the panel's stored
/// values live.
pub struct Files {
    /// The entrypoint's record of each setting at start, rewritten when a
    /// reload applies stored values.
    pub state: PathBuf,
    /// The values the panel stored, which the entrypoint reads at start.
    pub stored: PathBuf,
}

/// Builds the server's configuration again from the stored settings.
pub trait Renderer: Send {
    /// Writes the configuration to `config` and the settings' record to
    /// `state`, keeping the settings that wait for the next start at the
    /// values the server started with.
    fn render(&mut self, config: &Path, state: &Path) -> Result<(), String>;
}

/// The entrypoint's own builder, which ocserv checks the result of.
#[cfg(unix)]
pub struct System;

#[cfg(unix)]
impl Renderer for System {
    fn render(&mut self, config: &Path, state: &Path) -> Result<(), String> {
        let text = |path: &Path| {
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{} is not a UTF-8 path", path.display()))
        };
        let ran = crate::command::run(
            "/usr/local/libexec/ocserv-docker/render-config",
            &[&text(config)?, &text(state)?],
            &[],
        )?;
        if ran.status.success() {
            return Ok(());
        }
        Err(ran.failed("the server's configuration could not be built"))
    }
}

/// A builder for the tests and the development server: the configuration
/// stays as it is, and the record takes the stored values the way the
/// entrypoint would.
#[cfg(any(test, debug_assertions))]
pub struct Fake {
    /// The record at start.
    pub start: Vec<StateLine>,
    pub config: PathBuf,
    pub stored: PathBuf,
}

#[cfg(any(test, debug_assertions))]
impl Renderer for Fake {
    fn render(&mut self, config: &Path, state: &Path) -> Result<(), String> {
        let stored = read_stored(&self.stored)?;
        let mut text = String::new();
        for (name, apply, source, value) in &self.start {
            let (source, value) = match stored.get(name) {
                Some(stored) if source.is_open() && *apply == Apply::Reload => {
                    (Source::Panel, stored.clone())
                }
                Some(_) | None => (source.clone(), value.clone()),
            };
            let (apply, source) = (
                match apply {
                    Apply::Reload => "reload",
                    Apply::Start => "start",
                },
                match &source {
                    Source::Environment => "environment",
                    Source::Panel => "panel",
                    Source::Default => "default",
                    Source::Override(by) => by.as_str(),
                },
            );
            text.push_str(&format!("{name}\t{apply}\t{source}\t{value}\n"));
        }
        fs::copy(&self.config, config).map_err(|error| format!("{}: {error}", config.display()))?;
        fs::write(state, text).map_err(|error| format!("{}: {error}", state.display()))
    }
}

/// The ocserv options that a reload does not change; a new configuration
/// that differs in any of them waits for the next start.
const NOT_RELOADED: &[&str] = &[
    "auth",
    "enable-auth",
    "acct",
    "listen-host",
    "udp-listen-host",
    "listen-netns",
    "tcp-port",
    "udp-port",
    "run-as-user",
    "run-as-group",
    "occtl-socket-file",
    "socket-file",
    "chroot-dir",
    "server-cert",
    "server-key",
    "dh-params",
    "pin-file",
    "srk-pin-file",
    "key-pin",
    "srk-pin",
    "ca-cert",
    "sec-mod-scale",
    "server-stats-reset-time",
    "pid-file",
    "log-level",
    "syslog-facility",
];

/// The options whose values differ between two configurations, and
/// whether a reload applies every one of them.
pub fn difference(running: &ServerConfig, next: &ServerConfig) -> (Vec<String>, bool) {
    let mut names: Vec<&str> = running.names().chain(next.names()).collect();
    names.sort_unstable();
    names.dedup();
    let changed: Vec<String> = names
        .into_iter()
        .filter(|name| running.values(name) != next.values(name))
        .map(str::to_owned)
        .collect();
    let reloadable = changed
        .iter()
        .all(|name| !NOT_RELOADED.contains(&name.as_str()));
    (changed, reloadable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    fn checked(name: &str, value: &str) -> Result<Option<String>, String> {
        check(spec_of(name).unwrap(), value)
    }

    #[test]
    fn values_are_checked_and_normalized_like_the_entrypoint_does() {
        assert_eq!(
            checked("DNS_SERVERS", " 10.0.0.53 , fd00::53,").unwrap(),
            Some("10.0.0.53,fd00::53".to_owned())
        );
        assert!(checked("DNS_SERVERS", "dns.example.com").is_err());
        assert_eq!(checked("IDLE_TIMEOUT", "").unwrap(), None);
        assert!(checked("IDLE_TIMEOUT", "-5").is_err());
        assert!(checked("IDLE_TIMEOUT", "99999999999999999999999").is_err());
        assert_eq!(checked("NAT", "False").unwrap(), Some("false".to_owned()));
        assert!(checked("NAT", "maybe").is_err());
        assert!(checked("BANNER", "say \"hi\"").is_err());
        assert!(checked("BANNER", "one\ttwo").is_err());
        assert_eq!(
            checked("TUNNEL_ROUTES", "10.0.0.0/255.0.0.0, 192.168.1.0/24").unwrap(),
            Some("10.0.0.0/255.0.0.0,192.168.1.0/24".to_owned())
        );
        assert!(checked("TUNNEL_ROUTES", "10.0.0.0/255.0.255.0").is_err());
        assert!(checked("TUNNEL_ROUTES", "10.0.0.0").is_err());
        assert!(checked("SPLIT_DNS_DOMAINS", "corp.example.com, bad domain").is_err());
        assert_eq!(
            checked("DEFAULT_DOMAIN", "a.example  b.example").unwrap(),
            Some("a.example b.example".to_owned())
        );
        assert!(checked("TUNNEL_MODE", "split").is_err());
        assert!(checked("LOG_LEVEL", "5").is_err());
        assert_eq!(checked("LOG_LEVEL", "3").unwrap(), Some("3".to_owned()));
        assert_eq!(
            checked("RESTRICT_TO_ROUTES", "Auto").unwrap(),
            Some("auto".to_owned())
        );
    }

    /// Reads the entrypoint's table from the repository around the crate,
    /// which the panel checks mount whole for this reason.
    #[test]
    fn the_settings_are_the_entrypoints_panel_settings() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../rootfs/usr/local/lib/ocserv-docker/settings.sh");
        let text = fs::read_to_string(&path).unwrap();
        let table = text
            .split("readonly PANEL_SETTINGS='")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .unwrap();
        let mut table: Vec<&str> = table
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        let mut specs: Vec<&str> = SPECS.iter().map(|spec| spec.name).collect();
        table.sort_unstable();
        specs.sort_unstable();
        assert_eq!(table, specs);
    }

    #[test]
    fn every_setting_appears_once() {
        for (index, spec) in SPECS.iter().enumerate() {
            assert!(
                SPECS[..index].iter().all(|other| other.name != spec.name),
                "{} twice",
                spec.name
            );
        }
    }

    #[test]
    fn the_state_and_the_stored_values_are_read() {
        let dir = TestDir::new();
        let state = dir.path().join("panel-settings");
        assert_eq!(read_state(&state).unwrap(), None);
        fs::write(
            &state,
            "DNS_SERVERS\treload\tpanel\t10.0.0.53\nMAX_CLIENTS\treload\tenvironment\t64\n\
             IDLE_TIMEOUT\treload\tOCSERV_CONF_IDLE_TIMEOUT\t\nNAT\tstart\tdefault\ttrue\n",
        )
        .unwrap();
        let read = read_state(&state).unwrap().unwrap();
        assert_eq!(read.len(), 4);
        assert_eq!(
            read[2].2,
            Source::Override("OCSERV_CONF_IDLE_TIMEOUT".to_owned())
        );
        assert_eq!((read[3].1, read[3].3.as_str()), (Apply::Start, "true"));
        let stored_path = dir.path().join("settings.env");
        let mut stored = BTreeMap::new();
        stored.insert("NAT".to_owned(), "false".to_owned());
        write_stored(&stored_path, &stored).unwrap();
        assert_eq!(read_stored(&stored_path).unwrap(), stored);
        fs::write(&stored_path, "LISTEN_PORT=1\n").unwrap();
        assert!(read_stored(&stored_path).is_err());
    }

    #[test]
    fn a_start_setting_is_pending_until_the_server_uses_the_stored_value() {
        let setting = |stored: Option<&str>, source| Setting {
            name: "NAT".to_owned(),
            apply: Apply::Start,
            source,
            running: "true".to_owned(),
            stored: stored.map(str::to_owned),
        };
        assert!(setting(Some("false"), Source::Default).pending());
        assert!(!setting(Some("true"), Source::Panel).pending());
        assert!(setting(None, Source::Panel).pending());
        assert!(!setting(None, Source::Default).pending());
    }

    #[test]
    fn only_reloadable_differences_are_reloaded() {
        let running = ServerConfig::parse("dns = 9.9.9.9\nidle-timeout = 600\nauth = \"plain\"\n");
        let dns = ServerConfig::parse("dns = 10.0.0.53\nidle-timeout = 600\nauth = \"plain\"\n");
        assert_eq!(difference(&running, &dns), (vec!["dns".to_owned()], true));
        let auth =
            ServerConfig::parse("dns = 9.9.9.9\nidle-timeout = 600\nauth = \"plain[otp]\"\n");
        assert_eq!(
            difference(&running, &auth),
            (vec!["auth".to_owned()], false)
        );
        assert_eq!(difference(&running, &running), (Vec::new(), true));
    }
}
