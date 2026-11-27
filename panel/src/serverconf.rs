//! The options of the ocserv configuration the server runs with: the file the
//! entrypoint built from the environment, or the operator's own file in
//! POWER_USER and legacy mode. Lines are `name = value`, `#` starts a
//! comment, and the global options end at the first `[vhost:...]` section.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The global options of an ocserv configuration, in file order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerConfig {
    options: Vec<(String, String)>,
}

impl ServerConfig {
    pub fn parse(text: &str) -> ServerConfig {
        let mut options = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                break;
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((name, value)) = line.split_once('=') {
                options.push((name.trim().to_owned(), unquoted(value.trim()).to_owned()));
            }
        }
        ServerConfig { options }
    }

    pub fn read(path: &Path) -> Result<ServerConfig, String> {
        fs::read_to_string(path)
            .map(|text| ServerConfig::parse(&text))
            .map_err(|error| {
                format!(
                    "the VPN server's configuration {} could not be read: {error}",
                    path.display()
                )
            })
    }

    /// The name of every global option, once per line that gives it.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.options.iter().map(|(name, _)| name.as_str())
    }

    /// Every value given for `name`, in file order, for the options ocserv
    /// collects, such as routes and DNS servers.
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.options
            .iter()
            .filter(|(option, _)| option == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// The value ocserv keeps for a single-valued option known by any of
    /// `names`: the last one given.
    pub fn last(&self, names: &[&str]) -> Option<&str> {
        self.options
            .iter()
            .rev()
            .find(|(option, _)| names.contains(&option.as_str()))
            .map(|(_, value)| value.as_str())
    }

    /// The one-time password file a `plain[...]` sign-in method names with
    /// `otp=`. ocserv then asks every user with a password for a code as
    /// well, and refuses one with no secret in the file.
    pub fn otp_file(&self) -> Option<&Path> {
        self.values("auth").into_iter().find_map(|method| {
            method
                .strip_prefix("plain[")?
                .strip_suffix(']')?
                .split(',')
                .find_map(|option| option.strip_prefix("otp="))
                .map(Path::new)
        })
    }

    /// Whether a client certificate signs users in: `certificate` among the
    /// auth methods, which are all required, or the enable-auth ones, any of
    /// which suffices.
    pub fn certificate_sign_in(&self) -> bool {
        self.values("auth")
            .into_iter()
            .chain(self.values("enable-auth"))
            .any(|method| method == "certificate")
    }

    /// The secret a client adds to the address, as `https://host/?secret`,
    /// when ocserv hides behind camouflage.
    pub fn camouflage_secret(&self) -> Option<&str> {
        match self.last(&["camouflage"]) {
            Some(value) if is_true(value) => self.last(&["camouflage_secret"]),
            Some(_) | None => None,
        }
    }

    /// Whether Cisco Secure Client can connect: `cisco-client-compat`, or its
    /// older form, `always-require-cert = false`, in file order.
    pub fn cisco_compatible(&self) -> bool {
        let mut compatible = false;
        for (name, value) in &self.options {
            if name == "cisco-client-compat" {
                compatible = is_true(value);
            } else if name == "always-require-cert" && !is_true(value) {
                compatible = true;
            }
        }
        compatible
    }

    /// The server's certificate file, its own certificate first.
    pub fn server_cert(&self) -> Option<&Path> {
        self.last(&["server-cert"]).map(Path::new)
    }

    fn number(&self, names: &[&str], default: u64) -> Result<u64, String> {
        match self.last(names) {
            None => Ok(default),
            Some(value) => value.parse().map_err(|error| {
                format!(
                    "the VPN server's {} is not a whole number: '{value}': {error}",
                    names[0]
                )
            }),
        }
    }
}

/// A value without the double quotes around it, if it has them.
fn unquoted(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
}

/// Whether ocserv reads a boolean option's value as on: true or yes, in any
/// case.
fn is_true(value: &str) -> bool {
    value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
}

/// How ocserv scores the addresses clients connect from, and bans them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanPolicy {
    /// The score at which an address is banned; 0 turns bans off.
    pub max_score: u64,
    /// How long a ban lasts, in seconds.
    pub ban_seconds: u64,
    /// How long an address's points last before they start over, in
    /// seconds.
    pub reset_seconds: u64,
    pub wrong_password_points: u64,
    pub connection_points: u64,
}

impl BanPolicy {
    /// The policy `config` sets, with ocserv's own defaults for what it
    /// leaves out. `min-reauth-time` is the older name of `ban-time`.
    pub fn of(config: &ServerConfig) -> Result<BanPolicy, String> {
        Ok(BanPolicy {
            max_score: config.number(&["max-ban-score"], 80)?,
            ban_seconds: config.number(&["ban-time", "min-reauth-time"], 300)?,
            reset_seconds: config.number(&["ban-reset-time"], 1200)?,
            wrong_password_points: config.number(&["ban-points-wrong-password"], 10)?,
            connection_points: config.number(&["ban-points-connection"], 1)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "# Generated from environment variables
auth = \"plain[passwd=/config/ocpasswd]\"
tcp-port = 4443
dns = 9.9.9.9
dns = 1.1.1.1
route = 10.20.0.0/16
max-ban-score = 60
ban-time = 600
banner = \"Welcome\"
max-ban-score = 90

[vhost:other.example.com]
max-ban-score = 5
dns = 10.0.0.53
";

    #[test]
    fn global_options_are_read_in_order_up_to_the_first_section() {
        let config = ServerConfig::parse(CONFIG);
        assert_eq!(config.values("dns"), ["9.9.9.9", "1.1.1.1"]);
        assert_eq!(config.values("route"), ["10.20.0.0/16"]);
        assert_eq!(config.last(&["dns"]), Some("1.1.1.1"));
        assert_eq!(config.last(&["banner"]), Some("Welcome"));
        assert_eq!(config.last(&["max-ban-score"]), Some("90"));
        assert_eq!(config.last(&["no-such-option"]), None);
    }

    #[test]
    fn the_ban_policy_keeps_the_last_value_and_ocserv_defaults() {
        let policy = BanPolicy::of(&ServerConfig::parse(CONFIG)).unwrap();
        assert_eq!(
            policy,
            BanPolicy {
                max_score: 90,
                ban_seconds: 600,
                reset_seconds: 1200,
                wrong_password_points: 10,
                connection_points: 1,
            }
        );
        let empty = BanPolicy::of(&ServerConfig::default()).unwrap();
        assert_eq!((empty.max_score, empty.ban_seconds), (80, 300));
    }

    #[test]
    fn the_sign_in_and_connection_options_the_onboarding_kit_reads() {
        let config = ServerConfig::parse(
            "auth = \"plain[passwd=/config/ocpasswd,otp=/config/users.oath]\"\n\
             server-cert = /config/certs/server-cert.pem\n\
             camouflage = TRUE\n\
             camouflage_secret = \"hidden-door\"\n\
             cisco-client-compat = yes\n",
        );
        assert_eq!(config.otp_file(), Some(Path::new("/config/users.oath")));
        assert_eq!(config.camouflage_secret(), Some("hidden-door"));
        assert!(config.cisco_compatible());
        assert_eq!(
            config.server_cert(),
            Some(Path::new("/config/certs/server-cert.pem"))
        );
        let plain = ServerConfig::parse(CONFIG);
        assert_eq!(plain.otp_file(), None);
        assert_eq!(plain.camouflage_secret(), None);
        assert!(!plain.cisco_compatible());
        let older = ServerConfig::parse(
            "camouflage = false\ncamouflage_secret = unused\nalways-require-cert = false\n",
        );
        assert_eq!(older.camouflage_secret(), None);
        assert!(older.cisco_compatible());
    }

    #[test]
    fn certificate_sign_in_is_read_from_auth_and_enable_auth() {
        let read = |text: &str| ServerConfig::parse(text).certificate_sign_in();
        assert!(!read("auth = \"plain[passwd=/config/ocpasswd]\"\n"));
        assert!(read("auth = \"certificate\"\n"));
        assert!(read(
            "auth = \"certificate\"\nauth = \"plain[passwd=/config/ocpasswd]\"\n"
        ));
        assert!(read(
            "auth = \"plain[passwd=/config/ocpasswd]\"\nenable-auth = \"certificate\"\n"
        ));
    }

    #[test]
    fn the_older_name_of_the_ban_time_counts() {
        let config = ServerConfig::parse("min-reauth-time = 120\n");
        assert_eq!(BanPolicy::of(&config).unwrap().ban_seconds, 120);
    }

    #[test]
    fn a_ban_option_that_is_not_a_number_is_an_error() {
        let config = ServerConfig::parse("max-ban-score = lots\n");
        let error = BanPolicy::of(&config).unwrap_err();
        assert!(error.contains("max-ban-score"), "{error}");
    }
}
