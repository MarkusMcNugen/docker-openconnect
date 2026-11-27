//! The settings the panel reads from its environment.
//!
//! Every value is validated; an invalid one stops the command with a message
//! that names the variable. An empty variable counts as unset, as it does in
//! the entrypoint.

use std::ffi::OsString;
use std::fmt;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::blocklist::AutoBlock;
use crate::firewall::Backend;
use crate::net::{self, Network};
#[cfg(any(unix, test))]
use crate::service::Policy;

/// The port the panel listens on when PANEL_PORT is unset.
pub const DEFAULT_PORT: u16 = 8443;

/// The longest DNS name in characters, without a trailing dot.
const MAX_NAME_LEN: usize = 253;

/// The longest DNS label in characters.
const MAX_LABEL_LEN: usize = 63;

/// The longest Linux user name the image creates, in characters.
const MAX_USER_LEN: usize = 32;

/// The OWASP minimum Argon2id memory cost, in KiB, with two passes.
pub const MIN_ARGON2_MEMORY_KIB: u32 = 19_456;

/// The OWASP minimum Argon2id passes, with 19 MiB of memory.
pub const MIN_ARGON2_PASSES: u32 = 2;

/// The host name or address browsers use to reach the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// A DNS name in lower case, without a trailing dot.
    Name(String),
    /// An IPv4 or IPv6 address.
    Address(IpAddr),
}

impl Host {
    /// Parses an IP address or a host name. As in browsers, a value that
    /// contains a colon is an IPv6 address and a value whose last
    /// dot-separated part is all digits is an IPv4 address; either must parse
    /// strictly. Anything else must be a host name of letters, digits and
    /// hyphens in dot-separated labels, and is folded to lower case.
    pub fn parse(value: &str) -> Result<Host, String> {
        if value.contains(':') {
            return value
                .parse::<Ipv6Addr>()
                .map(|address| Host::Address(IpAddr::V6(address)))
                .map_err(|error| format!("'{value}' is not an IPv6 address: {error}"));
        }
        let last_label = match value.rsplit_once('.') {
            Some((_, last)) => last,
            None => value,
        };
        if !last_label.is_empty() && last_label.bytes().all(|byte| byte.is_ascii_digit()) {
            return value
                .parse::<Ipv4Addr>()
                .map(|address| Host::Address(IpAddr::V4(address)))
                .map_err(|error| format!("'{value}' is not an IPv4 address: {error}"));
        }
        let name = value.to_ascii_lowercase();
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(format!(
                "'{value}' is not a host name: it must be 1 to {MAX_NAME_LEN} characters long"
            ));
        }
        for label in name.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(format!(
                    "'{value}' is not a host name: each dot-separated part must be 1 to \
                     {MAX_LABEL_LEN} characters long"
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(format!(
                    "'{value}' is not a host name: a part cannot start or end with a hyphen"
                ));
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(format!(
                    "'{value}' is not a host name: only letters, digits, hyphens and dots are \
                     allowed"
                ));
            }
        }
        Ok(Host::Name(name))
    }

    /// The host as it appears in the authority of an https URL.
    pub fn authority(&self) -> String {
        match self {
            Host::Name(name) => name.clone(),
            Host::Address(IpAddr::V4(address)) => address.to_string(),
            Host::Address(IpAddr::V6(address)) => format!("[{address}]"),
        }
    }
}

/// A variable that is invalid, or required and missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// The environment variable at fault.
    pub variable: &'static str,
    /// What is wrong with it.
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.variable, self.message)
    }
}

impl std::error::Error for ConfigError {}

/// The panel's validated settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// PANEL_HOSTNAME, else SRV_CN: the name or address browsers use.
    pub host: Host,
    /// PANEL_PORT: the HTTPS port inside the container.
    pub port: u16,
    /// $CONFIG_DIR/panel: admins, the settings layer, the audit log and the
    /// panel's certificate.
    pub data_dir: PathBuf,
    /// PANEL_RUNTIME_DIR: where helper.sock is created.
    pub runtime_dir: PathBuf,
    /// PASSWD_FILE, else $CONFIG_DIR/ocpasswd, as the entrypoint sets it:
    /// the VPN users' password file.
    pub passwd_file: PathBuf,
    /// OTP_FILE, else $CONFIG_DIR/users.oath, as the entrypoint sets it: the
    /// VPN users' one-time password file.
    pub otp_file: PathBuf,
    /// OCSERV_CONFIG, else $RUNTIME_DIR/ocserv.conf, as the entrypoint sets
    /// it: the configuration the VPN server runs with.
    pub ocserv_config: PathBuf,
    /// VPN_ADDRESS, else SRV_CN with LISTEN_PORT: the address VPN clients
    /// connect to, which a published port can make differ from the
    /// container's own.
    pub vpn_address: VpnAddress,
    /// PANEL_USER: the account the web process runs as.
    pub service_user: String,
    /// PANEL_ADMIN_USER: the name of the first admin.
    pub admin_user: String,
    /// PANEL_ADMIN_PASSWORD_FILE: the first admin's password, such as a
    /// Docker secret.
    pub admin_password_file: Option<PathBuf>,
    /// PANEL_LAN_NETWORKS: where a password alone signs in.
    pub lan_networks: Vec<Network>,
    /// PANEL_ALLOWED_NETWORKS: more networks that may reach the panel,
    /// beyond loopback, the Docker host and the VPN pools.
    pub allowed_networks: Vec<Network>,
    /// PANEL_ALLOW_VPN: whether connected VPN clients may reach the panel.
    pub allow_vpn: bool,
    /// PANEL_REQUIRE_CLIENT_CERT: whether a browser must present a client
    /// certificate from the image's CA.
    pub require_client_cert: bool,
    /// PANEL_CERT and PANEL_KEY: the operator's own certificate and key, used
    /// instead of the panel's certificate from the image's CA.
    pub own_certificate: Option<(PathBuf, PathBuf)>,
    /// PANEL_HISTORY_HOURS: how much dashboard history is kept in memory.
    pub history_hours: u64,
    /// PANEL_SAMPLE_SECONDS: how often the dashboard samples ocserv.
    pub sample_seconds: u64,
    /// PANEL_SESSION_IDLE_MINUTES.
    pub session_idle_minutes: u64,
    /// PANEL_SESSION_MAX_HOURS.
    pub session_max_hours: u64,
    /// PANEL_REAUTH_MINUTES: how old a sign-in may be for sensitive actions.
    pub reauth_minutes: u64,
    /// PANEL_SECOND_FACTOR_MINUTES: how long a sign-in waits for its second
    /// factor.
    pub second_factor_minutes: u64,
    /// PANEL_LOGIN_MAX_FAILURES.
    pub max_failures: u32,
    /// PANEL_LOCKOUT_MINUTES.
    pub lockout_minutes: u64,
    /// PANEL_MIN_PASSWORD_LENGTH: the shortest admin password.
    pub min_password_length: usize,
    /// PANEL_ARGON2_MEMORY_KIB.
    pub argon2_memory_kib: u32,
    /// PANEL_ARGON2_PASSES.
    pub argon2_passes: u32,
    /// The VPN user portal, when PANEL_PORTAL_ENABLED=true.
    pub portal: Option<PortalSettings>,
    /// PANEL_BLOCK_AFTER_BANS, PANEL_BLOCK_WINDOW_HOURS and PANEL_BLOCK_HOURS:
    /// an address ocserv bans that many times within the window is blocked
    /// at the firewall for that long; 0 bans blocks nothing by itself.
    pub blocking: AutoBlock,
    /// PANEL_FIREWALL, which the entrypoint sets: the firewall it loaded.
    pub firewall: Option<Backend>,
    /// $CONFIG_DIR/certs: the client CA that signs VPN users' certificates,
    /// its revocation list and the revoked certificates.
    pub certs_dir: PathBuf,
    /// PANEL_CLIENT_CERT_DAYS: how long a VPN user's certificate is valid.
    pub client_cert_days: u64,
    /// CERT_KEY_TYPE: the kind of key the panel makes for a key file.
    pub key_type: KeyType,
    /// PANEL_SOURCE_CHECK, which firewall.sh sets: whether the firewall
    /// drops each packet from a tunnel whose source is not routed back
    /// through that tunnel, without which the site-to-site rules open
    /// nothing.
    pub source_check: bool,
    /// $RUNTIME_DIR/site-firewall.lock: the lock that keeps the helper's
    /// site syncs and those of ocserv's session scripts from interleaving.
    pub site_lock: PathBuf,
}

/// What `ocpanel site-sync` reads, which the entrypoint sets whether the
/// panel is on or off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteSync {
    /// $CONFIG_DIR/panel/site-rules.json: the rules and egress choices.
    pub sites_file: PathBuf,
    /// OCSERV_CONFIG, else $RUNTIME_DIR/ocserv.conf: the configuration
    /// ocserv runs with, which names the pools and the per-user and
    /// per-group directories.
    pub ocserv_config: PathBuf,
    /// PANEL_FIREWALL: the firewall firewall.sh loaded.
    pub firewall: Backend,
    /// PANEL_SOURCE_CHECK, as for the helper.
    pub source_check: bool,
    /// $RUNTIME_DIR/site-firewall.lock, as for the helper.
    pub site_lock: PathBuf,
}

impl SiteSync {
    /// Reads the settings through `get`, as `Settings::from_env` does.
    pub fn from_env<F>(get: F) -> Result<SiteSync, ConfigError>
    where
        F: Fn(&str) -> Option<OsString>,
    {
        let config_dir = absolute_path(&get, "CONFIG_DIR", "/config")?;
        let runtime_dir = absolute_path(&get, "RUNTIME_DIR", "/run/ocserv")?;
        Ok(SiteSync {
            sites_file: config_dir.join("panel").join("site-rules.json"),
            ocserv_config: match text(&get, "OCSERV_CONFIG")? {
                Some(value) => require_absolute("OCSERV_CONFIG", &value)?,
                None => runtime_dir.join("ocserv.conf"),
            },
            firewall: match text(&get, "PANEL_FIREWALL")? {
                Some(value) => Backend::parse(&value).map_err(|message| ConfigError {
                    variable: "PANEL_FIREWALL",
                    message,
                })?,
                None => {
                    return Err(ConfigError {
                        variable: "PANEL_FIREWALL",
                        message: "not set; firewall.sh sets it to the firewall it loaded"
                            .to_owned(),
                    });
                }
            },
            source_check: flag(&get, "PANEL_SOURCE_CHECK", false)?,
            site_lock: runtime_dir.join("site-firewall.lock"),
        })
    }
}

/// The kind of private key the container creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// ECDSA on the P-256 curve.
    Ecdsa,
    /// RSA with 3072 bits.
    Rsa,
}

/// The VPN user portal's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalSettings {
    /// PANEL_PORTAL_PORT: the portal's HTTPS port inside the container.
    pub port: u16,
    /// PANEL_PORTAL_NETWORKS: the networks that may reach the portal; every
    /// address when empty.
    pub networks: Vec<Network>,
    /// PANEL_PORTAL_CERT and PANEL_PORTAL_KEY: a certificate and key used
    /// instead of the panel's own.
    pub own_certificate: Option<(PathBuf, PathBuf)>,
}

impl Settings {
    /// Reads the settings through `get`, which returns a variable's value or
    /// `None` when it is unset.
    pub fn from_env<F>(get: F) -> Result<Settings, ConfigError>
    where
        F: Fn(&str) -> Option<OsString>,
    {
        let host = match text(&get, "PANEL_HOSTNAME")? {
            Some(value) => parse_host("PANEL_HOSTNAME", &value)?,
            None => match text(&get, "SRV_CN")? {
                Some(value) => parse_host("SRV_CN", &value)?,
                None => {
                    return Err(ConfigError {
                        variable: "PANEL_HOSTNAME",
                        message: "not set, and SRV_CN is not set either".to_owned(),
                    });
                }
            },
        };
        let port = match text(&get, "PANEL_PORT")? {
            Some(value) => parse_port(&value)?,
            None => DEFAULT_PORT,
        };
        let config_dir = absolute_path(&get, "CONFIG_DIR", "/config")?;
        let lan_networks = match text(&get, "PANEL_LAN_NETWORKS")? {
            Some(value) => net::parse_list(&value).map_err(|message| ConfigError {
                variable: "PANEL_LAN_NETWORKS",
                message,
            })?,
            None => Vec::new(),
        };
        let allowed_networks = match text(&get, "PANEL_ALLOWED_NETWORKS")? {
            Some(value) => net::parse_list(&value).map_err(|message| ConfigError {
                variable: "PANEL_ALLOWED_NETWORKS",
                message,
            })?,
            None => Vec::new(),
        };
        let own_certificate = certificate_pair(&get, "PANEL_CERT", "PANEL_KEY")?;
        let portal = if flag(&get, "PANEL_PORTAL_ENABLED", false)? {
            let portal_port = number(&get, "PANEL_PORTAL_PORT", 8444, 1, u16::MAX)?;
            let listen_port = number(&get, "LISTEN_PORT", 4443, 1, u16::MAX)?;
            if portal_port == port || portal_port == listen_port {
                return Err(ConfigError {
                    variable: "PANEL_PORTAL_PORT",
                    message: format!(
                        "{portal_port} is already the panel's port or the VPN's; choose another"
                    ),
                });
            }
            Some(PortalSettings {
                port: portal_port,
                networks: match text(&get, "PANEL_PORTAL_NETWORKS")? {
                    Some(value) => net::parse_list(&value).map_err(|message| ConfigError {
                        variable: "PANEL_PORTAL_NETWORKS",
                        message,
                    })?,
                    None => Vec::new(),
                },
                own_certificate: certificate_pair(&get, "PANEL_PORTAL_CERT", "PANEL_PORTAL_KEY")?,
            })
        } else {
            None
        };
        let admin_password_file = match text(&get, "PANEL_ADMIN_PASSWORD_FILE")? {
            Some(value) => Some(require_absolute("PANEL_ADMIN_PASSWORD_FILE", &value)?),
            None => None,
        };
        Ok(Settings {
            host,
            port,
            data_dir: config_dir.join("panel"),
            runtime_dir: absolute_path(&get, "PANEL_RUNTIME_DIR", "/run/ocpanel")?,
            passwd_file: match text(&get, "PASSWD_FILE")? {
                Some(value) => require_absolute("PASSWD_FILE", &value)?,
                None => config_dir.join("ocpasswd"),
            },
            otp_file: match text(&get, "OTP_FILE")? {
                Some(value) => require_absolute("OTP_FILE", &value)?,
                None => config_dir.join("users.oath"),
            },
            ocserv_config: match text(&get, "OCSERV_CONFIG")? {
                Some(value) => require_absolute("OCSERV_CONFIG", &value)?,
                None => absolute_path(&get, "RUNTIME_DIR", "/run/ocserv")?.join("ocserv.conf"),
            },
            vpn_address: match text(&get, "VPN_ADDRESS")? {
                Some(value) => parse_vpn_address(&value)?,
                None => VpnAddress {
                    host: match text(&get, "SRV_CN")? {
                        Some(value) => parse_host("SRV_CN", &value)?,
                        None => Host::Name("vpn.example.com".to_owned()),
                    },
                    port: number(&get, "LISTEN_PORT", 4443, 1, u16::MAX)?,
                },
            },
            service_user: user_name(&get, "PANEL_USER", "ocpanel")?,
            admin_user: match text(&get, "PANEL_ADMIN_USER")? {
                Some(value) => value,
                None => "admin".to_owned(),
            },
            admin_password_file,
            lan_networks,
            allowed_networks,
            allow_vpn: flag(&get, "PANEL_ALLOW_VPN", true)?,
            require_client_cert: flag(&get, "PANEL_REQUIRE_CLIENT_CERT", false)?,
            own_certificate,
            history_hours: number(&get, "PANEL_HISTORY_HOURS", 24, 1, 168)?,
            sample_seconds: number(&get, "PANEL_SAMPLE_SECONDS", 10, 1, 3600)?,
            session_idle_minutes: number(&get, "PANEL_SESSION_IDLE_MINUTES", 30, 1, 1440)?,
            session_max_hours: number(&get, "PANEL_SESSION_MAX_HOURS", 12, 1, 168)?,
            reauth_minutes: number(&get, "PANEL_REAUTH_MINUTES", 10, 1, 1440)?,
            second_factor_minutes: number(&get, "PANEL_SECOND_FACTOR_MINUTES", 5, 1, 60)?,
            max_failures: number(&get, "PANEL_LOGIN_MAX_FAILURES", 5, 1, 100)?,
            lockout_minutes: number(&get, "PANEL_LOCKOUT_MINUTES", 15, 1, 1440)?,
            min_password_length: number(&get, "PANEL_MIN_PASSWORD_LENGTH", 12, 8, 128)?,
            argon2_memory_kib: number(
                &get,
                "PANEL_ARGON2_MEMORY_KIB",
                MIN_ARGON2_MEMORY_KIB,
                MIN_ARGON2_MEMORY_KIB,
                4_194_304,
            )?,
            argon2_passes: number(
                &get,
                "PANEL_ARGON2_PASSES",
                MIN_ARGON2_PASSES,
                MIN_ARGON2_PASSES,
                64,
            )?,
            portal,
            blocking: AutoBlock {
                bans: number(&get, "PANEL_BLOCK_AFTER_BANS", 3, 0, 100)?,
                window: number(&get, "PANEL_BLOCK_WINDOW_HOURS", 24, 1, 720)? * 3600,
                duration: number(&get, "PANEL_BLOCK_HOURS", 24, 1, 8760)? * 3600,
            },
            firewall: match text(&get, "PANEL_FIREWALL")? {
                Some(value) => Some(Backend::parse(&value).map_err(|message| ConfigError {
                    variable: "PANEL_FIREWALL",
                    message,
                })?),
                None => None,
            },
            certs_dir: config_dir.join("certs"),
            client_cert_days: number(&get, "PANEL_CLIENT_CERT_DAYS", 365, 1, 3650)?,
            key_type: match text(&get, "CERT_KEY_TYPE")?.map(|value| value.to_ascii_lowercase()) {
                None => KeyType::Ecdsa,
                Some(value) if value == "ecdsa" => KeyType::Ecdsa,
                Some(value) if value == "rsa" => KeyType::Rsa,
                Some(value) => {
                    return Err(ConfigError {
                        variable: "CERT_KEY_TYPE",
                        message: format!("'{value}' is not ecdsa or rsa"),
                    });
                }
            },
            source_check: flag(&get, "PANEL_SOURCE_CHECK", false)?,
            site_lock: absolute_path(&get, "RUNTIME_DIR", "/run/ocserv")?
                .join("site-firewall.lock"),
        })
    }

    /// The sign-in rules the helper applies.
    #[cfg(any(unix, test))]
    pub fn policy(&self) -> Policy {
        Policy {
            lan_networks: self.lan_networks.clone(),
            max_failures: self.max_failures,
            lockout: self.lockout_minutes * 60,
            min_password_length: self.min_password_length,
            reauth: self.reauth_minutes * 60,
        }
    }
}

/// Returns a variable's value: `None` when it is unset or empty, an error
/// when it is not valid UTF-8.
pub fn text<F>(get: &F, variable: &'static str) -> Result<Option<String>, ConfigError>
where
    F: Fn(&str) -> Option<OsString>,
{
    match get(variable) {
        None => Ok(None),
        Some(raw) => match raw.into_string() {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(raw) => Err(ConfigError {
                variable,
                message: format!("{raw:?} is not valid UTF-8"),
            }),
        },
    }
}

/// Reads `true` or `false`, the spelling the entrypoint uses.
fn flag<F>(get: &F, variable: &'static str, default: bool) -> Result<bool, ConfigError>
where
    F: Fn(&str) -> Option<OsString>,
{
    match text(get, variable)?.as_deref() {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(other) => Err(ConfigError {
            variable,
            message: format!("'{other}' is not true or false"),
        }),
    }
}

/// A certificate and key given as a pair of absolute paths in `cert` and
/// `key`; none when neither is set.
fn certificate_pair<F>(
    get: &F,
    cert: &'static str,
    key: &'static str,
) -> Result<Option<(PathBuf, PathBuf)>, ConfigError>
where
    F: Fn(&str) -> Option<OsString>,
{
    match (text(get, cert)?, text(get, key)?) {
        (None, None) => Ok(None),
        (Some(cert_path), Some(key_path)) => Ok(Some((
            require_absolute(cert, &cert_path)?,
            require_absolute(key, &key_path)?,
        ))),
        (Some(_set), None) => Err(ConfigError {
            variable: key,
            message: format!("not set, but {cert} is; set both or neither"),
        }),
        (None, Some(_set)) => Err(ConfigError {
            variable: cert,
            message: format!("not set, but {key} is; set both or neither"),
        }),
    }
}

fn parse_host(variable: &'static str, value: &str) -> Result<Host, ConfigError> {
    Host::parse(value).map_err(|message| ConfigError { variable, message })
}

/// Parses a port number from 1 to 65535, written in decimal digits only.
fn parse_port(value: &str) -> Result<u16, ConfigError> {
    number_text("PANEL_PORT", value, 1, u16::MAX)
}

/// The address VPN clients connect to, as the onboarding kit gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnAddress {
    pub host: Host,
    pub port: u16,
}

impl VpnAddress {
    /// `vpn.example.com:4443`, or `vpn.example.com` on port 443.
    pub fn text(&self) -> String {
        match self.port {
            443 => self.host.authority(),
            port => format!("{}:{port}", self.host.authority()),
        }
    }
}

/// Parses VPN_ADDRESS: a host name or address and an optional port, which
/// is 443 when left out; an IPv6 address goes in brackets.
fn parse_vpn_address(value: &str) -> Result<VpnAddress, ConfigError> {
    let fail = |message: String| ConfigError {
        variable: "VPN_ADDRESS",
        message,
    };
    if value.contains('/') {
        return Err(fail(format!(
            "'{value}' is not a host and port: give them without a scheme or path, such as \
             vpn.example.com:443"
        )));
    }
    let (host, port) = match value.strip_prefix('[') {
        Some(rest) => {
            let (inside, after) = rest.split_once(']').ok_or_else(|| {
                fail(format!(
                    "'{value}' opens an IPv6 address with [ but never closes it"
                ))
            })?;
            let port = match after {
                "" => None,
                after => Some(after.strip_prefix(':').ok_or_else(|| {
                    fail(format!(
                        "'{value}' has something other than :port after the ]"
                    ))
                })?),
            };
            (inside, port)
        }
        None => match value.rsplit_once(':') {
            Some((host, _)) if host.contains(':') => {
                return Err(fail(format!(
                    "'{value}' is an IPv6 address without brackets: write it as [address]:port"
                )));
            }
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        },
    };
    let host = Host::parse(host).map_err(fail)?;
    let port = match port {
        Some(port) => number_text("VPN_ADDRESS", port, 1, u16::MAX)?,
        None => 443,
    };
    Ok(VpnAddress { host, port })
}

/// Reads a whole number written in decimal digits only, from `min` to `max`.
fn number<F, T>(
    get: &F,
    variable: &'static str,
    default: T,
    min: T,
    max: T,
) -> Result<T, ConfigError>
where
    F: Fn(&str) -> Option<OsString>,
    T: FromStr + PartialOrd + Display + Copy,
    <T as FromStr>::Err: Display,
{
    match text(get, variable)? {
        Some(value) => number_text(variable, &value, min, max),
        None => Ok(default),
    }
}

fn number_text<T>(variable: &'static str, value: &str, min: T, max: T) -> Result<T, ConfigError>
where
    T: FromStr + PartialOrd + Display + Copy,
    <T as FromStr>::Err: Display,
{
    let invalid = |detail: String| ConfigError {
        variable,
        message: format!("'{value}' is not a whole number from {min} to {max}{detail}"),
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(String::new()));
    }
    let parsed: T = value
        .parse()
        .map_err(|error| invalid(format!(" ({error})")))?;
    if parsed < min || parsed > max {
        return Err(invalid(String::new()));
    }
    Ok(parsed)
}

/// CONFIG_DIR, else /config, which the entrypoint uses without exporting.
pub fn config_dir<F>(get: &F) -> Result<PathBuf, ConfigError>
where
    F: Fn(&str) -> Option<OsString>,
{
    absolute_path(get, "CONFIG_DIR", "/config")
}

fn absolute_path<F>(get: &F, variable: &'static str, default: &str) -> Result<PathBuf, ConfigError>
where
    F: Fn(&str) -> Option<OsString>,
{
    match text(get, variable)? {
        Some(value) => require_absolute(variable, &value),
        None => Ok(PathBuf::from(default)),
    }
}

fn require_absolute(variable: &'static str, value: &str) -> Result<PathBuf, ConfigError> {
    let path = Path::new(value);
    if !path.has_root() {
        return Err(ConfigError {
            variable,
            message: format!("'{value}' is not an absolute path"),
        });
    }
    Ok(path.to_owned())
}

/// A Linux user name: a lower-case letter or underscore, then lower-case
/// letters, digits, underscores and hyphens.
fn user_name<F>(get: &F, variable: &'static str, default: &str) -> Result<String, ConfigError>
where
    F: Fn(&str) -> Option<OsString>,
{
    let value = match text(get, variable)? {
        Some(value) => value,
        None => return Ok(default.to_owned()),
    };
    let mut bytes = value.bytes();
    let first_ok = matches!(bytes.next(), Some(b'a'..=b'z' | b'_'));
    let rest_ok = bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
    if !first_ok || !rest_ok || value.len() > MAX_USER_LEN {
        return Err(ConfigError {
            variable,
            message: format!("'{value}' is not a user name"),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(*value)))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn settings(pairs: &[(&str, &str)]) -> Result<Settings, ConfigError> {
        let mut all = vec![("PANEL_HOSTNAME", "vpn.example.com")];
        all.extend_from_slice(pairs);
        Settings::from_env(env(&all))
    }

    #[test]
    fn defaults() {
        let settings = Settings::from_env(env(&[("PANEL_HOSTNAME", "vpn.example.com")])).unwrap();
        assert_eq!(settings.host, Host::Name("vpn.example.com".to_owned()));
        assert_eq!(settings.port, DEFAULT_PORT);
        assert_eq!(settings.data_dir, PathBuf::from("/config/panel"));
        assert_eq!(settings.runtime_dir, PathBuf::from("/run/ocpanel"));
        assert_eq!(
            settings.ocserv_config,
            PathBuf::from("/run/ocserv/ocserv.conf")
        );
        assert_eq!(settings.service_user, "ocpanel");
        assert_eq!(settings.admin_user, "admin");
        assert_eq!(settings.admin_password_file, None);
        assert!(settings.lan_networks.is_empty());
        assert_eq!(settings.session_idle_minutes, 30);
        assert_eq!(settings.session_max_hours, 12);
        assert_eq!(settings.reauth_minutes, 10);
        assert_eq!(settings.second_factor_minutes, 5);
        assert_eq!(settings.max_failures, 5);
        assert_eq!(settings.lockout_minutes, 15);
        assert_eq!(settings.min_password_length, 12);
        assert_eq!(settings.argon2_memory_kib, 19_456);
        assert_eq!(settings.argon2_passes, 2);
        assert_eq!(settings.policy().lockout, 900);
        assert!(settings.allowed_networks.is_empty());
        assert!(settings.allow_vpn);
        assert!(!settings.require_client_cert);
        assert_eq!(settings.own_certificate, None);
        assert_eq!(settings.history_hours, 24);
        assert_eq!(settings.sample_seconds, 10);
    }

    #[test]
    fn flags_are_true_or_false() {
        let set = settings(&[
            ("PANEL_ALLOW_VPN", "false"),
            ("PANEL_REQUIRE_CLIENT_CERT", "true"),
        ])
        .unwrap();
        assert!(!set.allow_vpn);
        assert!(set.require_client_cert);
        for value in ["yes", "TRUE", "1", "off"] {
            let error = settings(&[("PANEL_ALLOW_VPN", value)]).unwrap_err();
            assert_eq!(error.variable, "PANEL_ALLOW_VPN", "for {value:?}");
        }
    }

    #[test]
    fn an_own_certificate_needs_both_files() {
        let set = settings(&[
            ("PANEL_CERT", "/certs/panel.pem"),
            ("PANEL_KEY", "/certs/panel.key"),
        ])
        .unwrap();
        assert_eq!(
            set.own_certificate,
            Some((
                PathBuf::from("/certs/panel.pem"),
                PathBuf::from("/certs/panel.key")
            ))
        );
        let error = settings(&[("PANEL_CERT", "/certs/panel.pem")]).unwrap_err();
        assert_eq!(error.variable, "PANEL_KEY");
        let error = settings(&[("PANEL_KEY", "/certs/panel.key")]).unwrap_err();
        assert_eq!(error.variable, "PANEL_CERT");
        let error = settings(&[
            ("PANEL_CERT", "panel.pem"),
            ("PANEL_KEY", "/certs/panel.key"),
        ])
        .unwrap_err();
        assert_eq!(error.variable, "PANEL_CERT");
    }

    #[test]
    fn allowed_networks_are_parsed() {
        let set = settings(&[("PANEL_ALLOWED_NETWORKS", "10.0.0.0/8, 192.168.50.7")]).unwrap();
        assert_eq!(set.allowed_networks.len(), 2);
        let error = settings(&[("PANEL_ALLOWED_NETWORKS", "office")]).unwrap_err();
        assert_eq!(error.variable, "PANEL_ALLOWED_NETWORKS");
    }

    #[test]
    fn panel_hostname_wins_over_srv_cn() {
        let get = env(&[
            ("PANEL_HOSTNAME", "panel.example.com"),
            ("SRV_CN", "vpn.example.com"),
        ]);
        let settings = Settings::from_env(get).unwrap();
        assert_eq!(settings.host, Host::Name("panel.example.com".to_owned()));
    }

    #[test]
    fn falls_back_to_srv_cn() {
        let settings = Settings::from_env(env(&[("SRV_CN", "vpn.example.com")])).unwrap();
        assert_eq!(settings.host, Host::Name("vpn.example.com".to_owned()));
    }

    #[test]
    fn empty_counts_as_unset() {
        let get = env(&[
            ("PANEL_HOSTNAME", ""),
            ("SRV_CN", "vpn.example.com"),
            ("PANEL_PORT", ""),
        ]);
        let settings = Settings::from_env(get).unwrap();
        assert_eq!(settings.host, Host::Name("vpn.example.com".to_owned()));
        assert_eq!(settings.port, DEFAULT_PORT);
    }

    #[test]
    fn missing_host_names_the_variable() {
        let error = Settings::from_env(env(&[])).unwrap_err();
        assert_eq!(error.variable, "PANEL_HOSTNAME");
        assert!(error.message.contains("SRV_CN"));
    }

    #[test]
    fn invalid_srv_cn_names_srv_cn() {
        let error = Settings::from_env(env(&[("SRV_CN", "bad name")])).unwrap_err();
        assert_eq!(error.variable, "SRV_CN");
    }

    #[test]
    fn host_names_fold_to_lower_case() {
        assert_eq!(
            Host::parse("VPN.Example.COM"),
            Ok(Host::Name("vpn.example.com".to_owned()))
        );
    }

    #[test]
    fn single_label_names_are_names() {
        assert_eq!(Host::parse("vpn"), Ok(Host::Name("vpn".to_owned())));
    }

    #[test]
    fn invalid_host_names_are_refused() {
        let long_label = "a".repeat(MAX_LABEL_LEN + 1);
        let long_name = ["a"; 128].join(".");
        for value in [
            "",
            "vpn..example.com",
            "vpn.example.com.",
            "-vpn.example.com",
            "vpn-.example.com",
            "vpn_1.example.com",
            "vpn example.com",
            "https://vpn.example.com",
            "v\u{e9}pn.example.com",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(Host::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn addresses_are_addresses() {
        assert_eq!(
            Host::parse("192.168.1.20"),
            Ok(Host::Address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))))
        );
        assert_eq!(
            Host::parse("fd3e:7a0c:5b19::1"),
            Ok(Host::Address(IpAddr::V6(Ipv6Addr::new(
                0xfd3e, 0x7a0c, 0x5b19, 0, 0, 0, 0, 1
            ))))
        );
    }

    #[test]
    fn malformed_addresses_are_refused_not_taken_as_names() {
        for value in [
            "1.2.3.999",
            "1.2.3",
            "123",
            "fd3e:::1",
            "vpn.example.com:8443",
        ] {
            assert!(Host::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn authority_brackets_ipv6_only() {
        assert_eq!(
            Host::parse("vpn.example.com").unwrap().authority(),
            "vpn.example.com"
        );
        assert_eq!(
            Host::parse("192.168.1.20").unwrap().authority(),
            "192.168.1.20"
        );
        assert_eq!(Host::parse("fd3e::1").unwrap().authority(), "[fd3e::1]");
    }

    #[test]
    fn ports_from_1_to_65535() {
        for (value, port) in [("1", 1), ("8443", 8443), ("08443", 8443), ("65535", 65535)] {
            assert_eq!(settings(&[("PANEL_PORT", value)]).unwrap().port, port);
        }
        for value in [
            "0",
            "65536",
            "+8443",
            "-1",
            "84 43",
            "8443a",
            "99999999999999999999",
        ] {
            let error = settings(&[("PANEL_PORT", value)]).unwrap_err();
            assert_eq!(error.variable, "PANEL_PORT", "for {value:?}");
        }
    }

    #[test]
    fn the_portal_is_off_unless_enabled_and_listens_on_8444() {
        assert_eq!(settings(&[]).unwrap().portal, None);
        let on = ("PANEL_PORTAL_ENABLED", "true");
        let portal = settings(&[on]).unwrap().portal.unwrap();
        assert_eq!(portal.port, 8444);
        assert!(portal.networks.is_empty());
        assert_eq!(portal.own_certificate, None);
        let narrowed = settings(&[
            on,
            ("PANEL_PORTAL_NETWORKS", "10.0.0.0/8"),
            ("PANEL_PORTAL_CERT", "/certs/portal.pem"),
            ("PANEL_PORTAL_KEY", "/certs/portal-key.pem"),
        ])
        .unwrap()
        .portal
        .unwrap();
        assert_eq!(narrowed.networks.len(), 1);
        assert_eq!(
            narrowed.own_certificate,
            Some((
                PathBuf::from("/certs/portal.pem"),
                PathBuf::from("/certs/portal-key.pem")
            ))
        );
        for clash in ["8443", "4443"] {
            let error = settings(&[on, ("PANEL_PORTAL_PORT", clash)]).unwrap_err();
            assert_eq!(error.variable, "PANEL_PORTAL_PORT", "{clash}");
        }
        let half = settings(&[on, ("PANEL_PORTAL_CERT", "/certs/portal.pem")]).unwrap_err();
        assert_eq!(half.variable, "PANEL_PORTAL_KEY");
    }

    #[test]
    fn numbers_stay_inside_their_ranges() {
        let set = settings(&[
            ("PANEL_SESSION_IDLE_MINUTES", "45"),
            ("PANEL_LOGIN_MAX_FAILURES", "10"),
            ("PANEL_ARGON2_MEMORY_KIB", "65536"),
            ("PANEL_ARGON2_PASSES", "3"),
        ])
        .unwrap();
        assert_eq!(set.session_idle_minutes, 45);
        assert_eq!(set.max_failures, 10);
        assert_eq!(set.argon2_memory_kib, 65_536);
        assert_eq!(set.argon2_passes, 3);
        for (variable, value) in [
            ("PANEL_SESSION_IDLE_MINUTES", "0"),
            ("PANEL_SESSION_MAX_HOURS", "169"),
            ("PANEL_LOGIN_MAX_FAILURES", "0"),
            ("PANEL_MIN_PASSWORD_LENGTH", "7"),
            ("PANEL_ARGON2_MEMORY_KIB", "19455"),
            ("PANEL_ARGON2_PASSES", "1"),
            ("PANEL_LOCKOUT_MINUTES", "ten"),
        ] {
            let error = settings(&[(variable, value)]).unwrap_err();
            assert_eq!(error.variable, variable, "for {value:?}");
        }
    }

    #[test]
    fn lan_networks_are_parsed() {
        let set = settings(&[("PANEL_LAN_NETWORKS", "192.168.1.0/24, fd00::/8")]).unwrap();
        assert_eq!(set.lan_networks.len(), 2);
        let error = settings(&[("PANEL_LAN_NETWORKS", "192.168.1.0/24, lan")]).unwrap_err();
        assert_eq!(error.variable, "PANEL_LAN_NETWORKS");
    }

    #[test]
    fn paths_must_be_absolute() {
        let set = settings(&[
            ("CONFIG_DIR", "/srv/vpn"),
            ("PANEL_ADMIN_PASSWORD_FILE", "/run/secrets/admin"),
        ])
        .unwrap();
        assert_eq!(set.data_dir, PathBuf::from("/srv/vpn/panel"));
        assert_eq!(
            set.admin_password_file,
            Some(PathBuf::from("/run/secrets/admin"))
        );
        let runtime = settings(&[("RUNTIME_DIR", "/var/run/vpn")]).unwrap();
        assert_eq!(
            runtime.ocserv_config,
            PathBuf::from("/var/run/vpn/ocserv.conf")
        );
        let own = settings(&[("OCSERV_CONFIG", "/config/ocserv.conf")]).unwrap();
        assert_eq!(own.ocserv_config, PathBuf::from("/config/ocserv.conf"));
        for variable in [
            "CONFIG_DIR",
            "PANEL_RUNTIME_DIR",
            "PANEL_ADMIN_PASSWORD_FILE",
            "RUNTIME_DIR",
            "OCSERV_CONFIG",
        ] {
            let error = settings(&[(variable, "relative/path")]).unwrap_err();
            assert_eq!(error.variable, variable);
        }
    }

    #[test]
    fn the_vpn_address_defaults_to_srv_cn_and_the_listening_port() {
        let defaults = settings(&[]).unwrap();
        assert_eq!(defaults.vpn_address.text(), "vpn.example.com:4443");
        let named = settings(&[("SRV_CN", "VPN.Corp.Example"), ("LISTEN_PORT", "443")]).unwrap();
        assert_eq!(named.vpn_address.text(), "vpn.corp.example");
        for (value, text) in [
            ("vpn.example.com:10443", "vpn.example.com:10443"),
            ("vpn.example.com", "vpn.example.com"),
            ("203.0.113.5:4443", "203.0.113.5:4443"),
            ("[2001:db8::5]:443", "[2001:db8::5]"),
            ("[2001:db8::5]", "[2001:db8::5]"),
        ] {
            let set = settings(&[("VPN_ADDRESS", value)]).unwrap();
            assert_eq!(set.vpn_address.text(), text, "{value}");
        }
        for bad in [
            "https://vpn.example.com",
            "vpn.example.com/path",
            "2001:db8::5",
            "[2001:db8::5",
            "[2001:db8::5]x",
            "vpn.example.com:0",
            "vpn.example.com:http",
            "bad_host:443",
        ] {
            let error = settings(&[("VPN_ADDRESS", bad)]).unwrap_err();
            assert_eq!(error.variable, "VPN_ADDRESS", "{bad}");
        }
    }

    #[test]
    fn service_user_names() {
        assert_eq!(
            settings(&[("PANEL_USER", "web_1")]).unwrap().service_user,
            "web_1"
        );
        for bad in ["Web", "1web", "web user", "-web", &"w".repeat(33)] {
            let error = settings(&[("PANEL_USER", bad)]).unwrap_err();
            assert_eq!(error.variable, "PANEL_USER", "for {bad:?}");
        }
    }

    #[test]
    fn site_sync_reads_what_the_entrypoint_sets() {
        let sync = SiteSync::from_env(env(&[("PANEL_FIREWALL", "nftables")])).unwrap();
        assert_eq!(
            sync,
            SiteSync {
                sites_file: PathBuf::from("/config/panel/site-rules.json"),
                ocserv_config: PathBuf::from("/run/ocserv/ocserv.conf"),
                firewall: Backend::Nftables,
                source_check: false,
                site_lock: PathBuf::from("/run/ocserv/site-firewall.lock"),
            }
        );
        let moved = SiteSync::from_env(env(&[
            ("PANEL_FIREWALL", "iptables"),
            ("PANEL_SOURCE_CHECK", "true"),
            ("CONFIG_DIR", "/srv/vpn"),
            ("RUNTIME_DIR", "/var/run/vpn"),
            ("OCSERV_CONFIG", "/srv/vpn/ocserv.conf"),
        ]))
        .unwrap();
        assert_eq!(
            (
                moved.sites_file,
                moved.ocserv_config,
                moved.firewall,
                moved.source_check,
                moved.site_lock
            ),
            (
                PathBuf::from("/srv/vpn/panel/site-rules.json"),
                PathBuf::from("/srv/vpn/ocserv.conf"),
                Backend::Iptables,
                true,
                PathBuf::from("/var/run/vpn/site-firewall.lock")
            )
        );
        assert_eq!(
            SiteSync::from_env(env(&[])).unwrap_err().variable,
            "PANEL_FIREWALL"
        );
        let helper = settings(&[("PANEL_SOURCE_CHECK", "true")]).unwrap();
        assert!(helper.source_check);
        assert_eq!(
            helper.site_lock,
            PathBuf::from("/run/ocserv/site-firewall.lock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_values_are_refused() {
        use std::os::unix::ffi::OsStringExt;
        let get = |name: &str| (name == "PANEL_HOSTNAME").then(|| OsString::from_vec(vec![0xff]));
        let error = Settings::from_env(get).unwrap_err();
        assert_eq!(error.variable, "PANEL_HOSTNAME");
    }
}
