//! Per-user and per-group settings: the files ocserv reads from the
//! directories its `config-per-user` and `config-per-group` options name,
//! when a user connects. The panel manages a fixed IPv4 address (users
//! only), routes, DNS servers, download and upload limits, and whether a
//! user is held to their routes; every other line of a file is kept as it
//! stands. A user's own file wins over their group's, which wins over the
//! server's configuration.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::extras;
use crate::files;
use crate::net::Network;
use crate::serverconf::ServerConfig;
use crate::vpnusers;

/// Bytes per second in a megabit per second.
const BYTES_PER_MEGABIT: f64 = 125_000.0;

/// The lowest limit accepted, in bytes per second. ocserv counts limits in
/// whole kilobytes, so anything below 1000 would mean no limit at all.
const MIN_LIMIT: u64 = 1_250;

/// The options the panel manages; other lines of a file are kept.
const MANAGED: [&str; 6] = [
    "explicit-ipv4",
    "route",
    "dns",
    "tx-data-per-sec",
    "rx-data-per-sec",
    "restrict-user-to-routes",
];

/// Whose settings a file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    User,
    Group,
}

impl Owner {
    pub fn noun(self) -> &'static str {
        match self {
            Owner::User => "user",
            Owner::Group => "group",
        }
    }
}

/// The settings the panel manages for a user or a group; none means the
/// value comes from the group or the server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    /// The VPN address the user always gets; users only.
    pub fixed_ipv4: Option<String>,
    /// Networks sent through the tunnel, or `default` for every network.
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    /// The most the server sends to the client, in bytes per second.
    pub download: Option<u64>,
    /// The most the server takes from the client, in bytes per second.
    pub upload: Option<u64>,
    /// Whether traffic outside the routes is dropped.
    pub restrict: Option<bool>,
    /// The options beyond these six, by ocserv option; see extras.rs.
    #[serde(default)]
    pub extra: BTreeMap<String, Vec<String>>,
}

impl Overrides {
    /// The managed settings in an ocserv configuration's lines.
    pub fn from_config(config: &ServerConfig) -> Result<Overrides, String> {
        let limit = |name: &str| -> Result<Option<u64>, String> {
            match config.last(&[name]) {
                None => Ok(None),
                Some(value) => value
                    .parse()
                    .map(Some)
                    .map_err(|error| format!("{name} is not a whole number: '{value}': {error}")),
            }
        };
        let restrict = match config.last(&["restrict-user-to-routes"]) {
            None => None,
            Some("true") => Some(true),
            Some("false") => Some(false),
            Some(other) => {
                return Err(format!(
                    "restrict-user-to-routes is neither true nor false: '{other}'"
                ));
            }
        };
        Ok(Overrides {
            fixed_ipv4: config.last(&["explicit-ipv4"]).map(str::to_owned),
            routes: config
                .values("route")
                .into_iter()
                .map(str::to_owned)
                .collect(),
            dns: config
                .values("dns")
                .into_iter()
                .map(str::to_owned)
                .collect(),
            download: limit("tx-data-per-sec")?,
            upload: limit("rx-data-per-sec")?,
            restrict,
            extra: extras::from_config(config)?,
        })
    }

    /// The settings in effect when `self` is laid over `below`: each value
    /// set here wins, and the rest come from below.
    pub fn over(&self, below: &Overrides) -> Overrides {
        Overrides {
            fixed_ipv4: self.fixed_ipv4.clone().or_else(|| below.fixed_ipv4.clone()),
            routes: if self.routes.is_empty() {
                below.routes.clone()
            } else {
                self.routes.clone()
            },
            dns: if self.dns.is_empty() {
                below.dns.clone()
            } else {
                self.dns.clone()
            },
            download: self.download.or(below.download),
            upload: self.upload.or(below.upload),
            restrict: self.restrict.or(below.restrict),
            extra: {
                let mut extra = below.extra.clone();
                extra.extend(self.extra.clone());
                extra
            },
        }
    }

    /// The lines that set these values in a per-user or per-group file.
    fn lines(&self) -> Result<Vec<String>, String> {
        let mut lines = Vec::new();
        if let Some(address) = &self.fixed_ipv4 {
            lines.push(format!("explicit-ipv4 = {address}"));
        }
        lines.extend(self.routes.iter().map(|route| format!("route = {route}")));
        lines.extend(self.dns.iter().map(|server| format!("dns = {server}")));
        if let Some(limit) = self.download {
            lines.push(format!("tx-data-per-sec = {limit}"));
        }
        if let Some(limit) = self.upload {
            lines.push(format!("rx-data-per-sec = {limit}"));
        }
        if let Some(restrict) = self.restrict {
            lines.push(format!("restrict-user-to-routes = {restrict}"));
        }
        lines.extend(extras::lines(&self.extra)?);
        Ok(lines)
    }
}

/// The settings as a form sends them: one route or DNS server per line,
/// limits in megabits per second, and the restriction as `inherit`, `yes`
/// or `no`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Form {
    pub fixed_ipv4: String,
    pub routes: String,
    pub dns: String,
    pub download: String,
    pub upload: String,
    pub restrict: String,
    /// The fields of the options beyond these six, by ocserv option.
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
}

/// Checks a form for `owner`. `context` holds the server's pools, inside
/// whose IPv4 pool a fixed address must lie, and the other groups' pools;
/// `taken` the fixed addresses other users already have.
pub fn check(
    form: &Form,
    owner: Owner,
    context: &extras::Context<'_>,
    taken: &[(String, Ipv4Addr)],
) -> Result<Overrides, String> {
    let pool = context.pool;
    let fixed_ipv4 = match form.fixed_ipv4.trim() {
        "" => None,
        text => {
            if owner == Owner::Group {
                return Err("a fixed VPN address belongs to a user, not a group".to_owned());
            }
            let address: Ipv4Addr = text
                .parse()
                .map_err(|error| format!("'{text}' is not an IPv4 address: {error}"))?;
            if let Some(pool) = pool {
                if !pool.contains(IpAddr::V4(address)) {
                    return Err(format!(
                        "{address} is outside the VPN's address pool, {pool}"
                    ));
                }
                let (first, last) = pool.edges();
                if first == IpAddr::V4(address) || last == IpAddr::V4(address) {
                    return Err(format!(
                        "{address} is the pool's network or broadcast address"
                    ));
                }
            }
            if let Some((user, _)) = taken.iter().find(|(_, other)| *other == address) {
                return Err(format!("{address} is already the fixed address of {user}"));
            }
            Some(address.to_string())
        }
    };
    let mut routes = Vec::new();
    for line in form
        .routes
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let route = if line.eq_ignore_ascii_case("default") {
            "default".to_owned()
        } else {
            Network::parse(line)
                .map_err(|error| format!("in the routes, {error}"))?
                .to_string()
        };
        if !routes.contains(&route) {
            routes.push(route);
        }
    }
    if routes.len() > 1 && routes.iter().any(|route| route == "default") {
        return Err(
            "\"default\" sends every network through the tunnel, so it takes no other routes"
                .to_owned(),
        );
    }
    let mut dns = Vec::new();
    for line in form
        .dns
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let server: IpAddr = line
            .parse()
            .map_err(|error| format!("DNS server '{line}' is not an IP address: {error}"))?;
        let server = server.to_string();
        if !dns.contains(&server) {
            dns.push(server);
        }
    }
    let restrict = match form.restrict.as_str() {
        "" | "inherit" => None,
        "yes" => Some(true),
        "no" => Some(false),
        other => {
            return Err(format!(
                "'{other}' is not a choice for the route restriction"
            ));
        }
    };
    Ok(Overrides {
        fixed_ipv4,
        routes,
        dns,
        download: limit(&form.download, "download limit")?,
        upload: limit(&form.upload, "upload limit")?,
        restrict,
        extra: extras::check(&form.extra, owner, context)?,
    })
}

/// A limit typed in Mbps, as bytes per second; none when empty.
pub fn limit(text: &str, what: &str) -> Result<Option<u64>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let megabits: f64 = text
        .parse()
        .map_err(|error| format!("the {what} '{text}' is not a number: {error}"))?;
    if !megabits.is_finite() || megabits <= 0.0 || megabits > 100_000.0 {
        return Err(format!(
            "the {what} must be more than 0 Mbps and at most 100000 Mbps"
        ));
    }
    let bytes = (megabits * BYTES_PER_MEGABIT).round();
    if bytes < MIN_LIMIT as f64 {
        return Err(format!(
            "the {what} must be at least 0.01 Mbps, the least ocserv can enforce"
        ));
    }
    // The bounds above keep the value positive and well inside u64.
    Ok(Some(bytes as u64))
}

/// The settings in words, for the audit log: "routes 10.20.0.0/16, DNS
/// 10.20.0.53, download limit 50 Mbps", or "nothing" when none is set.
pub fn describe(settings: &Overrides) -> String {
    let mut parts = Vec::new();
    if let Some(address) = &settings.fixed_ipv4 {
        parts.push(format!("fixed address {address}"));
    }
    if !settings.routes.is_empty() {
        parts.push(format!("routes {}", settings.routes.join(" and ")));
    }
    if !settings.dns.is_empty() {
        parts.push(format!("DNS {}", settings.dns.join(" and ")));
    }
    if let Some(limit) = settings.download {
        parts.push(format!("download limit {}", rate(limit)));
    }
    if let Some(limit) = settings.upload {
        parts.push(format!("upload limit {}", rate(limit)));
    }
    match settings.restrict {
        Some(true) => parts.push("held to its routes".to_owned()),
        Some(false) => parts.push("not held to its routes".to_owned()),
        None => {}
    }
    parts.extend(extras::describe(&settings.extra));
    if parts.is_empty() {
        "nothing".to_owned()
    } else {
        parts.join(", ")
    }
}

/// A limit with its unit: "50 Mbps", "0.5 Mbps".
pub fn rate(bytes: u64) -> String {
    format!("{} Mbps", megabits(bytes))
}

/// A limit in bytes per second as Mbps, for a form: up to three decimals,
/// without trailing zeros.
pub fn megabits(bytes: u64) -> String {
    let text = format!("{:.3}", bytes as f64 / BYTES_PER_MEGABIT);
    text.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// The server's IPv4 pool, from `ipv4-network`, with `ipv4-netmask` when
/// the network has no prefix; none when the configuration sets no pool.
pub fn pool(config: &ServerConfig) -> Result<Option<Network>, String> {
    let Some(network) = config.last(&["ipv4-network"]) else {
        return Ok(None);
    };
    let text = match (network.contains('/'), config.last(&["ipv4-netmask"])) {
        (false, Some(mask)) => {
            let mask: Ipv4Addr = mask
                .parse()
                .map_err(|error| format!("the VPN's ipv4-netmask '{mask}': {error}"))?;
            let bits = u32::from(mask);
            if bits.leading_ones() + bits.trailing_zeros() != 32 {
                return Err(format!("the VPN's ipv4-netmask {mask} is not contiguous"));
            }
            format!("{network}/{}", bits.leading_ones())
        }
        (true, _) | (false, None) => network.to_owned(),
    };
    Network::parse(&text).map(Some)
}

/// A network as ocserv's iroute option takes it: in CIDR form, or for IPv4
/// with a dotted netmask, as 10.10.0.0/255.255.255.0.
pub fn route_network(value: &str) -> Result<Network, String> {
    if let Some((address, mask)) = value.split_once('/')
        && mask.contains('.')
    {
        let parsed: Ipv4Addr = mask
            .parse()
            .map_err(|error| format!("'{value}' has no valid netmask: {error}"))?;
        let bits = u32::from(parsed);
        if bits.leading_ones() + bits.trailing_zeros() != 32 {
            return Err(format!("the netmask of '{value}' is not contiguous"));
        }
        return Network::parse(&format!("{address}/{}", bits.leading_ones()));
    }
    Network::parse(value)
}

/// A user or group name that is a file name in its directory: a name the
/// password file can hold, other than `.` and `..`.
pub fn check_owner_name(name: &str, owner: Owner) -> Result<(), String> {
    vpnusers::check_name(name, &format!("{} name", owner.noun()))?;
    if name == "." || name == ".." {
        return Err(format!("'{name}' cannot be a {} name", owner.noun()));
    }
    Ok(())
}

/// The per-user and per-group directories ocserv reads, as its running
/// configuration names them; none when it reads no such files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directories {
    pub users: Option<PathBuf>,
    pub groups: Option<PathBuf>,
}

impl Directories {
    pub fn of(config: &ServerConfig) -> Directories {
        let dir = |name: &str| config.last(&[name]).map(PathBuf::from);
        Directories {
            users: dir("config-per-user"),
            groups: dir("config-per-group"),
        }
    }

    pub fn of_owner(&self, owner: Owner) -> Option<&Path> {
        match owner {
            Owner::User => self.users.as_deref(),
            Owner::Group => self.groups.as_deref(),
        }
    }

    /// The settings in `name`'s file; none when it has no file.
    pub fn read(&self, owner: Owner, name: &str) -> Result<Option<Overrides>, String> {
        let Some(dir) = self.of_owner(owner) else {
            return Ok(None);
        };
        check_owner_name(name, owner)?;
        let path = dir.join(name);
        match fs::read_to_string(&path) {
            Ok(text) => Overrides::from_config(&ServerConfig::parse(&text))
                .map(Some)
                .map_err(|error| format!("{}: {error}", path.display())),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    /// Replaces the managed settings in `name`'s file, keeping its other
    /// lines, and creates the file when it has none.
    pub fn write(&self, owner: Owner, name: &str, overrides: &Overrides) -> Result<(), String> {
        let dir = self.of_owner(owner).ok_or_else(|| unread(owner))?;
        check_owner_name(name, owner)?;
        let path = dir.join(name);
        let existing = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let mut lines: Vec<String> = existing
            .lines()
            .filter(|line| !is_managed(line))
            .map(str::to_owned)
            .collect();
        lines.extend(overrides.lines()?);
        let mut text = lines.join("\n");
        text.push('\n');
        files::write_private(&path, text.as_bytes())
    }

    /// Removes `name`'s file; false when it had none.
    pub fn remove(&self, owner: Owner, name: &str) -> Result<bool, String> {
        let dir = self.of_owner(owner).ok_or_else(|| unread(owner))?;
        check_owner_name(name, owner)?;
        let path = dir.join(name);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    /// The names that have a file in the owner's directory, sorted.
    pub fn names(&self, owner: Owner) -> Result<Vec<String>, String> {
        let Some(dir) = self.of_owner(owner) else {
            return Ok(Vec::new());
        };
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("{}: {error}", dir.display())),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if check_owner_name(&name, owner).is_ok() && !name.ends_with(".tmp") {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }

    /// The address pools the groups' files give, but `except`'s.
    pub fn group_pools(&self, except: Option<&str>) -> Result<Vec<(String, Network)>, String> {
        let mut pools = Vec::new();
        for name in self.names(Owner::Group)? {
            if except == Some(name.as_str()) {
                continue;
            }
            let Some(settings) = self.read(Owner::Group, &name)? else {
                continue;
            };
            if let Some(pool) = settings
                .extra
                .get("ipv4-network")
                .and_then(|values| values.first())
            {
                let network = Network::parse(pool)
                    .map_err(|error| format!("the pool of group {name}: {error}"))?;
                pools.push((name, network));
            }
        }
        Ok(pools)
    }

    /// The networks the users' and groups' files publish with iroute, each
    /// with the user or group that publishes it.
    pub fn publishers(&self) -> Result<Vec<(Owner, String, Network)>, String> {
        let mut published = Vec::new();
        for owner in [Owner::User, Owner::Group] {
            for name in self.names(owner)? {
                let Some(settings) = self.read(owner, &name)? else {
                    continue;
                };
                for value in settings.extra.get("iroute").into_iter().flatten() {
                    let network = route_network(value).map_err(|error| {
                        format!("a network {} {name} publishes: {error}", owner.noun())
                    })?;
                    published.push((owner, name.clone(), network));
                }
            }
        }
        Ok(published)
    }

    /// The networks the users' and groups' files publish, but `except`'s,
    /// each with who publishes it, as "user alex" or "group lab".
    pub fn published(&self, except: (Owner, &str)) -> Result<Vec<(String, Network)>, String> {
        Ok(self
            .publishers()?
            .into_iter()
            .filter(|(owner, name, _network)| (*owner, name.as_str()) != except)
            .map(|(owner, name, network)| (format!("{} {name}", owner.noun()), network))
            .collect())
    }

    /// The fixed addresses the users' files give, but `except`'s.
    pub fn fixed_addresses(&self, except: &str) -> Result<Vec<(String, Ipv4Addr)>, String> {
        let mut taken = Vec::new();
        for name in self.names(Owner::User)? {
            if name == except {
                continue;
            }
            if let Some(address) = self
                .read(Owner::User, &name)?
                .and_then(|overrides| overrides.fixed_ipv4)
            {
                let parsed = address.parse().map_err(|error| {
                    format!("the fixed address of {name}, '{address}', is not IPv4: {error}")
                })?;
                taken.push((name, parsed));
            }
        }
        Ok(taken)
    }
}

/// Why settings cannot be written when ocserv reads no such files.
fn unread(owner: Owner) -> String {
    format!(
        "the VPN server reads no per-{} settings: its configuration sets no config-per-{}",
        owner.noun(),
        owner.noun()
    )
}

/// Whether a line of a per-user or per-group file sets an option the panel
/// manages.
fn is_managed(line: &str) -> bool {
    line.split_once('=')
        .is_some_and(|(name, _)| MANAGED.contains(&name.trim()) || extras::manages(name.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    fn form(pairs: &[(&str, &str)]) -> Form {
        let mut form = Form::default();
        for (name, value) in pairs {
            let value = (*value).to_owned();
            match *name {
                "fixed_ipv4" => form.fixed_ipv4 = value,
                "routes" => form.routes = value,
                "dns" => form.dns = value,
                "download" => form.download = value,
                "upload" => form.upload = value,
                "restrict" => form.restrict = value,
                other => panic!("no field {other}"),
            }
        }
        form
    }

    fn pool() -> Network {
        Network::parse("192.168.255.0/24").unwrap()
    }

    fn context(pool: Option<&Network>) -> extras::Context<'_> {
        extras::Context {
            pool,
            pool6: None,
            group_pools: &[],
            published: &[],
            local: &[],
        }
    }

    #[test]
    fn a_form_becomes_settings() {
        let pool = pool();
        let checked = check(
            &form(&[
                ("fixed_ipv4", " 192.168.255.50 "),
                ("routes", "10.20.0.0/16\n\n10.20.0.0/16\nfd00::/8\n"),
                ("dns", "10.20.0.53\n2001:db8::53"),
                ("download", "50"),
                ("upload", "0.5"),
                ("restrict", "yes"),
            ]),
            Owner::User,
            &context(Some(&pool)),
            &[],
        )
        .unwrap();
        assert_eq!(
            checked,
            Overrides {
                fixed_ipv4: Some("192.168.255.50".to_owned()),
                routes: vec!["10.20.0.0/16".to_owned(), "fd00::/8".to_owned()],
                dns: vec!["10.20.0.53".to_owned(), "2001:db8::53".to_owned()],
                download: Some(6_250_000),
                upload: Some(62_500),
                restrict: Some(true),
                extra: BTreeMap::new(),
            }
        );
        assert_eq!(megabits(6_250_000), "50");
        assert_eq!(megabits(62_500), "0.5");
        assert_eq!(
            check(&Form::default(), Owner::Group, &context(None), &[]).unwrap(),
            Overrides::default()
        );
    }

    #[test]
    fn bad_forms_are_refused() {
        let taken = [("jo".to_owned(), Ipv4Addr::new(192, 168, 255, 9))];
        for (pairs, owner) in [
            (vec![("fixed_ipv4", "192.168.255.50")], Owner::Group),
            (vec![("fixed_ipv4", "10.0.0.1")], Owner::User),
            (vec![("fixed_ipv4", "192.168.255.255")], Owner::User),
            (vec![("fixed_ipv4", "192.168.255.9")], Owner::User),
            (vec![("fixed_ipv4", "fd00::1")], Owner::User),
            (vec![("routes", "default\n10.0.0.0/8")], Owner::User),
            (vec![("routes", "10.0.0.0/33")], Owner::User),
            (vec![("dns", "resolver.example")], Owner::User),
            (vec![("download", "-1")], Owner::User),
            (vec![("download", "0.001")], Owner::User),
            (vec![("upload", "lots")], Owner::User),
            (vec![("restrict", "maybe")], Owner::User),
        ] {
            let pool = pool();
            assert!(
                check(&form(&pairs), owner, &context(Some(&pool)), &taken).is_err(),
                "{pairs:?}"
            );
        }
    }

    #[test]
    fn the_pool_comes_from_the_network_and_its_netmask() {
        let pool_text = |text: &str| {
            super::pool(&ServerConfig::parse(text))
                .map(|found| found.map(|network| network.to_string()))
        };
        assert_eq!(
            pool_text("ipv4-network = 192.168.255.0/24\n")
                .unwrap()
                .as_deref(),
            Some("192.168.255.0/24")
        );
        assert_eq!(
            pool_text("ipv4-network = 10.10.0.0\nipv4-netmask = 255.255.0.0\n")
                .unwrap()
                .as_deref(),
            Some("10.10.0.0/16")
        );
        assert!(pool_text("ipv4-network = 10.10.0.0\nipv4-netmask = 255.0.255.0\n").is_err());
        assert_eq!(pool_text("dns = 9.9.9.9\n").unwrap(), None);
    }

    #[test]
    fn a_user_file_wins_over_the_group_and_the_server() {
        let server = Overrides {
            dns: vec!["9.9.9.9".to_owned()],
            routes: vec!["default".to_owned()],
            ..Overrides::default()
        };
        let group = Overrides {
            routes: vec!["10.20.0.0/16".to_owned()],
            download: Some(1_000_000),
            ..Overrides::default()
        };
        let user = Overrides {
            download: Some(2_000_000),
            restrict: Some(false),
            ..Overrides::default()
        };
        let effective = user.over(&group.over(&server));
        assert_eq!(effective.routes, ["10.20.0.0/16"]);
        assert_eq!(effective.dns, ["9.9.9.9"]);
        assert_eq!(effective.download, Some(2_000_000));
        assert_eq!(effective.restrict, Some(false));
    }

    #[test]
    fn files_keep_their_other_lines_and_names_stay_inside_their_directory() {
        let dir = TestDir::new();
        let groups = dir.path().join("config-per-group");
        let users = dir.path().join("config-per-user");
        fs::create_dir_all(&groups).unwrap();
        fs::create_dir_all(&users).unwrap();
        fs::write(
            groups.join("staff"),
            "# kept\nroute = 10.0.0.0/8\nipv6-subnet-prefix = 64\nkeepalive = 60\ndns = 1.1.1.1\n",
        )
        .unwrap();
        let directories = Directories {
            users: Some(users.clone()),
            groups: Some(groups.clone()),
        };
        let staff = Overrides {
            routes: vec!["10.20.0.0/16".to_owned()],
            upload: Some(125_000),
            extra: [("idle-timeout".to_owned(), vec!["900".to_owned()])].into(),
            ..Overrides::default()
        };
        directories.write(Owner::Group, "staff", &staff).unwrap();
        assert_eq!(
            fs::read_to_string(groups.join("staff")).unwrap(),
            "# kept\nipv6-subnet-prefix = 64\nroute = 10.20.0.0/16\nrx-data-per-sec = 125000\n\
             idle-timeout = 900\n"
        );
        assert_eq!(
            directories.read(Owner::Group, "staff").unwrap(),
            Some(staff)
        );
        assert_eq!(directories.read(Owner::Group, "contractors").unwrap(), None);
        assert_eq!(directories.names(Owner::Group).unwrap(), ["staff"]);
        for bad in ["..", ".", "a/b", ""] {
            assert!(
                directories
                    .write(Owner::User, bad, &Overrides::default())
                    .is_err(),
                "{bad}"
            );
        }
        let fixed = Overrides {
            fixed_ipv4: Some("192.168.255.9".to_owned()),
            ..Overrides::default()
        };
        directories.write(Owner::User, "jo", &fixed).unwrap();
        assert_eq!(
            directories.fixed_addresses("sam").unwrap(),
            [("jo".to_owned(), Ipv4Addr::new(192, 168, 255, 9))]
        );
        assert!(directories.fixed_addresses("jo").unwrap().is_empty());
        assert!(directories.remove(Owner::User, "jo").unwrap());
        assert!(!directories.remove(Owner::User, "jo").unwrap());
        let unread = Directories {
            users: None,
            groups: None,
        };
        assert!(
            unread
                .write(Owner::Group, "staff", &Overrides::default())
                .is_err()
        );
        assert_eq!(unread.read(Owner::Group, "staff").unwrap(), None);
    }

    #[test]
    fn published_networks_come_with_who_publishes_them() {
        let dir = TestDir::new();
        let groups = dir.path().join("config-per-group");
        let users = dir.path().join("config-per-user");
        fs::create_dir_all(&groups).unwrap();
        fs::create_dir_all(&users).unwrap();
        fs::write(
            users.join("branch"),
            "iroute = 10.10.0.0/24\niroute = 10.11.0.0/255.255.255.0\n",
        )
        .unwrap();
        fs::write(groups.join("lab"), "iroute = fd00:10::/64\n").unwrap();
        let directories = Directories {
            users: Some(users.clone()),
            groups: Some(groups),
        };
        let net = |text: &str| Network::parse(text).unwrap();
        assert_eq!(
            directories.publishers().unwrap(),
            [
                (Owner::User, "branch".to_owned(), net("10.10.0.0/24")),
                (Owner::User, "branch".to_owned(), net("10.11.0.0/24")),
                (Owner::Group, "lab".to_owned(), net("fd00:10::/64")),
            ]
        );
        assert_eq!(
            directories.published((Owner::User, "branch")).unwrap(),
            [("group lab".to_owned(), net("fd00:10::/64"))]
        );
        assert_eq!(
            route_network("10.12.0.0/255.255.0.0").unwrap(),
            net("10.12.0.0/16")
        );
        for bad in ["10.12.0.0/255.0.255.0", "10.12.0.0/255.255.0", "nonsense"] {
            assert!(route_network(bad).is_err(), "{bad}");
        }
        fs::write(users.join("branch"), "iroute = 10.10.0.0/nonsense\n").unwrap();
        let error = directories.publishers().unwrap_err();
        assert!(error.contains("user branch"), "{error}");
    }
}
