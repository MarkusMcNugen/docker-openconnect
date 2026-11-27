//! The per-user and per-group options beyond the six overrides.rs manages
//! by hand: what each holds, how a value is checked, and how it is written.
//! ocserv 1.6.0 refuses a user's session when their file is malformed, so
//! every value the panel writes is checked first.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::net::Network;
use crate::overrides::Owner;
use crate::serverconf::ServerConfig;

/// What an option holds, which decides how its value is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// On or off.
    Switch,
    /// A whole number of seconds, at least 1.
    Seconds,
    /// A whole number from `min` to `max`.
    Number { min: u64, max: u64 },
    /// Domain names, one per line.
    Domains,
    /// Networks in CIDR form, one per line.
    Networks,
    /// One IP address.
    Address,
    /// An IPv6 address inside the server's IPv6 pool.
    Address6,
    /// A private IPv4 network of the group's own, which overlaps the
    /// server's pools and every other group's pool nowhere.
    Pool,
    /// ocserv-fw port rules: `proto(port)` items separated by commas, all
    /// inside `!( )` to block those ports instead.
    Ports,
    /// Networks behind the user, in CIDR form, one per line, for
    /// site-to-site: none may overlap the VPN's pools, a group's pool, the
    /// container's own networks or another user's or group's.
    Published,
}

/// An option beyond the six, as the settings pages offer it.
pub struct Extra {
    pub option: &'static str,
    pub kind: Kind,
    pub label: &'static str,
    /// The owner it belongs to, when only users or only groups take it.
    pub only: Option<Owner>,
}

const fn extra(option: &'static str, kind: Kind, label: &'static str) -> Extra {
    Extra {
        option,
        kind,
        label,
        only: None,
    }
}

/// The options in the order the pages show them.
pub const EXTRAS: &[Extra] = &[
    extra(
        "split-dns",
        Kind::Domains,
        "Domains resolved through the VPN only",
    ),
    extra(
        "tunnel-all-dns",
        Kind::Switch,
        "Send every DNS query through the tunnel",
    ),
    extra(
        "no-route",
        Kind::Networks,
        "Networks kept out of the tunnel",
    ),
    extra("nbns", Kind::Address, "NetBIOS name server"),
    Extra {
        option: "ipv4-network",
        kind: Kind::Pool,
        label: "Address pool",
        only: Some(Owner::Group),
    },
    Extra {
        option: "explicit-ipv6",
        kind: Kind::Address6,
        label: "Fixed IPv6 address",
        only: Some(Owner::User),
    },
    extra(
        "max-same-clients",
        Kind::Number {
            min: 0,
            max: u32::MAX as u64,
        },
        "Most sessions at once",
    ),
    extra("idle-timeout", Kind::Seconds, "Disconnect after idle"),
    extra(
        "mobile-idle-timeout",
        Kind::Seconds,
        "Disconnect phones after idle",
    ),
    extra("session-timeout", Kind::Seconds, "Longest session"),
    extra("keepalive", Kind::Seconds, "Keepalive"),
    extra("dpd", Kind::Seconds, "Dead peer detection"),
    extra(
        "mobile-dpd",
        Kind::Seconds,
        "Dead peer detection for phones",
    ),
    extra("stats-report-time", Kind::Seconds, "Report traffic every"),
    extra(
        "mtu",
        Kind::Number {
            min: 1280,
            max: 9000,
        },
        "MTU",
    ),
    extra(
        "net-priority",
        Kind::Number { min: 0, max: 6 },
        "Packet priority",
    ),
    extra(
        "restrict-user-to-ports",
        Kind::Ports,
        "Ports the user may reach",
    ),
    extra(
        "deny-roaming",
        Kind::Switch,
        "Keep a session on one address",
    ),
    extra("no-udp", Kind::Switch, "TCP only, without the UDP channel"),
    Extra {
        option: "iroute",
        kind: Kind::Published,
        label: "Site-to-site networks behind this user",
        only: Some(Owner::User),
    },
];

/// The option named `option`, if it is one of these.
pub fn extra_of(option: &str) -> Option<&'static Extra> {
    EXTRAS.iter().find(|extra| extra.option == option)
}

/// Whether a file line's option is one of these, or the netmask written
/// with a group's pool.
pub fn manages(option: &str) -> bool {
    option == "ipv4-netmask" || extra_of(option).is_some()
}

/// What the checks need besides the value.
pub struct Context<'a> {
    /// The server's IPv4 and IPv6 pools.
    pub pool: Option<&'a Network>,
    pub pool6: Option<&'a Network>,
    /// The other groups' pools.
    pub group_pools: &'a [(String, Network)],
    /// The networks other users and groups publish, each with who does, as
    /// "user alex" or "group lab".
    pub published: &'a [(String, Network)],
    /// The networks the container's own interfaces reach.
    pub local: &'a [Network],
}

/// Every option's values in a file's lines; a group's pool as one network
/// in CIDR form.
pub fn from_config(config: &ServerConfig) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut values = BTreeMap::new();
    for extra in EXTRAS {
        let found: Vec<String> = if extra.kind == Kind::Pool {
            match crate::overrides::pool(config)? {
                Some(network) => vec![network.to_string()],
                None => Vec::new(),
            }
        } else {
            config
                .values(extra.option)
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        if !found.is_empty() {
            values.insert(extra.option.to_owned(), found);
        }
    }
    Ok(values)
}

/// The lines that write `values`, in the order of EXTRAS.
pub fn lines(values: &BTreeMap<String, Vec<String>>) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    for extra in EXTRAS {
        let Some(found) = values.get(extra.option) else {
            continue;
        };
        for value in found {
            match extra.kind {
                Kind::Pool => {
                    let network = Network::parse(value)
                        .map_err(|error| format!("the stored pool: {error}"))?;
                    let (IpAddr::V4(first), _) = network.edges() else {
                        return Err(format!("the stored pool {value} is not IPv4"));
                    };
                    lines.push(format!("ipv4-network = {first}"));
                    lines.push(format!("ipv4-netmask = {}", netmask(&network)?));
                }
                Kind::Ports => lines.push(format!("{} = \"{value}\"", extra.option)),
                _ => lines.push(format!("{} = {value}", extra.option)),
            }
        }
    }
    Ok(lines)
}

/// The dotted netmask of an IPv4 network.
fn netmask(network: &Network) -> Result<Ipv4Addr, String> {
    let (IpAddr::V4(first), IpAddr::V4(last)) = network.edges() else {
        return Err(format!("{network} is not IPv4"));
    };
    Ok(Ipv4Addr::from(!(u32::from(first) ^ u32::from(last))))
}

/// The values typed into the form fields of the options, by option, each
/// checked and in the form ocserv reads; an empty field or "inherit"
/// leaves the option to the group or the server.
pub fn check(
    form: &BTreeMap<String, String>,
    owner: Owner,
    context: &Context<'_>,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut values = BTreeMap::new();
    for (option, text) in form {
        let Some(extra) = extra_of(option) else {
            return Err(format!("{option} is not a setting this page changes"));
        };
        let text = text.trim();
        if text.is_empty() || text == "inherit" {
            continue;
        }
        if extra.only.is_some_and(|only| only != owner) {
            return Err(format!(
                "{} belongs to a {}, not a {}",
                extra.label,
                other(owner).noun(),
                owner.noun()
            ));
        }
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        let label = extra.label;
        let checked: Vec<String> = match extra.kind {
            Kind::Switch => match text {
                "on" | "true" => vec!["true".to_owned()],
                "off" | "false" => vec!["false".to_owned()],
                other => return Err(format!("'{other}' is not a choice for {label}")),
            },
            Kind::Seconds => vec![number(text, 1, u64::from(u32::MAX), label)?.to_string()],
            Kind::Number { min, max } => vec![number(text, min, max, label)?.to_string()],
            Kind::Domains => {
                for line in &lines {
                    if !line
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
                    {
                        return Err(format!("{label}: '{line}' is not a domain name"));
                    }
                }
                lines.iter().map(|line| (*line).to_owned()).collect()
            }
            Kind::Networks => {
                let mut networks = Vec::new();
                for line in &lines {
                    if !line.contains('/') {
                        return Err(format!(
                            "{label}: '{line}' needs a prefix, as in 10.0.0.0/8"
                        ));
                    }
                    networks.push(
                        Network::parse(line)
                            .map_err(|error| format!("{label}: {error}"))?
                            .to_string(),
                    );
                }
                networks
            }
            Kind::Address => {
                let address: IpAddr = text
                    .parse()
                    .map_err(|error| format!("{label}: '{text}' is not an IP address: {error}"))?;
                vec![address.to_string()]
            }
            Kind::Address6 => {
                let address: Ipv6Addr = text.parse().map_err(|error| {
                    format!("{label}: '{text}' is not an IPv6 address: {error}")
                })?;
                if let Some(pool6) = context.pool6
                    && !pool6.contains(IpAddr::V6(address))
                {
                    return Err(format!("{address} is outside the VPN's IPv6 pool, {pool6}"));
                }
                vec![address.to_string()]
            }
            Kind::Pool => vec![check_pool(text, context)?],
            Kind::Ports => vec![check_ports(text)?],
            Kind::Published => check_published(&lines, context)?,
        };
        values.insert(option.clone(), checked);
    }
    Ok(values)
}

fn other(owner: Owner) -> Owner {
    match owner {
        Owner::User => Owner::Group,
        Owner::Group => Owner::User,
    }
}

fn number(text: &str, min: u64, max: u64, label: &str) -> Result<u64, String> {
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} must be a whole number"));
    }
    let value: u64 = text
        .parse()
        .map_err(|error| format!("{label} must be a whole number: {error}"))?;
    if value < min || value > max {
        return Err(format!("{label} must be from {min} to {max}"));
    }
    Ok(value)
}

/// A group's own pool: a private IPv4 network in CIDR form that overlaps
/// the server's pools and every other group's pool nowhere.
fn check_pool(text: &str, context: &Context<'_>) -> Result<String, String> {
    if !text.contains('/') {
        return Err(format!(
            "the address pool '{text}' needs a prefix, as in 10.20.0.0/24"
        ));
    }
    let network = Network::parse(text).map_err(|error| format!("the address pool: {error}"))?;
    let (IpAddr::V4(first), IpAddr::V4(last)) = network.edges() else {
        return Err(format!("the address pool {network} is not IPv4"));
    };
    if !(first.is_private() && last.is_private()) {
        return Err(format!(
            "the address pool {network} is not a private network (10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16)"
        ));
    }
    if u32::from(last) - u32::from(first) < 3 {
        return Err(format!(
            "the address pool {network} is too small for any client"
        ));
    }
    let overlaps = |other: &Network| {
        let (other_first, other_last) = other.edges();
        network.contains(other_first)
            || network.contains(other_last)
            || other.contains(IpAddr::V4(first))
    };
    for server in [context.pool, context.pool6].into_iter().flatten() {
        if overlaps(server) {
            return Err(format!(
                "the address pool {network} overlaps the VPN's own pool, {server}"
            ));
        }
    }
    if let Some((group, _)) = context
        .group_pools
        .iter()
        .find(|(_, other)| overlaps(other))
    {
        return Err(format!(
            "the address pool {network} overlaps the pool of group {group}"
        ));
    }
    Ok(network.to_string())
}

/// Whether two networks share an address.
fn overlap(one: &Network, other: &Network) -> bool {
    let (first, last) = one.edges();
    let (other_first, _) = other.edges();
    other.contains(first) || other.contains(last) || one.contains(other_first)
}

/// Networks published behind a user, in CIDR form. ocserv routes each one to
/// the publishing session's tunnel and refuses a session whose route is
/// already there, a network inside another one would take that part of its
/// traffic, and a network over the VPN's pools or the container's own would
/// take theirs, so each overlap is refused.
fn check_published(lines: &[&str], context: &Context<'_>) -> Result<Vec<String>, String> {
    let mut networks: Vec<Network> = Vec::new();
    for line in lines {
        if !line.contains('/') {
            return Err(format!(
                "the network '{line}' needs a prefix, as in 10.10.0.0/24"
            ));
        }
        let network = Network::parse(line).map_err(|error| format!("the network: {error}"))?;
        for server in [context.pool, context.pool6].into_iter().flatten() {
            if overlap(&network, server) {
                return Err(format!(
                    "the network {network} overlaps the VPN's own pool, {server}"
                ));
            }
        }
        if let Some((group, _)) = context
            .group_pools
            .iter()
            .find(|(_, pool)| overlap(&network, pool))
        {
            return Err(format!(
                "the network {network} overlaps the address pool of group {group}"
            ));
        }
        if let Some(local) = context.local.iter().find(|local| overlap(&network, local)) {
            return Err(format!(
                "the network {network} overlaps the container's own network {local}"
            ));
        }
        if let Some((owner, other)) = context
            .published
            .iter()
            .find(|(_, other)| overlap(&network, other))
        {
            return Err(format!(
                "the network {network} overlaps {other}, which {owner} publishes"
            ));
        }
        if let Some(twice) = networks.iter().find(|other| overlap(&network, other)) {
            return Err(format!("the networks {network} and {twice} overlap"));
        }
        networks.push(network);
    }
    Ok(networks.iter().map(ToString::to_string).collect())
}

/// ocserv-fw port rules, normalized with one space after each comma.
fn check_ports(text: &str) -> Result<String, String> {
    let compact: String = text.chars().filter(|char| !char.is_whitespace()).collect();
    let (negated, inner) = match compact
        .strip_prefix("!(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        Some(inner) => (true, inner),
        None => (false, compact.as_str()),
    };
    let mut rules = Vec::new();
    for item in inner.split("),").map(|item| item.trim_end_matches(')')) {
        let Some((protocol, port)) = item.split_once('(') else {
            return Err(format!("'{item}' is not a rule like tcp(443)"));
        };
        match protocol {
            "tcp" | "udp" | "sctp" => {
                number(port, 1, 65_535, "a port")?;
            }
            "icmp" | "icmpv6" => {
                if !port.is_empty() {
                    return Err(format!("{protocol}() takes no port"));
                }
            }
            other => {
                return Err(format!(
                    "'{other}' is not a protocol the firewall knows: tcp, udp, sctp, icmp or icmpv6"
                ));
            }
        }
        rules.push(format!("{protocol}({port})"));
    }
    let joined = rules.join(", ");
    Ok(if negated {
        format!("!({joined})")
    } else {
        joined
    })
}

/// The options set in `values`, in words, for the audit log.
pub fn describe(values: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    EXTRAS
        .iter()
        .filter_map(|extra| {
            values
                .get(extra.option)
                .map(|found| format!("{} {}", extra.option, found.join(" and ")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(option, value)| ((*option).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn context<'a>(
        pool: &'a Network,
        pool6: &'a Network,
        groups: &'a [(String, Network)],
    ) -> Context<'a> {
        Context {
            pool: Some(pool),
            pool6: Some(pool6),
            group_pools: groups,
            published: &[],
            local: &[],
        }
    }

    #[test]
    fn published_networks_overlap_nothing_the_server_or_others_use() {
        let pool = Network::parse("192.168.255.0/24").unwrap();
        let pool6 = Network::parse("fd3e:7a0c:5b19::/48").unwrap();
        let groups = [("staff".to_owned(), Network::parse("10.30.0.0/24").unwrap())];
        let published = [(
            "user branch".to_owned(),
            Network::parse("10.50.0.0/16").unwrap(),
        )];
        let local = [Network::parse("172.17.0.0/16").unwrap()];
        let context = Context {
            published: &published,
            local: &local,
            ..context(&pool, &pool6, &groups)
        };
        let publish = |text: &str| check(&form(&[("iroute", text)]), Owner::User, &context);
        let values = publish("10.10.0.0/24\n10.11.0.0/24").unwrap();
        assert_eq!(values["iroute"], ["10.10.0.0/24", "10.11.0.0/24"]);
        assert_eq!(
            lines(&values).unwrap(),
            ["iroute = 10.10.0.0/24", "iroute = 10.11.0.0/24"]
        );
        for (text, fault) in [
            ("10.10.0.0", "needs a prefix"),
            ("192.168.0.0/16", "VPN's own pool"),
            ("10.30.0.128/25", "pool of group staff"),
            ("172.17.5.0/24", "container's own network"),
            ("10.50.1.0/24", "which user branch publishes"),
            ("10.60.0.0/24\n10.60.0.0/16", "overlap"),
        ] {
            let error = publish(text).unwrap_err();
            assert!(error.contains(fault), "{text}: {error}");
        }
    }

    #[test]
    fn values_are_checked_and_written_as_ocserv_reads_them() {
        let pool = Network::parse("192.168.255.0/24").unwrap();
        let pool6 = Network::parse("fd3e:7a0c:5b19::/48").unwrap();
        let groups = [("staff".to_owned(), Network::parse("10.30.0.0/24").unwrap())];
        let context = context(&pool, &pool6, &groups);
        let values = check(
            &form(&[
                ("split-dns", "corp.example.com\n\nlab.example.com"),
                ("tunnel-all-dns", "off"),
                ("idle-timeout", "1200"),
                ("ipv4-network", "10.20.0.7/24"),
                ("restrict-user-to-ports", "tcp(443),udp( 53 )"),
                ("no-udp", "inherit"),
            ]),
            Owner::Group,
            &context,
        )
        .unwrap();
        assert_eq!(values["ipv4-network"], ["10.20.0.0/24"]);
        assert!(!values.contains_key("no-udp"));
        assert_eq!(
            lines(&values).unwrap(),
            [
                "split-dns = corp.example.com",
                "split-dns = lab.example.com",
                "tunnel-all-dns = false",
                "ipv4-network = 10.20.0.0",
                "ipv4-netmask = 255.255.255.0",
                "idle-timeout = 1200",
                "restrict-user-to-ports = \"tcp(443), udp(53)\"",
            ]
        );
        let read = from_config(&ServerConfig::parse(&lines(&values).unwrap().join("\n"))).unwrap();
        assert_eq!(read, values);
    }

    #[test]
    fn values_ocserv_would_refuse_are_refused() {
        let pool = Network::parse("192.168.255.0/24").unwrap();
        let pool6 = Network::parse("fd3e:7a0c:5b19::/48").unwrap();
        let groups = [("staff".to_owned(), Network::parse("10.30.0.0/24").unwrap())];
        let context = context(&pool, &pool6, &groups);
        for (option, value, owner) in [
            ("ipv4-network", "192.168.255.128/26", Owner::Group),
            ("ipv4-network", "10.30.0.128/25", Owner::Group),
            ("ipv4-network", "8.8.8.0/24", Owner::Group),
            ("ipv4-network", "10.20.0.0", Owner::Group),
            ("ipv4-network", "10.20.0.0/24", Owner::User),
            ("iroute", "10.10.0.0/24", Owner::Group),
            ("explicit-ipv6", "fd00::1", Owner::User),
            ("mtu", "576", Owner::User),
            ("net-priority", "7", Owner::User),
            ("idle-timeout", "0", Owner::User),
            ("split-dns", "bad domain", Owner::User),
            ("no-route", "10.0.0.1", Owner::User),
            ("restrict-user-to-ports", "http(80)", Owner::User),
            ("restrict-user-to-ports", "tcp(70000)", Owner::User),
            ("tunnel-all-dns", "maybe", Owner::User),
            ("listen-host", "x", Owner::User),
        ] {
            assert!(
                check(&form(&[(option, value)]), owner, &context).is_err(),
                "{option} = {value} accepted"
            );
        }
        assert_eq!(
            check(
                &form(&[("restrict-user-to-ports", "!( tcp(25), icmp() )")]),
                Owner::User,
                &context
            )
            .unwrap()["restrict-user-to-ports"],
            ["!(tcp(25), icmp())"]
        );
    }
}
