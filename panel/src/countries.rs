//! Country rules: new connections to the VPN's ports, the panel's and the
//! portal's are dropped when they come from listed countries (block), or
//! from any country but the listed ones (allow). Loopback, private and
//! link-local ranges and the exempt networks always pass, and connections
//! already open are left alone.
//!
//! The rules live in their own nftables table. Country lists run to tens of
//! thousands of ranges, so they load in batches that a container in a user
//! namespace can send, each batch into a set of its own, and a reload fills
//! the generation of sets the rules do not read before it points the rules
//! at it in one transaction: the rules in force only ever read whole sets.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use maxminddb::{Reader, WithinOptions, geoip2};
use serde::{Deserialize, Serialize};

use crate::files;
use crate::net::Network;

/// A country database in MaxMind's format with the GeoIP2 Country layout:
/// DB-IP Lite, which the image carries, or MaxMind GeoLite2.
pub struct Countries {
    reader: Reader<Vec<u8>>,
}

impl Countries {
    pub fn open(path: &Path) -> Result<Countries, String> {
        let reader = Reader::open_readfile(path).map_err(|error| {
            format!(
                "the country database {} cannot be read: {error}",
                path.display()
            )
        })?;
        Ok(Countries { reader })
    }

    /// A database held in memory, as a download before it is installed.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Countries, String> {
        let reader = Reader::from_source(bytes)
            .map_err(|error| format!("the data is not a country database: {error}"))?;
        Ok(Countries { reader })
    }

    /// Every network the database places in one of `codes`, ISO codes in
    /// any case, IPv4 and IPv6 apart.
    pub fn networks(&self, codes: &[String]) -> Result<(Vec<Network>, Vec<Network>), String> {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        let walk = self
            .reader
            .networks(WithinOptions::default())
            .map_err(|error| format!("the country database cannot be walked: {error}"))?;
        for item in walk {
            let found =
                item.map_err(|error| format!("the country database cannot be read: {error}"))?;
            let record: Option<geoip2::Country> = found
                .decode()
                .map_err(|error| format!("a country record cannot be read: {error}"))?;
            let Some(code) = record.and_then(|record| record.country.iso_code) else {
                continue;
            };
            if !codes.iter().any(|listed| listed.eq_ignore_ascii_case(code)) {
                continue;
            }
            let text = found
                .network()
                .map_err(|error| {
                    format!("a network of the country database cannot be read: {error}")
                })?
                .to_string();
            let network = Network::parse(&text)?;
            if network.is_ipv4() {
                v4.push(network);
            } else {
                v6.push(network);
            }
        }
        Ok((v4, v6))
    }

    /// The ISO 3166 code, in capitals, of the country the database places
    /// `address` in; none for an address in no country, as a private one.
    pub fn lookup(&self, address: IpAddr) -> Result<Option<String>, String> {
        let address = address.to_canonical();
        let found = self
            .reader
            .lookup(address)
            .map_err(|error| format!("{address} cannot be looked up: {error}"))?;
        let record: Option<geoip2::Country> = found
            .decode()
            .map_err(|error| format!("the country record of {address} cannot be read: {error}"))?;
        Ok(record.and_then(|record| record.country.iso_code.map(str::to_ascii_uppercase)))
    }

    /// Every country the database knows: its ISO code in capitals and its
    /// English name.
    pub fn names(&self) -> Result<BTreeMap<String, String>, String> {
        let mut names = BTreeMap::new();
        let walk = self
            .reader
            .networks(WithinOptions::default())
            .map_err(|error| format!("the country database cannot be walked: {error}"))?;
        for item in walk {
            let found =
                item.map_err(|error| format!("the country database cannot be read: {error}"))?;
            let record: Option<geoip2::Country> = found
                .decode()
                .map_err(|error| format!("a country record cannot be read: {error}"))?;
            let Some(country) = record.map(|record| record.country) else {
                continue;
            };
            if let (Some(code), Some(name)) = (country.iso_code, country.names.english) {
                names
                    .entry(code.to_ascii_uppercase())
                    .or_insert_with(|| name.to_owned());
            }
        }
        Ok(names)
    }

    /// What the database calls itself, as DBIP-Country-Lite or
    /// GeoLite2-Country.
    pub fn kind(&self) -> &str {
        &self.reader.metadata().database_type
    }

    /// When the database was built, in Unix seconds.
    pub fn built(&self) -> u64 {
        self.reader.metadata().build_epoch
    }
}

/// The table that holds the country rules.
pub const TABLE: &str = "inet vpn_countries";

/// DB-IP Lite, the country database the image carries.
pub const DBIP_DB: &str = "/usr/local/share/ocserv-docker/geo/dbip-country-lite.mmdb";

/// The database to read: MaxMind GeoLite2 under the config directory when
/// an admin's key has fetched it, else DB-IP Lite.
pub fn database_path(config_dir: &Path) -> PathBuf {
    let maxmind = crate::geoip::database_file(config_dir);
    if maxmind.exists() {
        maxmind
    } else {
        PathBuf::from(DBIP_DB)
    }
}

/// Where the panel keeps the country rules it stores.
pub fn stored_path(config_dir: &Path) -> PathBuf {
    config_dir.join("panel").join("country-rules.json")
}

/// Why country rules that are on do nothing on legacy iptables.
pub const NEEDS_NFTABLES: &str =
    "the country rules need nftables, so they are off on this legacy iptables firewall";

/// The rules a country rule may be.
const RULES: [&str; 3] = ["off", "block", "allow"];

/// The country rules the admin panel stored, beneath the environment's
/// COUNTRY_RULE and COUNTRIES.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stored {
    /// off, block or allow.
    pub rule: String,
    /// ISO 3166 codes in capitals, each once.
    pub countries: Vec<String>,
}

impl Default for Stored {
    fn default() -> Stored {
        Stored {
            rule: "off".to_owned(),
            countries: Vec::new(),
        }
    }
}

/// Reads the rules the panel stored at `path`; without the file the rule
/// is off and no country is listed.
pub fn read_stored(path: &Path) -> Result<Stored, String> {
    let stored: Stored = match fs::read_to_string(path) {
        Ok(text) => {
            serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?
        }
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Stored::default()),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if !RULES.contains(&stored.rule.as_str()) {
        return Err(format!(
            "{}: the rule {} is not off, block or allow",
            path.display(),
            stored.rule
        ));
    }
    if let Some(code) = stored.countries.iter().find(|code| !valid_code(code)) {
        return Err(format!(
            "{}: {code} is not a two-letter country code",
            path.display()
        ));
    }
    Ok(stored)
}

/// Replaces the stored rules, readable by root only.
pub fn write_stored(path: &Path, stored: &Stored) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(stored)
        .map_err(|error| format!("the country rules cannot be written: {error}"))?;
    files::write_private(path, &text)
}

/// What the container's environment gives the country rules: the rule and
/// the countries where it sets them, which the panel cannot change, and,
/// from firewall.sh, the ports the rules guard and the networks that always
/// pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// COUNTRY_RULE in lower case, when set.
    pub rule: Option<String>,
    /// COUNTRIES, when set.
    pub countries: Option<String>,
    /// COUNTRY_PORTS.
    pub ports: Vec<u16>,
    /// COUNTRY_EXEMPT.
    pub exempt: Vec<Network>,
}

impl Environment {
    /// Reads the environment through `get`, which returns a variable's value
    /// or none when it is unset. An empty value counts as unset, and
    /// COUNTRY_PORTS must be set.
    pub fn from_env<F>(get: &F) -> Result<Environment, String>
    where
        F: Fn(&str) -> Option<OsString>,
    {
        let text =
            |name: &'static str| crate::config::text(get, name).map_err(|error| error.to_string());
        let rule = match text("COUNTRY_RULE")? {
            Some(rule) => {
                let rule = rule.trim().to_ascii_lowercase();
                if !RULES.contains(&rule.as_str()) {
                    return Err(format!(
                        "COUNTRY_RULE must be off, block or allow, not {rule}"
                    ));
                }
                Some(rule)
            }
            None => None,
        };
        let Some(port_list) = text("COUNTRY_PORTS")? else {
            return Err("COUNTRY_PORTS is not set; firewall.sh sets it".to_owned());
        };
        let mut ports = Vec::new();
        for word in words(&port_list) {
            let port: u16 = word
                .parse()
                .map_err(|error| format!("COUNTRY_PORTS: {word} is not a port: {error}"))?;
            ports.push(port);
        }
        let exempt = match text("COUNTRY_EXEMPT")? {
            Some(list) => {
                crate::net::parse_list(&list).map_err(|error| format!("COUNTRY_EXEMPT: {error}"))?
            }
            None => Vec::new(),
        };
        Ok(Environment {
            rule,
            countries: text("COUNTRIES")?,
            ports,
            exempt,
        })
    }
}

/// The country rules in force: the environment's rule and countries where
/// it sets them, else the stored ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// off, block or allow.
    pub rule: String,
    /// The listed countries, separated by commas or spaces.
    pub countries: String,
}

pub fn effective(environment: &Environment, stored: &Stored) -> Effective {
    Effective {
        rule: match &environment.rule {
            Some(rule) => rule.clone(),
            None => stored.rule.clone(),
        },
        countries: match &environment.countries {
            Some(countries) => countries.clone(),
            None => stored.countries.join(" "),
        },
    }
}

/// The rules `effective` asks for, checked, guarding the environment's
/// ports and letting its exempt networks pass; none while the rule is off.
pub fn input_for(
    effective: &Effective,
    environment: &Environment,
) -> Result<Option<RuleInput>, String> {
    if effective.rule == "off" {
        return Ok(None);
    }
    rule_input(
        &effective.rule,
        &effective.countries,
        &environment.ports,
        &environment.exempt,
    )
    .map(Some)
}

/// The valid codes of a list separated by commas or spaces, in capitals,
/// each once, in order.
pub fn codes(text: &str) -> Vec<String> {
    let mut listed: Vec<String> = Vec::new();
    for code in words(text).map(str::to_ascii_uppercase) {
        if valid_code(&code) && !listed.contains(&code) {
            listed.push(code);
        }
    }
    listed
}

/// A country database with the name of every country it knows.
pub struct Named {
    pub countries: Countries,
    pub names: BTreeMap<String, String>,
}

impl Named {
    pub fn open(path: &Path) -> Result<Named, String> {
        let countries = Countries::open(path)?;
        let names = countries.names()?;
        Ok(Named { countries, names })
    }
}

/// The country rules as the panel's helper keeps them: what the
/// environment gives, where the panel's own are stored, and the database
/// the panel places addresses and names countries with, or why it could
/// not be read.
pub struct Setup {
    pub environment: Environment,
    pub stored: PathBuf,
    pub database: Result<Named, String>,
    /// MaxMind GeoLite2's key and its download.
    pub maxmind: crate::geoip::Maxmind,
}

/// Runs one nft script as a single transaction.
#[cfg(unix)]
fn run_nft(script: &str) -> Result<(), String> {
    let ran = crate::command::run("nft", &["-f", "-"], script.as_bytes())?;
    if ran.status.success() {
        Ok(())
    } else {
        Err(ran.failed("nft refused the country rules"))
    }
}

/// Makes the firewall's country rules match `input`, reading the listed
/// countries' networks from the database at `database`, or removes their
/// table while `input` is none.
#[cfg(unix)]
pub fn load(input: Option<&RuleInput>, database: &Path) -> Result<(), String> {
    let listing = crate::command::run(
        "nft",
        &["-t", "list", "table", "inet", "vpn_countries"],
        &[],
    )?;
    let present = if listing.status.success() {
        true
    } else if listing.stderr.contains("No such file or directory") {
        false
    } else {
        return Err(listing.failed("the country rules' table cannot be listed"));
    };
    let Some(input) = input else {
        if present {
            run_nft(&format!("delete table {TABLE}\n"))?;
        }
        return Ok(());
    };
    let database = Countries::open(database)?;
    let (v4, v6) = database.networks(&input.codes)?;
    let loaded = if present {
        read_listing(&listing.stdout)
    } else {
        Loaded::default()
    };
    for script in nft_loads(input, &ranges(&v4)?, &ranges(&v6)?, &loaded) {
        run_nft(&script)?;
    }
    Ok(())
}

/// Brings the firewall's country rules up to date at start, before ocserv
/// runs: COUNTRY_RULE and COUNTRIES where the environment sets them, else
/// the rules the panel stored, on the firewall PANEL_FIREWALL names.
/// Returns a warning when the rules are on and that firewall cannot carry
/// them.
#[cfg(unix)]
pub fn sync<F>(get: &F) -> Result<Option<&'static str>, String>
where
    F: Fn(&str) -> Option<OsString>,
{
    use crate::firewall::Backend;

    let config_dir = crate::config::config_dir(get).map_err(|error| error.to_string())?;
    let backend =
        match crate::config::text(get, "PANEL_FIREWALL").map_err(|error| error.to_string())? {
            Some(value) => {
                Backend::parse(&value).map_err(|error| format!("PANEL_FIREWALL: {error}"))?
            }
            None => {
                return Err(
                    "PANEL_FIREWALL is not set; firewall.sh sets it to the firewall it loaded"
                        .to_owned(),
                );
            }
        };
    let environment = Environment::from_env(get)?;
    let stored = read_stored(&stored_path(&config_dir))?;
    let input = input_for(&effective(&environment, &stored), &environment)?;
    match backend {
        Backend::Nftables => {
            load(input.as_ref(), &database_path(&config_dir))?;
            Ok(None)
        }
        Backend::Iptables => Ok(input.map(|_input| NEEDS_NFTABLES)),
    }
}

/// The named counter the drop rules count into. It belongs to the table, not
/// to a rule, so it keeps counting across the reloads that replace the
/// rules; the alert sender reads and zeroes it on the hour.
pub const DROP_COUNTER: &str = "dropped";

/// Reads and zeroes the country rules' drop counter in one step: what it
/// counted since the last reading, or nothing while the rules are off and
/// their table is gone.
#[cfg(unix)]
pub fn reset_drop_counter() -> crate::alerts::Counter {
    use crate::alerts::Counter;

    let mut args = vec!["reset", "counter"];
    args.extend(TABLE.split_whitespace());
    args.push(DROP_COUNTER);
    let ran = match crate::command::run("nft", &args, &[]) {
        Ok(ran) => ran,
        Err(error) => return Counter::Unreadable(error),
    };
    if ran.status.success() {
        return match drop_count(&ran.stdout) {
            Ok((packets, bytes)) => Counter::Read { packets, bytes },
            Err(error) => Counter::Unreadable(error),
        };
    }
    if ran.stderr.contains("No such file or directory") {
        return Counter::Absent;
    }
    Counter::Unreadable(ran.failed("nft could not read the country rules' drop counter"))
}

/// The packets and bytes a counter's listing shows, as `nft list counter`
/// and `nft reset counter` print it.
pub fn drop_count(listing: &str) -> Result<(u64, u64), String> {
    for line in listing.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let ["packets", packets, "bytes", bytes] = words.as_slice() {
            let packets = packets
                .parse()
                .map_err(|error| format!("the counter's packets '{packets}': {error}"))?;
            let bytes = bytes
                .parse()
                .map_err(|error| format!("the counter's bytes '{bytes}': {error}"))?;
            return Ok((packets, bytes));
        }
    }
    Err(format!(
        "nft listed no packets and bytes for the drop counter: {}",
        listing.trim()
    ))
}

/// Elements per nft script, and per set of listed networks. A script is one
/// netlink batch, which must fit the socket's send buffer, and a container
/// in a user namespace cannot raise that buffer past the host's
/// net.core.wmem_max: there, with the default limit, a batch of about 5,600
/// ranges loads and one of about 11,000 does not. nft reads a set's
/// elements back before each batch it adds to the set, so each batch of
/// listed networks fills a set of its own.
const BATCH: usize = 4000;

/// Loopback, private, link-local and shared ranges, which belong to no
/// country and always pass.
const ALWAYS_V4: [&str; 6] = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
];
const ALWAYS_V6: [&str; 3] = ["::1/128", "fc00::/7", "fe80::/10"];

/// What the rules do with the listed countries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Drop the listed countries.
    Block,
    /// Drop every country but the listed ones, and addresses in none.
    Allow,
}

/// The country rules, checked: what they do, to which countries, on which
/// ports, and the networks that always pass besides the fixed ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleInput {
    pub rule: Rule,
    /// ISO 3166 codes in capitals, each once.
    pub codes: Vec<String>,
    /// TCP and UDP ports, each once.
    pub ports: Vec<u16>,
    pub exempt: Vec<Network>,
}

impl RuleInput {
    /// Whether the rules let a new connection from `address`, which the
    /// database places in `country`, reach a port they guard.
    pub fn admits(&self, address: IpAddr, country: Option<&str>) -> Result<bool, String> {
        let address = address.to_canonical();
        for text in ALWAYS_V4.iter().chain(ALWAYS_V6.iter()) {
            if Network::parse(text)?.contains(address) {
                return Ok(true);
            }
        }
        if self.exempt.iter().any(|network| network.contains(address)) {
            return Ok(true);
        }
        let listed = country.is_some_and(|code| self.codes.iter().any(|listed| listed == code));
        Ok(match self.rule {
            Rule::Block => !listed,
            Rule::Allow => listed,
        })
    }
}

/// True for a two-letter ISO 3166 code in either case.
pub fn valid_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_alphabetic())
}

/// The items of a list separated by commas or white space.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|word| !word.is_empty())
}

/// Checks the country rules asked for: `rule` is block or allow, `codes`
/// two-letter country codes separated by commas or spaces, `ports` the
/// ports the rules guard, and `exempt` the networks that always pass.
pub fn rule_input(
    rule: &str,
    codes: &str,
    ports: &[u16],
    exempt: &[Network],
) -> Result<RuleInput, String> {
    let rule = match rule {
        "block" => Rule::Block,
        "allow" => Rule::Allow,
        other => {
            return Err(format!(
                "the country rule {other} is neither block nor allow"
            ));
        }
    };
    let mut listed: Vec<String> = Vec::new();
    for code in words(codes).map(str::to_ascii_uppercase) {
        if !valid_code(&code) {
            return Err(format!("{code} is not a two-letter country code"));
        }
        if !listed.contains(&code) {
            listed.push(code);
        }
    }
    if rule == Rule::Allow && listed.is_empty() {
        return Err(
            "allowing only listed countries needs at least one country, or every port it guards \
             would close"
                .to_owned(),
        );
    }
    let mut guarded: Vec<u16> = Vec::new();
    for &port in ports {
        if port == 0 {
            return Err("0 is not a port the country rules can guard".to_owned());
        }
        if !guarded.contains(&port) {
            guarded.push(port);
        }
    }
    if guarded.is_empty() {
        return Err("the country rules need a port to guard".to_owned());
    }
    let mut kept: Vec<Network> = Vec::new();
    for network in exempt {
        if !kept.contains(network) {
            kept.push(*network);
        }
    }
    Ok(RuleInput {
        rule,
        codes: listed,
        ports: guarded,
        exempt: kept,
    })
}

/// One of the table's two generations of sets. A reload fills the
/// generation the rules do not read, points the rules at it in one
/// transaction, then deletes the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    A,
    B,
}

impl Generation {
    /// What the names of the generation's sets begin with.
    fn prefix(self) -> &'static str {
        match self {
            Generation::A => "a_",
            Generation::B => "b_",
        }
    }
}

/// The table as `nft -t list table inet vpn_countries` shows it: the names
/// of its sets, and the generation its rules read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Loaded {
    pub sets: Vec<String>,
    pub live: Option<Generation>,
}

/// Reads a terse listing of the table.
pub fn read_listing(listing: &str) -> Loaded {
    let sets = listing
        .lines()
        .filter_map(|line| line.trim().strip_prefix("set "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_owned)
        .collect();
    let live = if listing.contains("@a_exempt4") {
        Some(Generation::A)
    } else if listing.contains("@b_exempt4") {
        Some(Generation::B)
    } else {
        None
    };
    Loaded { sets, live }
}

/// Points the rules at the sets whose names begin with `p`, `listed4` and
/// `listed6` among them, in one transaction. The guarded ports are matched
/// for TCP and UDP alike, as ocserv takes TLS on one and DTLS on the other.
fn rules(rule: Rule, p: &str, listed4: &[String], listed6: &[String]) -> String {
    let guarded = format!("meta l4proto {{ tcp, udp }} th dport @{p}ports");
    let drop = format!("counter name \"{DROP_COUNTER}\" drop");
    let mut script = format!(
        "flush chain {TABLE} input\n\
         add rule {TABLE} input ct state established,related accept\n\
         add rule {TABLE} input iifname \"lo\" accept\n\
         add rule {TABLE} input ip saddr @{p}exempt4 accept\n\
         add rule {TABLE} input ip6 saddr @{p}exempt6 accept\n"
    );
    match rule {
        Rule::Block => {
            for name in listed4 {
                script.push_str(&format!(
                    "add rule {TABLE} input ip saddr @{name} {guarded} {drop}\n"
                ));
            }
            for name in listed6 {
                script.push_str(&format!(
                    "add rule {TABLE} input ip6 saddr @{name} {guarded} {drop}\n"
                ));
            }
        }
        Rule::Allow => {
            for name in listed4 {
                script.push_str(&format!("add rule {TABLE} input ip saddr @{name} accept\n"));
            }
            for name in listed6 {
                script.push_str(&format!(
                    "add rule {TABLE} input ip6 saddr @{name} accept\n"
                ));
            }
            script.push_str(&format!("add rule {TABLE} input {guarded} {drop}\n"));
        }
    }
    script
}

/// The first and last address of `network` as numbers, and whether it is
/// IPv4.
fn span(network: &Network) -> (bool, u128, u128) {
    match network.edges() {
        (IpAddr::V4(first), IpAddr::V4(last)) => (
            true,
            u128::from(u32::from(first)),
            u128::from(u32::from(last)),
        ),
        (first, last) => (false, number(first), number(last)),
    }
}

fn number(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// `networks`, all of one family, as the fewest ranges that cover the same
/// addresses, in order: overlapping and adjacent networks join, and a range
/// is written as a network where it is one, else as first-last.
pub fn ranges(networks: &[Network]) -> Result<Vec<String>, String> {
    let mut family = None;
    let mut spans = Vec::with_capacity(networks.len());
    for network in networks {
        let (v4, first, last) = span(network);
        match family {
            Some(seen) if seen != v4 => {
                return Err(format!(
                    "{network} is not of the same family as the networks before it"
                ));
            }
            Some(_) => {}
            None => family = Some(v4),
        }
        spans.push((first, last));
    }
    spans.sort_unstable();
    let mut joined: Vec<(u128, u128)> = Vec::with_capacity(spans.len());
    for (first, last) in spans {
        match joined.last_mut() {
            Some(previous) if first <= previous.1.saturating_add(1) => {
                previous.1 = previous.1.max(last);
            }
            Some(_) | None => joined.push((first, last)),
        }
    }
    let v4 = family == Some(true);
    Ok(joined
        .into_iter()
        .map(|(first, last)| range_text(v4, first, last))
        .collect())
}

/// The addresses from `first` to `last` as nft writes them: a network when
/// they are one, else first-last.
fn range_text(v4: bool, first: u128, last: u128) -> String {
    // An IPv4 span's ends come from 32-bit addresses, so they fit in u32.
    let address = |n: u128| {
        if v4 {
            IpAddr::V4(Ipv4Addr::from(n as u32))
        } else {
            IpAddr::V6(Ipv6Addr::from(n))
        }
    };
    let host = last - first;
    if host & host.wrapping_add(1) == 0 && first & host == 0 {
        let bits = if v4 { 32 } else { 128 };
        format!("{}/{}", address(first), bits - host.count_ones())
    } else {
        format!("{}-{}", address(first), address(last))
    }
}

/// The nftables scripts that load the country rules into the table, in
/// order, each one transaction, given what the table holds now, and `v4`
/// and `v6`, the listed countries' networks as `ranges` joins them.
///
/// The first script makes the table and chain where missing and deletes
/// every set the rules do not read. The new generation's sets follow: the
/// ports and exempt networks, which merge what overlaps as it is added, and
/// the listed networks, BATCH to a set. One script then points the rules at
/// them, and the last deletes the generation they read before.
pub fn nft_loads(input: &RuleInput, v4: &[String], v6: &[String], loaded: &Loaded) -> Vec<String> {
    let new = match loaded.live {
        Some(Generation::A) => Generation::B,
        Some(Generation::B) | None => Generation::A,
    };
    let p = new.prefix();
    let old = loaded.live.map(Generation::prefix);
    let mut first = format!(
        "table {TABLE} {{\n    counter {DROP_COUNTER} {{ }}\n    chain input {{ type filter hook input priority filter - 10; policy accept; }}\n}}\n"
    );
    for name in &loaded.sets {
        if old.is_none_or(|prefix| !name.starts_with(prefix)) {
            first.push_str(&format!("delete set {TABLE} {name}\n"));
        }
    }
    let mut loads = vec![first];

    let mut exempt4: Vec<String> = ALWAYS_V4.iter().map(|net| (*net).to_owned()).collect();
    let mut exempt6: Vec<String> = ALWAYS_V6.iter().map(|net| (*net).to_owned()).collect();
    for network in &input.exempt {
        let list = if network.is_ipv4() {
            &mut exempt4
        } else {
            &mut exempt6
        };
        let text = network.to_string();
        if !list.contains(&text) {
            list.push(text);
        }
    }
    let ports: Vec<String> = input.ports.iter().map(u16::to_string).collect();
    let mut script = format!(
        "add set {TABLE} {p}ports {{ type inet_service; }}\n\
         add set {TABLE} {p}exempt4 {{ type ipv4_addr; flags interval; auto-merge; }}\n\
         add set {TABLE} {p}exempt6 {{ type ipv6_addr; flags interval; auto-merge; }}\n"
    );
    let mut count = 0;
    for (name, items) in [
        ("ports", &ports),
        ("exempt4", &exempt4),
        ("exempt6", &exempt6),
    ] {
        for chunk in items.chunks(BATCH) {
            if count + chunk.len() > BATCH {
                loads.push(std::mem::take(&mut script));
                count = 0;
            }
            script.push_str(&format!(
                "add element {TABLE} {p}{name} {{ {} }}\n",
                chunk.join(", ")
            ));
            count += chunk.len();
        }
    }
    loads.push(script);

    let mut listed: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    for (index, (family, kind, items)) in [("4", "ipv4_addr", v4), ("6", "ipv6_addr", v6)]
        .into_iter()
        .enumerate()
    {
        for (k, chunk) in items.chunks(BATCH).enumerate() {
            let name = format!("{p}listed{family}_{k}");
            loads.push(format!(
                "add set {TABLE} {name} {{ type {kind}; flags interval; }}\n\
                 add element {TABLE} {name} {{ {} }}\n",
                chunk.join(", ")
            ));
            listed[index].push(name);
        }
    }
    loads.push(rules(input.rule, p, &listed[0], &listed[1]));

    if let Some(prefix) = old {
        let gone: String = loaded
            .sets
            .iter()
            .filter(|name| name.starts_with(prefix))
            .map(|name| format!("delete set {TABLE} {name}\n"))
            .collect();
        if !gone.is_empty() {
            loads.push(gone);
        }
    }
    loads
}

/// Databases built in memory for the tests, in the MaxMind DB format: IPv4
/// only, with 24-bit records; country databases with a GeoIP2 Country record
/// of a code and an English name for each network, and any other kind from
/// records built with the encoders here.
#[cfg(test)]
pub mod sample {
    use std::net::Ipv4Addr;

    pub fn string(text: &str) -> Vec<u8> {
        let mut out = vec![(2 << 5) | u8::try_from(text.len()).unwrap()];
        out.extend_from_slice(text.as_bytes());
        out
    }

    pub fn double(value: f64) -> Vec<u8> {
        let mut out = vec![(3 << 5) | 8];
        out.extend(value.to_be_bytes());
        out
    }

    pub fn map(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![(7 << 5) | u8::try_from(pairs.len()).unwrap()];
        for (key, value) in pairs {
            out.extend(string(key));
            out.extend(value);
        }
        out
    }

    fn uint16(value: u16) -> Vec<u8> {
        let mut out = vec![(5 << 5) | 2];
        out.extend(value.to_be_bytes());
        out
    }

    pub fn uint32(value: u32) -> Vec<u8> {
        let mut out = vec![(6 << 5) | 4];
        out.extend(value.to_be_bytes());
        out
    }

    /// An extended type: the type in the byte after the control byte.
    fn uint64(value: u64) -> Vec<u8> {
        let mut out = vec![8, 9 - 7];
        out.extend(value.to_be_bytes());
        out
    }

    fn array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![u8::try_from(items.len()).unwrap(), 11 - 7];
        for item in items {
            out.extend(item);
        }
        out
    }

    #[derive(Clone, Copy)]
    enum Slot {
        Empty,
        Node(u32),
        Data(u32),
    }

    /// A database that places each `(network, code, name)` in its country.
    pub fn database(countries: &[(&str, &str, &str)]) -> Vec<u8> {
        let records: Vec<(&str, Vec<u8>)> = countries
            .iter()
            .map(|(network, code, name)| {
                (
                    *network,
                    map(&[(
                        "country",
                        map(&[
                            ("iso_code", string(code)),
                            ("names", map(&[("en", string(name))])),
                        ]),
                    )]),
                )
            })
            .collect();
        database_of("Test-Country", &records)
    }

    /// A database of `kind` that gives each `(network, record)` its record,
    /// encoded with the functions here.
    pub fn database_of(kind: &str, records: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        let mut nodes = vec![[Slot::Empty, Slot::Empty]];
        for (network, record) in records {
            let offset = u32::try_from(data.len()).unwrap();
            data.extend(record);
            let (address, prefix) = network.split_once('/').unwrap();
            let bits = u32::from(address.parse::<Ipv4Addr>().unwrap());
            let prefix: u32 = prefix.parse().unwrap();
            let mut node = 0;
            for depth in 0..prefix {
                let side = usize::from((bits >> (31 - depth)) & 1 == 1);
                if depth + 1 == prefix {
                    nodes[node][side] = Slot::Data(offset);
                    continue;
                }
                node = match nodes[node][side] {
                    Slot::Node(next) => usize::try_from(next).unwrap(),
                    Slot::Empty => {
                        nodes.push([Slot::Empty, Slot::Empty]);
                        let next = nodes.len() - 1;
                        nodes[node][side] = Slot::Node(u32::try_from(next).unwrap());
                        next
                    }
                    Slot::Data(_) => panic!("{network} lies inside another network"),
                };
            }
        }
        let count = u32::try_from(nodes.len()).unwrap();
        let mut out = Vec::new();
        for node in &nodes {
            for slot in node {
                let record = match *slot {
                    Slot::Empty => count,
                    Slot::Node(next) => next,
                    Slot::Data(offset) => count + 16 + offset,
                };
                out.extend(&record.to_be_bytes()[1..]);
            }
        }
        out.extend([0; 16]);
        out.extend(data);
        out.extend(b"\xAB\xCD\xEFMaxMind.com");
        out.extend(map(&[
            ("binary_format_major_version", uint16(2)),
            ("binary_format_minor_version", uint16(0)),
            ("build_epoch", uint64(0)),
            ("database_type", string(kind)),
            (
                "description",
                map(&[("en", string("countries for the tests"))]),
            ),
            ("ip_version", uint16(4)),
            ("languages", array(&[string("en")])),
            ("node_count", uint32(count)),
            ("record_size", uint16(24)),
        ]));
        out
    }

    /// The database the tests share: 192.0.2.0/24 in China, 203.0.113.0/24
    /// in the United States, and 198.51.100.0/24 in no country.
    pub fn named() -> super::Named {
        let countries = super::Countries::from_bytes(database(&[
            ("192.0.2.0/24", "CN", "China"),
            ("203.0.113.0/24", "US", "United States"),
        ]))
        .unwrap();
        let names = countries.names().unwrap();
        super::Named { countries, names }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> Network {
        Network::parse(text).unwrap()
    }

    #[test]
    fn the_rules_asked_for_are_checked() {
        let input = rule_input(
            "block",
            "cn, ru cn",
            &[4443, 8443, 4443],
            &[net("203.0.113.0/24")],
        )
        .unwrap();
        assert_eq!(input.rule, Rule::Block);
        assert_eq!(input.codes, ["CN", "RU"]);
        assert_eq!(input.ports, [4443, 8443]);
        assert_eq!(input.exempt, [net("203.0.113.0/24")]);
        for (rule, codes, ports, fault) in [
            ("deny", "CN", &[4443][..], "neither block nor allow"),
            ("block", "CHN", &[4443][..], "two-letter"),
            ("allow", "", &[4443][..], "at least one country"),
            ("block", "CN", &[][..], "a port to guard"),
            ("block", "CN", &[0][..], "0 is not a port"),
        ] {
            let error = rule_input(rule, codes, ports, &[]).unwrap_err();
            assert!(error.contains(fault), "{error}");
        }
    }

    #[test]
    fn networks_join_into_the_fewest_ranges() {
        let joined = ranges(&[
            net("10.0.1.0/24"),
            net("10.0.0.0/24"),
            net("10.0.3.0/24"),
            net("10.0.0.128/25"),
        ])
        .unwrap();
        assert_eq!(joined, ["10.0.0.0/23", "10.0.3.0/24"]);
        let odd = ranges(&[net("10.0.1.0/24"), net("10.0.2.0/24")]).unwrap();
        assert_eq!(odd, ["10.0.1.0-10.0.2.255"]);
        assert_eq!(
            ranges(&[net("2001:db8::/33"), net("2001:db8:8000::/33")]).unwrap(),
            ["2001:db8::/32"]
        );
        assert!(ranges(&[net("10.0.0.0/8"), net("2001:db8::/32")]).is_err());
    }

    #[test]
    fn a_load_fills_the_other_generation_in_batches_and_swaps_in_one_step() {
        let input = rule_input("block", "CN", &[4443, 8443], &[net("198.51.100.7/32")]).unwrap();
        let v4: Vec<String> = (0..4001)
            .map(|n| format!("11.{}.{}.0/24", n / 256, n % 256))
            .collect();
        let loaded = read_listing(
            "table inet vpn_countries {\n\tset a_ports {\n\tset a_exempt4 {\n\tset a_listed4_0 {\n\
             \tset stray {\n\t\tip saddr @a_exempt4 accept\n}",
        );
        assert_eq!(loaded.live, Some(Generation::A));
        let loads = nft_loads(&input, &v4, &[], &loaded);
        assert!(loads[0].contains("delete set inet vpn_countries stray"));
        assert!(!loads[0].contains("a_ports"));
        assert!(loads[1].contains("add set inet vpn_countries b_ports"));
        assert!(loads[1].contains("198.51.100.7/32") && loads[1].contains("127.0.0.0/8"));
        assert!(loads[2].contains("b_listed4_0") && loads[3].contains("b_listed4_1"));
        assert_eq!(loads[3].matches("11.").count(), 1);
        let swap = &loads[4];
        assert!(swap.starts_with("flush chain inet vpn_countries input"));
        let blocked = "ip saddr @b_listed4_0 meta l4proto { tcp, udp } th dport @b_ports \
                       counter name \"dropped\" drop";
        assert!(swap.contains(blocked), "{swap}");
        assert!(loads[0].contains("counter dropped { }"), "{}", loads[0]);
        assert!(loads[5].contains("delete set inet vpn_countries a_listed4_0"));
        assert_eq!(loads.len(), 6);
        let allow = rule_input("allow", "DE", &[4443], &[]).unwrap();
        let fresh = nft_loads(&allow, &["5.0.0.0/8".to_owned()], &[], &Loaded::default());
        let swap = &fresh[fresh.len() - 1];
        assert!(swap.contains("ip saddr @a_listed4_0 accept"));
        assert!(swap.ends_with(
            "meta l4proto { tcp, udp } th dport @a_ports counter name \"dropped\" drop\n"
        ));
    }

    #[test]
    fn the_drop_counter_reads_as_nft_prints_it() {
        let listing =
            "table inet vpn_countries {\n\tcounter dropped {\n\t\tpackets 4 bytes 360\n\t}\n}\n";
        assert_eq!(drop_count(listing).unwrap(), (4, 360));
        assert!(drop_count("table inet vpn_countries {\n}\n").is_err());
        assert!(drop_count("\t\tpackets many bytes 360\n").is_err());
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_database_places_addresses_and_names_countries() {
        let named = sample::named();
        let database = &named.countries;
        assert_eq!(database.kind(), "Test-Country");
        assert_eq!(
            database.lookup(ip("203.0.113.9")).unwrap().as_deref(),
            Some("US")
        );
        assert_eq!(
            database.lookup(ip("::ffff:192.0.2.5")).unwrap().as_deref(),
            Some("CN"),
            "an IPv4 address in IPv6 form is looked up as IPv4"
        );
        assert_eq!(database.lookup(ip("198.51.100.1")).unwrap(), None);
        assert_eq!(
            named.names.into_iter().collect::<Vec<_>>(),
            [
                ("CN".to_owned(), "China".to_owned()),
                ("US".to_owned(), "United States".to_owned())
            ]
        );
        let (v4, v6) = database.networks(&["us".to_owned()]).unwrap();
        assert_eq!((v4, v6), (vec![net("203.0.113.0/24")], Vec::new()));
    }

    #[test]
    fn the_rules_admit_what_the_firewall_lets_through() {
        let block = rule_input("block", "CN", &[4443], &[net("192.0.2.128/25")]).unwrap();
        assert!(!block.admits(ip("192.0.2.5"), Some("CN")).unwrap());
        assert!(
            block.admits(ip("192.0.2.200"), Some("CN")).unwrap(),
            "exempt"
        );
        assert!(block.admits(ip("203.0.113.9"), Some("US")).unwrap());
        assert!(block.admits(ip("198.51.100.1"), None).unwrap());
        let allow = rule_input("allow", "US", &[4443], &[]).unwrap();
        assert!(allow.admits(ip("203.0.113.9"), Some("US")).unwrap());
        assert!(!allow.admits(ip("192.0.2.5"), Some("CN")).unwrap());
        assert!(!allow.admits(ip("198.51.100.1"), None).unwrap());
        assert!(allow.admits(ip("10.1.2.3"), None).unwrap(), "private");
        assert!(allow.admits(ip("::ffff:192.168.1.20"), None).unwrap());
    }

    #[test]
    fn stored_rules_round_trip_and_are_checked() {
        let dir = crate::testdir::TestDir::new();
        let path = dir.path().join("country-rules.json");
        assert_eq!(read_stored(&path).unwrap(), Stored::default());
        let stored = Stored {
            rule: "allow".to_owned(),
            countries: vec!["US".to_owned(), "CA".to_owned()],
        };
        write_stored(&path, &stored).unwrap();
        assert_eq!(read_stored(&path).unwrap(), stored);
        fs::write(&path, r#"{"rule":"deny","countries":[]}"#).unwrap();
        assert!(
            read_stored(&path)
                .unwrap_err()
                .contains("not off, block or allow")
        );
        fs::write(&path, r#"{"rule":"block","countries":["CHN"]}"#).unwrap();
        assert!(read_stored(&path).unwrap_err().contains("CHN"));
    }

    #[test]
    fn the_environment_wins_where_it_sets_a_value() {
        let get = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| OsString::from(value))
            }
        };
        let environment = Environment::from_env(&get(&[
            ("COUNTRY_RULE", "Block"),
            ("COUNTRIES", ""),
            ("COUNTRY_PORTS", "4443 4443 8443"),
            ("COUNTRY_EXEMPT", "203.0.113.0/24"),
        ]))
        .unwrap();
        assert_eq!(environment.rule.as_deref(), Some("block"));
        assert_eq!(environment.countries, None, "empty is unset");
        assert_eq!(environment.ports, [4443, 4443, 8443]);
        let stored = Stored {
            rule: "allow".to_owned(),
            countries: vec!["US".to_owned()],
        };
        assert_eq!(
            effective(&environment, &stored),
            Effective {
                rule: "block".to_owned(),
                countries: "US".to_owned()
            }
        );
        let input = input_for(&effective(&environment, &stored), &environment)
            .unwrap()
            .unwrap();
        assert_eq!(
            (input.ports, input.exempt),
            (vec![4443, 8443], vec![net("203.0.113.0/24")])
        );
        let off = Stored::default();
        assert_eq!(
            input_for(&effective(&Environment::default(), &off), &environment).unwrap(),
            None
        );
        assert!(
            Environment::from_env(&get(&[("COUNTRY_RULE", "deny"), ("COUNTRY_PORTS", "1")]))
                .unwrap_err()
                .contains("off, block or allow")
        );
        assert!(
            Environment::from_env(&get(&[]))
                .unwrap_err()
                .contains("COUNTRY_PORTS")
        );
        assert_eq!(codes("cn, ru RU,xx1"), ["CN", "RU"]);
    }
}
