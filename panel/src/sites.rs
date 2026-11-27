//! Site-to-site access: the rules that decide who reaches the networks VPN
//! users publish behind them, and which of those networks reach beyond the
//! VPN.
//!
//! A VPN user publishes the networks of a site whose router signs in as
//! that user. A rule opens one direction, from a source to a destination,
//! for new connections and their replies: from every VPN client, a group's
//! sessions or a network, to a group's sessions or a network. Two sites
//! reach each other both ways only with a rule for each way, and nothing
//! else crosses from one tunnel to another while CLIENT_TO_CLIENT is off. A
//! site's networks reach beyond the VPN only while its egress is on.
//!
//! The panel keeps the rules in its data directory. The container firewall
//! carries them out in the `site_rules` chain and the `site_*` sets of its
//! nftables table, or with legacy iptables in its VPN_SITES chains, which
//! hold the rules between networks only. `ocpanel site-sync` brings that
//! part up to date at start and at every connect and disconnect, and the
//! helper does whenever the rules, the published networks or the pools
//! change.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::files;
use crate::firewall::TABLE;
use crate::net::Network;
use crate::occtl::Session;
use crate::overrides::{self, Directories, Owner};
use crate::serverconf::ServerConfig;
use crate::vpnusers;

/// One end of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum End {
    /// Every VPN client: the addresses of the server's pools and of the
    /// groups' own pools. A source only.
    Clients,
    /// The sessions of a group.
    Group(String),
    /// A network, kept in CIDR form.
    Network(#[serde(with = "network_text")] Network),
}

impl End {
    /// The end as the Sites page and the audit log name it.
    pub fn describe(&self) -> String {
        match self {
            End::Clients => "every VPN client".to_owned(),
            End::Group(name) => format!("group {name}"),
            End::Network(network) => network.to_string(),
        }
    }
}

/// A network end as the text `Network` reads and writes.
mod network_text {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::net::Network;

    pub fn serialize<S: Serializer>(network: &Network, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(network)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Network, D::Error> {
        let text = String::deserialize(deserializer)?;
        Network::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// A rule: `from` may open connections to `to`, whose replies come back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: u64,
    pub from: End,
    pub to: End,
    /// The admin who added it.
    pub by: String,
    /// When, in Unix seconds.
    pub created: u64,
}

/// The file's contents.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    rules: Vec<Rule>,
    /// The users whose published networks reach beyond the VPN.
    egress: BTreeSet<String>,
}

/// The rules and the egress choices, kept in a file.
#[derive(Debug)]
pub struct Sites {
    path: PathBuf,
    saved: Saved,
}

impl Sites {
    /// Reads the file at `path`; a missing file holds no rule and lets no
    /// site out.
    pub fn open(path: &Path) -> Result<Sites, String> {
        let saved: Saved = match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|error| format!("{}: {error}", path.display()))?,
            Err(error) if error.kind() == ErrorKind::NotFound => Saved::default(),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        for rule in &saved.rules {
            check(&rule.from, &rule.to)
                .map_err(|error| format!("{}: rule {}: {error}", path.display(), rule.id))?;
        }
        Ok(Sites {
            path: path.to_owned(),
            saved,
        })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.saved.rules
    }

    /// Whether the networks `user` publishes reach beyond the VPN.
    pub fn egress(&self, user: &str) -> bool {
        self.saved.egress.contains(user)
    }

    /// The groups the rules name, each once, in order.
    pub fn groups(&self) -> BTreeSet<String> {
        let mut groups = BTreeSet::new();
        for rule in &self.saved.rules {
            for end in [&rule.from, &rule.to] {
                if let End::Group(name) = end {
                    groups.insert(name.clone());
                }
            }
        }
        groups
    }

    /// Adds a rule from `from` to `to`, made by `by` at `now`, and saves the
    /// rules; the rule's id. `check` must accept it, and no rule may repeat
    /// it.
    pub fn add(&mut self, from: End, to: End, by: &str, now: u64) -> Result<u64, String> {
        check(&from, &to)?;
        if self
            .saved
            .rules
            .iter()
            .any(|rule| rule.from == from && rule.to == to)
        {
            return Err(format!(
                "a rule from {} to {} is there already",
                from.describe(),
                to.describe()
            ));
        }
        let id = self
            .saved
            .rules
            .iter()
            .map(|rule| rule.id)
            .max()
            .map_or(1, |last| last + 1);
        self.saved.rules.push(Rule {
            id,
            from,
            to,
            by: by.to_owned(),
            created: now,
        });
        self.save()?;
        Ok(id)
    }

    /// Removes the rule `id` and saves the rules; the rule, if there was
    /// one.
    pub fn remove(&mut self, id: u64) -> Result<Option<Rule>, String> {
        let Some(index) = self.saved.rules.iter().position(|rule| rule.id == id) else {
            return Ok(None);
        };
        let removed = self.saved.rules.remove(index);
        self.save()?;
        Ok(Some(removed))
    }

    /// Puts `rule`, which `remove` took out, back in its place and saves the
    /// rules.
    pub fn restore(&mut self, rule: Rule) -> Result<(), String> {
        let index = self.saved.rules.partition_point(|kept| kept.id < rule.id);
        self.saved.rules.insert(index, rule);
        self.save()
    }

    /// Lets the networks `user` publishes reach beyond the VPN, or keeps
    /// them inside it, and saves; whether that changed anything.
    pub fn set_egress(&mut self, user: &str, on: bool) -> Result<bool, String> {
        let changed = if on {
            self.saved.egress.insert(user.to_owned())
        } else {
            self.saved.egress.remove(user)
        };
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    fn save(&self) -> Result<(), String> {
        let text = serde_json::to_vec_pretty(&self.saved)
            .map_err(|error| format!("the site-to-site rules could not be written: {error}"))?;
        files::write_private(&self.path, &text)
    }
}

/// Refuses a rule that cannot work: one that leads to every VPN client,
/// which is a source only; one naming a group by a name no group can have;
/// one between an IPv4 and an IPv6 network; and one from a network to
/// itself.
pub fn check(from: &End, to: &End) -> Result<(), String> {
    if *to == End::Clients {
        return Err("every VPN client can be where a rule starts, not where it leads".to_owned());
    }
    for end in [from, to] {
        if let End::Group(name) = end {
            vpnusers::check_name(name, "group name")?;
        }
    }
    if let (End::Network(source), End::Network(destination)) = (from, to) {
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(format!(
                "{source} and {destination} are not both IPv4 or both IPv6"
            ));
        }
        if source == destination {
            return Err(format!("a rule from {source} to itself opens nothing"));
        }
    }
    Ok(())
}

/// A session's start or end, as ocserv's session script reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Connect {
        group: Option<String>,
        addresses: Vec<IpAddr>,
    },
    Disconnect {
        addresses: Vec<IpAddr>,
    },
}

impl Event {
    /// The event ocserv's session script reports with `reason`, from the
    /// variables ocserv sets for it: GROUPNAME, IP_REMOTE and IPV6_REMOTE.
    pub fn from_script(
        reason: &str,
        variable: impl Fn(&str) -> Option<String>,
    ) -> Result<Event, String> {
        let mut addresses = Vec::new();
        for name in ["IP_REMOTE", "IPV6_REMOTE"] {
            if let Some(text) = variable(name).filter(|text| !text.is_empty()) {
                addresses.push(
                    text.parse::<IpAddr>().map_err(|error| {
                        format!("{name} is '{text}', not an IP address: {error}")
                    })?,
                );
            }
        }
        match reason {
            "connect" => Ok(Event::Connect {
                group: variable("GROUPNAME").filter(|group| !group.is_empty()),
                addresses,
            }),
            "disconnect" => Ok(Event::Disconnect { addresses }),
            other => Err(format!("'{other}' is not connect or disconnect")),
        }
    }
}

/// A VPN session as the site part sees it: its group and its VPN
/// addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub group: Option<String>,
    pub addresses: Vec<IpAddr>,
}

impl Member {
    /// The sessions occtl lists.
    pub fn of_sessions(sessions: &[Session]) -> Result<Vec<Member>, String> {
        let mut members = Vec::new();
        for session in sessions {
            let mut addresses = Vec::new();
            for text in [&session.vpn_ipv4, &session.vpn_ipv6].into_iter().flatten() {
                addresses.push(
                    text.parse::<IpAddr>().map_err(|error| {
                        format!("occtl gave '{text}' as a VPN address: {error}")
                    })?,
                );
            }
            members.push(Member {
                group: session.group.clone(),
                addresses,
            });
        }
        Ok(members)
    }
}

/// What the firewall's site part holds at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Each rule's source and destination.
    pub rules: Vec<(End, End)>,
    /// Every VPN client's networks: the server's pools and the groups'.
    pub clients: Vec<Network>,
    /// The VPN addresses of the sessions of each group a rule names.
    pub members: BTreeMap<String, BTreeSet<IpAddr>>,
    /// The published networks that stay inside the VPN.
    pub closed: Vec<Network>,
    /// The published networks that reach beyond it.
    pub open: Vec<Network>,
    /// Whether the firewall drops each packet from a tunnel whose source is
    /// not routed back through that tunnel. Without that check a client
    /// could send as any other, so the rules open nothing.
    pub checked: bool,
}

impl Plan {
    /// The plan for `sites`, with `clients` as every VPN client's networks,
    /// `published` as each published network with its user or group, and
    /// the `sessions` occtl lists with `event` applied to them: ocserv can
    /// list a session before its script runs, and after.
    pub fn new(
        sites: &Sites,
        clients: Vec<Network>,
        published: &[(Owner, String, Network)],
        sessions: &[Member],
        event: Option<&Event>,
        checked: bool,
    ) -> Plan {
        let mut members: BTreeMap<String, BTreeSet<IpAddr>> = sites
            .groups()
            .into_iter()
            .map(|group| (group, BTreeSet::new()))
            .collect();
        for session in sessions {
            if let Some(group) = &session.group
                && let Some(held) = members.get_mut(group)
            {
                held.extend(session.addresses.iter().copied());
            }
        }
        if let Some(event) = event {
            let (group, addresses) = match event {
                Event::Connect { group, addresses } => (group.as_ref(), addresses),
                Event::Disconnect { addresses } => (None, addresses),
            };
            for held in members.values_mut() {
                for address in addresses {
                    held.remove(address);
                }
            }
            if let Some(held) = group.and_then(|group| members.get_mut(group)) {
                held.extend(addresses.iter().copied());
            }
        }
        let mut closed = Vec::new();
        let mut open = Vec::new();
        for (owner, name, network) in published {
            if *owner == Owner::User && sites.egress(name) {
                open.push(*network);
            } else {
                closed.push(*network);
            }
        }
        Plan {
            rules: sites
                .rules()
                .iter()
                .map(|rule| (rule.from.clone(), rule.to.clone()))
                .collect(),
            clients,
            members,
            closed,
            open,
            checked,
        }
    }
}

/// Every VPN client's networks in `config`: the server's IPv4 and IPv6
/// pools, and the groups' own pools in `directories`.
pub fn clients(config: &ServerConfig, directories: &Directories) -> Result<Vec<Network>, String> {
    let mut networks: Vec<Network> = overrides::pool(config)?.into_iter().collect();
    if let Some(text) = config.last(&["ipv6-network"]) {
        networks.push(
            Network::parse(text).map_err(|error| format!("the VPN's ipv6-network: {error}"))?,
        );
    }
    networks.extend(
        directories
            .group_pools(None)?
            .into_iter()
            .map(|(_group, pool)| pool),
    );
    Ok(networks)
}

/// The name of the set of the VPN addresses of the `index`th group the
/// rules name, of IPv4 or IPv6. A group's name can hold characters a set's
/// name cannot, so the sets are numbered.
fn group_set(index: usize, v4: bool) -> String {
    format!("site_g{index}_{}", if v4 { 4 } else { 6 })
}

/// The networks of one family, as nft and iptables write them.
fn of_family(networks: &[Network], v4: bool) -> Vec<String> {
    networks
        .iter()
        .filter(|network| network.is_ipv4() == v4)
        .map(ToString::to_string)
        .collect()
}

/// The nft commands that make the firewall's site part match `plan` in one
/// transaction: the rules chain emptied, the group sets the plan no longer
/// needs deleted and the others made and filled, the sets of published
/// networks filled, and the rules added. `sets` names the sets the
/// firewall's table holds now; `nat4` and `nat6` say whether firewall.sh
/// loaded the address translation table of each family, whose
/// `site_egress` set lets the open networks out.
pub fn nft_commands(plan: &Plan, sets: &[String], nat4: bool, nat6: bool) -> String {
    let table = format!("inet {TABLE}");
    let mut commands = format!("flush chain {table} site_rules\n");
    let wanted: BTreeSet<String> = (0..plan.members.len())
        .flat_map(|index| [group_set(index, true), group_set(index, false)])
        .collect();
    for set in sets {
        if set.starts_with("site_g") && !wanted.contains(set) {
            commands.push_str(&format!("delete set {table} {set}\n"));
        }
    }
    for (index, addresses) in plan.members.values().enumerate() {
        for (v4, kind) in [(true, "ipv4_addr"), (false, "ipv6_addr")] {
            let set = group_set(index, v4);
            commands.push_str(&format!(
                "add set {table} {set} {{ type {kind}; }}\nflush set {table} {set}\n"
            ));
            let elements: Vec<String> = addresses
                .iter()
                .filter(|address| address.is_ipv4() == v4)
                .map(ToString::to_string)
                .collect();
            add_elements(&mut commands, &table, &set, &elements);
        }
    }
    for (v4, set) in [(true, "site_closed4"), (false, "site_closed6")] {
        commands.push_str(&format!("flush set {table} {set}\n"));
        add_elements(&mut commands, &table, set, &of_family(&plan.closed, v4));
    }
    if plan.checked {
        for (from, to) in &plan.rules {
            for v4 in [true, false] {
                if let Some(source) = nft_side(plan, from, v4, "saddr")
                    && let Some(destination) = nft_side(plan, to, v4, "daddr")
                {
                    commands.push_str(&format!(
                        "add rule {table} site_rules {source} {destination} accept\n"
                    ));
                }
            }
        }
    }
    for (v4, nat, family) in [(true, nat4, "ip"), (false, nat6, "ip6")] {
        if nat {
            let nat_table = format!("{family} {TABLE}");
            commands.push_str(&format!("flush set {nat_table} site_egress\n"));
            add_elements(
                &mut commands,
                &nat_table,
                "site_egress",
                &of_family(&plan.open, v4),
            );
        }
    }
    commands
}

/// Adds `elements` to `set`, when there are any.
fn add_elements(commands: &mut String, table: &str, set: &str, elements: &[String]) {
    if !elements.is_empty() {
        commands.push_str(&format!(
            "add element {table} {set} {{ {} }}\n",
            elements.join(", ")
        ));
    }
}

/// `end` as one side of an nft rule, the source or the destination as
/// `field` says, for IPv4 or IPv6; none when it has no address of that
/// family.
fn nft_side(plan: &Plan, end: &End, v4: bool, field: &str) -> Option<String> {
    let family = if v4 { "ip" } else { "ip6" };
    match end {
        End::Clients => {
            let pools = of_family(&plan.clients, v4);
            (!pools.is_empty()).then(|| format!("{family} {field} {{ {} }}", pools.join(", ")))
        }
        End::Group(name) => plan
            .members
            .keys()
            .position(|group| group == name)
            .map(|index| format!("{family} {field} @{}", group_set(index, v4))),
        End::Network(network) => {
            (network.is_ipv4() == v4).then(|| format!("{family} {field} {network}"))
        }
    }
}

/// The iptables-restore input that makes the site chains of one family
/// match `plan`, for `iptables-legacy-restore --noflush`, which empties each
/// chain it names before filling it. iptables keeps no set of a group's
/// addresses, so the rules that name a group are left out.
pub fn iptables_input(plan: &Plan, v4: bool) -> String {
    let mut input = String::from("*filter\n:VPN_SITES - [0:0]\n:VPN_SITES_CLOSED - [0:0]\n");
    if plan.checked {
        for (from, to) in &plan.rules {
            let End::Network(destination) = to else {
                continue;
            };
            if destination.is_ipv4() != v4 {
                continue;
            }
            let sources = match from {
                End::Clients => of_family(&plan.clients, v4),
                End::Network(source) => vec![source.to_string()],
                End::Group(_name) => Vec::new(),
            };
            for source in sources {
                input.push_str(&format!(
                    "-A VPN_SITES -s {source} -d {destination} -j ACCEPT\n"
                ));
            }
        }
    }
    for network in of_family(&plan.closed, v4) {
        input.push_str(&format!("-A VPN_SITES_CLOSED -s {network} -j DROP\n"));
    }
    input.push_str("COMMIT\n*nat\n:VPN_SITES_NAT - [0:0]\n");
    for network in of_family(&plan.open, v4) {
        input.push_str(&format!(
            "-A VPN_SITES_NAT -s {network} ! -o vpns+ -j MASQUERADE\n"
        ));
    }
    input.push_str("COMMIT\n");
    input
}

/// The names of the sets in the firewall's table, from what
/// `nft list sets inet` prints.
pub fn sets_in(listing: &str) -> Vec<String> {
    let wanted = format!("inet {TABLE}");
    let mut in_table = false;
    let mut sets = Vec::new();
    for line in listing.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("table ") {
            in_table = rest.trim_end_matches('{').trim() == wanted;
        } else if in_table && let Some(rest) = line.strip_prefix("set ") {
            sets.push(rest.trim_end_matches('{').trim().to_owned());
        }
    }
    sets
}

/// Whether `nft list tables` lists the address translation table that
/// firewall.sh loads for IPv4, and the one for IPv6.
pub fn nat_tables(listing: &str) -> (bool, bool) {
    let listed = |family: &str| {
        let wanted = format!("table {family} {TABLE}");
        listing.lines().any(|line| line.trim() == wanted)
    };
    (listed("ip"), listed("ip6"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    fn net(text: &str) -> Network {
        Network::parse(text).unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn group(name: &str) -> End {
        End::Group(name.to_owned())
    }

    #[test]
    fn rules_and_egress_are_kept_across_opens() {
        let dir = TestDir::new();
        let path = dir.path().join("site-rules.json");
        let mut sites = Sites::open(&path).unwrap();
        assert!(sites.rules().is_empty());
        let first = sites
            .add(
                group("staff"),
                End::Network(net("10.10.0.0/24")),
                "alex",
                100,
            )
            .unwrap();
        let second = sites.add(End::Clients, group("lab"), "alex", 200).unwrap();
        assert_eq!((first, second), (1, 2));
        let error = sites
            .add(
                group("staff"),
                End::Network(net("10.10.0.0/24")),
                "sam",
                300,
            )
            .unwrap_err();
        assert!(error.contains("is there already"), "{error}");
        assert!(sites.set_egress("branch", true).unwrap());
        assert!(!sites.set_egress("branch", true).unwrap());
        let mut sites = Sites::open(&path).unwrap();
        assert_eq!(sites.rules().len(), 2);
        assert_eq!(sites.rules()[0].by, "alex");
        assert!(sites.egress("branch") && !sites.egress("alex"));
        assert_eq!(
            sites.groups().into_iter().collect::<Vec<_>>(),
            ["lab", "staff"]
        );
        let removed = sites.remove(first).unwrap().unwrap();
        assert!(sites.remove(first).unwrap().is_none());
        sites.restore(removed).unwrap();
        let ids: Vec<u64> = Sites::open(&path)
            .unwrap()
            .rules()
            .iter()
            .map(|rule| rule.id)
            .collect();
        assert_eq!(ids, [1, 2]);
        assert!(sites.set_egress("branch", false).unwrap());
        assert!(!Sites::open(&path).unwrap().egress("branch"));
    }

    #[test]
    fn rules_that_cannot_work_are_refused() {
        for (from, to, fault) in [
            (group("staff"), End::Clients, "not where it leads"),
            (
                group("two words"),
                End::Network(net("10.10.0.0/24")),
                "group name",
            ),
            (
                End::Network(net("10.10.0.0/24")),
                End::Network(net("fd00::/64")),
                "not both IPv4 or both IPv6",
            ),
            (
                End::Network(net("10.10.0.0/24")),
                End::Network(net("10.10.0.0/24")),
                "to itself",
            ),
        ] {
            let error = check(&from, &to).unwrap_err();
            assert!(error.contains(fault), "{error}");
        }
        check(&group("lab"), &group("lab")).unwrap();
        check(&End::Clients, &End::Network(net("fd00::/64"))).unwrap();
    }

    #[test]
    fn a_damaged_file_is_an_error() {
        let dir = TestDir::new();
        let path = dir.path().join("site-rules.json");
        files::write_private(
            &path,
            br#"{"rules":[{"id":7,"from":"clients","to":"clients","by":"a","created":1}],"egress":[]}"#,
        )
        .unwrap();
        let error = Sites::open(&path).unwrap_err();
        assert!(error.contains("rule 7"), "{error}");
        files::write_private(
            &path,
            br#"{"rules":[{"id":1,"from":{"network":"nonsense"},"to":"clients","by":"a","created":1}],"egress":[]}"#,
        )
        .unwrap();
        assert!(Sites::open(&path).is_err());
    }

    /// The example file in the wiki's site-to-site how-to.
    #[test]
    fn the_rules_file_the_wiki_shows_is_read() {
        let dir = TestDir::new();
        let path = dir.path().join("site-rules.json");
        files::write_private(
            &path,
            br#"{
  "rules": [
    {
      "id": 1,
      "from": "clients",
      "to": { "network": "10.10.0.0/24" },
      "by": "admin",
      "created": 0
    },
    {
      "id": 2,
      "from": { "network": "10.10.0.0/24" },
      "to": { "network": "192.168.50.0/24" },
      "by": "admin",
      "created": 0
    }
  ],
  "egress": ["branch-office"]
}"#,
        )
        .unwrap();
        let sites = Sites::open(&path).unwrap();
        let ends: Vec<(End, End)> = sites
            .rules()
            .iter()
            .map(|rule| (rule.from.clone(), rule.to.clone()))
            .collect();
        assert_eq!(
            ends,
            [
                (End::Clients, End::Network(net("10.10.0.0/24"))),
                (
                    End::Network(net("10.10.0.0/24")),
                    End::Network(net("192.168.50.0/24"))
                ),
            ]
        );
        assert!(sites.egress("branch-office"));
    }

    /// Rules from staff's sessions to the branch office, from every client
    /// to lab's sessions, and from the branch office to headquarters both
    /// alone and from every client; headquarters reaches beyond the VPN.
    fn sample(dir: &TestDir) -> Sites {
        let mut sites = Sites::open(&dir.path().join("site-rules.json")).unwrap();
        for (from, to) in [
            (group("staff"), End::Network(net("10.10.0.0/24"))),
            (End::Clients, group("lab")),
            (
                End::Network(net("10.10.0.0/24")),
                End::Network(net("10.20.0.0/16")),
            ),
            (End::Clients, End::Network(net("10.20.0.0/16"))),
        ] {
            sites.add(from, to, "alex", 100).unwrap();
        }
        sites.set_egress("hq", true).unwrap();
        sites
    }

    fn sample_plan(sites: &Sites, event: Option<&Event>, checked: bool) -> Plan {
        let published = [
            (Owner::User, "branch".to_owned(), net("10.10.0.0/24")),
            (Owner::User, "hq".to_owned(), net("10.20.0.0/16")),
            (Owner::Group, "lab".to_owned(), net("fd00:10::/64")),
        ];
        let sessions = [
            Member {
                group: Some("staff".to_owned()),
                addresses: vec![ip("192.168.255.3"), ip("fd3e:7a0c:5b19::3")],
            },
            Member {
                group: Some("lab".to_owned()),
                addresses: vec![ip("10.30.0.5")],
            },
            Member {
                group: None,
                addresses: vec![ip("192.168.255.2")],
            },
        ];
        Plan::new(
            sites,
            vec![
                net("192.168.255.0/24"),
                net("fd3e:7a0c:5b19::/48"),
                net("10.30.0.0/24"),
            ],
            &published,
            &sessions,
            event,
            checked,
        )
    }

    #[test]
    fn the_plan_follows_the_sessions_and_the_event() {
        let dir = TestDir::new();
        let sites = sample(&dir);
        let members = |plan: &Plan, group: &str| -> Vec<String> {
            plan.members[group]
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        let plan = sample_plan(&sites, None, true);
        assert_eq!(members(&plan, "lab"), ["10.30.0.5"]);
        assert_eq!(
            members(&plan, "staff"),
            ["192.168.255.3", "fd3e:7a0c:5b19::3"]
        );
        assert_eq!(plan.closed, [net("10.10.0.0/24"), net("fd00:10::/64")]);
        assert_eq!(plan.open, [net("10.20.0.0/16")]);
        let connect = Event::Connect {
            group: Some("lab".to_owned()),
            addresses: vec![ip("192.168.255.3")],
        };
        let plan = sample_plan(&sites, Some(&connect), true);
        assert_eq!(members(&plan, "lab"), ["10.30.0.5", "192.168.255.3"]);
        assert_eq!(members(&plan, "staff"), ["fd3e:7a0c:5b19::3"]);
        let disconnect = Event::Disconnect {
            addresses: vec![ip("10.30.0.5")],
        };
        let plan = sample_plan(&sites, Some(&disconnect), true);
        assert!(members(&plan, "lab").is_empty());
    }

    #[test]
    fn nft_commands_rebuild_the_site_part_in_one_transaction() {
        let dir = TestDir::new();
        let sites = sample(&dir);
        let connect = Event::Connect {
            group: Some("lab".to_owned()),
            addresses: vec![ip("192.168.255.9")],
        };
        let plan = sample_plan(&sites, Some(&connect), true);
        let sets: Vec<String> = [
            "blocked4",
            "site_closed4",
            "site_g0_4",
            "site_g0_6",
            "site_g2_4",
            "site_g2_6",
        ]
        .map(str::to_owned)
        .to_vec();
        assert_eq!(
            nft_commands(&plan, &sets, true, false),
            "flush chain inet vpn_gateway site_rules\n\
             delete set inet vpn_gateway site_g2_4\n\
             delete set inet vpn_gateway site_g2_6\n\
             add set inet vpn_gateway site_g0_4 { type ipv4_addr; }\n\
             flush set inet vpn_gateway site_g0_4\n\
             add element inet vpn_gateway site_g0_4 { 10.30.0.5, 192.168.255.9 }\n\
             add set inet vpn_gateway site_g0_6 { type ipv6_addr; }\n\
             flush set inet vpn_gateway site_g0_6\n\
             add set inet vpn_gateway site_g1_4 { type ipv4_addr; }\n\
             flush set inet vpn_gateway site_g1_4\n\
             add element inet vpn_gateway site_g1_4 { 192.168.255.3 }\n\
             add set inet vpn_gateway site_g1_6 { type ipv6_addr; }\n\
             flush set inet vpn_gateway site_g1_6\n\
             add element inet vpn_gateway site_g1_6 { fd3e:7a0c:5b19::3 }\n\
             flush set inet vpn_gateway site_closed4\n\
             add element inet vpn_gateway site_closed4 { 10.10.0.0/24 }\n\
             flush set inet vpn_gateway site_closed6\n\
             add element inet vpn_gateway site_closed6 { fd00:10::/64 }\n\
             add rule inet vpn_gateway site_rules ip saddr @site_g1_4 ip daddr 10.10.0.0/24 accept\n\
             add rule inet vpn_gateway site_rules ip saddr { 192.168.255.0/24, 10.30.0.0/24 } ip daddr @site_g0_4 accept\n\
             add rule inet vpn_gateway site_rules ip6 saddr { fd3e:7a0c:5b19::/48 } ip6 daddr @site_g0_6 accept\n\
             add rule inet vpn_gateway site_rules ip saddr 10.10.0.0/24 ip daddr 10.20.0.0/16 accept\n\
             add rule inet vpn_gateway site_rules ip saddr { 192.168.255.0/24, 10.30.0.0/24 } ip daddr 10.20.0.0/16 accept\n\
             flush set ip vpn_gateway site_egress\n\
             add element ip vpn_gateway site_egress { 10.20.0.0/16 }\n"
        );
    }

    #[test]
    fn without_the_source_check_no_rule_opens_anything() {
        let dir = TestDir::new();
        let plan = sample_plan(&sample(&dir), None, false);
        let commands = nft_commands(&plan, &[], true, true);
        assert!(!commands.contains("add rule"), "{commands}");
        assert!(commands.contains("add element inet vpn_gateway site_closed4 { 10.10.0.0/24 }"));
        assert!(commands.contains("flush set ip6 vpn_gateway site_egress\n"));
        assert!(!iptables_input(&plan, true).contains("-A VPN_SITES "));
    }

    #[test]
    fn iptables_holds_the_rules_between_networks() {
        let dir = TestDir::new();
        let plan = sample_plan(&sample(&dir), None, true);
        assert_eq!(
            iptables_input(&plan, true),
            "*filter\n\
             :VPN_SITES - [0:0]\n\
             :VPN_SITES_CLOSED - [0:0]\n\
             -A VPN_SITES -s 10.10.0.0/24 -d 10.20.0.0/16 -j ACCEPT\n\
             -A VPN_SITES -s 192.168.255.0/24 -d 10.20.0.0/16 -j ACCEPT\n\
             -A VPN_SITES -s 10.30.0.0/24 -d 10.20.0.0/16 -j ACCEPT\n\
             -A VPN_SITES_CLOSED -s 10.10.0.0/24 -j DROP\n\
             COMMIT\n\
             *nat\n\
             :VPN_SITES_NAT - [0:0]\n\
             -A VPN_SITES_NAT -s 10.20.0.0/16 ! -o vpns+ -j MASQUERADE\n\
             COMMIT\n"
        );
        assert_eq!(
            iptables_input(&plan, false),
            "*filter\n\
             :VPN_SITES - [0:0]\n\
             :VPN_SITES_CLOSED - [0:0]\n\
             -A VPN_SITES_CLOSED -s fd00:10::/64 -j DROP\n\
             COMMIT\n\
             *nat\n\
             :VPN_SITES_NAT - [0:0]\n\
             COMMIT\n"
        );
    }

    #[test]
    fn listings_show_the_firewalls_sets_and_tables() {
        let sets = "table inet vpn_gateway {\n\
                    \tset blocked4 {\n\
                    \t\ttype ipv4_addr\n\
                    \t\tflags interval\n\
                    \t}\n\
                    \tset site_g0_4 {\n\
                    \t\ttype ipv4_addr\n\
                    \t}\n\
                    }\n\
                    table inet ocserv_fw {\n\
                    \tset site_g9_4 {\n\
                    \t\ttype ipv4_addr\n\
                    \t}\n\
                    }\n";
        assert_eq!(sets_in(sets), ["blocked4", "site_g0_4"]);
        let tables = "table inet vpn_gateway\ntable ip vpn_gateway\ntable inet ocserv_fw\n";
        assert_eq!(nat_tables(tables), (true, false));
        assert_eq!(nat_tables(""), (false, false));
    }

    #[test]
    fn script_events_come_from_ocservs_variables() {
        let variables = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _value)| *key == name)
                    .map(|(_key, value)| (*value).to_owned())
            }
        };
        assert_eq!(
            Event::from_script(
                "connect",
                variables(&[
                    ("GROUPNAME", "lab"),
                    ("IP_REMOTE", "192.168.255.9"),
                    ("IPV6_REMOTE", "")
                ])
            )
            .unwrap(),
            Event::Connect {
                group: Some("lab".to_owned()),
                addresses: vec![ip("192.168.255.9")],
            }
        );
        assert_eq!(
            Event::from_script(
                "connect",
                variables(&[("GROUPNAME", ""), ("IP_REMOTE", "192.168.255.9")])
            )
            .unwrap(),
            Event::Connect {
                group: None,
                addresses: vec![ip("192.168.255.9")],
            }
        );
        assert_eq!(
            Event::from_script(
                "disconnect",
                variables(&[("IP_REMOTE", "192.168.255.9"), ("IPV6_REMOTE", "fd3e::9")])
            )
            .unwrap(),
            Event::Disconnect {
                addresses: vec![ip("192.168.255.9"), ip("fd3e::9")],
            }
        );
        assert!(Event::from_script("connect", variables(&[("IP_REMOTE", "nonsense")])).is_err());
        assert!(Event::from_script("reconnect", variables(&[])).is_err());
    }
}
