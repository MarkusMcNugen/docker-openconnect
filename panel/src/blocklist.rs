//! The firewall blocklist: addresses and networks the container's firewall
//! drops on every port before ocserv, the panel or the portal sees them. It
//! is kept in the panel's data directory so it survives restarts; the
//! firewall loads it at start and the helper changes it live.

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::files;
use crate::net::Network;

/// Who `Block::by` names for a block made after repeated bans.
pub const AUTOMATIC: &str = "automatic";

/// A number of hours in words, in whole days when it is a multiple of a
/// day: "1 hour", "36 hours", "1 day", "7 days".
pub fn hours_text(hours: u64) -> String {
    let (count, unit) = match hours {
        hours if hours > 0 && hours % 24 == 0 => (hours / 24, "day"),
        hours => (hours, "hour"),
    };
    match count {
        1 => format!("1 {unit}"),
        count => format!("{count} {unit}s"),
    }
}

/// One blocked address or network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    /// The address or network in CIDR notation, as `Network` writes it.
    pub network: String,
    /// When the block began, in Unix seconds.
    pub since: u64,
    /// When it lifts, in Unix seconds; none for a block that stays.
    pub until: Option<u64>,
    /// The admin who made it, or `AUTOMATIC`.
    pub by: String,
    /// Why, as the Bans page shows it.
    pub reason: String,
}

/// When an address is blocked by itself: after `bans` bans of it within
/// `window` seconds, for `duration` seconds. `bans` of 0 blocks nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoBlock {
    pub bans: u32,
    pub window: u64,
    pub duration: u64,
}

/// The blocklist and the bans counted toward automatic blocks.
pub struct Blocklist {
    path: PathBuf,
    blocks: Vec<Block>,
    bans: HashMap<IpAddr, Vec<u64>>,
    auto: AutoBlock,
}

impl Blocklist {
    /// Reads the blocklist at `path`; a missing file is an empty list. Every
    /// block must name a network.
    pub fn open(path: &Path, auto: AutoBlock) -> Result<Blocklist, String> {
        let blocks: Vec<Block> = match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|error| format!("{}: {error}", path.display()))?,
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        for block in &blocks {
            Network::parse(&block.network)
                .map_err(|error| format!("{}: {error}", path.display()))?;
        }
        Ok(Blocklist {
            path: path.to_owned(),
            blocks,
            bans: HashMap::new(),
            auto,
        })
    }

    #[cfg(test)]
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    pub fn auto(&self) -> AutoBlock {
        self.auto
    }

    /// The blocks still in force at `now`.
    pub fn active(&self, now: u64) -> impl Iterator<Item = &Block> {
        self.blocks
            .iter()
            .filter(move |block| block.until.is_none_or(|until| now < until))
    }

    /// The block in force at `now` that covers `address`, if one does.
    pub fn blocking(&self, address: IpAddr, now: u64) -> Result<Option<&Block>, String> {
        for block in self.active(now) {
            if Network::parse(&block.network)?.contains(address) {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }

    /// The block that overlaps `network`, if one does: the firewall's sets
    /// hold no two networks that share an address.
    pub fn overlapping(&self, network: &Network) -> Result<Option<&Block>, String> {
        let (first, last) = network.edges();
        for block in &self.blocks {
            let blocked = Network::parse(&block.network)?;
            let (blocked_first, blocked_last) = blocked.edges();
            if blocked.contains(first)
                || blocked.contains(last)
                || network.contains(blocked_first)
                || network.contains(blocked_last)
            {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }

    /// Adds `block`, which no other block may overlap, and saves the list.
    pub fn add(&mut self, block: Block) -> Result<(), String> {
        let network = Network::parse(&block.network)?;
        if let Some(existing) = self.overlapping(&network)? {
            return Err(format!(
                "{} overlaps the block of {}",
                block.network, existing.network
            ));
        }
        self.blocks.push(block);
        self.save()
    }

    /// Removes the block of `network` and saves the list; the block, if
    /// there was one.
    pub fn remove(&mut self, network: &str) -> Result<Option<Block>, String> {
        let Some(index) = self
            .blocks
            .iter()
            .position(|block| block.network == network)
        else {
            return Ok(None);
        };
        let removed = self.blocks.remove(index);
        self.save()?;
        Ok(Some(removed))
    }

    /// Makes the block of `network` stay until it is lifted, adding `note`
    /// to its reason; whether there was one.
    pub fn keep(&mut self, network: &str, note: &str) -> Result<bool, String> {
        let Some(block) = self
            .blocks
            .iter_mut()
            .find(|block| block.network == network)
        else {
            return Ok(false);
        };
        block.until = None;
        block.reason = format!("{}; {note}", block.reason);
        self.save()?;
        Ok(true)
    }

    /// Removes the blocks that lifted by `now` and returns them.
    pub fn expire(&mut self, now: u64) -> Result<Vec<Block>, String> {
        let (lifted, kept): (Vec<Block>, Vec<Block>) = std::mem::take(&mut self.blocks)
            .into_iter()
            .partition(|block| block.until.is_some_and(|until| until <= now));
        self.blocks = kept;
        if !lifted.is_empty() {
            self.save()?;
        }
        Ok(lifted)
    }

    /// Counts a ban of `address` by ocserv at `now`. When it makes the
    /// number of bans within the window, the block that is due: the address,
    /// or for IPv6 its /64 as ocserv bans it, unless a block covers it
    /// already or `admitted` holds an address in it.
    pub fn count_ban(
        &mut self,
        address: IpAddr,
        now: u64,
        admitted: &[IpAddr],
    ) -> Result<Option<Block>, String> {
        if self.auto.bans == 0 {
            return Ok(None);
        }
        let window = self.auto.window;
        self.bans
            .retain(|_address, times| times.iter().any(|time| now < time + window));
        let times = self.bans.entry(address).or_default();
        times.retain(|time| now < time + window);
        times.push(now);
        let count = times.len();
        if count < self.auto.bans as usize {
            return Ok(None);
        }
        let network = match address {
            IpAddr::V4(_) => Network::parse(&address.to_string())?,
            IpAddr::V6(_) => Network::parse(&format!("{address}/64"))?,
        };
        if admitted.iter().any(|kept| network.contains(*kept))
            || self.overlapping(&network)?.is_some()
        {
            return Ok(None);
        }
        self.bans.remove(&address);
        Ok(Some(Block {
            network: network.to_string(),
            since: now,
            until: Some(now + self.auto.duration),
            by: AUTOMATIC.to_owned(),
            reason: format!("banned {count} times within {}", hours_text(window / 3600)),
        }))
    }

    fn save(&self) -> Result<(), String> {
        let text = serde_json::to_vec_pretty(&self.blocks)
            .map_err(|error| format!("the blocklist could not be written: {error}"))?;
        files::write_private(&self.path, &text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    const DAY: u64 = 86_400;

    const RULING: AutoBlock = AutoBlock {
        bans: 3,
        window: DAY,
        duration: DAY,
    };

    fn block(network: &str, until: Option<u64>) -> Block {
        Block {
            network: network.to_owned(),
            since: 100,
            until,
            by: "alex".to_owned(),
            reason: "by hand".to_owned(),
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn blocks_are_kept_across_opens_and_lift_when_due() {
        let dir = TestDir::new();
        let path = dir.path().join("blocklist.json");
        let mut list = Blocklist::open(&path, RULING).unwrap();
        list.add(block("192.0.2.7/32", Some(1000))).unwrap();
        list.add(block("2001:db8:1::/48", None)).unwrap();
        let list = Blocklist::open(&path, RULING).unwrap();
        assert_eq!(list.blocks().len(), 2);
        assert_eq!(list.active(999).count(), 2);
        assert_eq!(list.active(1000).count(), 1);
        let mut list = list;
        let lifted = list.expire(1000).unwrap();
        assert_eq!(lifted.len(), 1);
        assert_eq!(lifted[0].network, "192.0.2.7/32");
        assert!(list.keep("2001:db8:1::/48", "kept by sam").unwrap());
        assert!(!list.keep("192.0.2.7/32", "kept by sam").unwrap());
        assert_eq!(list.blocks()[0].reason, "by hand; kept by sam");
        assert!(list.remove("2001:db8:1::/48").unwrap().is_some());
        assert!(list.remove("2001:db8:1::/48").unwrap().is_none());
        assert!(Blocklist::open(&path, RULING).unwrap().blocks().is_empty());
    }

    #[test]
    fn the_block_covering_an_address_is_found_while_it_is_in_force() {
        let dir = TestDir::new();
        let mut list = Blocklist::open(&dir.path().join("blocklist.json"), RULING).unwrap();
        list.add(block("203.0.113.0/24", Some(1000))).unwrap();
        list.add(block("2001:db8:5::/64", None)).unwrap();
        let network = |address: &str, now: u64| {
            list.blocking(ip(address), now)
                .unwrap()
                .map(|block| block.network.clone())
        };
        assert_eq!(
            network("203.0.113.9", 999).as_deref(),
            Some("203.0.113.0/24")
        );
        assert_eq!(
            network("::ffff:203.0.113.9", 999).as_deref(),
            Some("203.0.113.0/24")
        );
        assert_eq!(network("203.0.113.9", 1000), None);
        assert_eq!(network("198.51.100.1", 999), None);
        assert_eq!(
            network("2001:db8:5::7", u64::MAX).as_deref(),
            Some("2001:db8:5::/64")
        );
        assert_eq!(network("2001:db8:6::7", 0), None);
    }

    #[test]
    fn hours_read_as_words() {
        for (hours, text) in [
            (1, "1 hour"),
            (36, "36 hours"),
            (24, "1 day"),
            (168, "7 days"),
            (0, "0 hours"),
        ] {
            assert_eq!(hours_text(hours), text);
        }
    }

    #[test]
    fn overlapping_blocks_are_refused() {
        let dir = TestDir::new();
        let mut list = Blocklist::open(&dir.path().join("blocklist.json"), RULING).unwrap();
        list.add(block("192.0.2.0/24", None)).unwrap();
        for overlapping in ["192.0.2.7/32", "192.0.0.0/16", "192.0.2.128/25"] {
            let error = list.add(block(overlapping, None)).unwrap_err();
            assert!(
                error.contains("overlaps the block of 192.0.2.0/24"),
                "{error}"
            );
        }
        list.add(block("192.0.3.0/24", None)).unwrap();
    }

    #[test]
    fn a_damaged_list_is_an_error() {
        let dir = TestDir::new();
        let path = dir.path().join("blocklist.json");
        files::write_private(&path, b"[{\"network\":\"nonsense\",\"since\":1,\"until\":null,\"by\":\"a\",\"reason\":\"b\"}]")
            .unwrap();
        assert!(Blocklist::open(&path, RULING).is_err());
    }

    #[test]
    fn the_third_ban_within_a_day_blocks_for_a_day() {
        let dir = TestDir::new();
        let mut list = Blocklist::open(&dir.path().join("blocklist.json"), RULING).unwrap();
        let address = ip("198.51.100.9");
        assert_eq!(list.count_ban(address, 0, &[]).unwrap(), None);
        assert_eq!(list.count_ban(address, DAY, &[]).unwrap(), None);
        assert_eq!(list.count_ban(address, DAY + 10, &[]).unwrap(), None);
        let due = list.count_ban(address, DAY + 20, &[]).unwrap().unwrap();
        assert_eq!(
            (due.network.as_str(), due.until, due.by.as_str()),
            ("198.51.100.9/32", Some(2 * DAY + 20), AUTOMATIC)
        );
        assert!(
            due.reason.contains("3 times within 1 day"),
            "{}",
            due.reason
        );
        let v6 = list
            .count_ban(ip("2001:db8:4:2::"), 0, &[])
            .unwrap()
            .into_iter()
            .chain(list.count_ban(ip("2001:db8:4:2::"), 1, &[]).unwrap())
            .chain(list.count_ban(ip("2001:db8:4:2::"), 2, &[]).unwrap())
            .next()
            .unwrap();
        assert_eq!(v6.network, "2001:db8:4:2::/64");
    }

    #[test]
    fn the_docker_host_and_covered_addresses_are_not_blocked_again() {
        let dir = TestDir::new();
        let mut list = Blocklist::open(&dir.path().join("blocklist.json"), RULING).unwrap();
        let host = ip("10.89.0.1");
        for now in 0..3 {
            assert_eq!(list.count_ban(host, now, &[host]).unwrap(), None);
        }
        list.add(block("203.0.113.0/24", None)).unwrap();
        for now in 0..3 {
            assert_eq!(list.count_ban(ip("203.0.113.5"), now, &[]).unwrap(), None);
        }
        let mut off = Blocklist::open(
            &dir.path().join("off.json"),
            AutoBlock { bans: 0, ..RULING },
        )
        .unwrap();
        for now in 0..5 {
            assert_eq!(off.count_ban(ip("192.0.2.1"), now, &[]).unwrap(), None);
        }
    }
}
