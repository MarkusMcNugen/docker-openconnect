//! IP networks in CIDR notation, as PANEL_LAN_NETWORKS and the other network
//! lists are written.

use std::fmt;
use std::net::IpAddr;

/// An IPv4 or IPv6 network: an address and a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    /// Parses `address/prefix`, or a bare address as a single-host network.
    /// Bits beyond the prefix are ignored, so `192.168.1.7/24` is
    /// `192.168.1.0/24`.
    pub fn parse(value: &str) -> Result<Network, String> {
        let (address_text, prefix_text) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value, None),
        };
        let address: IpAddr = address_text
            .parse()
            .map_err(|error| format!("'{value}' is not an IP network: {error}"))?;
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix_text {
            None => max,
            Some(text) => {
                if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(format!(
                        "'{value}' is not an IP network: the prefix must be a number"
                    ));
                }
                let prefix: u8 = text.parse().map_err(|error| {
                    format!("'{value}' is not an IP network: the prefix is {error}")
                })?;
                if prefix > max {
                    return Err(format!(
                        "'{value}' is not an IP network: the prefix is longer than {max}"
                    ));
                }
                prefix
            }
        };
        Ok(Network { address, prefix })
    }

    /// Whether `address` is inside this network. IPv4 addresses written as
    /// IPv4-mapped IPv6 addresses (`::ffff:192.168.1.20`), as a dual-stack
    /// socket reports IPv4 clients, match IPv4 networks.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = mask_u32(self.prefix);
                u32::from(network) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = mask_u128(self.prefix);
                u128::from(network) & mask == u128::from(candidate) & mask
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    /// The network's first and last addresses; for IPv4, its network and
    /// broadcast addresses.
    pub fn edges(&self) -> (IpAddr, IpAddr) {
        match self.address {
            IpAddr::V4(address) => {
                let mask = mask_u32(self.prefix);
                let first = u32::from(address) & mask;
                (
                    IpAddr::V4(std::net::Ipv4Addr::from(first)),
                    IpAddr::V4(std::net::Ipv4Addr::from(first | !mask)),
                )
            }
            IpAddr::V6(address) => {
                let mask = mask_u128(self.prefix);
                let first = u128::from(address) & mask;
                (
                    IpAddr::V6(std::net::Ipv6Addr::from(first)),
                    IpAddr::V6(std::net::Ipv6Addr::from(first | !mask)),
                )
            }
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            IpAddr::V4(address) => {
                let masked = u32::from(address) & mask_u32(self.prefix);
                write!(f, "{}/{}", std::net::Ipv4Addr::from(masked), self.prefix)
            }
            IpAddr::V6(address) => {
                let masked = u128::from(address) & mask_u128(self.prefix);
                write!(f, "{}/{}", std::net::Ipv6Addr::from(masked), self.prefix)
            }
        }
    }
}

/// Parses a list of networks separated by commas, spaces or both.
pub fn parse_list(value: &str) -> Result<Vec<Network>, String> {
    value
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|item| !item.is_empty())
        .map(Network::parse)
        .collect()
}

/// Whether `address` is inside any of `networks`.
pub fn any_contains(networks: &[Network], address: IpAddr) -> bool {
    networks.iter().any(|network| network.contains(address))
}

fn mask_u32(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        bits => u32::MAX << (32 - u32::from(bits)),
    }
}

fn mask_u128(prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        bits => u128::MAX << (128 - u32::from(bits)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn ipv4_networks() {
        let lan = Network::parse("192.168.1.0/24").unwrap();
        assert!(lan.contains(ip("192.168.1.20")));
        assert!(lan.contains(ip("192.168.1.255")));
        assert!(!lan.contains(ip("192.168.2.1")));
        assert!(!lan.contains(ip("fd3e::1")));
    }

    #[test]
    fn host_bits_are_ignored() {
        let lan = Network::parse("192.168.1.7/24").unwrap();
        assert!(lan.contains(ip("192.168.1.200")));
        assert_eq!(lan.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn a_bare_address_is_one_host() {
        let host = Network::parse("10.0.0.5").unwrap();
        assert!(host.contains(ip("10.0.0.5")));
        assert!(!host.contains(ip("10.0.0.6")));
        assert_eq!(host.to_string(), "10.0.0.5/32");
    }

    #[test]
    fn ipv6_networks() {
        let pool = Network::parse("fd3e:7a0c:5b19::/48").unwrap();
        assert!(pool.contains(ip("fd3e:7a0c:5b19::e")));
        assert!(pool.contains(ip("fd3e:7a0c:5b19:ffff::1")));
        assert!(!pool.contains(ip("fd3e:7a0c:5b1a::1")));
        assert!(!pool.contains(ip("192.168.1.1")));
    }

    #[test]
    fn mapped_ipv4_matches_ipv4_networks() {
        let lan = Network::parse("192.168.1.0/24").unwrap();
        assert!(lan.contains(ip("::ffff:192.168.1.20")));
        assert!(!lan.contains(ip("::ffff:192.168.2.20")));
    }

    #[test]
    fn prefix_zero_is_everything_of_one_family() {
        let all4 = Network::parse("0.0.0.0/0").unwrap();
        assert!(all4.contains(ip("203.0.113.9")));
        assert!(!all4.contains(ip("2001:db8::1")));
        let all6 = Network::parse("::/0").unwrap();
        assert!(all6.contains(ip("2001:db8::1")));
    }

    #[test]
    fn invalid_networks_are_refused() {
        for value in [
            "",
            "192.168.1.0/",
            "192.168.1.0/33",
            "fd00::/129",
            "192.168.1.0/+8",
            "192.168.1.0/2a",
            "192.168.1/24",
            "lan",
            "192.168.1.0/24/8",
        ] {
            assert!(Network::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn lists_split_on_commas_and_spaces() {
        let list = parse_list("192.168.1.0/24, 10.0.0.0/8 fd00::/8,,").unwrap();
        assert_eq!(list.len(), 3);
        assert!(any_contains(&list, ip("10.1.2.3")));
        assert!(any_contains(&list, ip("fd12::1")));
        assert!(!any_contains(&list, ip("172.16.0.1")));
        assert_eq!(parse_list("").unwrap(), Vec::new());
        assert!(parse_list("192.168.1.0/24, nope").is_err());
    }
}
