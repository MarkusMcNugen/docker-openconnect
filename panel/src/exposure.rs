//! Who may reach the panel: loopback, the Docker host, the VPN pools unless
//! PANEL_ALLOW_VPN=false, PANEL_ALLOWED_NETWORKS and PANEL_LAN_NETWORKS. The
//! web process drops every other address before any TLS.

use std::net::Ipv4Addr;

use crate::config::Settings;
use crate::net::Network;

/// The IPv4 default gateway in a /proc/net/route table, which is the Docker
/// host as the container sees it; none when there is no default route or it
/// has no gateway. The kernel writes addresses as hexadecimal in host byte
/// order, little-endian on every platform the image ships for.
pub fn default_gateway(table: &str) -> Result<Option<Ipv4Addr>, String> {
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [
            _interface,
            destination,
            gateway,
            _flags,
            _refs,
            _use,
            _metric,
            mask,
            ..,
        ] = fields.as_slice()
        else {
            return Err(format!(
                "a /proc/net/route line has too few fields: '{line}'"
            ));
        };
        if *destination != "00000000" || *mask != "00000000" {
            continue;
        }
        let raw = u32::from_str_radix(gateway, 16).map_err(|error| {
            format!("the default route's gateway '{gateway}' is not hexadecimal: {error}")
        })?;
        let address = Ipv4Addr::from(raw.to_le_bytes());
        return Ok((!address.is_unspecified()).then_some(address));
    }
    Ok(None)
}

/// The networks the container's own interfaces reach directly, from a
/// /proc/net/route table: every route without a gateway but the default
/// one, leaving out the VPN's tun devices, whose routes lead to clients.
pub fn local_networks(table: &str) -> Result<Vec<Network>, String> {
    let mut networks = Vec::new();
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [
            interface,
            destination,
            gateway,
            _flags,
            _refs,
            _use,
            _metric,
            mask,
            ..,
        ] = fields.as_slice()
        else {
            return Err(format!(
                "a /proc/net/route line has too few fields: '{line}'"
            ));
        };
        if interface.starts_with("vpns") || *gateway != "00000000" || *mask == "00000000" {
            continue;
        }
        let hex = |text: &str| {
            u32::from_str_radix(text, 16)
                .map_err(|error| format!("'{text}' in /proc/net/route is not hexadecimal: {error}"))
        };
        let address = Ipv4Addr::from(hex(destination)?.to_le_bytes());
        let prefix = hex(mask)?.count_ones();
        networks.push(Network::parse(&format!("{address}/{prefix}"))?);
    }
    Ok(networks)
}

/// The admitted networks on this host: the Docker host from /proc/net/route
/// and the VPN pools from PANEL_VPN_NETWORKS, which the entrypoint exports.
/// The web process and the container firewall both use this list.
pub fn on_this_host(settings: &Settings) -> Result<Vec<Network>, String> {
    let table = std::fs::read_to_string("/proc/net/route")
        .map_err(|error| format!("/proc/net/route: {error}"))?;
    let pools = match std::env::var("PANEL_VPN_NETWORKS") {
        Ok(value) if value.is_empty() => Vec::new(),
        Ok(value) => crate::net::parse_list(&value)
            .map_err(|error| format!("PANEL_VPN_NETWORKS: {error}"))?,
        Err(std::env::VarError::NotPresent) => Vec::new(),
        Err(std::env::VarError::NotUnicode(value)) => {
            return Err(format!("PANEL_VPN_NETWORKS is not valid UTF-8: {value:?}"));
        }
    };
    allowed(settings, default_gateway(&table)?, &pools)
}

/// The networks the web process admits, as the settings and the container's
/// own network define them.
pub fn allowed(
    settings: &Settings,
    gateway: Option<Ipv4Addr>,
    vpn_pools: &[Network],
) -> Result<Vec<Network>, String> {
    let mut networks = vec![Network::parse("127.0.0.0/8")?, Network::parse("::1/128")?];
    if let Some(gateway) = gateway {
        networks.push(Network::parse(&gateway.to_string())?);
    }
    if settings.allow_vpn {
        networks.extend(vpn_pools.iter().cloned());
    }
    networks.extend(settings.allowed_networks.iter().cloned());
    networks.extend(settings.lan_networks.iter().cloned());
    Ok(networks)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
         eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
         eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";

    #[test]
    fn the_default_route_names_the_docker_host() {
        assert_eq!(
            default_gateway(TABLE).unwrap(),
            Some(Ipv4Addr::new(172, 17, 0, 1))
        );
    }

    #[test]
    fn the_local_networks_leave_out_the_default_route_and_the_tunnels() {
        let table = format!(
            "{TABLE}\
             vpns0\t0200A8C0\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n\
             eth1\t00000A0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
             eth1\t0000140A\t0100000A\t0003\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
        );
        let networks: Vec<String> = local_networks(&table)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(networks, ["172.17.0.0/16", "10.10.0.0/24"]);
    }

    #[test]
    fn no_default_route_means_no_host() {
        let table = "Iface\tDestination\tGateway\n";
        assert_eq!(default_gateway(table).unwrap(), None);
        let direct = "header\neth0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert_eq!(default_gateway(direct).unwrap(), None);
    }

    #[test]
    fn a_short_line_is_an_error() {
        assert!(default_gateway("header\neth0\t00000000\n").is_err());
    }
}
