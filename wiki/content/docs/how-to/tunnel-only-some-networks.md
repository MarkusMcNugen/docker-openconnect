---
title: Tunnel Only Some Networks
weight: 3
---

By default every client packet goes through the VPN. To reach only your home network through it and leave the rest of the client's traffic alone, switch the tunnel to split mode, in the [admin panel](../use-the-admin-panel/) or in the container's environment.

## Send only some networks through the VPN

### In the admin panel

On **Settings**, under **Tunnel and firewall**, set **Tunnel mode** to **Only the listed networks** and list them in **Networks through the tunnel**, separated by commas. Under **DNS**, set **DNS servers** and **Domains resolved through the VPN only** so that clients resolve names on your network. The tunnel settings wait for the next container start, so restart the container once you have saved them.

![The Tunnel and firewall section of the Settings page, with the tunnel mode set to only the listed networks and two networks listed](/images/panel/settings-split.png)

### From the command line

```yaml
    environment:
      TUNNEL_MODE: split-include
      TUNNEL_ROUTES: 192.168.1.0/24
      DNS_SERVERS: 192.168.1.1
      SPLIT_DNS_DOMAINS: home.example.com
```

### Either way

- The networks are written as CIDR or address/netmask.
- **Send every DNS query through the tunnel**, `TUNNEL_ALL_DNS`, is on by default, so the client's local network cannot see its DNS queries; turn it off to send only the domains resolved through the VPN.
- **Hold clients to their routes**, `RESTRICT_TO_ROUTES`, is automatic: on in this mode, so a client reaches the listed networks and the DNS servers and nothing else through the server. Turn it off to let clients reach more.

## Give one group other networks

A group's own routes replace the server's for its members, so one group can reach networks the others cannot, or every network.

### In the admin panel

On **Groups**, **Change settings** on the group, then list the networks in **Routes**, one per line, or `default` for every network. A user's own settings, opened from their name on **VPN users**, do the same for one user. ocserv reads the routes when a member next connects.

![A group's settings page with two networks of its own in Routes](/images/panel/group-routes.png)

### From the command line

```text
# /config/config-per-group/staff
route = 10.20.0.0/16
route = 10.30.0.0/16
```

[Customize ocserv](../customize-ocserv/#per-user-and-per-group-settings) covers the per-group and per-user files.

## Exclude a network

Networks kept out of the tunnel stay outside the VPN in either mode. In full-tunnel mode they let clients keep reaching their own printer or NAS.

### In the admin panel

On **Settings**, under **Tunnel and firewall**, list them in **Networks kept out of the tunnel**. For one group or user, the same field is under **More settings** on its settings page.

### From the command line

```yaml
      NO_ROUTES: 192.168.0.0/24
```

## Leak protection in split mode

In split mode only the listed networks are tunneled by design, so the client's internet traffic, IPv6 included, uses its own connection. DNS stays in the tunnel unless **Send every DNS query through the tunnel** is off.
