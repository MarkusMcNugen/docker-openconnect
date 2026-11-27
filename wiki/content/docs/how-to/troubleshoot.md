---
title: Troubleshoot
weight: 10
---

The container checks its environment before ocserv starts and stops with a message saying what to change. Read it with `docker logs openconnect`.

## The container stops at start

| Message | Fix |
|---|---|
| `/dev/net/tun is missing` or `cannot be opened` | Add `--device /dev/net/tun` (compose: `devices: [/dev/net/tun:/dev/net/tun]`) and `--cap-add NET_ADMIN`. |
| `IPv4 forwarding is off` | Add `--sysctl net.ipv4.ip_forward=1`. |
| `neither nftables nor iptables can be used` | Add `--cap-add NET_ADMIN`, and `NET_RAW` when the host has no nf_tables. |
| `IPV6=true but ...` | Add the IPv6 sysctls from [Container Requirements](../../reference/container-requirements/#kernel-settings), or set `IPV6=auto`. |
| `TUNNEL_MODE=split-include needs at least one route` | Set `TUNNEL_ROUTES`. |
| `SERVER_CERT (...) and SERVER_KEY (...) must both exist` | Mount the certificate folder, or unset both to use the private CA. |
| `<VARIABLE> must be ...` | The variable's value is invalid; the message names the accepted values. |
| `command failed: ocserv --test-config ...` | ocserv rejected the configuration; the lines above the message name the option. Check `EXTRA_CONFIG` and `OCSERV_CONF_*` values. |
| `could not load the firewall's site-to-site rules` | The line above names the problem in `/config/panel/site-rules.json`, such as a rule that cannot work; correct it as in [Connect Sites Through The VPN](../connect-sites-through-the-vpn/#3-open-the-way-with-rules). |

## Warnings at start

| Message | Meaning |
|---|---|
| `IPv6 leak protection is off because ...` | The tunnel cannot carry IPv6, so a full-tunnel client with native IPv6 could send IPv6 around the VPN. Add the IPv6 sysctls. |
| `IPv6 forwarding is off` | Client IPv6 traffic stays in the tunnel and is dropped there; IPv6-only sites do not load over the VPN. Add `--sysctl net.ipv6.conf.all.forwarding=1`. |
| `nftables is unavailable on this kernel; using legacy iptables` | The firewall works; route restriction in split-include mode is off, and site-to-site rules cannot name a group. |
| `this kernel cannot check where tunnel traffic comes from ...` | A VPN client could send as another, so no site-to-site rule opens anything. Load `nft_fib_inet` on the host, or `ipt_rpfilter` and `ip6t_rpfilter` where the firewall is legacy iptables. |
| `no VPN users exist yet` | Add one: see [Manage Users](../manage-users/). |
| `... was edited by hand under the 1.x image ...` | See [Upgrade From 1.x](../upgrade-from-1x/). |

## Clients

**Cisco Secure Client says the server is untrusted.** Install `/config/certs/ca.pem` on the device as a trusted CA, or use a public certificate: [Use Your Own Certificate](../use-your-own-certificate/).

**OpenConnect asks to accept the certificate.** Pass `--servercert=pin-sha256:...` with the pin from the start-up log.

**The connection works but is slow.** The session is running over TCP only: `occtl show users` shows `(no-dtls)` for it. Either the UDP port is not forwarded, so forward UDP 4443 (or `UDP_PORT`) to the host, or the client's openconnect is built with OpenSSL, as Alpine's package is; those builds do not get ocserv's UDP channel. The GnuTLS builds that Debian, Ubuntu and Fedora ship do.

**Logins fail with a correct password.** Too many wrong attempts ban the client's address for `BAN_TIME` seconds; [lift the ban](#lift-a-ban-or-block-an-address) on the panel's **Bans** page or with `occtl`.

**In split-include mode a LAN host is unreachable.** Route restriction allows only `TUNNEL_ROUTES`; add the host's network to it.

**A Cisco client fails on a camouflaged server.** Turn off captive portal detection in its profile.

## Watch the server

### In the admin panel

The **Dashboard** shows whether the VPN server runs, the connected sessions, the failed sign-ins and the banned addresses, with charts of sessions and traffic over the last `PANEL_HISTORY_HOURS`. **Live events** lists connections, disconnections, failed sign-ins and bans as they happen, newest first, kept as long. A failed sign-in appears once ocserv refuses it, and a ban only at `LOG_LEVEL` 2 or higher, the default.

![The Live events page: refused sign-ins with the reason and address, connections with the client and VPN addresses, a disconnection with its traffic, and a ban](/images/panel/events.png)

### From the command line

```bash
docker logs -f openconnect
docker exec openconnect occtl show status
```

The container log carries ocserv's log, each connect and disconnect, and each refused client. [Logs](../../reference/logs/) explains the lines.

## Lift a ban or block an address

ocserv bans an address for `BAN_TIME` seconds when its ban points reach `MAX_BAN_SCORE`: a wrong password adds `BAN_POINTS_WRONG_PASSWORD` points, 10 by default, and each connection 1, and the points start over after `BAN_RESET_TIME` seconds.

### In the admin panel

**Bans** lists the banned addresses with the time each ban has left, and the addresses gathering points toward a ban. **Unban** lifts a ban and clears the address's points at once.

Below them, the firewall blocklist drops everything from an address or network on every port, the VPN's, the panel's and the user portal's, and ends its VPN sessions; **Keep** makes a timed block stay until it is lifted. An address ocserv bans 3 times within a day is blocked for a day by itself, and `PANEL_BLOCK_AFTER_BANS`, `PANEL_BLOCK_WINDOW_HOURS` and `PANEL_BLOCK_HOURS` change that. Your own address, loopback and the Docker host cannot be blocked. Behind a load balancer, where the firewall sees only the balancer, the VPN still refuses a blocked client when its session starts.

![The Bans page: banned addresses with the time left and an Unban button, addresses with ban points, and the firewall blocklist with a form to block an address or network](/images/panel/bans.png)

### From the command line

```bash
docker exec openconnect occtl show ip bans
docker exec openconnect occtl show ip ban points
docker exec openconnect occtl unban ip 203.0.113.250
```

The firewall blocklist belongs to the panel. Without it, block an address in the host's firewall.

## Read the audit log

### In the admin panel

Owners read **Audit log**: every sign-in, refusal and change in the panel and the user portal, newest first, 100 entries to a page, each with who acted, from where, and what came of it.

![The Audit log page: each entry's time, admin, address, action, result and detail](/images/panel/audit.png)

### From the command line

Each entry is written to `/config/panel/audit.log` before the panel answers, and copied to the container log:

```bash
docker exec openconnect tail -n 20 /config/panel/audit.log
```

## More detail

Set `LOG_LEVEL=3` for debug output, or `4` to log HTTP requests, and recreate the container. `docker exec openconnect cat /run/ocserv/ocserv.conf` shows the configuration the variables produced.
