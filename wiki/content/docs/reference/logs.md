---
title: Logs
weight: 5
---

Everything the container writes goes to standard output and standard error, which `docker logs openconnect` shows. Two kinds of lines appear: the entrypoint's and the session hook's, which start with a UTC timestamp and a level, and ocserv's own, which do not.

## Start-up

A first start with the default settings, from the smoke test (the container there is named `ocsmoke4156776-main`):

```text
2026-11-25T21:12:04Z [info] created a private CA in /config/certs/ca.pem
2026-11-25T21:12:05Z [info] created a server certificate for ocsmoke4156776-main, valid 825 days; clients must trust /config/certs/ca.pem or pin the server key
2026-11-25T21:12:05Z [warn] no VPN users exist yet. Add one with: docker exec -it <container> ocpasswd -c /config/ocpasswd <username>
2026-11-25T21:12:05Z [info] OpenConnect VPN Server 1.6.0
2026-11-25T21:12:05Z [info] configuration: /run/ocserv/ocserv.conf
2026-11-25T21:12:05Z [info] listening on TCP 4443 and UDP 4443
2026-11-25T21:12:05Z [info] tunnel: all, IPv4 192.168.255.0/24, IPv6 on (fd3e:7a0c:5b19::/48), DNS 9.9.9.9,1.1.1.1
2026-11-25T21:12:05Z [info] limits: 128 clients, 4 sessions per user; Cisco compatibility true; camouflage off
2026-11-25T21:12:05Z [info] firewall: nftables, NAT true, client isolation on, route restriction false
2026-11-25T21:12:05Z [info] server key pin for clients: pin-sha256:/uEGWoG2HjfBX9bEqNGhB3QvcQGU5ChZGoDBVuLVQgA=
note: vhost:default: setting 'plain' as primary authentication method
note: the cisco-client-compat option implies select-group-by-url = true; enabling
note: setting 'file' as supplemental config option
listening (TCP) on 0.0.0.0:4443...
listening (TCP) on [::]:4443...
listening (UDP) on 0.0.0.0:4443...
listening (UDP) on [::]:4443...
main: Starting 1 instances of ocserv-sm
main: initialized OpenConnect VPN Server 1.6.0
sec-mod: reading supplemental config from files
sec-mod: sec-mod initialized (socket: /run/ocserv/ocserv.sock.b99a024d.0)
```

| Line | Meaning |
|---|---|
| `created a private CA ...`, `created a server certificate ...` | First start without a configured certificate. |
| `reissued the self-signed server certificate because ...` | The created certificate was renewed with the same key. |
| `renamed the unmodified 1.x file ...` | An upgrade from the 1.x image; see [Upgrade From 1.x](../../how-to/upgrade-from-1x/). |
| `configuration: ...` | The file ocserv runs with. `/run/ocserv/ocserv.conf` is generated from the environment; `/config/ocserv.conf` is used as it stands. |
| `tunnel: ...` | The tunnel mode, the IPv4 pool, whether IPv6 leak protection is on, and the DNS servers. |
| `firewall: ...` | The firewall backend, NAT, client isolation and route restriction. |
| `downloaded MaxMind GeoLite2 Country` | A MaxMind key is set and the copy was missing or three days old; see [Block Or Allow Countries](../../how-to/block-countries/). |
| `[warn] MaxMind GeoLite2 was not downloaded, ...` | The download failed for the reason given, so countries come from the copy in place or from DB-IP Lite. |
| `[warn] ... is over 30 days old and no MaxMind key keeps it current ...` | A GeoLite2 copy with no key to keep it current; remove it, or set a key. |
| `[warn] the country rules need nftables, ...` | A country rule is on, and the firewall is legacy iptables, which cannot carry it. |
| `server key pin for clients: ...` | The value OpenConnect clients pass to `--servercert`. |

With `PANEL_ENABLED=true`, the admin panel adds its own lines:

| Line | Meaning |
|---|---|
| `panel: https://<host>:<port>` and the lines after it | The panel's address and what its settings turn on: passkeys, the networks where a password alone signs in, session lengths, the sign-in lock, and the user portal's address or `user portal: off`. |
| `panel: first admin '<name>' created as owner; one-time password: ...` | The first start's admin and the password it must replace at its first sign-in. It is shown only here and never written to a file. |
| `panel: web process running as uid <n>, connected to helper <version>` | The unprivileged web process started and reached the root helper. |
| `panel: serving https on port <port>` | The panel is up. |
| `panel: serving the VPN user portal on port <port>` | The user portal is up, with `PANEL_PORTAL_ENABLED=true`. |
| `ocpanel helper: try <n> of a message of <alerts> to <admin>'s <kind> channel failed: ...` | An alert could not go out, for the reason given. It is tried again after a minute and after ten minutes, and the Alerts page shows the last try's reason; see [Get Alerts](../../how-to/get-alerts/#how-alerts-go-out). |
| `ocpanel helper: location databases: downloaded <copy>` | The location checks fetched newer city or network data, as `DB-IP dbip-city-lite-2026-11` or `MaxMind GeoLite2-ASN`; see [Check Where Sign-ins Come From](../../how-to/check-where-sign-ins-come-from/). |
| `ocpanel helper: the location database download failed: ...` | The location checks keep the copies they read, or wait for their first data, and look again on their schedule. The Bans page shows the same reason. |
| `ocpanel helper: ...` or `ocpanel web: ...` | Something the panel could not do, such as a connection that failed, a block whose time ran out that could not be lifted, or a GeoLite2 download that failed. |

Lines that start with `[warn]` say what is off or missing; [Troubleshoot](../../how-to/troubleshoot/) lists each. A line with `[error]` is followed by the container stopping.

## Sessions

The session hook writes one line when a client connects and one when it disconnects. ocserv adds its own lines about logins, which `LOG_LEVEL` controls. A connection, from the smoke test:

```text
sec-mod: using 'plain' authentication to authenticate user (session: vB+lnY)
sec-mod: initiating session for user 'smoke' (session: vB+lnY)
main[smoke]:10.89.0.3:60970 new user session
2026-11-25T21:25:01Z [info] user smoke connected from 10.89.0.3, VPN address 192.168.255.80 and fd3e:7a0c:5b19:d468:269:57ba:9ec2:d9cf, device vpns0
main[smoke]:10.89.0.3:60970 user logged in
worker[smoke]: 10.89.0.3 sending IPv4 192.168.255.80
worker[smoke]: 10.89.0.3 sending IPv6 fd3e:7a0c:5b19:d468:269:57ba:9ec2:d9cf/128
worker[smoke]: 10.89.0.3 adding DNS 9.9.9.9
worker[smoke]: 10.89.0.3 adding DNS 1.1.1.1
```

The connect line names the user, the client's own address, its IPv4 and IPv6 tunnel addresses and its tun device. The disconnect line, `user <name> disconnected after <seconds> s, <bytes> bytes in, <bytes> bytes out`, gives the session's length and traffic.

With the admin panel on, a client whose address is on the panel's blocklist is refused instead of connected, with `[warn] refused user <name> from <address>: the admin panel's blocklist holds <network>`. With the location checks on, a sign-in they find implausible is refused with `[warn] refused user <name> from <address>: the location checks scored the sign-in <score> of 100: <reasons>`; an unusual one connects after `[warn] user <name> from <address>: unusual for the location checks, scored <score> of 100: <reasons>`; and one whose check could not run connects after `[warn] user <name> from <address>: let in without a location check, which could not run: <why>`. With site-to-site rules that name a group, a session the firewall could not take in logs `[warn] the firewall did not take in this connect for the site-to-site rules`, and the session gets nothing those rules give its group; with `disconnect` in that line, the address keeps them until the next connection or disconnection brings the firewall up to date. With `SERVER_DRAIN_MS` set, a stop logs ocserv's `termination request received; waiting <milliseconds> ms`, and the sessions end when that time is up.

ocserv asks again after a wrong password, three tries in all, and refuses the sign-in after the third wrong password or after a wrong code. A refused sign-in appears as ocserv's `plain-auth: error authenticating user '<name>'` or `plain-auth: OTP auth failed for '<name>'`, and the worker's `failed authentication for '<name>'`. Every wrong password adds to the client address's ban score, including the ones ocserv asks again for, which leave no line in the log.

## Levels

`LOG_LEVEL` sets how much ocserv writes: `1` basic, `2` info (the default), `3` debug, `4` HTTP requests, `8` sensitive data, `9` TLS. The entrypoint's own lines do not depend on it.
