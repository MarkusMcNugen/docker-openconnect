---
title: Environment Variables
weight: 1
---

Every setting the container reads. All are optional. Values are read at each container start, so changing one and recreating the container applies it. The variables are validated before anything starts: an invalid value stops the container with a message naming the variable.

Read by `rootfs/usr/local/lib/ocserv-docker/settings.sh`, which applies every default, and turned into `ocserv.conf` by `rootfs/usr/local/lib/ocserv-docker/config.sh`.

**Booleans** accept `true`/`false`, `yes`/`no`, `on`/`off` and `1`/`0`, in any case. **Lists** are comma-separated; spaces around items are ignored.

## Listening

| Variable | Default | What it sets |
|---|---|---|
| `LISTEN_PORT` | `4443` | TCP port ocserv listens on inside the container (`tcp-port`). Publish the same port with `-p`. |
| `UDP_PORT` | value of `LISTEN_PORT` | UDP port for the DTLS data channel (`udp-port`). |
| `DTLS` | `true` | `false` serves TCP only; clients then send all traffic over TLS, which is slower. |
| `LISTEN_HOST` | unset | Address or host name to listen on (`listen-host`). Unset listens on every address. |
| `PROXY_PROTOCOL` | `false` | `true` expects the PROXY protocol header from a reverse proxy or load balancer on the TCP port (`listen-proxy-proto`). See [Run Behind A Reverse Proxy](../../how-to/run-behind-a-reverse-proxy/) and [Run Several Servers Behind A Load Balancer](../../how-to/run-several-servers-behind-a-load-balancer/). |

## Tunnel

| Variable | Default | What it sets |
|---|---|---|
| `TUNNEL_MODE` | `all` | `all` sends every client packet through the VPN (`route = default`). `split-include` sends only `TUNNEL_ROUTES`. |
| `TUNNEL_ROUTES` | unset | Networks sent through the VPN in `split-include` mode, as CIDR (`192.168.1.0/24`) or address/netmask (`192.168.1.0/255.255.255.0`). Required in that mode. |
| `NO_ROUTES` | unset | Networks kept outside the VPN in either mode (`no-route`). |
| `VPN_NETWORK` | `192.168.255.0/24` | IPv4 pool client addresses come from (`ipv4-network`). The server takes the first address. |
| `IPV6` | `auto` | `auto` gives clients an IPv6 address and route whenever the container can carry IPv6, `true` requires it and stops the container when it cannot, `false` turns it off. See [Leak protection](../../explanation/security-model/#leak-protection). |
| `VPN_IPV6_NETWORK` | `fd3e:7a0c:5b19::/48` | IPv6 pool (`ipv6-network`). Each client gets one address from it (`ipv6-subnet-prefix = 128`). |
| `DNS_SERVERS` | `9.9.9.9,1.1.1.1` | DNS servers pushed to clients (`dns`). |
| `SPLIT_DNS_DOMAINS` | unset | Domains resolved with `DNS_SERVERS` while other names use the client's own resolver (`split-dns`). |
| `DEFAULT_DOMAIN` | unset | Search domain, or several separated by spaces (`default-domain`). |
| `TUNNEL_ALL_DNS` | `true` | Sends every DNS query through the VPN, in split-include mode too (`tunnel-all-dns`). |

## Firewall

The container's own firewall, loaded into its network namespace at start. See [The firewall](../../explanation/security-model/#the-firewall).

| Variable | Default | What it sets |
|---|---|---|
| `FIREWALL_BACKEND` | `auto` | `auto` uses nftables and falls back to legacy iptables on kernels without nf_tables. `nftables` or `iptables` forces one and stops the container when it is unavailable. |
| `NAT` | `true` | Translates client addresses to the container's address on the way out. `false` leaves them as they are, for a network that routes the VPN pool to the container. |
| `CLIENT_TO_CLIENT` | `false` | `true` lets VPN clients and the networks behind sites reach each other, whatever the [site-to-site rules](../../how-to/connect-sites-through-the-vpn/) say. |
| `RESTRICT_TO_ROUTES` | `auto` | Blocks clients from every network outside their routes (`restrict-user-to-routes`). `auto` turns it on in split-include mode. Needs nftables. |
| `COUNTRY_RULE` | unset | `block` drops new connections from the countries in `COUNTRIES` to the VPN's ports, the panel's and the portal's. `allow` drops them from every other country, and from addresses no country holds. `off` turns the rule off. Private ranges and `PANEL_LAN_NETWORKS` always pass. Unset, the rule chosen on the panel's Bans page applies, off until one is chosen. Needs nftables. |
| `COUNTRIES` | unset | Two-letter country codes, separated by commas or spaces, such as `CN, RU`. Unset, the countries listed on the panel's Bans page apply. An allow rule needs at least one. |
| `MAXMIND_ACCOUNT_ID` | unset | With `MAXMIND_LICENSE_KEY`, the key of a free MaxMind account: countries then come from MaxMind GeoLite2 Country, fetched at start when missing or three days old and every three days while the panel runs, instead of the image's DB-IP Lite. Unset, a key saved on the panel's Bans page is used. |
| `MAXMIND_LICENSE_KEY` | unset | The license key for `MAXMIND_ACCOUNT_ID`. |

## Security

| Variable | Default | What it sets |
|---|---|---|
| `CISCO_COMPAT` | `true` | Lets Cisco Secure Client and AnyConnect connect (`cisco-client-compat`, `dtls-legacy`). `false` admits only OpenConnect-protocol clients (OpenConnect 7.08 or later) and requires the data channel to use the same cipher as the TLS channel. |
| `TLS_PRIORITIES` | see below | GnuTLS priority string for TLS and DTLS (`tls-priorities`). |
| `CAMOUFLAGE_SECRET` | unset | Hides the VPN: without this string in the URL, the server answers like an ordinary web server with nothing on it (`camouflage`). Letters, digits and `. _ ~ -`. See [Hide The Server With Camouflage](../../how-to/hide-the-server-with-camouflage/). |
| `CAMOUFLAGE_REALM` | unset | When set, unauthorized requests get a `401` with this realm instead of a `404` (`camouflage_realm`). |
| `SECURITY_HEADERS` | `true` | Adds HSTS, `X-Frame-Options`, `X-Content-Type-Options`, a `default-src 'none'` CSP, `Referrer-Policy: no-referrer` and `Cache-Control: no-store` to every HTTP response (`included-http-headers`). |
| `BANNER` | unset | Text shown to clients after login (`banner`). |
| `PRE_LOGIN_BANNER` | unset | Text shown to clients before login (`pre-login-banner`). |

The default `TLS_PRIORITIES` is:

```text
NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2:-RSA:-DHE-RSA:-AES-128-CBC:-AES-256-CBC:-CAMELLIA-128-CBC:-CAMELLIA-256-CBC:-3DES-CBC:-ARCFOUR-128:-SHA1
```

It allows TLS 1.3 and 1.2 only, with ECDHE key exchange (forward secrecy) and AEAD ciphers (AES-GCM, ChaCha20-Poly1305). ocserv derives the DTLS data channel's ciphers from the same string. Cisco's legacy DTLS mode, used when `CISCO_COMPAT=true`, has its own fixed cipher list inside ocserv.

Compression is off (`compression = false`). `OCSERV_CONF_COMPRESSION=true` turns it on; [Security Model](../../explanation/security-model/#the-tls-channel) explains what that costs.

## Limits and timers

Each variable sets the ocserv option of the same name in lowercase with hyphens. An unset variable with no default leaves the option out, which ocserv treats as no limit.

| Variable | Default | Meaning |
|---|---|---|
| `MAX_CLIENTS` | `128` | Connected clients in total. `0` means ocserv's own ceiling of about 8,000. |
| `MAX_SAME_CLIENTS` | `4` | Sessions one user may hold at once. `0` is unlimited. |
| `IDLE_TIMEOUT` | unset | Seconds without traffic before a client is disconnected. |
| `MOBILE_IDLE_TIMEOUT` | unset | The same for mobile clients. |
| `SESSION_TIMEOUT` | unset | Seconds a client may stay connected before it must log in again. |
| `RX_DATA_PER_SEC` | unset | Bytes per second a client may send. |
| `TX_DATA_PER_SEC` | unset | Bytes per second sent to a client. |
| `AUTH_TIMEOUT` | `240` | Seconds a connection may take to log in. |
| `COOKIE_TIMEOUT` | `300` | Seconds a session cookie stays valid after a client disconnects, for roaming. |
| `MAX_BAN_SCORE` | `80` | Score at which a client address is banned. `0` turns banning off. |
| `BAN_TIME` | `300` | Seconds a ban lasts. |
| `BAN_RESET_TIME` | `1200` | Seconds after which an address's score is reset. |
| `BAN_POINTS_WRONG_PASSWORD` | `10` | Points a wrong password adds to the address's score. Each connection adds 1 more. |
| `RATE_LIMIT_MS` | `100` | Minimum milliseconds between new connections when the server is busy. |
| `KEEPALIVE` | `32400` | Seconds between keepalive packets. |
| `DPD` | `90` | Seconds between dead-peer checks. |
| `MOBILE_DPD` | `1800` | Seconds between dead-peer checks for mobile clients. |
| `SWITCH_TO_TCP_TIMEOUT` | `25` | Seconds without UDP traffic before the data moves to the TCP channel. |
| `MTU` | unset | Tunnel MTU offered to clients. Unset lets ocserv negotiate it. |
| `SERVER_DRAIN_MS` | unset | Milliseconds ocserv waits after a stop signal before it ends the sessions, with its ports already closed, so a load balancer's health check fails and new connections go elsewhere. Set it above the balancer's check interval. Unset stops at once. |
| `LOG_LEVEL` | `2` | `0` or `2` info, `1` basic, `3` debug, `4` HTTP, `8` sensitive, `9` TLS. |

## Users

| Variable | Default | What it sets |
|---|---|---|
| `PASSWD_FILE` | `/config/ocpasswd` | Password file, written with `ocpasswd`. Created empty when it is under `/config` and missing; a missing file elsewhere stops the container. |
| `OTP_FILE` | `/config/users.oath` | One-time-password file. When it exists, every login needs the password and the current code. See [Add Two-Factor Login](../../how-to/add-two-factor-login/). |
| `AUTH_MODE` | `password` | How users sign in: `password`, `certificate` (a client certificate alone), `both` (the certificate and the password) or `either` (one of the two). Certificates must come from the client CA in `/config/certs/client-ca.pem`, which signs nothing else. See [Sign In With Certificates](../../how-to/sign-in-with-certificates/). |

## Certificates

When `SERVER_CERT` and `SERVER_KEY` are left at their defaults and the files do not exist, the container creates a private CA and a server certificate signed by it. See [Use Your Own Certificate](../../how-to/use-your-own-certificate/) to use a public one instead.

| Variable | Default | What it sets |
|---|---|---|
| `SERVER_CERT` | `/config/certs/server-cert.pem` | Server certificate, or chain, in PEM. ocserv reloads it when the file changes. |
| `SERVER_KEY` | `/config/certs/server-key.pem` | Its private key. |
| `CERT_KEY_TYPE` | `ecdsa` | Key type for created keys, the admin panel's key files included: `ecdsa` (P-256) or `rsa` (3072 bits). |
| `SRV_CN` | `vpn.example.com` | Host name clients connect to; written into the certificate's common name and subject alternative names. |
| `SRV_SAN` | unset | More host names or IP addresses the certificate covers. |
| `SRV_ORG` | `OCSERV` | Organization in the server certificate. |
| `SRV_DAYS` | `825` | Days the server certificate is valid. It is renewed with the same key 30 days before expiry, or when `SRV_CN` or `SRV_SAN` change. |
| `CA_CN` | `VPN CA` | Common name of the private CA. |
| `CA_ORG` | `OCSERV` | Organization of the private CA. |
| `CA_DAYS` | `3650` | Days the CA is valid. |

## Admin panel

The panel is off unless `PANEL_ENABLED=true`. Every other variable here applies only when it is on.

| Variable | Default | What it sets |
|---|---|---|
| `PANEL_ENABLED` | `false` | `true` runs the web admin panel beside ocserv. |
| `PANEL_HOSTNAME` | value of `SRV_CN` | Host name or address browsers use for the panel; requests for any other host are refused. |
| `PANEL_PORT` | `8443` | HTTPS port of the panel inside the container. |
| `PANEL_LAN_NETWORKS` | unset | Networks from which an admin's password alone signs in; from anywhere else a second factor is required. |
| `PANEL_ALLOWED_NETWORKS` | unset | More networks that may reach the panel, beyond loopback, the Docker host and the VPN pools. |
| `PANEL_ALLOW_VPN` | `true` | `false` keeps connected VPN clients out of the panel. |
| `PANEL_REQUIRE_CLIENT_CERT` | `false` | `true` requires a browser certificate from the image's CA. |
| `PANEL_CERT`, `PANEL_KEY` | unset | Your own certificate and key for the panel, instead of the one issued from the image's CA. Set both or neither. |
| `PANEL_ADMIN_USER` | `admin` | Name of the first admin, created with a one-time password printed to the log. |
| `PANEL_ADMIN_PASSWORD_FILE` | unset | Absolute path to a file holding the first admin's password, instead of the one-time password. |
| `PANEL_MIN_PASSWORD_LENGTH` | `12` | Shortest password, from 8 to 128 characters, for admins and for VPN passwords set through the panel or the user portal. |
| `PANEL_LOGIN_MAX_FAILURES` | `5` | Wrong passwords in a row that lock an account or block an address from signing in. |
| `PANEL_LOCKOUT_MINUTES` | `15` | How long that lock lasts. |
| `PANEL_SESSION_IDLE_MINUTES` | `30` | Minutes without use that end a panel or portal session. |
| `PANEL_SESSION_MAX_HOURS` | `12` | Hours after which any session ends. |
| `PANEL_REAUTH_MINUTES` | `10` | How recent a sign-in must be for sensitive changes, such as an admin removing a passkey or a VPN user changing their password in the portal. |
| `PANEL_SECOND_FACTOR_MINUTES` | `5` | How long a sign-in waits for its second factor, a new authenticator key for its first code, and a passkey prompt for the browser's answer. |
| `PANEL_HISTORY_HOURS` | `24` | Hours of dashboard history and live events kept in memory, from 1 to 168. |
| `PANEL_SAMPLE_SECONDS` | `10` | How often the dashboard samples the VPN server. |
| `PANEL_BLOCK_AFTER_BANS` | `3` | Bans of one address within `PANEL_BLOCK_WINDOW_HOURS` that block it at the firewall on every port. `0` blocks only by hand. |
| `PANEL_BLOCK_WINDOW_HOURS` | `24` | The window those bans are counted in. |
| `PANEL_BLOCK_HOURS` | `24` | How long an automatic block lasts. |
| `PANEL_CLIENT_CERT_DAYS` | `365` | Days a VPN user's certificate from the Certificates page is valid, from 1 to 3650. |
| `PANEL_SMTP_HOST` | unset | The mail server every admin's email alerts go through, instead of the one an owner saves on the **Alerts** page; needs `PANEL_SMTP_FROM`. See [Get Alerts](../../how-to/get-alerts/#3-set-the-mail-server-for-email). |
| `PANEL_SMTP_SECURITY` | `starttls` | How the mail server is reached: `tls`, usually on port 465; `starttls`, usually on 587; or `plain`, usually on 25, only to a relay that takes no password. |
| `PANEL_SMTP_PORT` | the usual port of `PANEL_SMTP_SECURITY` | The mail server's port. |
| `PANEL_SMTP_USER`, `PANEL_SMTP_PASSWORD` | unset | The sign-in to the mail server. Set both or neither; `plain` takes neither. |
| `PANEL_SMTP_FROM` | unset | The address email alerts come from. |
| `VPN_ADDRESS` | `SRV_CN` with `LISTEN_PORT` | Address VPN clients connect to, as the onboarding kit and the user portal give it: a host or address and an optional port, `443` when left out, an IPv6 address in brackets (`[2001:db8::5]:443`). Set it when you publish another port than the container's. |

### User portal

| Variable | Default | What it sets |
|---|---|---|
| `PANEL_PORTAL_ENABLED` | `false` | `true` serves a portal where VPN users sign in with their VPN password to see how to connect, change their password, set up or replace their authenticator key and end their own sessions. |
| `PANEL_PORTAL_PORT` | `8444` | HTTPS port of the portal inside the container; it may not be the panel's or the VPN's. The portal answers at the host of `VPN_ADDRESS` and at `PANEL_HOSTNAME`. |
| `PANEL_PORTAL_NETWORKS` | unset | Networks that may reach the portal. Unset admits every address. |
| `PANEL_PORTAL_CERT`, `PANEL_PORTAL_KEY` | unset | A certificate and key for the portal, such as a public one for the VPN's name; unset uses the panel's. Set both or neither. |

### Location checks

| Variable | Default | What it sets |
|---|---|---|
| `LOCATION_CHECKS` | unset | `true` scores every sign-in to the VPN and the panel by where it comes from, alerts on an unusual one and refuses an implausible one once the account is learned; `false` turns the checks off. Unset, the setting on the panel's Bans page applies, off until an owner turns it on. Needs `PANEL_ENABLED=true`. See [Check Where Sign-ins Come From](../../how-to/check-where-sign-ins-come-from/). |
| `LOCATION_REFRESH_HOURS` | `6` | How often, from 1 to 168 hours, the panel looks for newer city and network data while the checks are on. Unset, the panel's setting applies. |

## Files and ownership

| Variable | Default | What it sets |
|---|---|---|
| `POWER_USER` | `false` | `true` uses `/config/ocserv.conf` as the whole configuration and applies none of the variables that shape it; the firewall and certificate variables still apply. When the file does not exist, it is written once from the current variables. |
| `EXTRA_CONFIG` | `/config/ocserv-extra.conf` | An ocserv.conf fragment applied over the variables. Each option it names replaces that option; `[vhost:...]` sections are added at the end. |
| `PUID`, `PGID` | unset | When set, `/config` is given to this user and group at each start, so the host account can edit it. |
| `CONFIG_DIR` | `/config` | Where the container keeps its state. |
| `RUNTIME_DIR` | `/run/ocserv` | Where the generated `ocserv.conf`, sockets and pid file go. |

## Any other ocserv option

`OCSERV_CONF_<OPTION>` sets any ocserv option, including those with no variable above. The option name is the variable's suffix in lowercase with `_` turned into `-`: `OCSERV_CONF_SERVER_STATS_RESET_TIME=86400` writes `server-stats-reset-time = 86400`, and `OCSERV_CONF_CAMOUFLAGE_SECRET` writes `camouflage_secret`, the one option family whose name keeps underscores.

- The value is written as given, so string options that ocserv quotes need the quotes: `OCSERV_CONF_DEFAULT_DOMAIN='"example.com"'`.
- An empty value removes the option, even one the container sets by default: `OCSERV_CONF_TRY_MTU_DISCOVERY=` drops `try-mtu-discovery`.
- Repeatable options take several values: on separate lines for any option, or comma-separated for `route`, `no-route`, `iroute`, `dns`, `ipv4-dns`, `ipv6-dns`, `nbns`, `split-dns` and `select-group`.

The options and their meanings are in ocserv's [manual](https://ocserv.openconnect-vpn.net/ocserv.8.html).

## Precedence

Later layers win, one option at a time:

1. The built-in defaults and the variables on this page.
2. `EXTRA_CONFIG`.
3. `OCSERV_CONF_*` variables.

[How The Configuration Is Built](../../explanation/how-the-configuration-is-built/) shows the layers with an example.
