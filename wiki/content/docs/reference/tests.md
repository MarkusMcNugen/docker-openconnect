---
title: Tests
weight: 6
---

`tests/run.sh` is the one test runner. It prints a timestamped `PASS` or `FAIL` line per check, then a count, and exits non-zero when any check fails.

```bash
bash tests/run.sh unit
bash tests/run.sh smoke IMAGE
bash tests/run.sh emulated IMAGE
```

The smoke and emulated modes use podman when it is installed and Docker otherwise; `CONTAINER_ENGINE=docker` chooses one.

## unit

Runs the entrypoint modules in a clean environment in any bash 5 shell, without containers. It checks:

- the configuration the defaults produce, option by option;
- IPv6, split-include, excluded routes and route restriction;
- the sign-in methods of each `AUTH_MODE`, with the client CA and the certificate fields that name the user and groups;
- that `OCSERV_CONF_*` variables beat named variables, split list options, remove options when empty and keep `camouflage_*` names;
- that `/config/ocserv-extra.conf` replaces options, keeps `[vhost:...]` sections at the end, and loses to `OCSERV_CONF_*`;
- that invalid values stop the start: non-numeric limits, unknown booleans, bad networks, ports, DNS servers, routes, quotes in text, unknown modes and key types;
- the route, netmask, option-name and certificate-name helpers;
- the nftables rule set text for isolation, NAT and MSS clamping, the check that tunnel traffic comes from the tunnel's own addresses, the site-to-site chain and sets in their place, and the groups' own address pools read from their settings files and translated like the server's pool;
- the legacy iptables chains for the same, the source check through `rpfilter` included;
- the admin panel's stored settings filling what the environment leaves unset, and the record of where each setting came from;
- the country rules: the ports and exempt networks the firewall script hands `ocpanel country-sync`, the panel's rules taking over where `COUNTRY_RULE` is unset, a failed load stopping the start, a GeoLite2 download logged or warned about without stopping it, and invalid rules, country codes and MaxMind keys stopping the start without echoing the key;
- the mail server for email alerts: a server with TLS and a sign-in, and a plain relay without one, load; a `PANEL_SMTP_*` variable without `PANEL_SMTP_HOST`, a missing From address, an unknown encryption, a password without a user name, and a password over a plain connection stop the start without echoing the password;
- the session script refusing a connecting client that the panel's blocklist holds, or whose address cannot be checked, before it logs the connection, and passing each connection and disconnection to the site-to-site rules without refusing a session when that fails;
- reading the VPN pools from a 1.x and from a generated configuration;
- recognizing 1.x files: with the 1.x entrypoint's rewritten lines, with Windows line endings, emptied by its port rewrite, edited by hand, and of the wrong kind; retiring stock files and keeping edited ones; leaving `POWER_USER` files alone.

## smoke

Starts IMAGE with the settings in `docker-compose.yml` (all capabilities dropped but the listed ones, read-only, `no-new-privileges`) and connects OpenConnect clients from Alpine containers. It checks:

- **The server:** starts; adds a user from standard input; turns IPv6 leak protection on; loads the nftables firewall with a drop policy; logs the key pin the client computes; pushes the DNS servers; starts every worker without a signal stack error; logs connections and disconnections.
- **The tunnel:** the client connects with the key pin, gets IPv4 and IPv6 addresses from the pools, routes IPv4 and IPv6 internet addresses into the tunnel, pings the server's tunnel address, and reaches the internet over HTTPS and DNS through the tunnel. Set `SMOKE_INTERNET=0` to skip the two internet checks.
- **Isolation:** a second session of the same user reaches the server but not the first client.
- **The UDP channel:** a client whose openconnect is built with GnuTLS, as Debian's is, gets a DTLS 1.2 channel with an AEAD cipher. The Alpine clients' openconnect is built with OpenSSL and sends an empty DTLS session ID, which ocserv cannot route, so they stay on TCP; the test prints their state as a note.
- **Restarts:** the server comes back with the same certificate and one firewall table.
- **Split tunneling:** a listed route and the DNS servers go into the tunnel, other traffic stays outside, and ocserv's per-client restriction table is loaded.
- **Camouflage:** the server answers `404` without the secret and admits a client with it.
- **Upgrades:** a stock 1.x `/config` starts with its files renamed and the environment in use; a hand-edited 1.x `ocserv.conf` starts and is used as it stands, with a warning; `POWER_USER` without a configuration writes one.
- **Two-factor login:** the login includes the one-time-password file; a code from the wrong secret is refused and the server logs the failed code check; the password with the current TOTP code is accepted.
- **The admin panel:** off by default; when on, the root helper and the unprivileged web process run apart, the panel's own certificate and key are not the VPN server's, every response carries the security headers, other host names and forms from other sites are refused, the first admin's one-time password must be replaced, a second factor is required outside the trusted networks, where the setup page offers an authenticator app or a passkey, VPN users, groups, bans, live events and the onboarding kit work from the panel, all audited and shown on the Audit log page, an admin added on the Admins page signs in with the one-time password shown there, a setting saved on the Settings page reaches the running server with a reload and is kept for the next start, a group's further settings reach the file ocserv reads while a group pool inside the server's pool is refused, and with the location checks on and no data yet every VPN connect runs its check through the root-only location socket and goes through.
- **The panel with codes on:** a user the panel adds gets an authenticator key on the onboarding kit and connects with it; resetting the key makes the old one fail; the one-time-password file stays whole and private.
- **The user portal:** a user with a key signs in with the password and a code and sees how to connect; a user without one sets up a key in the portal and connects to the VPN with it; a password change ends the old password; `ocpasswd` stores SHA-256-crypt hashes; wrong passwords lock the portal for a while.
- **The firewall blocklist:** an admin blocks a connected client from the Bans page, its tunnel ends and the VPN and the panel refuse it, the block holds after the container is recreated on its volume, and lifting it lets the client connect again.
- **Country rules:** a client at 203.0.113.20, an address in no country and in no private range, connects to a server attached to its network. A block rule from the environment loads its sets and chain and lets the client in; an allow rule drops it, and the table's drop counter counts it, while a private address still connects; an allow rule an owner sets on the Bans page loads at once, credits DB-IP, survives the container being recreated, and goes with its table when turned off; the audit log records both changes.
- **Alerts:** an owner adds a webhook at a client's private address over http, which the Alerts page marks unencrypted without showing its token, and asks for a test; the helper posts the test message to the webhook's path as JSON, the audit log records the send without the token, and `alerts.json` is readable by root only.
- **Group pools:** a group with an address pool of its own in its settings file; after the next start the firewall translates the pool, and a member gets an address from it, reaches the server and resolves names on the internet through the translation.
- **Site-to-site networks:** a user publishes 10.88.0.0/24 behind the client it connects from; no other client reaches it without a rule; a rule from every client lets clients in one way only; a rule back to the group staff lets the site reach a member, whose address leaves the group's set when they disconnect, so a user outside staff is not reached; the network reaches the internet only once an admin turns its egress on; a user an admin puts in staff on the VPN users page keeps their password and is reached by the site from their next connection; the audit log records it all. With the panel off, a rule written by hand into `/config/panel/site-rules.json` loads at start, a client reaches the site, and the site does not reach the client.
- **Certificates:** the first start with certificate sign-in creates the client CA and its revocation list; a client signs in with a certificate from it and is refused without one, and a revoked certificate is refused after a reload; with `either`, the password or the certificate alone signs in; with `both`, the certificate signs in only with the right password.
- **Certificates from the panel:** an admin issues a key file in AES-256 and one in 3DES and a certificate for a signing request, and a client signs in with each; the certificate names the user, not the request's own name; a request with an RSA 1024 key is refused; a revoked certificate is refused; a locked user's certificate is refused and the session script says why, until the user is unlocked; the audit log records it all and no passphrase.
- **A load balancer:** HAProxy passes the VPN's port on with the PROXY protocol and health checks it without errors; ocserv logs the client's own address; the dashboard names the container; a block made on the Bans page ends the client's session and refuses it again through the balancer until it is lifted; a drain time saved on the Settings page reaches ocserv with a reload, and a stop then closes the port at once, keeps the session for that time, does not start the panel's helper again, and ends with status 0.

`SMOKE_SAMPLES=1` also prints the server log and `occtl` output, marked `sample|`.

## emulated

For a platform that runs only under QEMU, where tunnels and netfilter do not work: every shipped program runs, except `nft`, which opens a netfilter socket even to print its version and so is checked by loading its libraries; the unit suite passes inside the image with its own bash and tools, and ocserv accepts a configuration rendered with certificates the image's `certtool` created. `TEST_PLATFORM=linux/arm/v7` selects the platform.
