---
title: Files Under /config
weight: 3
---

Everything the container keeps lives in the `/config` volume. Mount it from the host to keep users and certificates across container updates.

| Path | Created | Contents |
|---|---|---|
| `ocpasswd` | empty, at first start | Users and their password hashes, written with `ocpasswd`. Mode `0600`. |
| `users.oath` | by you | One-time-password secrets. When it exists, logins need a code. Mode `0600`. |
| `certs/ca.pem` | at first start, when no certificate is configured | The private CA's certificate. Clients that do not pin the server key must trust it. |
| `certs/ca-key.pem` | the same | The CA's private key. Mode `0600`. |
| `certs/server-cert.pem` | the same | The server certificate, signed by the CA. |
| `certs/server-key.pem` | the same | The server's private key. Kept when the certificate is renewed, so a pinned key keeps working. Mode `0600`. |
| `certs/client-ca.pem`, `certs/client-ca-key.pem` | at the first start that uses certificates or the admin panel | The client CA, which signs VPN users' certificates and nothing else, and its private key, mode `0600`. See [Sign In With Certificates](../../how-to/sign-in-with-certificates/). |
| `certs/client-crl.pem` | the same, written again at every start, every revocation and once a day | The client CA's revocation list, valid for a year. |
| `certs/client-revoked/` | the same | The revoked certificates the revocation list is written from. |
| `certs/.generated` | with the server certificate | The certificate's SHA-256, expiry and names, which tell the container the certificate is its own and when to renew it. A certificate that does not match is never touched. |
| `ocserv-extra.conf` | by you | ocserv options applied over the environment variables. See [Environment Variables](../environment-variables/#precedence). |
| `ocserv.conf` | by you, or once when `POWER_USER=true` | The whole configuration, used only when `POWER_USER=true` or when it is a hand-edited file from the 1.x image. |
| `config-per-user/` | by you | ocserv per-user settings, one file per user name. Used when the directory exists. |
| `config-per-group/` | by you | The same per group. |
| `hooks/connect.sh` | by you | Runs after each client connects, as root, with ocserv's connection variables in its environment. A non-zero exit refuses the session. |
| `hooks/disconnect.sh` | by you | Runs after each client disconnects. |
| `*.legacy` | at upgrade | Untouched files from the 1.x image, renamed. See [Upgrade From 1.x](../../how-to/upgrade-from-1x/). |
| `users.oath.lock`, `users.oath.new` | while a code is checked or a key changes | The lock and the half-written copy liboath and the admin panel use when they rewrite `users.oath`. The container removes any left at start, and the panel removes a lock no running process holds. |
| `panel/admins.json` | when the panel first starts | The panel's admins, their Argon2 password hashes and second factors: authenticator keys, and the public keys of their passkeys. Owned by root, mode `0600`. |
| `panel/audit.log` | the same | One JSON line per sign-in and change made in the panel or the user portal. Passwords and keys are never written to it. |
| `panel/tls/cert.pem`, `panel/tls/key.pem` | the same, unless `PANEL_CERT` is set | The panel's own certificate, issued from the image's CA, and its own key, apart from the VPN server's. The key is root's, mode `0600`. |
| `panel/client-certificates.json` | at the first certificate the panel issues | Each VPN user's certificate the panel issued: the certificate, its user and groups, who issued it, when it expires and whether it is revoked. Never a key or passphrase. Mode `0600`. |
| `panel/country-rules.json` | when an owner first saves the country rules | The country rule and the listed countries chosen on the Bans page, beneath `COUNTRY_RULE` and `COUNTRIES`. Owned by root, mode `0600`. |
| `panel/site-rules.json` | at the first site-to-site rule or egress choice | The site-to-site rules and each site's egress choice. Owned by root, mode `0600`. |
| `panel/alerts.json` | when an admin first saves alerts or a channel | What each admin chose on the Alerts page and where it goes, with the channels' tokens and webhook URLs, and the mail server an owner saved with its password. Owned by root, mode `0600`. |
| `panel/country-drops.json` | at the first hourly reading of the country rules' counter | The packets and bytes the country rules dropped so far today, for the daily summary, so a restart loses at most an hour of them. |
| `geoip/GeoLite2-Country.mmdb` | at the first download with a MaxMind key | MaxMind GeoLite2 Country, which the country rules read instead of the image's DB-IP Lite; fetched again once three days old. Mode `0600`. |
| `geoip/maxmind.conf` | when MaxMind accepts a key an owner saves on the Bans page | That MaxMind account ID and license key. Mode `0600`. |
| `geoip/dbip-city-lite-YYYY-MM.mmdb`, `geoip/dbip-asn-lite-YYYY-MM.mmdb` | while the location checks are on, at their first look for data | DB-IP City Lite and ASN Lite, named by their month, which place the addresses the location checks judge and name their networks; a newer month replaces the older. Mode `0600`. |
| `geoip/GeoLite2-City.mmdb`, `geoip/GeoLite2-ASN.mmdb` | the same, while a MaxMind key is set | MaxMind GeoLite2 City and ASN, which the location checks read instead of DB-IP's; fetched again once three days old. Mode `0600`. |
| `panel/location-checks.json` | when an owner first saves the location checks | Whether the checks are on and how often they look for newer data, as chosen on the Bans page, beneath `LOCATION_CHECKS` and `LOCATION_REFRESH_HOURS`. Owned by root, mode `0600`. |
| `panel/locations.json` | at the first sign-in the location checks learn | What each VPN user's and admin's sign-ins showed: the areas they sign in from, their networks, countries, devices and hours, their last place, and any vacation. An area is forgotten 180 days after it was last seen, and each account keeps its 50 most recent. Owned by root, mode `0600`. |
| `panel/blocklist.json` | at the first block | The firewall blocklist: each blocked address or network, when its block lifts, who made it and why. The firewall loads it at every start. |
| `panel/settings.env` | when an owner saves the Settings page | The server settings changed in the panel, one variable and value per line. The container reads it at every start beneath the environment: a variable the environment sets wins, and a line naming a variable the panel does not manage stops the start. |

## The generated configuration

Without `POWER_USER`, the configuration is written to `/run/ocserv/ocserv.conf` at every start. Read it to see what the variables produced:

```bash
docker exec openconnect cat /run/ocserv/ocserv.conf
```

## Ownership and modes

At each start the container sets `certs/` to `0700` and the key, password and one-time-password files to `0600`. With `PUID` and `PGID` set, it also gives the whole of `/config` to that user and group. Hooks run as root, so anyone who can write to `/config/hooks` can run commands in the container.
