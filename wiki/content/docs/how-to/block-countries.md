---
title: Block Or Allow Countries
weight: 4
---

The container's firewall can drop new connections by the country they come from: from the countries you list, or from every country but those. The rules guard the VPN's port, the admin panel's and the user portal's. They apply before ocserv or the panel sees a connection, and leave connections already open alone. Countries come from DB-IP's IP to Country Lite database, which the image carries, or from MaxMind GeoLite2 with the key of a free MaxMind account.

## 1. Choose the rule and the countries

### In the admin panel

On **Bans**, the **Countries** card holds the rule and the list. Choose **Block the listed countries** or **Allow only the listed countries**, add countries with **Add a country**, clear one to take it off the list, and select **Save and apply**. The firewall loads the rule at once. Only owners change it.

![The Countries card on the Bans page blocking Russia, with China suggested, beside the failed sign-ins of the last 24 hours by country](/images/panel/countries.png)

Beside the card, **Failed sign-ins by country** counts the failed sign-ins of the live events the panel keeps, by the country of their address. When one country holds at least 10 of them and a tenth of them all, no VPN user connected from there, and the list does not hold it yet, the card suggests adding it.

### From the environment

```text
COUNTRY_RULE=block
COUNTRIES=CN, RU
```

Each wins over the panel's on its own: set only `COUNTRY_RULE`, and the panel still chooses the countries. See [Environment variables](../../reference/environment-variables/#firewall).

### Either way

- Loopback, the private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, the shared range 100.64.0.0/10, link-local addresses, fc00::/7) and the networks in `PANEL_LAN_NETWORKS` always pass.
- An allow rule also drops addresses that no country holds.
- The panel refuses a rule that would drop the address you are signed in from, which would lose you the panel at your next connection.
- The rules need nftables. Where the container falls back to legacy iptables they stay off, and the start says so.

## 2. Use MaxMind GeoLite2 instead (optional)

MaxMind's GeoLite2 Country is free with a MaxMind account. Create a license key in the account, then give the container the account ID and the key.

### In the admin panel

On **Bans**, the **Country database** card names the database in use and takes the key. **Save and download** fetches GeoLite2 with it and keeps the key once MaxMind accepts it; reload the page to see how the download ended. **Remove the key** goes back to DB-IP Lite.

![The Country database card on the Bans page, with DB-IP Lite in use and fields for a MaxMind account ID and license key](/images/panel/country-database.png)

### From the environment

```text
MAXMIND_ACCOUNT_ID=123456
MAXMIND_LICENSE_KEY=your_license_key
```

The environment's key wins over the panel's.

### Either way

- The container fetches GeoLite2 at start when there is no copy or the copy is three days old. While the panel runs, it checks every six hours and fetches a new copy once the old one is three days old, then loads the country rules again from it.
- The copy and the panel's key live in `/config/geoip`, readable by root only. The audit log names the account, never the license key.
- A download that fails leaves the countries to the copy in place, or to DB-IP Lite. The start's log, or the card, says why.

## 3. Check it

The rules live in a table of their own:

```bash
docker exec openconnect nft list table inet vpn_countries
```

**Live events**, **Sessions** and the dashboard show each address's country with its flag.

## Behind a load balancer

With `PROXY_PROTOCOL=true`, VPN connections reach the container from the balancer, so the firewall sees the balancer's address, not the client's, and a country rule judges the balancer. Filter VPN clients by country on the balancer then; the rules still guard the panel and the portal, which you reach directly. See [Run several servers behind a load balancer](../run-several-servers-behind-a-load-balancer/).
