---
title: Check Where Sign-ins Come From
weight: 4
---

The admin panel's location checks score each sign-in to the VPN and to the panel from 0 to 100, by where it comes from against where and how the account signed in before. From 50 the sign-in goes through with an alert; from 80 it is refused, once the account has 30 days and 10 sign-ins behind it and is not on vacation. A stolen password used from the other side of the world is stopped, while a phone whose carrier moves it between networks is not. The checks need the panel, `PANEL_ENABLED=true`, and are off until you turn them on.

## 1. Turn the checks on

### In the admin panel

On **Bans**, the **Location checks** card holds the setting. Choose **On**, set how often the panel looks for newer data, 6 hours unless you change it, and select **Save**. Only owners change it.

![The Location checks card on the Bans page, on, with DB-IP City Lite and ASN Lite in use and the last download two hours ago](/images/panel/location-checks.png)

Turning the checks on downloads DB-IP City Lite and ASN Lite, about 65 MB, into `/config/geoip`: at once from the panel, or five minutes after the container starts. They take about 140 MB there and in the panel helper's memory, and until they are read, sign-ins go through unchecked. With the key of a free MaxMind account, set as for [the country rules](../block-countries/#2-use-maxmind-geolite2-instead-optional), the panel downloads MaxMind GeoLite2 City and ASN instead.

### From the environment

```text
LOCATION_CHECKS=true
LOCATION_REFRESH_HOURS=6
```

Each wins over the panel's on its own. `LOCATION_CHECKS=true` without `PANEL_ENABLED=true` stops the start. See [Environment variables](../../reference/environment-variables/#location-checks).

## 2. What a sign-in scores

| Sign | Adds |
|---|---|
| A move from the account's last sign-in that would need more than 1,000 km/h, over more than 500 km | 80 |
| A session of the account still open more than 500 km away | 80 |
| More than 500 km from every area the account signs in from | 40 |
| A network, by its autonomous system number, the account has not used | 20 |
| A country the account has not used | 20 |
| For a VPN sign-in, a device type and platform, or a client version, the account has not used | 10 |
| A time of day more than 2 hours from every sign-in of the account's last 30 days | 10 |

The score stops at 100.

- New networks, countries and devices count from an account's second sign-in, and the time of day once it has 10, so turning the checks on alerts on no one.
- Sign-ins within 50 km of each other share one area. An area is forgotten 180 days after it was last seen, and each account keeps its 50 most recent.
- A sign-in that goes through is learned, an unusual one too; a refused one is not.
- A sign-in from a private address, which no database places, is never refused.
- A refused admin sees: "This sign-in was refused because it does not fit where this account usually signs in from. An admin has been alerted."
- For a VPN sign-in, ocserv's session script asks the panel and waits at most 5 seconds. A check that cannot run lets the client in, and **Live events** and the alerts say so.

## 3. Get alerted

On **Alerts**, choose **Location checks**. Each refused or unusual VPN sign-in, and each one let in without a check, then reaches your channels with its score and reasons. A refused or unusual sign-in to the panel reaches the owners and the admin who signed in. See [Get Alerts](../get-alerts/).

## 4. Allow a place

On **VPN users**, **Refused by the location checks** lists the VPN sign-ins the checks refused among the live events the panel keeps. When the user really is there, **Allow this place** makes the place's area, network and country usual for them and counts it as where they are now, so their next sign-in from there goes through. A refusal's alert links to the page. Owners and operators allow places.

![The Refused by the location checks card on the VPN users page, with a refused sign-in from Germany and its reasons](/images/panel/location-refused.png)

A session of the user's that is still open far away still scores 80: end it on **Sessions** first.

## 5. Go on vacation

While an account is on vacation, a sign-in the checks find implausible goes through with an alert instead of being refused, through the last day picked, at most 60 days ahead.

- An admin sets their own on **Your account**.
- An owner sets another admin's with **Vacation** on **Admins**.
- An owner or operator sets a VPN user's with **Vacation** on **VPN users**.

![The Vacation dialog for an admin, with the last day to pick](/images/panel/vacation.png)

## 6. Check it

**Live events** shows each refused, unusual and unchecked VPN sign-in under **Location checks**, and the audit log each refused or unusual admin sign-in. The session script's lines are in the container log; see [Logs](../../reference/logs/#sessions). The data in use:

```bash
docker exec openconnect ls -l /config/geoip
```

## Behind a load balancer

With `PROXY_PROTOCOL=true`, ocserv takes each client's own address from the balancer, so the checks judge the client's address, not the balancer's. See [Run several servers behind a load balancer](../run-several-servers-behind-a-load-balancer/).

## Credits

The places and networks come from [IP Geolocation by DB-IP](https://db-ip.com), under the Creative Commons Attribution 4.0 license, or, with a MaxMind key, from GeoLite2 data created by MaxMind, available from [maxmind.com](https://www.maxmind.com). The Bans page credits the data in use.
