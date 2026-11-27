---
title: Customize ocserv
weight: 8
---

Four ways to change ocserv beyond the named variables, from the lightest to the heaviest: the admin panel's Settings page, one `OCSERV_CONF_*` variable, `/config/ocserv-extra.conf`, and a configuration file of your own. [How The Configuration Is Built](../../explanation/how-the-configuration-is-built/) explains how they combine.

## The Settings page

With the [admin panel](../use-the-admin-panel/) on, owners change the server settings the container's environment leaves unset on **Settings**: DNS, messages, connection limits and timeouts, bans, the PROXY protocol and drain time for a [load balancer](../run-several-servers-behind-a-load-balancer/), how VPN users [sign in](../sign-in-with-certificates/), and the [tunnel](../tunnel-only-some-networks/) and firewall. A setting that the environment, an `OCSERV_CONF_*` variable or `/config/ocserv-extra.conf` gives is greyed out and names where it comes from, as **Most clients at once** and **Disconnect after idle** are here:

![The Connections section of the Settings page: limits and timeouts, two of them greyed out because the container's environment and ocserv-extra.conf set them](/images/panel/settings-connections.png)

Saving applies what ocserv can take with a reload while users stay connected; the tunnel and firewall settings and how users sign in wait for the next container start, marked as waiting until then. The panel keeps the values in `/config/panel/settings.env`, which fills what the environment leaves unset at every start. Each field's caption names its variable, so the same value can go into the environment instead.

## One option: OCSERV_CONF_*

Any ocserv option can be set with `OCSERV_CONF_` and the option's name in capitals with `_` for `-`:

```yaml
    environment:
      OCSERV_CONF_SERVER_STATS_RESET_TIME: "86400"
      OCSERV_CONF_DENY_ROAMING: "true"
      OCSERV_CONF_ROUTE: "10.0.0.0/8, 172.16.0.0/12"
```

An empty value removes an option the container sets. [Environment Variables](../../reference/environment-variables/#any-other-ocserv-option) has the rules for quoting and repeated options.

## Several options: /config/ocserv-extra.conf

Write ocserv options in ocserv's own format:

```text
# /config/ocserv-extra.conf
deny-roaming = true
select-group = staff
select-group = guests[Guest access]
auto-select-group = false

[vhost:vpn2.example.com]
server-cert = /config/certs/vpn2-cert.pem
server-key = /config/certs/vpn2-key.pem
```

Each option in the file replaces that option's values from the variables. Virtual host sections are added at the end of the configuration.

## Everything: POWER_USER

`POWER_USER=true` makes the container use `/config/ocserv.conf` as it stands. When the file does not exist, the container writes it once from the current variables, so you start from your current configuration and edit it. The firewall, certificate and ownership variables still apply. Changes take effect at the next restart; most can also be loaded with `docker exec openconnect occtl reload`. The panel's Settings page then offers nothing, since it does not change a file of your own.

## Per-user and per-group settings

Settings for a group win over the server's, and a user's own settings win over their group's.

### In the admin panel

On **Groups**, **Change settings** opens a group's settings, and on **VPN users** a user's name opens theirs: routes, DNS servers, bandwidth limits, whether they are held to their routes and, for a user, a fixed VPN address. **More settings** adds split DNS, networks kept out of the tunnel, timeouts, session limits, MTU, the ports a user may reach, TCP only, a group's own address pool, and the networks behind a user that is a site router. Each empty field shows the value it inherits. ocserv reads the settings when a user next connects.

![A group's settings page after saving: routes and a DNS server of its own, with the fields it leaves empty showing the server's values](/images/panel/group-routes.png)

A group's own address pool must be a private network that overlaps the server's pool and every other group's pool nowhere; the container translates it, and admits it to the panel and the user portal, from the next start.

### From the command line

Create `/config/config-per-user/` or `/config/config-per-group/` and the container turns on ocserv's per-user or per-group settings; with the panel on, the container creates both. Each file is named after a user or group and holds options such as:

```text
# /config/config-per-user/alice
route = 10.10.0.0/16
max-same-clients = 1
explicit-ipv4 = 192.168.255.50
```

The options allowed there are listed in ocserv's [manual](https://ocserv.openconnect-vpn.net/ocserv.8.html) under `config-per-user`.

## Connection hooks

`/config/hooks/connect.sh` runs after each client connects and `/config/hooks/disconnect.sh` after each disconnects, as root, with ocserv's variables in the environment: `USERNAME`, `GROUPNAME`, `IP_REAL` (the client's address), `IP_REMOTE` and `IPV6_REMOTE` (its VPN addresses), `DEVICE`, and on disconnect `STATS_BYTES_IN`, `STATS_BYTES_OUT` and `STATS_DURATION`. A connect hook that exits non-zero refuses the session. A hook without the executable bit runs with `/bin/sh`.

```sh
#!/bin/sh
# /config/hooks/connect.sh
logger -t vpn "$USERNAME connected from $IP_REAL"
```
