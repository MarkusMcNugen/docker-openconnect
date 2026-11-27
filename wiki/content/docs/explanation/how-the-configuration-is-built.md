---
title: How The Configuration Is Built
weight: 2
---

At every start the entrypoint (`rootfs/usr/local/bin/docker-entrypoint.sh`) writes a complete `ocserv.conf` to `/run/ocserv/ocserv.conf` and starts ocserv with it. Nothing is edited in place, so a restart never accumulates duplicate lines, and the file always matches the current variables.

## The start sequence

1. Read and check every variable (`settings.sh`). An invalid value stops the container with a message naming it.
2. Recognize files left by the 1.x image (`legacy.sh`).
3. Decide whether the tunnel can carry IPv6, and choose nftables or legacy iptables.
4. Create the CA and server certificate if none is configured, or renew one the container created (`certs.sh`).
5. Write the configuration (`config.sh`).
6. Give `/config` to `PUID`/`PGID` when set, and limit key files to their owner.
7. Check `/dev/net/tun` and IPv4 forwarding, and load the firewall.
8. Have ocserv check the configuration (`ocserv --test-config`), print a summary, and start ocserv in the foreground with its logs on standard error.

## The layers

The configuration is built from three layers. A later layer replaces an earlier one option by option:

1. **Defaults and named variables**, such as `MAX_CLIENTS` or `DNS_SERVERS`.
2. **`EXTRA_CONFIG`** (`/config/ocserv-extra.conf`), an ocserv.conf fragment. Every option it names replaces all values the first layer gave that option. Lines from the first `[vhost:...]` header on are added at the end of the file.
3. **`OCSERV_CONF_*` variables**, one per option. An empty value removes the option.

For example, with these settings:

```text
DNS_SERVERS=9.9.9.9,1.1.1.1
OCSERV_CONF_MAX_CLIENTS=500
```

and this `/config/ocserv-extra.conf`:

```text
dns = 192.168.1.1
max-clients = 64
```

the configuration has `dns = 192.168.1.1` as its only DNS server, from the extra file, and `max-clients = 500`, from the variable.

## Power user mode

With `POWER_USER=true` the container uses `/config/ocserv.conf` as it stands and the configuration variables do not apply. The firewall, certificate and file-ownership variables still do, and the firewall reads the VPN pools from that file. When the file does not exist, the container writes it once from the current variables, so switching to power user mode starts from the configuration you already had.

Prefer `EXTRA_CONFIG` or `OCSERV_CONF_*` when you need only a few options: the rest of the configuration keeps getting new defaults as the image changes.
