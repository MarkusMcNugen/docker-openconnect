---
title: Upgrade From 1.x
weight: 9
---

Pull the new image and recreate the container with the same `/config` volume. Users, certificates and keys carry over unchanged, so clients keep connecting with the same password and the same server key.

## What happens to the old files

The 1.x image copied `ocserv.conf`, `connect.sh` and `disconnect.sh` into `/config` and rewrote parts of `ocserv.conf` at every start. On the first start of the new image (`rootfs/usr/local/lib/ocserv-docker/legacy.sh`):

| You had | The container |
|---|---|
| The `ocserv.conf` the 1.x image wrote, never edited by hand | Renames it to `ocserv.conf.legacy` and builds the configuration from environment variables, with every new default. |
| An `ocserv.conf` you edited by hand | Uses it as the whole configuration, as `POWER_USER=true` would, and warns at each start. |
| `POWER_USER=true` | Uses your `ocserv.conf` as it stands, as before. |
| The 1.x `connect.sh` and `disconnect.sh`, unedited | Renames them to `.legacy`; the container logs connections itself. |
| `connect.sh` or `disconnect.sh` you edited | Runs them after its own log line, and warns. |

A file counts as unedited when it matches one of the versions the 1.x image shipped, ignoring the lines the 1.x entrypoint rewrote (ports, `dns`, `route` and `split-dns`) and line endings.

## Moving a hand-edited configuration to variables

A hand-edited 1.x configuration keeps its 1.x settings, including the older TLS settings and compression. To move to the new defaults:

1. Note what you changed in `/config/ocserv.conf`.
2. Express each change as a variable, an `OCSERV_CONF_*` variable or a line in `/config/ocserv-extra.conf`; see [Customize ocserv](../customize-ocserv/).
3. Rename `/config/ocserv.conf` and restart.

## Changed run options

- `--privileged` is no longer needed. Replace it with the flags in [Container Requirements](../../reference/container-requirements/).
- The variables of 1.x work as before: `LISTEN_PORT`, `DNS_SERVERS`, `TUNNEL_MODE`, `TUNNEL_ROUTES`, `SPLIT_DNS_DOMAINS`, `POWER_USER` and the `CA_*` and `SRV_*` certificate variables. `POWER_USER` accepts `yes` and `no` as well as `true` and `false`.
- The default DNS servers are Quad9 and Cloudflare (`9.9.9.9`, `1.1.1.1`); set `DNS_SERVERS` to keep others.
- A user can hold 4 sessions at once by default; set `MAX_SAME_CLIENTS` for more.
- VPN clients can no longer reach each other by default; set `CLIENT_TO_CLIENT=true` to allow it.
