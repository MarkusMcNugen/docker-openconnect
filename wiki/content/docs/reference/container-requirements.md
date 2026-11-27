---
title: Container Requirements
weight: 2
---

What the container needs from Docker, and what each piece is for. `docker-compose.yml` in the repository sets all of it, and the smoke test (`tests/run.sh smoke`) runs the image with exactly these settings.

The container does not need `--privileged`.

## Ports

| Port | Protocol | Use |
|---|---|---|
| `4443` | TCP | Login and the TLS channel. |
| `4443` | UDP | The DTLS data channel. Without it, clients fall back to TCP, which is slower. |

Change both with `LISTEN_PORT` and publish the new port, or keep `4443` inside and map another port outside: `-p 443:4443 -p 443:4443/udp`.

## Device

| Device | Why |
|---|---|
| `/dev/net/tun` | Each client's tunnel is a tun device. The entrypoint opens the device at start and stops with a message if it cannot. |

## Capabilities

The image works with Docker's default capabilities plus `NET_ADMIN`. The compose file drops everything else:

| Capability | Needed by |
|---|---|
| `NET_ADMIN` | Creating tun devices and their addresses and routes; loading the firewall. |
| `NET_RAW` | Legacy iptables, on hosts without nftables. |
| `NET_BIND_SERVICE` | Listening on a port below 1024. |
| `SETUID`, `SETGID` | Starting ocserv's worker processes as the unprivileged `ocserv` user. |
| `KILL` | ocserv signaling its workers, which run as another user. |
| `CHOWN`, `FOWNER`, `DAC_OVERRIDE` | Giving `/config` to `PUID`/`PGID`, limiting key files to their owner, and reading files the host user owns. |

## Kernel settings

| Setting | Value | Why |
|---|---|---|
| `net.ipv4.ip_forward` | `1` | Forwarding client traffic. Required; the container stops without it. |
| `net.ipv6.conf.all.forwarding` | `1` | Forwarding client IPv6 traffic. Without it, IPv6 still stays inside the tunnel and is dropped there. |
| `net.ipv6.conf.all.disable_ipv6` | `0` | Lets the tunnel carry IPv6, which is what keeps a client's native IPv6 inside the VPN. |
| `net.ipv6.conf.default.disable_ipv6` | `0` | The same, for tun devices created after start. |

`/proc/sys` is read-only in a container that is not privileged, so these are set with `--sysctl` or `sysctls:`. The IPv6 settings fail to apply only on a host whose kernel was booted with IPv6 removed (`ipv6.disable=1`); remove them there and set `IPV6=false`.

## Hardening options

| Option | Effect |
|---|---|
| `read_only: true` with `tmpfs` on `/run` and `/tmp` | Nothing in the image can be changed at run time. The generated configuration, sockets and pid file live on the tmpfs. |
| `no-new-privileges:true` | No process can gain privileges through a set-user-ID program. |
| `cap_drop: [ALL]` with the list above | Only the capabilities the server uses. |

## Kernel features

| Feature | Use |
|---|---|
| nf_tables, with NAT and masquerade | The firewall, and ocserv's route restriction. |
| legacy iptables (`ip_tables`, `iptable_nat`, `xt_TCPMSS`) | Used when nf_tables is missing, without route restriction. |
| tun | The tunnels. |
| seccomp | ocserv's worker sandbox (`isolate-workers`). |
