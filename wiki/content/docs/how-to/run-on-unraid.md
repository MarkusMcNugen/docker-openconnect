---
title: Run On unRAID
weight: 7
---

## Template settings

| Setting | Value |
|---|---|
| Repository | `markusmcnugen/openconnect` |
| Network type | Bridge |
| Port 4443 TCP | `4443` |
| Port 4443 UDP | `4443` |
| Path `/config` | `/mnt/user/appdata/openconnect` |
| Variable `SRV_CN` | the name clients connect to |
| Variable `PUID` | `99` |
| Variable `PGID` | `100` |

`PUID=99` and `PGID=100` give the appdata folder to unRAID's `nobody:users`, so it can be read and edited over the network share. The container still limits the key and password files to their owner.

## Extra parameters

Turn on the advanced view and set **Extra Parameters** to:

```text
--device=/dev/net/tun --cap-drop=ALL --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=KILL --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE --cap-add=NET_RAW --cap-add=SETGID --cap-add=SETUID --security-opt=no-new-privileges:true --read-only --tmpfs=/run --tmpfs=/tmp --sysctl=net.ipv4.ip_forward=1 --sysctl=net.ipv6.conf.all.forwarding=1 --sysctl=net.ipv6.conf.all.disable_ipv6=0 --sysctl=net.ipv6.conf.default.disable_ipv6=0
```

Leave **Privileged** off; the container does not need it.

## Adding users

Open the container's console from the Docker tab, or run from the unRAID terminal:

```bash
docker exec -it openconnect ocpasswd -c /config/ocpasswd alice
```

## Reaching the unRAID box over the VPN

In bridge mode, clients reach the LAN and the unRAID host's LAN address through the container's NAT. Use `TUNNEL_MODE=split-include` with `TUNNEL_ROUTES` set to your LAN to send only LAN traffic through the VPN; see [Tunnel Only Some Networks](../tunnel-only-some-networks/).
