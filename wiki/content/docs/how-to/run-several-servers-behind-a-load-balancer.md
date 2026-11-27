---
title: Run Several Servers Behind A Load Balancer
weight: 6
---

ocserv keeps its sessions, cookies, address leases and bans in each server's own memory, so containers do not share them. Several containers can still stand behind one TCP load balancer: each is a whole VPN server, the balancer spreads new connections across them, and a client whose server goes away signs in again on another.

## 1. Share the certificate and the users

Clients check the server's key pin, so every server must present the same key. Start the first server once, then copy its `/config/certs` into the other servers' volumes before their first start. Each server renews its certificate with that key, so the pin stays the same.

Every server needs the same users. Put the password file on a directory all of them mount, create it before the first start, and point `PASSWD_FILE` at it (and `OTP_FILE`, when users have codes). ocserv reads the file at each sign-in, so a user added on one server can sign in on all of them. Change users from one server's panel: `ocpasswd` and the panel do not guard the file against two servers changing it in the same moment.

## 2. Give each server its own name, pool and panel

```yaml
services:
  vpn1:
    image: markusmcnugen/openconnect:latest
    hostname: vpn1
    stop_grace_period: 30s
    ports:
      - "4443:4443/tcp"
      - "8443:8443/tcp"
    environment:
      SRV_CN: vpn.example.com
      VPN_ADDRESS: vpn.example.com
      VPN_NETWORK: 192.168.101.0/24
      PASSWD_FILE: /users/ocpasswd
      PROXY_PROTOCOL: "true"
      SERVER_DRAIN_MS: "15000"
      DTLS: "false"
      PANEL_ENABLED: "true"
      PANEL_HOSTNAME: vpn1.example.com
    volumes:
      - ./vpn1:/config
      - ./users:/users
    # devices, cap_drop, cap_add, security_opt, read_only, tmpfs and
    # sysctls as in docker-compose.yml
```

Repeat it for `vpn2` with its own `hostname`, `VPN_NETWORK`, `PANEL_HOSTNAME` and `/config` volume, and other host ports when it runs on the same host.

- `SRV_CN` and `VPN_ADDRESS` name the balancer, which is what clients connect to and what the onboarding kit shows.
- A pool of its own per server keeps every VPN address unique, so a log line or a block names one client.
- `hostname` names the container, and the panel's dashboard says which one you are managing.

### The balancer settings in the admin panel

Instead of `PROXY_PROTOCOL` and `SERVER_DRAIN_MS` in the environment, set them on each server's panel, on **Settings** under **Load balancer**. Both apply with a reload, so connected users stay connected.

![The Load balancer section of the Settings page, with the PROXY protocol on and a drain time of 15000 ms](/images/panel/settings-load-balancer.png)

## 3. Put HAProxy in front

```text
frontend vpn
    bind :443
    mode tcp
    timeout client 1h
    default_backend ocserv

backend ocserv
    mode tcp
    balance source
    timeout connect 5s
    timeout server 1h
    server vpn1 10.0.0.11:4443 send-proxy-v2 check check-send-proxy inter 2s
    server vpn2 10.0.0.12:4443 send-proxy-v2 check check-send-proxy inter 2s
```

- `send-proxy-v2` passes each client's own address to ocserv, which `PROXY_PROTOCOL: "true"` expects. Without it every client would arrive from the balancer's address, and a few wrong passwords would ban the balancer and with it everyone.
- `check` tests each server every 2 s, and `check-send-proxy` makes the checks carry the PROXY header like the traffic, since ocserv expects it on every connection.
- `balance source` keeps an address on the same server, so a client that reconnects from the same address resumes its session without signing in again. A client on a new network may land on another server and signs in there.
- The timeouts must be longer than the dead peer detection intervals, 90 s and for phones 1800 s by default, or the balancer cuts quiet sessions.

## 4. Stop one server at a time

With `SERVER_DRAIN_MS` set, a server that is told to stop closes its port at once and keeps its sessions for that long. The balancer's health check fails, so new connections go to the other servers; then the sessions end, and those clients sign in again on another server.

- Set `SERVER_DRAIN_MS` above the time the balancer takes to mark a server down: with `inter 2s` and HAProxy's default of 3 failed checks, 6 s.
- Set `stop_grace_period` at least 10 s above the drain time. Docker gives a container 10 s to stop, then ends it at once.

To update, pull the new image and recreate the servers one after another.

## What each server keeps to itself

- **Sessions and cookies.** A client that lands on another server signs in again.
- **Bans and the panel's blocklist.** Block an address on every server's panel. The PROXY protocol gives each server the client's own address, and the session script refuses a blocked client even though its connections come from the balancer.
- **The panel.** Each server runs its own, with its own admins and audit log. Reach each panel directly at its `PANEL_HOSTNAME`, never through the balancer: the panel does not read the PROXY protocol, so through the balancer every request would carry the balancer's address, and with the balancer inside `PANEL_LAN_NETWORKS` every admin would sign in with the password alone. The same goes for the user portal.
- **Per-user and per-group settings.** They live in each server's `/config`; copy them to every server.

## The UDP channel

HAProxy carries TCP only, so the example turns the UDP channel off with `DTLS: "false"`. To keep it, use a balancer that also carries UDP on the same port and sends each client's UDP to the server that holds its TCP connection, for example by choosing the server from the client's address for both.
