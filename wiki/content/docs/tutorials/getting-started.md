---
title: Getting Started
weight: 1
---

This tutorial runs the server, adds a user, connects a client and checks that the client's traffic, IPv6 included, goes through the VPN. It takes a Linux host with Docker and a client machine with [OpenConnect](https://www.infradead.org/openconnect/) or Cisco Secure Client.

## 1. Start the server

Create a folder for the server's state and start the container. Replace `vpn.example.com` with the name clients will connect to.

```bash
mkdir -p /srv/openconnect

docker run -d --name openconnect --restart unless-stopped \
  -p 4443:4443/tcp -p 4443:4443/udp \
  -v /srv/openconnect:/config \
  -e SRV_CN=vpn.example.com \
  --device /dev/net/tun \
  --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add KILL \
  --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add NET_RAW \
  --cap-add SETGID --cap-add SETUID \
  --security-opt no-new-privileges:true \
  --read-only --tmpfs /run --tmpfs /tmp \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.default.disable_ipv6=0 \
  markusmcnugen/openconnect
```

The same settings as a compose file are in the repository's [`docker-compose.yml`](https://github.com/MarkusMcNugen/docker-openconnect/blob/main/docker-compose.yml); `docker compose up -d` starts it.

[Container Requirements](../../reference/container-requirements/) explains each flag.

To manage the server from a browser as well, add these lines before the image name, with your LAN's network:

```bash
  -e PANEL_ENABLED=true -p 8443:8443 \
  -e PANEL_ALLOWED_NETWORKS=192.168.1.0/24 -e PANEL_LAN_NETWORKS=192.168.1.0/24 \
```

`PANEL_ALLOWED_NETWORKS` lets your LAN reach the [admin panel](../../how-to/use-the-admin-panel/), and `PANEL_LAN_NETWORKS` lets an admin there sign in with the password alone; from anywhere else the panel also asks for a second factor. The steps below show the panel's way where it has one.

## 2. Read the start-up log

```bash
docker logs openconnect
```

On the first start the container creates a private CA and a server certificate in `/srv/openconnect/certs`, warns that no users exist yet, and prints a summary ending with the server's key pin:

```text
2026-11-25T21:12:05Z [info] firewall: nftables, NAT true, client isolation on, route restriction false
2026-11-25T21:12:05Z [info] server key pin for clients: pin-sha256:/uEGWoG2HjfBX9bEqNGhB3QvcQGU5ChZGoDBVuLVQgA=
```

Your pin is different: it is derived from the key your server just created.

Keep the pin: clients use it to recognize the server. [Logs](../../reference/logs/) lists every line the container writes.

## 3. Add a user

### In the admin panel

Find the panel's one-time password in the log, `docker logs openconnect 2>&1 | grep "one-time password"`, sign in at `https://vpn.example.com:8443/` as `admin` and choose your own password. The browser warns about the panel's certificate until it trusts the private CA, `/srv/openconnect/certs/ca.pem`. On **VPN users**, type `alice` and **Add user**. The panel shows alice's onboarding kit with a generated password, the server's key pin and how to set up each client; hand it to her.

![The VPN users page: a form to add a user above the list of users](/images/panel/users.png)

### From the command line

```bash
docker exec -it openconnect ocpasswd -c /config/ocpasswd alice
```

`ocpasswd` asks for the password twice. The change applies to the next sign-in; nothing needs restarting. [Manage Users](../../how-to/manage-users/) covers changing, locking and removing users.

## 4. Open the port

Forward TCP and UDP port 4443 on your router to the Docker host. Without UDP, clients still connect but carry traffic over TCP, which is slower.

## 5. Connect a client

### OpenConnect

```bash
sudo openconnect --user=alice --servercert=pin-sha256:... https://vpn.example.com:4443/
```

Use the pin from step 2. OpenConnect checks that the server's key matches it, so the private CA does not need to be installed on the client.

### Cisco Secure Client

Copy `/srv/openconnect/certs/ca.pem` to the device and install it as a trusted CA certificate, then add a connection to `vpn.example.com:4443`. Cisco's client refuses servers it cannot verify unless the CA is trusted. With a public certificate (see [Use Your Own Certificate](../../how-to/use-your-own-certificate/)) this step is not needed.

## 6. Check the tunnel

On the connected client:

```bash
curl -4 https://ifconfig.co
curl -6 https://ifconfig.co
```

The IPv4 address is your server's public address. If the Docker host has IPv6, the IPv6 address is the server's too; if it does not, the IPv6 request fails instead of going out through the client's own network, because the client's IPv6 traffic is routed into the tunnel and dropped there. Either way, nothing leaves outside the VPN.

On the server, the panel's **Sessions** page lists the connected session, and so does:

```bash
docker exec openconnect occtl show users
```

[Commands](../../reference/commands/) has its output.

## Next steps

- [Use Your Own Certificate](../../how-to/use-your-own-certificate/) so clients trust the server without a pin.
- [Add Two-Factor Login](../../how-to/add-two-factor-login/).
- [Hide The Server With Camouflage](../../how-to/hide-the-server-with-camouflage/).
- [Environment Variables](../../reference/environment-variables/) for every setting.
