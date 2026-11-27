---
title: Security Model
weight: 1
---

What protects the server and its clients, and where each protection is set. The defaults are on in every install; [Environment Variables](../../reference/environment-variables/) lists how to change each.

## Leak protection

A VPN leaks when a client's traffic reaches the internet without passing through the tunnel. Three paths are closed.

**IPv6.** A full-tunnel client that has native IPv6 at home or on mobile data would send IPv6 traffic straight out if the VPN only carried IPv4. The container gives every client an IPv6 address from `VPN_IPV6_NETWORK` and an IPv6 default route through the tunnel, so IPv6 traffic enters the tunnel too. When the Docker host has IPv6, that traffic is translated and forwarded like IPv4. When it does not, the traffic is dropped inside the container and the client's applications fall back to IPv4, which is the behavior of a network with no IPv6. In both cases nothing leaves outside the tunnel. The entrypoint turns this on whenever the tunnel device can carry IPv6 (`IPV6=auto`) and prints a warning at start when it cannot (`rootfs/usr/local/lib/ocserv-docker/system.sh`, `detect_ipv6`).

**DNS.** Clients get the DNS servers in `DNS_SERVERS` and send every query through the tunnel (`tunnel-all-dns`), in split-include mode as well, so the local network cannot see or change name lookups.

**Routes.** In full-tunnel mode the client's default route is the tunnel (`route = default`). In split-include mode only the listed networks are tunneled, and route restriction stops a client from using the server to reach anything else.

## The firewall

The container loads its own firewall into its network namespace before ocserv starts (`rootfs/usr/local/lib/ocserv-docker/firewall.sh`). With nftables it is one table, loaded atomically, so a half-applied rule set never exists:

- **Forwarding is denied by default.** Only traffic from a client, and the replies to it, is forwarded. A connection from outside to a client's VPN address is dropped, so clients are not reachable from the networks the server sits on.
- **Clients are isolated.** Traffic from one VPN client to another is dropped, so a compromised device cannot scan or attack the others. [Site-to-site rules](../../how-to/connect-sites-through-the-vpn/) open only the paths they name, between clients and the networks behind sites, and a site's networks reach past the VPN only when the admin panel lets them. `CLIENT_TO_CLIENT=true` allows all traffic between clients.
- **A tunnel speaks only for its own addresses.** A packet from a tunnel must come from an address that tunnel owns: the client's VPN address, or a network published behind it. Anything else is dropped before any rule sees it, so a client cannot send as another client or as a site. On a kernel that cannot make this check, the container warns at start and no site-to-site rule opens anything.
- **The container is closed to clients.** A client can ping the server's tunnel address and nothing else on the container.
- **TCP MSS clamping** keeps TCP segments within the tunnel's MTU, so large downloads do not stall on dropped oversized packets.
- **Source NAT** translates client addresses to the container's own address on the way out. `NAT=false` leaves it off for a network that routes the VPN pool instead.
- **Route restriction** (split-include mode) is applied per client by ocserv's own nftables helper, which allows the client's routes and DNS servers and rejects everything else.

Hosts without nf_tables get the same rules through legacy iptables, without route restriction and without site-to-site rules that name a group.

## The TLS channel

Logins and the TCP channel use TLS 1.3 or 1.2 only. Key exchange is ECDHE, so a stolen server key cannot decrypt recorded sessions (forward secrecy), and the only ciphers are AEAD ones: AES-GCM and ChaCha20-Poly1305. CBC ciphers, static RSA key exchange, SHA-1 MACs and every older protocol version are removed. The UDP data channel used by OpenConnect clients (DTLS-PSK) takes its ciphers from the same settings, so it is DTLS 1.2 with the same AEAD ciphers.

Cisco Secure Client and AnyConnect negotiate their UDP channel through Cisco's older method, which ocserv implements with its own fixed cipher list that can include AES-CBC with SHA-1. `CISCO_COMPAT=false` turns that method off and requires the UDP channel to use the TLS channel's cipher; only OpenConnect-protocol clients connect then.

Compression is off (`compression = false`). Compressing data before encrypting it lets an attacker who can inject traffic learn secrets from the change in packet sizes. Support is compiled in, so `OCSERV_CONF_COMPRESSION=true` turns it on for a link where that trade is acceptable.

## Logins

- Passwords are checked by ocserv's security module, a separate process that holds the password file and the server key; the processes handling client connections never see either.
- Each wrong password adds `BAN_POINTS_WRONG_PASSWORD` to the client address's score, and an address over `MAX_BAN_SCORE` is banned for `BAN_TIME` seconds.
- `MAX_SAME_CLIENTS` caps the sessions one account can have open, which limits what a stolen password is worth.
- A one-time-password file adds a second factor to every login.
- `AUTH_MODE` adds client certificates, alone or with the password. They must come from a client CA that signs nothing else, so neither the server's certificate nor the panel's can sign anyone in, and a revoked certificate is refused. ocserv does not read the password file for a certificate, so with the admin panel on, the session script refuses a certificate whose user is locked or removed. A key file the panel makes is handed out once and kept nowhere; a key from a signing request never leaves the user's device.
- `CAMOUFLAGE_SECRET` makes the server answer like an empty web server unless the URL carries the secret, which hides it from scanners.

## The processes

ocserv's main process runs as root because it creates tun devices. Each client connection is handled by a worker process that runs as the unprivileged `ocserv` user with a seccomp filter limiting its system calls (`isolate-workers`) and a memory ceiling (`limit-worker-memory`). A bug in the code that parses client traffic is therefore contained to one sandboxed process.

The container runs with a read-only root file system, only the capabilities in [Container Requirements](../../reference/container-requirements/), and `no-new-privileges`.

## The admin panel

The panel is off unless `PANEL_ENABLED=true`, and when on it is split in two. A root helper holds every secret and makes every decision: admin passwords (Argon2), sessions, second factors, the VPN users' files, the firewall blocklist and the audit log. The web process that faces the network runs as its own unprivileged user with no capabilities, cannot gain privileges, and only forwards requests to the helper over a socket that only it can open. A bug in the code that parses web requests can therefore read no secret and change nothing the helper would refuse.

Requests must name the panel's own host, so a site that points its own name at the panel (DNS rebinding) is refused. Forms are accepted only with the panel's own `Origin` and a same-origin `Sec-Fetch-Site`. The panel sends `Referrer-Policy: same-origin` rather than `no-referrer`, because under `no-referrer` browsers send `Origin: null` with every form, which the origin check would refuse. Every change also carries a per-session token. Session cookies use the `__Host-` prefix with `Secure`, `HttpOnly` and `SameSite=Strict`, and every response carries a strict content security policy, `X-Frame-Options: DENY` and `Cache-Control: no-store`.

Outside `PANEL_LAN_NETWORKS`, an admin signs in with a passkey or a code from an authenticator app as well as the password. Wrong passwords lock the account and the address for a while. The user portal for VPN users follows the same rules on its own port, with its own sessions and lockouts, so no portal session is ever an admin session.

The panel's blocklist drops a blocked address at the firewall on every port. Behind a load balancer with `PROXY_PROTOCOL=true`, VPN connections reach the container from the balancer's address, so ocserv's session script also checks each connecting client's own address and refuses a blocked one, and refuses every client while the blocklist cannot be read. The panel and the portal do not read the PROXY protocol: reach them directly, never through a balancer, or every request carries the balancer's address and the checks above apply to it.

## The image

- ocserv is compiled from the release tarball after its signature is checked against the maintainer's key, pinned by fingerprint in the `Dockerfile`. A tarball without a valid signature from that key stops the build. The patches in `patches/` are the only changes made to the source; [How The Image Stays Current](../how-the-image-stays-current/#patches) describes each one.
- The binaries are built with stack protection, fortified string functions, full RELRO and position-independent code.
- The runtime image carries only the libraries the binaries link against, the firewall tools, `certtool`, bash and tini. Compilers stay in the build stages.
- Every published image has an SBOM and build provenance attached in the registry.
