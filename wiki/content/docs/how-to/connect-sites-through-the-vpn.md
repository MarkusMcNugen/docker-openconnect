---
title: Connect Sites Through The VPN
weight: 4
---

A site is a network behind a router that connects to the VPN as one of its users: a branch office, a home lab, a cloud network. The server routes the site's networks through that router's session, and rules decide who reaches them: every VPN client, a group, or another site. Nothing passes from one tunnel to another without a rule, and a site's networks reach past the VPN only when you turn that on.

## 1. Give the site a user and list its networks

Add a VPN user for the site's router, as in [Manage users](../manage-users/), and list the networks behind the router in that user's settings.

### In the admin panel

On **VPN users**, open the site's user by its name. Under **More settings**, list the networks in **Site-to-site networks behind this user**, one per line, and save. ocserv routes them through the user's session from its next connection.

![The last row of More settings on a user's settings page, with two networks in Site-to-site networks behind this user, above the Save settings button](/images/panel/site-networks.png)

### From the command line

```text
# /config/config-per-user/branch-office
iroute = 10.10.0.0/24
iroute = 10.10.1.0/24
```

### Either way

- The panel refuses a network that overlaps the VPN's address pools, a group's pool, the container's own networks or another site's networks; keep a hand-written file to the same.
- Each site needs its own user, and only one router can connect as that user: while one session routes the site's networks, ocserv refuses a second.

## 2. Connect the site's router

Run an OpenConnect client on the router as the site's user; the user's onboarding kit has the command and the server's key pin. Then:

- Turn on IP forwarding on the router, so it passes packets between the site and the tunnel.
- The site's hosts send their traffic for the VPN to the router. When the router is their default gateway, they already do.
- While the server tunnels every network, the router sends all of its traffic into the tunnel, so the site's hosts reach the internet only through the server, once **Beyond the VPN** is on for the site (step 4).

## 3. Open the way with rules

### In the admin panel

On **Sites**, a rule starts at **From**: every VPN client, a group, a published network or another network you type. It leads to **To**: a group, a published network or another network. **Add rule** loads it into the firewall at once, and **Remove** takes it out.

![The Sites page: two sites with their networks, whether each is connected and whether its networks reach beyond the VPN, and two rules between the group staff and a site's network](/images/panel/sites.png)

### From the command line

The rules live in `/config/panel/site-rules.json`, which the firewall loads at every start. Without the admin panel, write the file while the container is stopped:

```json
{
  "rules": [
    {
      "id": 1,
      "from": "clients",
      "to": { "network": "10.10.0.0/24" },
      "by": "admin",
      "created": 0
    },
    {
      "id": 2,
      "from": { "network": "10.10.0.0/24" },
      "to": { "network": "192.168.50.0/24" },
      "by": "admin",
      "created": 0
    }
  ],
  "egress": ["branch-office"]
}
```

An end is `"clients"`, `{ "group": "staff" }` or `{ "network": "10.10.0.0/24" }`, and every VPN client can only be where a rule starts. `id` numbers each rule; `by` and `created`, in Unix seconds, only label it on the Sites page. With the panel on, change the rules on the Sites page instead, since the panel rewrites the file with each change.

### Either way

- A rule lets new connections go one way and their replies come back. For connections both ways, add a rule each way.
- A rule for a group follows its members' sessions as they connect and disconnect. That takes the admin panel; without it, write rules between networks.
- Removing a rule stops the new connections it let through. Open ones last until they end.

## 4. Let a site's networks out of the VPN

A site's networks reach VPN clients and other sites only as the rules allow, and nothing past the VPN until **Beyond the VPN** is on for the site.

### In the admin panel

On **Sites**, **Turn on** under **Beyond the VPN** for the site. It is off for every site until you turn it on.

### From the command line

List the site's user under `egress` in `/config/panel/site-rules.json`, as `branch-office` is in the example above.

### Either way

With `NAT` on, the default, the site's traffic leaves with the server's address, as clients' traffic does. With `NAT` off it keeps the site's addresses, so your network must route them back to the container.

## When the rules cannot work

- The firewall checks that every packet from a tunnel comes from an address that tunnel owns, so a client cannot send as another client or as a site. On a kernel that cannot make this check, the container warns at start and no rule opens anything; the Sites page says so too.
- With legacy iptables, rules can name networks but not groups.
- `CLIENT_TO_CLIENT: "true"` lets every tunnel reach every other and every site, whatever the rules say.
- In split mode a client sends only its routed networks through the tunnel. Add a site's networks to the routes of the users and groups that should reach it, and other sites' networks to its router's routes, as in [Tunnel only some networks](../tunnel-only-some-networks/#give-one-group-other-networks).
