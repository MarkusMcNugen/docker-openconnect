---
title: Manage Users
weight: 1
---

VPN users live in `/config/ocpasswd`. The [admin panel](../use-the-admin-panel/) manages them on its **VPN users**, **Groups** and **Sessions** pages; without it, `ocpasswd` and `occtl` do the same from the command line. ocserv reads the file at every sign-in, so a change applies from the user's next sign-in, without a restart.

## Add a user, or change a password

### In the admin panel

On **VPN users**, type the user's name and, if they belong to groups, the groups separated by commas, then **Add user**. The panel generates a strong password unless you choose to type one. While the VPN asks for codes from an authenticator app, the new user also gets an authenticator key.

![The VPN users page: a form to add a user above the list of users, each with buttons for a new password, the authenticator, locking and removing](/images/panel/users.png)

Adding a user, **New password** and **Reset authenticator** open the user's onboarding kit: the server and its key pin, the password, the authenticator key, and how to set up each client, on one printable page. The panel keeps neither the password nor the key, so hand the kit to the user then.

![The onboarding kit for a new user: the connection details with the generated password, the authenticator key as a QR code and as text, and the client setup steps](/images/panel/kit.png)

### From the command line

```bash
docker exec -it openconnect ocpasswd -c /config/ocpasswd alice
```

`ocpasswd` asks for the password twice. Without a terminal it reads one line from standard input, which suits scripts and secrets managers:

```bash
printf '%s\n' "$PASSWORD" | docker exec -i openconnect ocpasswd -c /config/ocpasswd alice
```

Put a user in groups with `-g`: `ocpasswd -c /config/ocpasswd -g staff,admins alice`. Running it again with other groups changes them, and asks for the password again; the panel's **Groups** changes them without it.

## Lock, unlock and remove

### In the admin panel

On **VPN users**, **Lock** refuses the user's sign-ins and ends their sessions but keeps their password, and **Unlock** lets them sign in again. **Remove** deletes the user and their authenticator key, ends their sessions and revokes their [certificates](../sign-in-with-certificates/).

### From the command line

```bash
docker exec openconnect ocpasswd -c /config/ocpasswd -l alice   # lock
docker exec openconnect ocpasswd -c /config/ocpasswd -u alice   # unlock
docker exec openconnect ocpasswd -c /config/ocpasswd -d alice   # remove
```

Locking or removing a user stops new sign-ins. To end the sessions the user already has:

```bash
docker exec openconnect occtl terminate user alice
```

`terminate` also invalidates the user's session cookies, so the client cannot reconnect without signing in again.

## See who is connected

### In the admin panel

**Sessions** lists every connected client with its VPN address, the address it connects from, how long it has been connected, its traffic, and whether it uses UDP. The button at the end of a row ends that session: the device disconnects, and the user must sign in again.

![The Sessions page: each connected user with their client, VPN address, the address they connect from, time connected, traffic and channel](/images/panel/sessions.png)

### From the command line

```bash
docker exec openconnect occtl show users
docker exec openconnect occtl show user alice
docker exec openconnect occtl terminate id 245
```

[Commands](../../reference/commands/) shows what each prints.

## Put users in groups

Groups select [per-group settings](../customize-ocserv/#per-user-and-per-group-settings): routes, DNS servers, bandwidth limits and more, which every member shares.

### In the admin panel

**Groups** lists every group the users belong to or that has settings, with its members and what its settings come to. **Create group** makes a group before anyone is in it, and **Change settings** opens the group's settings.

![The Groups page: a form to create a group above a card for each group with its members, routes, DNS servers, bandwidth and route restriction](/images/panel/groups.png)

On **VPN users**, **Groups** on a user's row changes the groups they belong to, separated by commas or empty for none, and keeps their password. ocserv uses the new groups from the user's next connection.

![The VPN users table with the Groups form open on sam's row: the groups separated by commas and a Save button](/images/panel/user-groups.png)

### From the command line

Name the groups with `ocpasswd -g`, as above, and write each group's settings to `/config/config-per-group/<group>`, as [Customize ocserv](../customize-ocserv/#per-user-and-per-group-settings) shows.

## Use a password file from a secret

Point `PASSWD_FILE` at a file mounted from a Docker or compose secret. The container does not create or modify a password file outside `/config`, so the secret can be read-only.
