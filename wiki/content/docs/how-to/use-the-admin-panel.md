---
title: Use The Admin Panel
weight: 11
---

The image carries a web admin panel for running the VPN from a browser. It is off unless you turn it on. This page covers turning it on, signing in and the admins who use it; each task page shows the panel's way beside the command line's. Every variable the panel reads is in [Environment Variables](../../reference/environment-variables/#admin-panel), and how it is protected is in [Security Model](../../explanation/security-model/#the-admin-panel).

![The panel's dashboard: the VPN server's state, the connected sessions and the traffic over the last day, with every page in the sidebar](/images/panel/dashboard.png)

## 1. Turn it on

Add `PANEL_ENABLED=true` to the container's environment and publish the panel's port, `8443` unless `PANEL_PORT` says otherwise. In `docker-compose.yml`:

```yaml
    environment:
      PANEL_ENABLED: "true"
      PANEL_ALLOWED_NETWORKS: 192.168.1.0/24
    ports:
      - "8443:8443"
```

The panel admits loopback, the Docker host and connected VPN clients. `PANEL_ALLOWED_NETWORKS` adds your LAN; any other address is dropped by the container's firewall before it reaches the panel.

The panel serves its own certificate, issued from the image's CA. Trust `/config/certs/ca.pem` in your browser, or give the panel your own certificate with `PANEL_CERT` and `PANEL_KEY`.

## 2. Sign in the first time

The first start creates an owner named `admin` and prints a one-time password to the container log:

```bash
docker logs openconnect 2>&1 | grep "one-time password"
```

Open `https://vpn.example.com:8443/`, sign in with it, and choose your own password of at least `PANEL_MIN_PASSWORD_LENGTH` characters (12 by default). The one-time password then stops working. To create the first admin from a password file instead, set `PANEL_ADMIN_PASSWORD_FILE`.

![The panel's sign-in page, asking for the admin name and password](/images/panel/sign-in.png)

## 3. Set up a second factor

From the networks in `PANEL_LAN_NETWORKS`, the password alone signs in. From anywhere else the panel then asks for a second factor: one of your passkeys, or a six-digit code from an authenticator app. A new admin signing in from outside gets a session that can only set one up, an authenticator app or a passkey.

A passkey lives on your laptop, phone or security key, which unlocks it with its PIN, fingerprint or face. Browsers offer it only to the panel's own address, so a look-alike site cannot collect it. Passkeys work when browsers reach the panel at a host name, `PANEL_HOSTNAME` or else `SRV_CN`, never at an IP address. The container log says at start whether they are available:

```text
passkeys: available, bound to vpn.example.com
```

Your name at the foot of the sidebar opens **Your account**: your role, your password, your authenticator app, your passkeys and **Sign out everywhere else**. To add a passkey, name it, such as Work laptop, and choose **Add a passkey**; an admin can have up to 10. Replacing the authenticator app, adding a passkey once you have a second factor, and removing one all need a recent sign-in, and your last second factor cannot be removed.

![The Your account page: the admin's name and role, a button to change the password, the authenticator app with a button to replace it, two passkeys with when each was added, and a field to name and add another](/images/panel/account.png)

At a sign-in from outside, choose **Use a passkey**, or enter the code from the app:

![The second-factor page: a Use a passkey button, and below it a field for the code from the authenticator app](/images/panel/second-factor.png)

## Where each task is

- **Dashboard**: the server's state, the connected sessions and traffic over the last `PANEL_HISTORY_HOURS`, the newest events, and the container the panel runs in, which tells [several servers behind a load balancer](../run-several-servers-behind-a-load-balancer/) apart.
- **Sessions**, **VPN users** and **Groups**: [Manage Users](../manage-users/), and for authenticator keys [Add Two-Factor Login](../add-two-factor-login/).
- **Live events**, **Bans** and **Audit log**: [Troubleshoot](../troubleshoot/#watch-the-server), with the country rules in [Block Or Allow Countries](../block-countries/) and the location checks, their refusals and vacations in [Check Where Sign-ins Come From](../check-where-sign-ins-come-from/).
- **Alerts**: [Get Alerts](../get-alerts/), what alerts each admin and where: ntfy, Telegram, a webhook or email.
- **Sites**: [Connect Sites Through The VPN](../connect-sites-through-the-vpn/).
- **Settings**: [Customize ocserv](../customize-ocserv/#the-settings-page), with its tunnel section in [Tunnel Only Some Networks](../tunnel-only-some-networks/).
- **Certificates**: [Use Your Own Certificate](../use-your-own-certificate/) and [Sign In With Certificates](../sign-in-with-certificates/).

## Admins and roles

Admins are owners, operators or viewers. Owners manage everything, including settings, certificates, admins and the audit log; operators manage VPN users, groups, sessions and bans; viewers see every page but change nothing.

On **Admins**, an owner adds an admin with a role and a one-time password shown once, changes an admin's role, gives them a new one-time password, removes their second factors so they set up new ones, unlocks them and removes them. Removing second factors takes the authenticator app and every passkey, as after a lost or stolen device. A new admin, or one whose second factors were removed, can sign in with the password alone from any allowed network, but only to set up an authenticator app or a passkey. Only another owner can change your own account.

![The Admins page: a form to add an admin with a role, above the list of admins with their role, status, second factors and last sign-in](/images/panel/admins.png)

Every sign-in, refusal and change is written to `/config/panel/audit.log`, which owners read on [Audit log](../troubleshoot/#read-the-audit-log).

## Let VPN users help themselves

With `PANEL_PORTAL_ENABLED=true` and port `8444` published, VPN users sign in at `https://vpn.example.com:8444/` with their VPN user name and password. The portal shows them how to connect, with direct links to the clients, and lets them change their password, set up or replace their authenticator app and end their own sessions. While the VPN asks for codes, a user without a key can sign in with the password alone only to set one up. For a portal on the internet, give it a public certificate with `PANEL_PORTAL_CERT` and `PANEL_PORTAL_KEY`.

![The user portal's sign-in page, asking for the VPN user name and password](/images/panel/portal-sign-in.png)
