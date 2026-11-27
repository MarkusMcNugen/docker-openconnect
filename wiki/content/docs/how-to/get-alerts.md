---
title: Get Alerts
weight: 4
---

The admin panel can tell you when something needs your attention: through ntfy, a Telegram bot, a webhook such as Discord, Slack, Gotify or Home Assistant, or email. Each admin chooses what alerts them and where it goes, on the panel's **Alerts** page.

## 1. Choose what alerts you

On **Alerts**, tick what you want to hear about under **What alerts you**, then select **Save**:

- **Automatic blocks**: an address the firewall blocked after repeated bans (see `PANEL_BLOCK_AFTER_BANS`), as it happens.
- **Sign-ins from outside**: a sign-in to the panel from outside `PANEL_LAN_NETWORKS`, as it happens. Owners hear of every admin's; operators and viewers hear of their own.
- **Country rule drops**: once a day, just after midnight UTC, how many packets the [country rules](../block-countries/) dropped the day before. A day without drops sends nothing.
- **Location checks**: a sign-in the [location checks](../check-where-sign-ins-come-from/) refused or found unusual, as it happens, with its score and reasons, and a VPN sign-in let in because its check could not run. Owners hear of every admin's panel sign-ins; other admins hear of their own and of every VPN user's.

## 2. Add where alerts go

Under **Where alerts go**, add up to ten channels. Each one gets every alert you chose.

![The Where alerts go card with an ntfy topic, a Telegram chat, an unencrypted webhook on a home network and an email address, each with how its last message went](/images/panel/alerts.png)

### ntfy

Install the ntfy app and subscribe to a topic name only you know, then add the same topic with **Add ntfy**. Leave the server empty for ntfy.sh, or give your own ntfy server; a protected topic takes its access token. On ntfy.sh anyone who knows a topic's name can read it, so make the name long and hard to guess.

### Telegram

Message @BotFather to create a bot, which gives you its token, then send your bot any message. Open `https://api.telegram.org/bot<token>/getUpdates` in a browser: the number after `"chat":{"id":` is your chat ID. Add both with **Add Telegram**.

### A webhook

**Add a webhook** takes the URL a service gives you. Discord and Slack webhooks get messages in their own shape; any other URL gets a JSON body with `title`, `message` and `text`, which Gotify, Home Assistant, Mattermost and most others read.

### Email

**Add email** takes your address. Email goes through the panel's mail server, which an owner sets in the next step.

Then select **Send a test** beside the channel. Its line says how the last message went; reload the page to see a test arrive.

## 3. Set the mail server, for email

Owners set one mail server for every admin's email alerts. On **Alerts**, the **Mail server** card takes the server's name, how it is reached, the port when it is not the usual one, the address alerts come from, and the user name and password:

- **TLS**, usually on port 465, and **STARTTLS**, usually on port 587, are what mail providers offer.
- **None**, usually on port 25, reaches only a relay that takes no password, such as one on your network. A password is never sent unencrypted.

The password is never shown again. An empty password field keeps the saved one while the server and user name stay the same, so a saved password never goes to another server.

The environment can set the mail server instead, and then wins over the panel's:

```text
PANEL_SMTP_HOST=smtp.example.com
PANEL_SMTP_SECURITY=starttls
PANEL_SMTP_USER=alerts@example.com
PANEL_SMTP_PASSWORD=your-app-password
PANEL_SMTP_FROM=alerts@example.com
```

See [Environment variables](../../reference/environment-variables/#admin-panel).

## How alerts go out

- Alerts that come within a minute of a message to a channel wait and go together in the next one, so an attack that sets off many blocks arrives as a few messages, inside ntfy.sh's 250 messages a day and Telegram's limits.
- A message that cannot be sent is tried again after a minute and after ten minutes; each try waits at most 10 s to connect and 30 s in all. After the third try, the channel's line says why, and the audit log records it.
- `https://` URLs work anywhere. `http://` URLs reach only private addresses: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, link-local addresses and fc00::/7. Such a channel shows **Unencrypted**. Redirects are not followed, so a token never goes on to another host.
- Tokens, passwords and webhook URLs stay in `/config/panel/alerts.json`, readable by root only, and are never shown again in full. Each message sent, or given up, is in the audit log as `alert.send`.
