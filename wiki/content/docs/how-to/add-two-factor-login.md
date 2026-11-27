---
title: Add Two-Factor Login
weight: 5
---

With a one-time-password file in place, every sign-in needs the user's password and then a six-digit code from an authenticator app (TOTP, time-based one-time passwords). The container asks for codes whenever the file exists at start: `/config/users.oath`, unless `OTP_FILE` names another. Every user then needs a key in it, or cannot sign in.

## 1. Turn codes on

Create the file and restart the container:

```bash
docker exec openconnect touch /config/users.oath
docker restart openconnect
```

The container finds the file at start and adds it to the sign-in, as `auth = "plain[passwd=/config/ocpasswd,otp=/config/users.oath]"`.

## 2. Give each user a key

### In the admin panel

While the VPN asks for codes, **VPN users** marks each user without a key as unable to sign in. **Set up authenticator** gives that user a key, and every user added from then on gets one with their password. **Reset authenticator** replaces a key that was lost. Each opens the user's onboarding kit, which shows the key once, as a QR code to scan and as text to type:

![The onboarding kit: the connection details with the password, and the authenticator key as a QR code and as text](/images/panel/kit.png)

With the [user portal](../use-the-admin-panel/#let-vpn-users-help-themselves) on, users set up or replace their own key. A user without a key can sign in to the portal with the password alone, only to set one up.

### From the command line

On any machine with OpenSSL and Python, make a secret for each user:

```bash
secret=$(openssl rand -hex 20)
echo "$secret"
python3 -c "import base64,binascii,sys; print(base64.b32encode(binascii.unhexlify(sys.argv[1])).decode())" "$secret"
```

The first line is the secret in hex, for the server. The second is the same secret in base32, which authenticator apps take: add it to the app as a time-based account.

Then give the user a line in `/config/users.oath`:

```text
HOTP/T30 alice - 3a5f0c...the hex secret...
HOTP/T30 bob - 91d2e7...
```

`HOTP/T30` means a code that changes every 30 s. The format is the [mod-authn-otp users file](https://github.com/archiecobbs/mod-authn-otp/wiki/UsersFile); ocserv records each user's last code in it, so the file must stay writable. ocserv reads it at every sign-in, so a new line works without a restart.

## Signing in

Clients ask for the password, then for the code. OpenConnect can generate the code itself:

```bash
sudo openconnect --user=alice --token-mode=totp --token-secret=0x3a5f0c... https://vpn.example.com:4443/
```
