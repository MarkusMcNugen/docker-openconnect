---
title: Hide The Server With Camouflage
weight: 4
---

Camouflage makes the server answer every request like a web server with nothing on it unless the URL carries a secret. Scanners and censors probing the port see an empty site, not a VPN login.

```yaml
    environment:
      CAMOUFLAGE_SECRET: 7c1e9a0b4f2d
```

Use a long random string of letters, digits and `. _ ~ -`. Clients then connect to the server's address followed by `?` and the secret:

```bash
sudo openconnect --user=alice --servercert=pin-sha256:... 'https://vpn.example.com:4443/?7c1e9a0b4f2d'
```

Without the secret, the server answers `404 Not Found`. Set `CAMOUFLAGE_REALM` to answer `401 Unauthorized` with that realm instead, which looks like a password-protected site.

The secret is set in the environment only; the [admin panel](../use-the-admin-panel/) does not change it. It does hand it out: each user's [onboarding kit](../manage-users/#add-a-user-or-change-a-password) gives the address with the secret already on it.

## Cisco clients

Cisco Secure Client and AnyConnect probe the server address without the secret to detect captive portals. Turn off captive portal detection in the client's profile for it to connect to a camouflaged server.
