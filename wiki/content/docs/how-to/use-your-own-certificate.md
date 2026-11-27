---
title: Use Your Own Certificate
weight: 2
---

With a certificate from a public CA such as Let's Encrypt, clients trust the server without a pin or an installed CA, which Cisco Secure Client and AnyConnect need by default.

## Point the container at the files

Mount the certificate's folder and name the files:

```yaml
    volumes:
      - ./config:/config
      - /etc/letsencrypt:/certs:ro
    environment:
      SERVER_CERT: /certs/live/vpn.example.com/fullchain.pem
      SERVER_KEY: /certs/live/vpn.example.com/privkey.pem
```

Use the full chain, not only the certificate, so clients can verify it without fetching intermediates. When either file is missing the container stops with a message naming both, and it never creates or modifies certificates outside `/config/certs`.

Let's Encrypt keeps `live/` as links into `archive/`, so mount the whole `/etc/letsencrypt` folder, not `live/` alone.

## Renewals

ocserv checks the certificate files periodically and loads a renewed certificate without a restart; `docker exec openconnect occtl reload` loads it at once.

Keep the same private key across renewals if clients pin the key (`certbot renew --reuse-key`, or `reuse_key = True` in the renewal file). A new key changes the pin, and pinned clients then refuse the server until they are given the new one.

## See the certificate the server presents

### In the admin panel

**Certificates** shows the VPN server's certificate with the key pin clients check, the image's CA, the panel's own certificate, and the user portal's when it has one: who each is issued to and by, when it is valid, and when it expires, with a warning from 30 days before.

![The VPN server's certificate on the Certificates page: issued to and by vpn.example.com, its validity, and the key pin](/images/panel/certificates-server.png)

### From the command line

The container prints the pin at every start:

```bash
docker logs openconnect 2>&1 | grep "server key pin"
docker exec openconnect certtool --certificate-info --infile /config/certs/server-cert.pem
```

With `SERVER_CERT` set, give `certtool` that file instead.

## The private CA instead

Without `SERVER_CERT` and `SERVER_KEY`, the container creates a private CA and a server certificate for `SRV_CN` and `SRV_SAN`. It renews that certificate with the same key 30 days before it expires and when `SRV_CN` or `SRV_SAN` change, so pins keep working. Delete `/config/certs` to start over with a new CA and key.
