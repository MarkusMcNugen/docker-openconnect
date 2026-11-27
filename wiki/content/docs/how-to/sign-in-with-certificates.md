---
title: Sign In With Certificates
weight: 5
---

ocserv can sign VPN users in with a client certificate instead of their password, or together with it. The container keeps a certificate authority for that alone, the client CA, so no other certificate it has, such as the server's, can sign anyone in.

## 1. Choose how users sign in

| Method | `AUTH_MODE` | A user signs in with |
|---|---|---|
| Password | `password` | the password, the default |
| Certificate | `certificate` | a certificate alone |
| Password and certificate | `both` | a certificate and the password |
| Password or certificate | `either` | a certificate or the password |

### In the admin panel

On **Settings**, under **Sign-in**, choose the method in **How VPN users sign in** and save. It takes effect at the next container start.

![The Sign-in section of the Settings page, with Password and certificate chosen](/images/panel/settings-sign-in.png)

### From the command line

```yaml
    environment:
      AUTH_MODE: both
```

### Either way

A code from the [one-time-password file](../add-two-factor-login/) is asked with the password whenever the password is. The first start that uses certificates creates the client CA in `/config/certs/client-ca.pem`, its key, and its revocation list, `client-crl.pem`.

The certificate names the user in its user ID field and their groups in its organizational unit fields, so a certificate for `alex` in the group `staff` signs in as `alex` with the settings of `staff`. With `both`, the user must sign in with the password of the user the certificate names, and the groups come from the password file.

## 2. Issue a certificate

### In the admin panel

On **Certificates**, under **VPN users' certificates**, choose the user and how the key comes to be, then **Issue a certificate**:

![The VPN users' certificates section: the form to issue a certificate, and the certificates issued so far with buttons to renew and revoke each](/images/panel/certificates-users.png)

- **A new key in a key file:** the panel makes a key and its certificate and hands them out once, in a PKCS#12 file with a generated passphrase. It keeps neither, so give the user the file and the passphrase then, by two different ways. Choose **3DES, for older devices** for macOS 14 or earlier, iOS 17 or earlier and some Android versions, which cannot open AES-256 key files.
- **The user's own key, from a signing request:** paste the user's certificate signing request (CSR), and the panel signs a certificate for its key, which never leaves the user's device. The certificate names the user and their groups, whatever the request says. A key weaker than RSA 2048 is refused.

![An issued certificate's key file, shown once: the passphrase, the encryption, and the button to download the file](/images/panel/certificate-issued.png)

A certificate is valid for `PANEL_CLIENT_CERT_DAYS` days, 365 by default, and the page warns from 30 days before it expires.

### From the command line

Make the key and the certificate inside the container, where the client CA's key stays:

```bash
docker exec openconnect sh -c 'cd /tmp &&
  certtool --generate-privkey --key-type=ecdsa --outfile alex-key.pem &&
  printf "uid = alex\ncn = alex\nunit = staff\nexpiration_days = 365\nsigning_key\ntls_www_client\n" >alex.tmpl &&
  certtool --generate-certificate --load-privkey alex-key.pem \
    --load-ca-certificate /config/certs/client-ca.pem \
    --load-ca-privkey /config/certs/client-ca-key.pem \
    --template alex.tmpl --outfile alex-cert.pem &&
  certtool --to-p12 --load-privkey alex-key.pem --load-certificate alex-cert.pem \
    --p12-name alex --pkcs-cipher aes-256 --outder --outfile alex.p12'
docker cp openconnect:/tmp/alex.p12 .
docker exec openconnect sh -c 'cp /tmp/alex-cert.pem /config/certs/alex-cert.pem; rm -f /tmp/alex*'
```

`certtool --to-p12` asks for a passphrase that protects the key file. Keep the certificate, here `/config/certs/alex-cert.pem`, to revoke it later. For older devices, make the file with `--pkcs-cipher 3des-pkcs12 --hash SHA1` instead.

## 3. Connect with it

- **OpenConnect:** `openconnect --certificate alex.p12 vpn.example.com`, which asks for the passphrase. With a certificate from a signing request, `--certificate alex-cert.pem --sslkey alex-key.pem`.
- **Cisco Secure Client and AnyConnect:** import `alex.p12` into the user's certificate store, then connect as usual.
- **Network Manager:** choose the certificate and key in the VPN connection's settings.

## Renew and revoke

### In the admin panel

On **Certificates**, **Renew** issues a new certificate the same way, naming the user's groups as they are then, and leaves the old one valid until it expires. **Revoke** stops one at once and ends its user's sessions. Removing a user revokes their certificates. While certificates sign users in, the panel also refuses a certificate whose user is locked or no longer in the password file. Every issue, renewal and revocation is in the audit log.

### From the command line

Put the certificate in `/config/certs/client-revoked`, write the revocation list again and have ocserv load it:

```bash
docker exec openconnect sh -c 'mv /config/certs/alex-cert.pem /config/certs/client-revoked/ &&
  /usr/local/libexec/ocserv-docker/client-crl /config/certs && occtl reload'
```

The revocation list is valid for a year, and the container writes it again at every start and once a day.
