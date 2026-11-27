---
title: Run Behind A Reverse Proxy
weight: 6
---

To share port 443 with a web server, put a TCP proxy that routes by TLS server name (SNI) in front of both, and have it pass the VPN's connections through without decrypting them (TLS passthrough), so ocserv still terminates TLS itself.

## Keep the client addresses

Behind a proxy, every connection would appear to come from the proxy, and ocserv's ban system and logs would see only that address. Turn on the PROXY protocol on both sides so the proxy passes the real client address:

```yaml
    environment:
      PROXY_PROTOCOL: "true"
```

With it on, ocserv accepts only connections that start with a PROXY protocol header, so every TCP connection to the port must come through the proxy.

## Traefik

```yaml
tcp:
  routers:
    vpn:
      entryPoints: [websecure]
      rule: HostSNI(`vpn.example.com`)
      service: vpn
      tls:
        passthrough: true
  services:
    vpn:
      loadBalancer:
        proxyProtocol:
          version: 2
        servers:
          - address: openconnect:4443
```

## HAProxy

```text
frontend tls
    bind :443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }
    use_backend vpn if { req_ssl_sni -i vpn.example.com }

backend vpn
    mode tcp
    server ocserv openconnect:4443 send-proxy-v2
```

## The UDP channel

The proxy carries only TCP. Publish the UDP port directly (`-p 443:4443/udp`, for example) so clients can use the faster UDP channel; without it they stay on TCP.
