---
title: OpenConnect VPN Server
layout: hextra-home
---

{{< hextra/hero-headline >}}
OpenConnect VPN Server
{{< /hextra/hero-headline >}}

{{< hextra/hero-subtitle >}}
ocserv in Docker, built from the newest signed release, with a hardened default configuration and no traffic leaking around the tunnel.
{{< /hextra/hero-subtitle >}}

{{< hextra/hero-button text="Get started" link="docs/tutorials/getting-started/" >}}

{{< hextra/feature-grid >}}
  {{< hextra/feature-card title="Always current" subtitle="Every image is compiled from the newest ocserv release, checked against its maintainer's signing key. A new release is published within a day." >}}
  {{< hextra/feature-card title="No leaks" subtitle="Full-tunnel clients get an IPv6 address and route as well as IPv4, so native IPv6 cannot bypass the VPN, and DNS goes through the tunnel." >}}
  {{< hextra/feature-card title="Hardened" subtitle="TLS 1.3 and 1.2 with forward secrecy only, a default-drop firewall, isolated clients, sandboxed workers and a read-only container." >}}
  {{< hextra/feature-card title="Configured by environment" subtitle="Every ocserv option can be set from a Docker environment variable, with safe defaults for each." >}}
  {{< hextra/feature-card title="OpenConnect and Cisco clients" subtitle="Works with the OpenConnect clients and with Cisco Secure Client (AnyConnect) on every platform." >}}
  {{< hextra/feature-card title="Upgrades in place" subtitle="Existing installs keep their users, certificates and hand-edited settings." >}}
{{< /hextra/feature-grid >}}
