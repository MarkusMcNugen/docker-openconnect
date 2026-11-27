---
title: How The Image Stays Current
weight: 3
---

## The ocserv version

The `Dockerfile` builds whichever ocserv version `OCSERV_VERSION` names, and its default, `latest`, is resolved at build time by `scripts/latest-ocserv-version.sh`. The script reads the upstream download server's file list and picks the highest `X.Y.Z` tarball, so release candidates and other pre-releases are never chosen. The build then downloads that tarball and its signature and stops unless the signature was made by the key whose fingerprint the `Dockerfile` pins.

To build a specific version:

```bash
docker build --build-arg OCSERV_VERSION=1.6.0 -t openconnect .
```

## Patches

The build applies every file in `patches/` to the ocserv source before compiling it, and stops when one no longer applies, so a new ocserv release that changes the patched code cannot ship without the patch being checked against it.

`ocserv-worker-sigaltstack-size.patch` sizes the signal stack each worker process sets up. ocserv allocates it with the C library's `SIGSTKSZ`, a constant that musl fixes when the program is compiled, while the signal frame the kernel needs grows with the CPU's register state. On some x86-64 hosts the kernel refuses that stack, and every worker exits with `sigaltstack: Out of memory` before the TLS handshake, so no client can connect. The patch uses at least 64 KiB, and four times the minimum the kernel reports in `AT_MINSIGSTKSZ` where that is larger. The smoke test checks the server log for the error.

## Publishing

`.github/workflows/publish.yml` builds the image for `linux/amd64`, `linux/arm64` and `linux/arm/v7` and publishes it to `markusmcnugen/openconnect` on Docker Hub and `ghcr.io/markusmcnugen/docker-openconnect`:

- **On every push to main**, and when run by hand.
- **Every day**, when ocserv has released a version that has no image yet. A new ocserv release is therefore published within a day.
- **Every week**, whatever ocserv did, so the Alpine packages in the image carry their latest security fixes.

Each platform's image is tested before it is tagged: amd64 and arm64 run the full smoke test on native machines, connecting real OpenConnect clients through the tunnel; arm/v7, which runs only under emulation there, gets the checks that emulation allows. The release step tags the exact images that passed.

## Tags

| Tag | Points to |
|---|---|
| `latest` | The newest build. |
| `1.6.0` (the ocserv version) | The newest build of that ocserv version. |
| `1.6` | The newest build of that ocserv minor version. |
| `sha-<commit>` | The build of one commit of this repository. |

## The base image

Alpine is pinned by digest in both stages of the `Dockerfile`. Dependabot proposes new digests and new Alpine releases, and updates the workflow actions, each pinned to a commit.
