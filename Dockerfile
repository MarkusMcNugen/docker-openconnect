# syntax=docker/dockerfile:1

# Every Alpine stage uses the same release, pinned by digest.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# "latest" resolves to the newest stable release on the upstream download server.
ARG OCSERV_VERSION=latest
# Nikos Mavrogiannopoulos, the key every ocserv release is signed with.
ARG OCSERV_GPG_FINGERPRINT=1F42418905D8206AA754CCDC29EE58B996865171

RUN apk add --no-cache \
        build-base curl gnupg gperf linux-headers meson pax-utils pkgconf samurai xz \
        gnutls-dev libev-dev libnl3-dev libseccomp-dev lz4-dev nettle-dev oath-toolkit-dev \
        protobuf-c-dev radcli-dev readline-dev talloc-dev

COPY scripts/latest-ocserv-version.sh /usr/local/bin/latest-ocserv-version
COPY keys/ocserv-signing-key.asc /usr/src/ocserv-signing-key.asc
COPY patches/ /usr/src/patches/

WORKDIR /usr/src

# Download the release and verify its signature against the pinned key.
RUN set -eu; \
    version="$OCSERV_VERSION"; \
    if [ "$version" = latest ]; then version="$(sh /usr/local/bin/latest-ocserv-version)"; fi; \
    case "$version" in ''|*[!0-9.]*) echo "invalid OCSERV_VERSION: $version" >&2; exit 1 ;; esac; \
    url="https://www.infradead.org/ocserv/download/ocserv-$version.tar.xz"; \
    curl -fsSL --retry 3 -o ocserv.tar.xz "$url"; \
    curl -fsSL --retry 3 -o ocserv.tar.xz.sig "$url.sig"; \
    GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
    gpg --batch --quiet --import ocserv-signing-key.asc; \
    signer="$(gpg --batch --status-fd 1 --verify ocserv.tar.xz.sig ocserv.tar.xz 2>/dev/null \
        | awk '$2 == "VALIDSIG" { print $NF }')"; \
    if [ "$signer" != "$OCSERV_GPG_FINGERPRINT" ]; then \
        echo "ocserv-$version.tar.xz is not signed by $OCSERV_GPG_FINGERPRINT (signer: ${signer:-none})" >&2; \
        exit 1; \
    fi; \
    mkdir ocserv; \
    tar -xJf ocserv.tar.xz -C ocserv --strip-components=1; \
    printf '%s\n' "$version" > ocserv-version

# Apply the patches in patches/, compile with hardening flags and install into
# /out. A patch that no longer applies stops the build. Compression support is
# built in so it can be enabled, and the entrypoint turns it off by default:
# compressing before encrypting leaks plaintext length.
WORKDIR /usr/src/ocserv
RUN set -eu; \
    for p in /usr/src/patches/*.patch; do patch -p1 --forward --batch < "$p"; done; \
    hardening="-fstack-protector-strong -fstack-clash-protection -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security"; \
    case "$(uname -m)" in x86_64) hardening="$hardening -fcf-protection=full" ;; esac; \
    export CFLAGS="-O2 -pipe $hardening"; \
    export LDFLAGS="-Wl,-z,relro -Wl,-z,now -Wl,--as-needed"; \
    meson setup build \
        --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --buildtype=plain -Db_ndebug=false -Db_pie=true \
        -Dpam=disabled -Dradius=enabled -Dgssapi=disabled -Dliboath=enabled \
        -Dlibnl=enabled -Dmaxmind=disabled -Dgeoip=disabled -Dlz4=enabled \
        -Dcompression=enabled -Dseccomp=enabled -Dsystemd=disabled \
        -Doidc-auth=disabled -Dlatency-stats=disabled -Danyconnect-compat=enabled \
        -Dnamespaces=enabled -Dutmp=disabled -Dlibwrap=disabled -Dsock-diag=auto \
        -Dassume-glibc=false -Dtests=false -Dpager= -Dfirewall-script=nftables; \
    meson compile -C build; \
    DESTDIR=/out meson install -C build --no-rebuild --strip; \
    rm -rf /out/usr/share/man /out/usr/share/doc; \
    mkdir -p /out/usr/local/share/ocserv-docker; \
    cp ../ocserv-version /out/usr/local/share/ocserv-docker/ocserv-version; \
    scanelf --needed --nobanner --format '%n#p' --recursive /out/usr \
        | tr ',' '\n' | sort -u \
        | while read -r lib; do [ -e "/out/usr/lib/$lib" ] || printf 'so:%s\n' "$lib"; done \
        > /out/usr/local/share/ocserv-docker/runtime-deps


# The admin panel, compiled on the build machine's own platform for the target
# platform, so no platform is emulated. The binary is static.
FROM --platform=$BUILDPLATFORM docker.io/library/rust:1.100.0-alpine3.24@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS panel

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

ARG BUILDARCH
ARG BUILDVARIANT
ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /usr/src/panel
COPY panel/ ./

# The builder's own platform links with the image's gcc. Every other platform
# is cross-compiled with zig through cargo-zigbuild 0.24.1 or newer, which
# leaves out the -Wl,-O1 that zig 0.16 warns about. zig builds musl with many
# files open at once, so the soft open-file limit is raised to the hard one.
# cargo-zigbuild is installed from /, since cargo install warns when the
# panel's rust-toolchain.toml would choose the toolchain it builds with.
# hadolint ignore=SC3045,DL3003
RUN set -eu; \
    case "$TARGETARCH/$TARGETVARIANT" in \
        amd64/*) target=x86_64-unknown-linux-musl ;; \
        arm64/*) target=aarch64-unknown-linux-musl ;; \
        arm/v7) target=armv7-unknown-linux-musleabihf ;; \
        *) echo "unsupported platform: $TARGETARCH/$TARGETVARIANT" >&2; exit 1 ;; \
    esac; \
    rustup target add "$target"; \
    if [ "$TARGETARCH/$TARGETVARIANT" = "$BUILDARCH/$BUILDVARIANT" ]; then \
        cargo build --locked --release --target "$target"; \
    else \
        apk add --no-cache zig; \
        (cd / && cargo install --locked cargo-zigbuild@0.24.1); \
        ulimit -Sn "$(ulimit -Hn)"; \
        cargo zigbuild --locked --release --target "$target"; \
    fi; \
    install -D -m 0755 "target/$target/release/ocpanel" /out/usr/local/bin/ocpanel


# DB-IP Lite, the country database the country rules read unless a MaxMind
# key is given: this month's, or last month's until this month's appears.
# CC BY 4.0, credited "IP Geolocation by DB-IP" with a link to db-ip.com.
FROM --platform=$BUILDPLATFORM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS geo

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

RUN set -eu; \
    apk add --no-cache curl; \
    year="$(date -u +%Y)"; \
    month="$(date -u +%m)"; \
    m="${month#0}"; \
    if [ "$m" = 1 ]; then previous="$((year - 1))-12"; else previous="$year-$(printf %02d "$((m - 1))")"; fi; \
    base=https://download.db-ip.com/free/dbip-country-lite; \
    curl -fsSL --retry 3 -o /tmp/dbip.mmdb.gz "$base-$year-$month.mmdb.gz" \
        || curl -fsSL --retry 3 -o /tmp/dbip.mmdb.gz "$base-$previous.mmdb.gz"; \
    gunzip /tmp/dbip.mmdb.gz; \
    install -D -m 0644 /tmp/dbip.mmdb /out/usr/local/share/ocserv-docker/geo/dbip-country-lite.mmdb

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

ARG OCSERV_VERSION=latest

LABEL org.opencontainers.image.title="OpenConnect VPN Server" \
      org.opencontainers.image.description="ocserv, built from the newest signed upstream release, with a hardened default configuration" \
      org.opencontainers.image.source="https://github.com/MarkusMcNugen/docker-openconnect" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="$OCSERV_VERSION"

COPY --from=build /out/ /
COPY --from=panel /out/ /
COPY --from=geo /out/ /

# The running container keeps no package manager, and so no OpenSSL: apk
# and BusyBox's TLS helper for wget are its only users, while ocserv uses
# GnuTLS and the panel rustls. The package database stays, so scanners
# still see every package.
RUN set -eu; \
    apk upgrade --no-cache; \
    xargs -r apk add --no-cache < /usr/local/share/ocserv-docker/runtime-deps; \
    apk add --no-cache bash gnutls-utils iptables-legacy nftables tini; \
    addgroup -S ocserv; \
    adduser -S -D -H -h /var/empty -s /sbin/nologin -G ocserv -g ocserv ocserv; \
    addgroup -S ocpanel; \
    adduser -S -D -H -h /var/empty -s /sbin/nologin -G ocpanel -g ocpanel ocpanel; \
    ocserv --version; \
    occtl --version; \
    ocpasswd --version; \
    ocpanel --version; \
    apk del --no-cache apk-tools ssl_client libssl3 libcrypto3

COPY rootfs/ /

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh /usr/local/libexec/ocserv-docker/* \
    && chmod 0644 /usr/local/lib/ocserv-docker/*

VOLUME ["/config"]
EXPOSE 4443/tcp 4443/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["occtl", "show", "status"]

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["ocserv"]
