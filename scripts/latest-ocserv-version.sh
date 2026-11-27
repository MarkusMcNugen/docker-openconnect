#!/bin/sh
# Prints the newest stable ocserv version published on the upstream download
# server. Only X.Y.Z tarballs count, so release candidates and pre-releases
# are never selected. Used by the Dockerfile and by CI.
set -eu

url="${OCSERV_DOWNLOAD_URL:-https://www.infradead.org/ocserv/download/}"

listing="$(curl -fsSL --retry 3 --retry-delay 2 "$url")"

version="$(printf '%s\n' "$listing" \
    | grep -oE 'ocserv-[0-9]+\.[0-9]+\.[0-9]+\.tar\.xz' \
    | sed -E 's/^ocserv-(.*)\.tar\.xz$/\1/' \
    | sort -u -t. -k1,1n -k2,2n -k3,3n \
    | tail -n 1)"

if [ -z "$version" ]; then
    echo "no ocserv release tarball found at $url" >&2
    exit 1
fi

printf '%s\n' "$version"
