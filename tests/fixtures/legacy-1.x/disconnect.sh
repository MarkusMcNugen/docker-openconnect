#!/bin/bash
# Script to call when a client connects and obtains an IP.
# The following parameters are passed on the environment.
# REASON, USERNAME, GROUPNAME, DEVICE, IP_REAL (the real IP of the client),
# IP_REAL_LOCAL (the local interface IP the client connected), IP_LOCAL
# (the local IP in the P-t-P connection), IP_REMOTE (the VPN IP of the client),
# IPV6_LOCAL (the IPv6 local address if there are both IPv4 and IPv6
# assigned), IPV6_REMOTE (the IPv6 remote address), IPV6_PREFIX, and
# ID (a unique numeric ID); 
# REASON may be "connect" or "disconnect".
# In addition the following variables OCSERV_ROUTES (the applied routes for this
# client), OCSERV_NO_ROUTES, OCSERV_DNS (the DNS servers for this client),
# will contain a space separated list of routes or DNS servers. A version
# of these variables with the 4 or 6 suffix will contain only the IPv4 or
# IPv6 values.

# The disconnect script will receive the additional values: STATS_BYTES_IN,
# STATS_BYTES_OUT, STATS_DURATION that contain a 64-bit counter of the bytes
# output from the tun device, and the duration of the session in seconds.

echo "$(date) [info] User ${USERNAME} Disconnected - Bytes In: ${STATS_BYTES_IN} Bytes Out: ${STATS_BYTES_OUT} Duration:${STATS_DURATION}"
