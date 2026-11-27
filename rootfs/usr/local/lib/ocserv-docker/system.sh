# shellcheck shell=bash
# Checks the kernel features the server needs and prepares the directories
# and files it reads. Requires common.sh and settings.sh.

# Prints a sysctl's current value, or nothing when the kernel lacks it.
sysctl_read() {
    local path=/proc/sys/${1//.//}
    if [[ -r $path ]]; then
        printf '%s\n' "$(<"$path")"
    fi
}

# Sets a sysctl when it differs from the wanted value. Succeeds when the
# value is the wanted one afterward. /proc/sys is read-only in an
# unprivileged container, so the write is expected to fail there; the
# docker run --sysctl flag sets the value instead.
ensure_sysctl() {
    local name=$1 wanted=$2
    [[ $(sysctl_read "$name") == "$wanted" ]] && return 0
    if ! sysctl -w "$name=$wanted" >/dev/null 2>&1; then
        return 1
    fi
    [[ $(sysctl_read "$name") == "$wanted" ]]
}

prepare_dirs() {
    mkdir -p "$RUNTIME_DIR" "$CONFIG_DIR"
    chmod 0755 "$RUNTIME_DIR"
}

ensure_tun_device() {
    if [[ ! -c /dev/net/tun ]]; then
        mkdir -p /dev/net
        if ! mknod /dev/net/tun c 10 200 2>/dev/null; then
            die "/dev/net/tun is missing. Run the container with --device /dev/net/tun"
        fi
        chmod 0600 /dev/net/tun
    fi
    if ! (exec 3<>/dev/net/tun) 2>/dev/null; then
        die "/dev/net/tun cannot be opened. Run the container with --device /dev/net/tun --cap-add NET_ADMIN"
    fi
}

ensure_ip_forwarding() {
    ensure_sysctl net.ipv4.ip_forward 1 \
        || die "IPv4 forwarding is off, so VPN clients cannot reach any network. Run the container with --sysctl net.ipv4.ip_forward=1"
}

# Sets IPV6_ENABLED. IPv6 is enabled when the tunnel device can carry it,
# which is what keeps a full-tunnel client's native IPv6 inside the VPN.
detect_ipv6() {
    local disabled reason=""
    IPV6_ENABLED=false

    if [[ $IPV6 == false ]]; then
        if [[ $TUNNEL_MODE == all ]]; then
            warn "IPV6=false: clients that have native IPv6 can send IPv6 traffic outside the VPN"
        fi
        return 0
    fi

    disabled=$(sysctl_read net.ipv6.conf.default.disable_ipv6)
    if [[ -z $disabled ]]; then
        reason="the kernel has no IPv6 support"
    elif [[ $disabled != 0 ]] && ! ensure_sysctl net.ipv6.conf.default.disable_ipv6 0; then
        reason="IPv6 is disabled in the container; run it with --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0"
    fi

    if [[ -n $reason ]]; then
        [[ $IPV6 == true ]] && die "IPV6=true but $reason"
        if [[ $TUNNEL_MODE == all ]]; then
            warn "IPv6 leak protection is off because $reason. Clients that have native IPv6 can send IPv6 traffic outside the VPN."
        fi
        return 0
    fi

    IPV6_ENABLED=true
    if ! ensure_sysctl net.ipv6.conf.all.forwarding 1; then
        warn "IPv6 forwarding is off: client IPv6 traffic stays inside the tunnel and is dropped there, and IPv6-only sites do not load over the VPN. Run the container with --sysctl net.ipv6.conf.all.forwarding=1 to forward it"
    fi
}

# Creates an empty password file when the configured one is under CONFIG_DIR
# and missing.
ensure_passwd_file() {
    if [[ -f $PASSWD_FILE ]]; then
        return 0
    fi
    [[ $PASSWD_FILE == "$CONFIG_DIR"/* ]] || die "PASSWD_FILE $PASSWD_FILE does not exist"
    mkdir -p "${PASSWD_FILE%/*}"
    (umask 077 && : >"$PASSWD_FILE")
}

warn_if_no_users() {
    if [[ ! -s $PASSWD_FILE ]]; then
        warn "no VPN users exist yet. Add one with: docker exec -it <container> ocpasswd -c $PASSWD_FILE <username>"
    fi
}

# Gives the PUID/PGID owner the config directory, and limits secrets under it
# to their owner.
secure_config_dir() {
    local file
    if [[ -n ${PUID:-} ]]; then
        chown -R "$PUID:$PGID" "$CONFIG_DIR" || warn "could not give $CONFIG_DIR to $PUID:$PGID"
    fi
    if [[ -d $CONFIG_DIR/certs ]]; then
        chmod 0700 "$CONFIG_DIR/certs" || warn "could not restrict $CONFIG_DIR/certs to its owner"
    fi
    for file in "$SERVER_KEY" "$CONFIG_DIR/certs/ca-key.pem" "$CONFIG_DIR/certs/client-ca-key.pem" \
        "$PASSWD_FILE" "$OTP_FILE"; do
        [[ -f $file && $file == "$CONFIG_DIR"/* ]] || continue
        chmod 0600 "$file" || warn "could not restrict $file to its owner"
    done
}

# Removes the lock file and the half-written copy that a writer of the
# one-time password file leaves when it stops mid-change. liboath refuses
# every sign-in with a code while either exists, and before ocserv and the
# panel start, no writer can be running.
clear_otp_leftovers() {
    local leftover
    for leftover in "$OTP_FILE.lock" "$OTP_FILE.new"; do
        [[ -e $leftover ]] || continue
        if rm -f -- "$leftover"; then
            warn "removed $leftover, left by a writer of $OTP_FILE that stopped"
        else
            warn "could not remove $leftover; sign-ins with a code fail while it exists"
        fi
    done
}
