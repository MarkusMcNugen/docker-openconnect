#!/bin/bash
# Prepares the container and starts ocserv in the foreground. With arguments
# that do not start with "ocserv", runs them instead, for a debugging shell.
set -Eeuo pipefail

readonly LIB_DIR=/usr/local/lib/ocserv-docker
# shellcheck source=SCRIPTDIR/../lib/ocserv-docker/common.sh
source "$LIB_DIR/common.sh"
# shellcheck source=SCRIPTDIR/../lib/ocserv-docker/settings.sh
source "$LIB_DIR/settings.sh"
# shellcheck source=SCRIPTDIR/../lib/ocserv-docker/legacy.sh
source "$LIB_DIR/legacy.sh"
# shellcheck source=SCRIPTDIR/../lib/ocserv-docker/certs.sh
source "$LIB_DIR/certs.sh"
# shellcheck source=SCRIPTDIR/../lib/ocserv-docker/config.sh
source "$LIB_DIR/config.sh"
# shellcheck source=SCRIPTDIR/../lib/ocserv-docker/system.sh
source "$LIB_DIR/system.sh"
# shellcheck source=SCRIPTDIR/../lib/ocserv-docker/firewall.sh
source "$LIB_DIR/firewall.sh"

# Prints the server key's pin-sha256 value, which clients use to trust the
# server, or nothing when certtool reports none.
server_key_pin() {
    local line next=false
    while IFS= read -r line; do
        if $next; then
            line=${line//[[:space:]]/}
            [[ $line == pin-sha256:* ]] && printf '%s\n' "$line"
            return 0
        fi
        [[ $line == *"Public Key PIN:"* ]] && next=true
    done < <(certtool --certificate-info --infile "$SERVER_CERT" 2>/dev/null)
    return 0
}

log_summary() {
    local conf=$1 ipv6=off isolation=on camouflage=off udp="" version="" pin
    [[ $IPV6_ENABLED == true ]] && ipv6="on ($VPN_IPV6_NETWORK)"
    [[ $CLIENT_TO_CLIENT == true ]] && isolation=off
    [[ -n ${CAMOUFLAGE_SECRET:-} ]] && camouflage=on
    [[ $DTLS == true ]] && udp=" and UDP $UDP_PORT"
    read -r version < <(ocserv --version 2>&1)
    info "$version"
    info "configuration: $conf"
    if [[ $POWER_USER == true || $LEGACY_CONFIG == true ]]; then
        info "the configuration file is used as it stands; only the firewall and certificate settings apply"
    else
        info "listening on TCP $LISTEN_PORT$udp"
        info "tunnel: $TUNNEL_MODE, IPv4 $CONF_V4_NET, IPv6 $ipv6, DNS ${DNS_SERVERS}"
        info "limits: $MAX_CLIENTS clients, $MAX_SAME_CLIENTS sessions per user; Cisco compatibility $CISCO_COMPAT; camouflage $camouflage"
    fi
    info "firewall: $FW_BACKEND, NAT $NAT, client isolation $isolation, route restriction $RESTRICT_ENABLED"
    pin=$(server_key_pin)
    if [[ -n $pin ]]; then
        info "server key pin for clients: $pin"
    fi
}

OCSERV_PID=""
PANEL_PID=""
RELAY_PID=""
CRL_TIMER_PID=""
STOPPING=false

# Sends TERM to the supervised processes that are still running.
stop_children() {
    local pid
    for pid in "$OCSERV_PID" "$PANEL_PID"; do
        if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid"
        fi
    done
}

# The container is stopping: ocserv and the helper get TERM, and the helper is
# not started again while ocserv finishes, which with SERVER_DRAIN_MS set
# takes that long with its ports closed.
stop_requested() {
    STOPPING=true
    stop_children
}

# Starts the day-long wait after which the client CA's revocation list is
# written again, when the container keeps that CA: GnuTLS refuses every
# certificate once the list's next-update date passes.
start_crl_timer() {
    CRL_TIMER_PID=""
    [[ -f $CONFIG_DIR/certs/client-ca.pem ]] || return 0
    sleep 86400 &
    CRL_TIMER_PID=$!
}

# Acts on each supervised process that ends. ocserv ending ends the container
# with its status, as it does unsupervised, and so does the panel's log relay
# ending, since ocserv must not run without its log. The panel's helper
# ending is started again after a delay that doubles up to a minute, and the
# VPN is not touched, unless the container is stopping. The day-long timer
# ending writes the client CA's revocation list again; a failure is reported,
# and the list in place stays valid until its own next-update date.
supervise() {
    local status delay=1
    local -a pids
    trap stop_requested TERM INT
    while true; do
        pids=("$OCSERV_PID")
        [[ -n $RELAY_PID ]] && pids+=("$RELAY_PID")
        [[ -n $PANEL_PID ]] && pids+=("$PANEL_PID")
        [[ -n $CRL_TIMER_PID ]] && pids+=("$CRL_TIMER_PID")
        status=0
        wait -n "${pids[@]}" || status=$?
        if ! kill -0 "$OCSERV_PID" 2>/dev/null; then
            status=0
            wait "$OCSERV_PID" || status=$?
            stop_children
            if [[ -n $PANEL_PID ]]; then
                wait "$PANEL_PID" || warn "the admin panel's helper stopped with status $?"
            fi
            if [[ -n $RELAY_PID ]]; then
                wait "$RELAY_PID" || warn "the admin panel's log relay stopped with status $?"
            fi
            exit "$status"
        fi
        if [[ -n $RELAY_PID ]] && ! kill -0 "$RELAY_PID" 2>/dev/null; then
            warn "the admin panel's log relay exited with status $status; stopping ocserv, which must not run without its log"
            stop_children
            wait "$OCSERV_PID" || warn "ocserv stopped with status $?"
            if [[ -n $PANEL_PID ]]; then
                wait "$PANEL_PID" || warn "the admin panel's helper stopped with status $?"
            fi
            exit 1
        fi
        if [[ -n $CRL_TIMER_PID ]] && ! kill -0 "$CRL_TIMER_PID" 2>/dev/null; then
            CRL_TIMER_PID=""
            if [[ $STOPPING == false ]]; then
                write_client_crl "$CONFIG_DIR/certs" ||
                    warn "the revocation list of $CONFIG_DIR/certs/client-ca.pem could not be written again; certificate sign-in stops when the list in place expires"
                start_crl_timer
            fi
        fi
        if [[ -n $PANEL_PID ]] && ! kill -0 "$PANEL_PID" 2>/dev/null; then
            if [[ $STOPPING == false ]]; then
                warn "the admin panel's helper exited with status $status; starting it again in ${delay} s"
                sleep "$delay"
                delay=$((delay < 32 ? delay * 2 : 60))
            fi
            # A stop requested during the delay is handled once it ends.
            if [[ $STOPPING == true ]]; then
                PANEL_PID=""
                continue
            fi
            ocpanel helper &
            PANEL_PID=$!
        fi
    done
}

# With certificates and without the admin panel, the entrypoint stays as
# ocserv's supervisor to write the client CA's revocation list every day.
run_with_crl_timer() {
    local conf=$1
    shift
    ocserv --foreground --log-stderr --config "$conf" "$@" &
    OCSERV_PID=$!
    start_crl_timer
    supervise
}

# With the admin panel on, the entrypoint stays as the supervisor of ocserv,
# the panel's log relay and the panel's helper. ocserv's log passes through
# the relay, which copies every line to the container log and records failed
# sign-ins and bans; the session script records connects and disconnects.
run_with_panel() {
    local conf=$1 relay
    shift
    ocpanel check-config || die "the admin panel's settings are invalid"
    ensure_panel_certificate
    # The helper reads and changes the VPN users' files the entrypoint chose,
    # reads the configuration ocserv runs with, picks up the events the relay
    # and the session script leave in PANEL_EVENTS_DIR, and changes the
    # blocklist of the firewall PANEL_FIREWALL names.
    export PASSWD_FILE OTP_FILE OCSERV_CONFIG=$conf PANEL_EVENTS_DIR=$RUNTIME_DIR/panel-events \
        PANEL_FIREWALL=$FW_BACKEND
    install -d -m 0700 "$PANEL_EVENTS_DIR"
    exec {relay}> >(ocpanel log-relay)
    RELAY_PID=$!
    ocserv --foreground --log-stderr --config "$conf" "$@" 2>&"$relay" &
    OCSERV_PID=$!
    exec {relay}>&-
    ocpanel helper &
    PANEL_PID=$!
    start_crl_timer
    supervise
}

main() {
    local conf

    if (($# > 0)) && [[ $1 != ocserv ]]; then
        exec "$@"
    fi
    (($# > 0)) && shift

    load_panel_settings
    load_settings
    prepare_dirs
    handle_legacy_files
    detect_ipv6
    select_firewall_backend
    resolve_route_restriction
    ensure_certificates
    ensure_client_ca
    ensure_passwd_file

    if [[ $POWER_USER == true || $LEGACY_CONFIG == true ]]; then
        conf=$CONFIG_DIR/ocserv.conf
        if [[ ! -f $conf ]]; then
            conf_build
            conf_write "$conf" "Written from the environment because POWER_USER=true and this file did not exist. The container uses it as it stands."
            info "wrote $conf from the environment; edit it to change the server"
        fi
    else
        conf=$RUNTIME_DIR/ocserv.conf
        # The admin panel writes per-user and per-group settings, which
        # ocserv reads only from directories that exist when it starts.
        if [[ $PANEL_ENABLED == true ]]; then
            mkdir -p "$CONFIG_DIR/config-per-user" "$CONFIG_DIR/config-per-group"
        fi
        conf_build
        conf_write "$conf" "Generated from environment variables at container start and replaced at every start."
        # The admin panel's Settings page reads where each setting came from,
        # and its helper builds the configuration again with the decisions
        # made at this start when an owner changes a setting.
        write_settings_state "$RUNTIME_DIR/panel-settings"
        printf 'IPV6_ENABLED=%s\nRESTRICT_ENABLED=%s\n' "$IPV6_ENABLED" "$RESTRICT_ENABLED" \
            >"$RUNTIME_DIR/start-decisions"
        warn_if_no_users
    fi

    secure_config_dir
    clear_otp_leftovers
    read_tunnel_networks "$conf"
    [[ -n $CONF_V4_NET ]] || die "$conf sets no ipv4-network"
    # The panel admits the VPN pools unless PANEL_ALLOW_VPN=false; its
    # firewall rules and its helper both read them from here.
    # The groups' own pools are translated and admitted like the server's.
    read_group_pools "$CONFIG_DIR/config-per-group"
    local pool
    export PANEL_VPN_NETWORKS=$CONF_V4_NET${CONF_V6_NET:+,$CONF_V6_NET}
    for pool in "${GROUP_POOLS[@]}"; do
        PANEL_VPN_NETWORKS+=,$pool
    done

    ensure_tun_device
    ensure_ip_forwarding
    # The firewall's site-to-site part reads the pools and the per-user and
    # per-group directories from the configuration ocserv runs with.
    export OCSERV_CONFIG=$conf
    apply_firewall

    run_quiet ocserv --test-config --config "$conf"
    log_summary "$conf"
    if [[ $PANEL_ENABLED == true ]]; then
        run_with_panel "$conf" "$@"
    fi
    if [[ $AUTH_MODE != password ]]; then
        run_with_crl_timer "$conf" "$@"
    fi
    exec ocserv --foreground --log-stderr --config "$conf" "$@"
}

main "$@"
