# shellcheck shell=bash
# Firewall for the container's network namespace: source NAT for the tunnel
# networks, a default-drop forward policy that admits client traffic and its
# replies only, client isolation, input filtering on the tunnel devices and
# on the admin panel's port, the admin panel's blocklist, which every port
# drops, and TCP MSS clamping. A packet from a tunnel must come from an
# address routed back through that tunnel. The site-to-site part, which
# ocpanel fills, lets the admin panel's rules through between tunnels and
# keeps the networks VPN users publish inside the VPN unless the panel lets
# one out. nftables is preferred; legacy iptables serves kernels without
# nf_tables. Requires common.sh and settings.sh.
#
# Inputs: CONF_V4_NET and CONF_V6_NET from read_tunnel_networks, the groups'
# own pools in GROUP_POOLS from read_group_pools, and PANEL_VPN_NETWORKS,
# which the entrypoint exports from them all.

# ocserv-fw removes every nft table named ocserv_*, so this name avoids it.
readonly FW_TABLE=vpn_gateway

nft_usable() {
    nft add table ip "${FW_TABLE}_probe" >/dev/null 2>&1 || return 1
    nft delete table ip "${FW_TABLE}_probe" >/dev/null 2>&1
}

iptables_usable() {
    iptables-legacy -w -t nat -S POSTROUTING >/dev/null 2>&1
}

# Whether the kernel can look up routes in nftables, which the forward chain
# uses to check where tunnel traffic comes from.
nft_fib_usable() {
    printf 'table inet %s_probe {\n    chain probe {\n        fib saddr . iif oif missing drop\n    }\n}\n' \
        "$FW_TABLE" | nft -f - >/dev/null 2>&1 || return 1
    nft delete table inet "${FW_TABLE}_probe" >/dev/null 2>&1
}

# Whether the firewall drops each packet from a tunnel whose source address
# is not routed back through that tunnel. Without that check a VPN client
# could send as another client or as a site, so the site-to-site rules,
# which trust those addresses, open nothing. apply_firewall sets it.
SOURCE_CHECK=false

# Sets FW_BACKEND to "nftables" or "iptables".
select_firewall_backend() {
    case $FIREWALL_BACKEND in
        nftables)
            nft_usable || die "FIREWALL_BACKEND=nftables but nftables cannot be used here; the kernel needs nf_tables and the container needs --cap-add NET_ADMIN"
            FW_BACKEND=nftables
            ;;
        iptables)
            iptables_usable || die "FIREWALL_BACKEND=iptables but iptables cannot be used here; the container needs --cap-add NET_ADMIN and --cap-add NET_RAW"
            FW_BACKEND=iptables
            ;;
        auto)
            if nft_usable; then
                FW_BACKEND=nftables
            elif iptables_usable; then
                FW_BACKEND=iptables
                warn "nftables is unavailable on this kernel; using legacy iptables"
            else
                die "neither nftables nor iptables can be used. Run the container with --cap-add NET_ADMIN"
            fi
            ;;
    esac
}

# Sets RESTRICT_ENABLED from RESTRICT_TO_ROUTES. ocserv enforces route
# restriction through its nftables helper, so it needs FW_BACKEND=nftables.
resolve_route_restriction() {
    case $RESTRICT_TO_ROUTES in
        true)
            [[ $FW_BACKEND == nftables ]] || die "RESTRICT_TO_ROUTES=true needs nftables, which this kernel does not offer"
            RESTRICT_ENABLED=true
            ;;
        false) RESTRICT_ENABLED=false ;;
        auto)
            RESTRICT_ENABLED=false
            if [[ $TUNNEL_MODE == split-include ]]; then
                if [[ $FW_BACKEND == nftables ]]; then
                    RESTRICT_ENABLED=true
                else
                    warn "clients are not limited to TUNNEL_ROUTES because nftables is unavailable"
                fi
            fi
            ;;
    esac
}

# The admin panel's port and the networks admitted to it, as ocpanel reports
# them from the same settings and routes its web process uses. All three stay
# empty while the panel is off, and then no rule names the port.
PANEL_FW_PORT=""
PANEL_FW_V4=()
PANEL_FW_V6=()

# Sets PANEL_FW_PORT, PANEL_FW_V4 and PANEL_FW_V6.
read_panel_exposure() {
    local output network
    [[ $PANEL_ENABLED == true ]] || return 0
    PANEL_FW_PORT=$(ocpanel port) || die "the admin panel's settings are invalid"
    output=$(ocpanel allowed-networks) || die "the admin panel's settings are invalid"
    while IFS= read -r network; do
        case $network in
            "") ;;
            *:*) PANEL_FW_V6+=("$network") ;;
            *) PANEL_FW_V4+=("$network") ;;
        esac
    done <<<"$output"
}

# The VPN user portal's port and the networks PANEL_PORTAL_NETWORKS narrows
# it to. All three stay empty while the portal is off or open to every
# address, and then no rule names the port.
PORTAL_FW_PORT=""
PORTAL_FW_V4=()
PORTAL_FW_V6=()

# Sets PORTAL_FW_PORT, PORTAL_FW_V4 and PORTAL_FW_V6.
read_portal_exposure() {
    local output network
    [[ $PANEL_ENABLED == true ]] || return 0
    output=$(ocpanel portal-networks) || die "the user portal's settings are invalid"
    [[ -n $output ]] || return 0
    PORTAL_FW_PORT=$(ocpanel portal-port) || die "the user portal's settings are invalid"
    while IFS= read -r network; do
        case $network in
            "") ;;
            *:*) PORTAL_FW_V6+=("$network") ;;
            *) PORTAL_FW_V4+=("$network") ;;
        esac
    done <<<"$output"
}

# The networks the admin panel's firewall blocklist holds, which every port
# drops. Both stay empty while the panel is off.
BLOCKED_V4=()
BLOCKED_V6=()

# Sets BLOCKED_V4 and BLOCKED_V6 from the blocklist the panel keeps.
read_blocklist() {
    local output network
    [[ $PANEL_ENABLED == true ]] || return 0
    output=$(ocpanel blocked-networks) || die "the admin panel's firewall blocklist cannot be read"
    while IFS= read -r network; do
        case $network in
            "") ;;
            *:*) BLOCKED_V6+=("$network") ;;
            *) BLOCKED_V4+=("$network") ;;
        esac
    done <<<"$output"
}

# Prints the elements line of a blocklist set, or nothing for an empty one.
nft_set_elements() {
    local IFS=,
    (($# > 0)) || return 0
    printf '        elements = { %s }\n' "$*"
}

# Prints the input rules for the portal's port when its networks are
# narrowed: each listed network is accepted and every other address dropped.
nft_portal_rules() {
    local network
    [[ -n $PORTAL_FW_PORT ]] || return 0
    for network in "${PORTAL_FW_V4[@]}"; do
        printf '        tcp dport %s ip saddr %s accept\n' "$PORTAL_FW_PORT" "$network"
    done
    for network in "${PORTAL_FW_V6[@]}"; do
        printf '        tcp dport %s ip6 saddr %s accept\n' "$PORTAL_FW_PORT" "$network"
    done
    printf '        tcp dport %s drop\n' "$PORTAL_FW_PORT"
}

# Prints the input rules for the panel's port: each admitted network is
# accepted and every other address is dropped before it reaches the panel.
# One rule per network, so networks that overlap need no merging.
nft_panel_rules() {
    local network
    [[ -n $PANEL_FW_PORT ]] || return 0
    for network in "${PANEL_FW_V4[@]}"; do
        printf '        tcp dport %s ip saddr %s accept\n' "$PANEL_FW_PORT" "$network"
    done
    for network in "${PANEL_FW_V6[@]}"; do
        printf '        tcp dport %s ip6 saddr %s accept\n' "$PANEL_FW_PORT" "$network"
    done
    printf '        tcp dport %s drop\n' "$PANEL_FW_PORT"
}

# Prints the forward rule that drops a packet from a tunnel whose source
# address is not routed back through that tunnel, when SOURCE_CHECK is on.
nft_source_check() {
    [[ $SOURCE_CHECK == true ]] || return 0
    printf '        iifname "vpns*" fib saddr . iif oif missing drop\n'
}

# The site_rules chain and the site_closed sets start empty; ocpanel
# site-sync fills them, and the group sets the rules name, as the admin
# panel's rules, the published networks and the sessions change.
nft_filter_ruleset() {
    local between_clients=drop
    [[ $CLIENT_TO_CLIENT == true ]] && between_clients=accept
    cat <<EOF
table inet $FW_TABLE
delete table inet $FW_TABLE
table inet $FW_TABLE {
    set blocked4 {
        type ipv4_addr
        flags interval
$(nft_set_elements "${BLOCKED_V4[@]}")
    }
    set blocked6 {
        type ipv6_addr
        flags interval
$(nft_set_elements "${BLOCKED_V6[@]}")
    }
    set site_closed4 {
        type ipv4_addr
        flags interval
    }
    set site_closed6 {
        type ipv6_addr
        flags interval
    }
    chain site_rules {
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "lo" accept
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
$(nft_panel_rules)
$(nft_portal_rules)
        iifname "vpns*" ct state established,related accept
        iifname "vpns*" meta l4proto { icmp, ipv6-icmp } accept
        iifname "vpns*" drop
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid drop
$(nft_source_check)
        tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu
        ct state established,related accept
        iifname "vpns*" oifname "vpns*" jump site_rules
        iifname "vpns*" oifname "vpns*" $between_clients
        iifname "vpns*" ip saddr @site_closed4 drop
        iifname "vpns*" ip6 saddr @site_closed6 drop
        iifname "vpns*" accept
    }
}
EOF
}

# Prints the NAT table for one family ("ip" or "ip6"), or only its removal
# when NAT is off or the family has no tunnel network. Its site_egress set,
# which ocpanel site-sync fills, holds the published networks the admin
# panel lets out.
nft_nat_ruleset() {
    local family=$1 net type=ipv4_addr
    shift
    [[ $family == ip6 ]] && type=ipv6_addr
    printf 'table %s %s\ndelete table %s %s\n' "$family" "$FW_TABLE" "$family" "$FW_TABLE"
    [[ $NAT == true && -n ${1:-} ]] || return 0
    printf 'table %s %s {\n' "$family" "$FW_TABLE"
    printf '    set site_egress {\n        type %s\n        flags interval\n    }\n' "$type"
    printf '    chain postrouting {\n'
    printf '        type nat hook postrouting priority srcnat; policy accept;\n'
    for net in "$@"; do
        printf '        %s saddr %s oifname != "vpns*" masquerade\n' "$family" "$net"
    done
    printf '        %s saddr @site_egress oifname != "vpns*" masquerade\n' "$family"
    printf '    }\n}\n'
}

apply_nftables() {
    local output
    if ! output=$({ nft_filter_ruleset; nft_nat_ruleset ip "$CONF_V4_NET" "${GROUP_POOLS[@]}"; } | nft -f - 2>&1); then
        printf '%s\n' "$output" >&2
        die "could not load the nftables ruleset"
    fi
    [[ -d /proc/sys/net/ipv6 ]] || return 0
    if ! output=$(nft_nat_ruleset ip6 "$CONF_V6_NET" | nft -f - 2>&1); then
        printf '%s\n' "$output" >&2
        warn "could not load the IPv6 NAT table, so client IPv6 traffic stays inside the tunnel and is dropped there"
    fi
}

# Creates a chain that other chains jump to, or empties it when it exists.
ipt_new_chain() {
    local cmd=$1 table=$2 chain=$3
    "$cmd" -w -t "$table" -N "$chain" 2>/dev/null || "$cmd" -w -t "$table" -F "$chain"
}

# Drops each packet from a tunnel whose source address is not routed back
# through that tunnel. Returns non-zero when the kernel lacks the rpfilter
# match.
ipt_source_check() {
    local cmd=$1
    ipt_chain "$cmd" raw PREROUTING VPN_SPOOF || return 1
    "$cmd" -w -t raw -A VPN_SPOOF -i vpns+ -m rpfilter --invert -j DROP
}

# Creates the chain, or empties it when it exists, and puts a jump to it at
# the top of the built-in chain.
ipt_chain() {
    local cmd=$1 table=$2 parent=$3 chain=$4
    if ! "$cmd" -w -t "$table" -N "$chain" 2>/dev/null; then
        "$cmd" -w -t "$table" -F "$chain" || return 1
    fi
    if ! "$cmd" -w -t "$table" -C "$parent" -j "$chain" 2>/dev/null; then
        "$cmd" -w -t "$table" -I "$parent" 1 -j "$chain" || return 1
    fi
}

# Appends the input rules for the panel's port to VPN_INPUT: each network
# given is accepted and every other address is dropped.
ipt_panel_rules() {
    local cmd=$1 network
    shift
    [[ -n $PANEL_FW_PORT ]] || return 0
    for network in "$@"; do
        "$cmd" -w -A VPN_INPUT -p tcp --dport "$PANEL_FW_PORT" -s "$network" -j ACCEPT || return 1
    done
    "$cmd" -w -A VPN_INPUT -p tcp --dport "$PANEL_FW_PORT" -j DROP
}

# Appends the input rules for the portal's port to VPN_INPUT when its networks
# are narrowed: each network of cmd's family, IPv6 for ip6tables, is accepted
# and every other address dropped.
ipt_portal_rules() {
    local cmd=$1 network
    local -a networks=("${PORTAL_FW_V4[@]}")
    [[ -n $PORTAL_FW_PORT ]] || return 0
    [[ $cmd == ip6tables* ]] && networks=("${PORTAL_FW_V6[@]}")
    for network in "${networks[@]}"; do
        "$cmd" -w -A VPN_INPUT -p tcp --dport "$PORTAL_FW_PORT" -s "$network" -j ACCEPT || return 1
    done
    "$cmd" -w -A VPN_INPUT -p tcp --dport "$PORTAL_FW_PORT" -j DROP
}

# Fills VPN_BLOCK with a drop rule for each blocked network of cmd's family,
# IPv6 for ip6tables, after a rule that leaves loopback alone.
ipt_block_rules() {
    local cmd=$1 network
    local -a networks=("${BLOCKED_V4[@]}")
    [[ $cmd == ip6tables* ]] && networks=("${BLOCKED_V6[@]}")
    "$cmd" -w -A VPN_BLOCK -i lo -j RETURN || return 1
    for network in "${networks[@]}"; do
        "$cmd" -w -A VPN_BLOCK -s "$network" -j DROP || return 1
    done
}

# Loads the rules for one family. cmd is iptables-legacy or ip6tables-legacy;
# the arguments after the tunnel network are the family's networks admitted
# to the panel. Returns non-zero at the first command that fails.
ipt_family_rules() {
    local cmd=$1 icmp=$2 net=$3 between_clients=DROP
    shift 3
    [[ $CLIENT_TO_CLIENT == true ]] && between_clients=ACCEPT

    ipt_chain "$cmd" filter INPUT VPN_INPUT || return 1
    ipt_chain "$cmd" filter INPUT VPN_BLOCK || return 1
    ipt_block_rules "$cmd" || return 1
    ipt_panel_rules "$cmd" "$@" || return 1
    ipt_portal_rules "$cmd" || return 1
    "$cmd" -w -A VPN_INPUT -i vpns+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || return 1
    "$cmd" -w -A VPN_INPUT -i vpns+ -p "$icmp" -j ACCEPT || return 1
    "$cmd" -w -A VPN_INPUT -i vpns+ -j DROP || return 1

    # VPN_SITES holds the admin panel's site-to-site rules between networks
    # and VPN_SITES_CLOSED drops the published networks kept inside the VPN;
    # ocpanel site-sync fills both.
    ipt_chain "$cmd" filter FORWARD VPN_FORWARD || return 1
    ipt_new_chain "$cmd" filter VPN_SITES || return 1
    ipt_new_chain "$cmd" filter VPN_SITES_CLOSED || return 1
    "$cmd" -w -A VPN_FORWARD -m conntrack --ctstate INVALID -j DROP || return 1
    "$cmd" -w -A VPN_FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || return 1
    "$cmd" -w -A VPN_FORWARD -i vpns+ -o vpns+ -j VPN_SITES || return 1
    "$cmd" -w -A VPN_FORWARD -i vpns+ -o vpns+ -j "$between_clients" || return 1
    "$cmd" -w -A VPN_FORWARD -i vpns+ -j VPN_SITES_CLOSED || return 1
    "$cmd" -w -A VPN_FORWARD -i vpns+ -j ACCEPT || return 1
    "$cmd" -w -P FORWARD DROP || return 1

    ipt_chain "$cmd" mangle FORWARD VPN_MSS || return 1
    "$cmd" -w -t mangle -A VPN_MSS -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || return 1

    # VPN_SITES_NAT translates the published networks the admin panel lets
    # out; ocpanel site-sync fills it.
    ipt_chain "$cmd" nat POSTROUTING VPN_NAT || return 1
    ipt_new_chain "$cmd" nat VPN_SITES_NAT || return 1
    if [[ $NAT == true && -n $net ]]; then
        "$cmd" -w -t nat -A VPN_NAT -s "$net" ! -o vpns+ -j MASQUERADE || return 1
        # The groups' own pools are IPv4 networks, translated like the
        # server's pool.
        if [[ $icmp == icmp ]]; then
            for net in "${GROUP_POOLS[@]}"; do
                "$cmd" -w -t nat -A VPN_NAT -s "$net" ! -o vpns+ -j MASQUERADE || return 1
            done
        fi
        "$cmd" -w -t nat -A VPN_NAT -j VPN_SITES_NAT || return 1
    fi
}

apply_iptables() {
    local output
    if ! output=$(ipt_family_rules iptables-legacy icmp "$CONF_V4_NET" "${PANEL_FW_V4[@]}" 2>&1); then
        printf '%s\n' "$output" >&2
        die "could not load the IPv4 iptables rules"
    fi
    ipt_source_check iptables-legacy >/dev/null 2>&1 || SOURCE_CHECK=false
    [[ -d /proc/sys/net/ipv6 ]] || return 0
    if ! output=$(ipt_family_rules ip6tables-legacy ipv6-icmp "$CONF_V6_NET" "${PANEL_FW_V6[@]}" 2>&1); then
        printf '%s\n' "$output" >&2
        warn "could not load the IPv6 iptables rules, so client IPv6 traffic is not translated and may not be filtered"
        return 0
    fi
    ipt_source_check ip6tables-legacy >/dev/null 2>&1 || SOURCE_CHECK=false
}

# Loads the firewall's site-to-site part: the admin panel's rules, and the
# networks VPN users publish, kept inside the VPN unless the panel lets one
# out. ocpanel reads the firewall and the source check from the two
# variables here, and from ocserv's session script and the panel's helper,
# which inherit them, for as long as the container runs.
load_site_rules() {
    local output
    export PANEL_FIREWALL=$FW_BACKEND PANEL_SOURCE_CHECK=$SOURCE_CHECK
    if ! output=$(ocpanel site-sync 2>&1); then
        printf '%s\n' "$output" >&2
        die "could not load the firewall's site-to-site rules"
    fi
}

# Fetches MaxMind GeoLite2 when a key is set, in MAXMIND_ACCOUNT_ID and
# MAXMIND_LICENSE_KEY or from the admin panel, and the copy is missing or
# three days old. A download that fails leaves the countries to the copy in
# place or to DB-IP Lite.
update_geoip() {
    local output
    if output=$(ocpanel geoip-update 2>&1); then
        [[ -z $output ]] || info "$output"
    else
        warn "$output"
    fi
}

# Loads the country rules into their own nftables table, guarding the VPN's
# ports and the panel's and the portal's: COUNTRY_RULE (off, block or allow)
# and COUNTRIES where the environment sets them, else the rules the admin
# panel stored. PANEL_LAN_NETWORKS and the private ranges always pass. With
# the rule off ocpanel removes the table, and on legacy iptables it says why
# rules that are on do nothing. The panel's helper inherits the two
# variables here to load the rules again when an admin changes them.
load_country_rules() {
    local output
    export COUNTRY_PORTS="$LISTEN_PORT $UDP_PORT $PANEL_FW_PORT $PORTAL_FW_PORT"
    export COUNTRY_EXEMPT=${PANEL_LAN_NETWORKS:-}
    if ! output=$(ocpanel country-sync 2>&1); then
        printf '%s\n' "$output" >&2
        die "could not load the country rules"
    fi
    [[ -z $output ]] || warn "$output"
}

apply_firewall() {
    read_panel_exposure
    read_portal_exposure
    read_blocklist
    SOURCE_CHECK=true
    if [[ $FW_BACKEND == nftables ]]; then
        nft_fib_usable || SOURCE_CHECK=false
        apply_nftables
    else
        apply_iptables
    fi
    if [[ $SOURCE_CHECK != true ]]; then
        warn "this kernel cannot check where tunnel traffic comes from, so a VPN client could send as another and no site-to-site rule opens anything"
    fi
    load_site_rules
    update_geoip
    load_country_rules
}
