# shellcheck shell=bash
# Builds ocserv.conf from the validated settings. Layers, later ones winning
# per option: built-in defaults and named variables, then EXTRA_CONFIG, then
# OCSERV_CONF_* variables. Requires common.sh and settings.sh.
#
# Inputs set by the caller besides the settings: IPV6_ENABLED and
# RESTRICT_ENABLED ("true"/"false").

readonly SESSION_HOOK=/usr/local/libexec/ocserv-docker/session-hook

# Options whose OCSERV_CONF_* value is split on commas as well as newlines.
readonly -A LIST_OPTIONS=(
    ['route']=1 ['no-route']=1 ['iroute']=1 ['dns']=1 ['ipv4-dns']=1 ['ipv6-dns']=1
    ['nbns']=1 ['split-dns']=1 ['select-group']=1
)

declare -a CONF_KEYS=()
declare -A CONF_VALUES=()
# The options EXTRA_CONFIG or an OCSERV_CONF_* variable set or removed, each
# with the file or variable that did.
declare -A CONF_OVERRIDDEN=()
CONF_VHOST_TAIL=

conf_reset() {
    CONF_KEYS=()
    CONF_VALUES=()
    CONF_OVERRIDDEN=()
    CONF_VHOST_TAIL=
}

# Replaces every value of an option with the given values.
conf_set() {
    local key=$1
    shift
    if [[ ! -v CONF_VALUES[$key] ]]; then
        CONF_KEYS+=("$key")
    fi
    local IFS=$'\n'
    CONF_VALUES[$key]="$*"
}

# Appends one value to an option that may repeat.
conf_add() {
    local key=$1 value=$2
    if [[ -v CONF_VALUES[$key] ]]; then
        CONF_VALUES[$key]+=$'\n'"$value"
    else
        conf_set "$key" "$value"
    fi
}

conf_unset() {
    unset "CONF_VALUES[$1]"
}

# Writes the options in first-set order, then any vhost sections.
conf_write() {
    local out=$1 header=$2 key value
    local -A written=()
    {
        printf '# %s\n\n' "$header"
        for key in "${CONF_KEYS[@]}"; do
            [[ -v CONF_VALUES[$key] && ! -v written[$key] ]] || continue
            written[$key]=1
            while IFS= read -r value; do
                printf '%s = %s\n' "$key" "$value"
            done <<<"${CONF_VALUES[$key]}"
        done
        if [[ -n $CONF_VHOST_TAIL ]]; then
            printf '\n%s' "$CONF_VHOST_TAIL"
        fi
    } >"$out"
}

# Applies an ocserv.conf fragment. Each option named in the file replaces
# every value the earlier layers gave it; lines from the first [vhost:...]
# header onward are appended verbatim after the global options.
conf_apply_file() {
    local file=$1 line key value in_vhost=false
    local -A replaced=()
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        if $in_vhost || [[ $line =~ ^[[:space:]]*\[vhost: ]]; then
            in_vhost=true
            CONF_VHOST_TAIL+="$line"$'\n'
            continue
        fi
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ ! $line =~ ^[[:space:]]*([A-Za-z0-9_-]+)[[:space:]]*=[[:space:]]*(.*[^[:space:]])[[:space:]]*$ ]]; then
            die "$file: cannot parse line: $line"
        fi
        key=${BASH_REMATCH[1]}
        value=${BASH_REMATCH[2]}
        CONF_OVERRIDDEN[$key]=$file
        if [[ -v replaced[$key] ]]; then
            conf_add "$key" "$value"
        else
            conf_set "$key" "$value"
            replaced[$key]=1
        fi
    done <"$file"
}

# Maps an OCSERV_CONF_* variable name to the ocserv option it sets.
env_to_option() {
    local key=${1#OCSERV_CONF_}
    key=${key,,}
    key=${key//_/-}
    case $key in
        camouflage-secret | camouflage-realm) key=${key//-/_} ;;
    esac
    printf '%s\n' "$key"
}

# Applies the OCSERV_CONF_* variables in name order. An empty value removes
# the option. List options split on commas and newlines, others on newlines.
conf_apply_env() {
    local name key value first
    local -a values
    while IFS= read -r name; do
        [[ $name == OCSERV_CONF_?* ]] || continue
        key=$(env_to_option "$name")
        value=${!name}
        CONF_OVERRIDDEN[$key]=$name
        if [[ -z $value ]]; then
            conf_unset "$key"
            continue
        fi
        if [[ -v LIST_OPTIONS[$key] ]]; then
            split_list values "$value"
        else
            mapfile -t values <<<"$value"
        fi
        first=true
        for value in "${values[@]}"; do
            [[ -n $value ]] || continue
            if $first; then
                conf_set "$key" "$value"
                first=false
            else
                conf_add "$key" "$value"
            fi
        done
    done < <(compgen -e | sort)
}

auth_value() {
    local auth="plain[passwd=$PASSWD_FILE"
    if [[ -f $OTP_FILE ]]; then
        auth+=",otp=$OTP_FILE"
    fi
    printf '"%s]"\n' "$auth"
}

# The sign-in methods AUTH_MODE names. ocserv requires every auth line and
# accepts an enable-auth method on its own. Certificates must come from the
# client CA, which signs only VPN users' certificates; the user is the
# certificate's UID. A certificate alone gives the groups too, from its OU
# fields; with both methods they come from the password file, since ocserv
# then refuses a user whose group the certificate does not name, which is
# every user without a group.
conf_auth() {
    local certs=$CONFIG_DIR/certs
    case $AUTH_MODE in
        password) conf_set auth "$(auth_value)" ;;
        certificate) conf_set auth '"certificate"' ;;
        both)
            conf_set auth '"certificate"'
            conf_add auth "$(auth_value)"
            ;;
        either)
            conf_set auth "$(auth_value)"
            conf_set enable-auth '"certificate"'
            ;;
    esac
    [[ $AUTH_MODE != password ]] || return 0
    conf_set ca-cert "$certs/client-ca.pem"
    conf_set crl "$certs/client-crl.pem"
    conf_set cert-user-oid 0.9.2342.19200300.100.1.1
    if [[ $AUTH_MODE != both ]]; then
        conf_set cert-group-oid 2.5.4.11
    fi
}

# Populates the option store from the settings. Reads the filesystem only to
# test for the optional OTP file, per-user and per-group directories, and
# EXTRA_CONFIG.
conf_build() {
    local var option item

    conf_reset
    conf_auth
    conf_set tcp-port "$LISTEN_PORT"
    if [[ $DTLS == true ]]; then
        conf_set udp-port "$UDP_PORT"
    fi
    if [[ -n ${LISTEN_HOST:-} ]]; then
        conf_set listen-host "$LISTEN_HOST"
    fi
    conf_set listen-proxy-proto "$PROXY_PROTOCOL"

    conf_set run-as-user ocserv
    conf_set run-as-group ocserv
    conf_set socket-file "$RUNTIME_DIR/ocserv.sock"
    conf_set pid-file "$RUNTIME_DIR/ocserv.pid"
    conf_set use-occtl true
    conf_set isolate-workers true
    conf_set limit-worker-memory true

    conf_set server-cert "$SERVER_CERT"
    conf_set server-key "$SERVER_KEY"
    conf_set tls-priorities "\"$TLS_PRIORITIES\""
    conf_set cisco-client-compat "$CISCO_COMPAT"
    conf_set dtls-legacy "$CISCO_COMPAT"
    if [[ $CISCO_COMPAT == false ]]; then
        conf_set match-tls-dtls-ciphers true
    fi
    conf_set compression false
    conf_set rekey-time 172800
    conf_set rekey-method ssl

    while read -r var option _; do
        [[ -n $var && -n ${!var:-} ]] || continue
        conf_set "$option" "${!var}"
    done <<<"$NUMERIC_OPTIONS"
    conf_set server-stats-reset-time 604800
    conf_set try-mtu-discovery true

    conf_set connect-script "$SESSION_HOOK"
    conf_set disconnect-script "$SESSION_HOOK"
    # ocserv routes the networks a user or group publishes with iroute, for
    # site-to-site, only through these commands. %{RI} is the network in
    # CIDR form, which busybox ip takes for IPv4 and IPv6 alike.
    conf_set route-add-cmd '"ip route add %{RI} dev %{D}"'
    conf_set route-del-cmd '"ip route delete %{RI} dev %{D}"'

    conf_set device vpns
    conf_set predictable-ips true
    conf_set ping-leases false
    conf_set ipv4-network "$VPN_NETWORK"
    if [[ $IPV6_ENABLED == true ]]; then
        conf_set ipv6-network "$VPN_IPV6_NETWORK"
        conf_set ipv6-subnet-prefix 128
    fi
    if [[ -n ${DEFAULT_DOMAIN:-} ]]; then
        conf_set default-domain "\"$DEFAULT_DOMAIN\""
    fi
    for item in "${DNS_LIST[@]}"; do
        conf_add dns "$item"
    done
    for item in "${SPLIT_DNS_LIST[@]}"; do
        conf_add split-dns "$item"
    done
    conf_set tunnel-all-dns "$TUNNEL_ALL_DNS"

    if [[ $TUNNEL_MODE == all ]]; then
        conf_set route default
    else
        for item in "${TUNNEL_ROUTE_LIST[@]}"; do
            conf_add route "$item"
        done
    fi
    for item in "${NO_ROUTE_LIST[@]}"; do
        conf_add no-route "$item"
    done
    conf_set restrict-user-to-routes "$RESTRICT_ENABLED"
    conf_set client-bypass-protocol false

    if [[ -n ${CAMOUFLAGE_SECRET:-} ]]; then
        conf_set camouflage true
        conf_set camouflage_secret "\"$CAMOUFLAGE_SECRET\""
        if [[ -n ${CAMOUFLAGE_REALM:-} ]]; then
            conf_set camouflage_realm "\"$CAMOUFLAGE_REALM\""
        fi
    else
        conf_set camouflage false
    fi
    if [[ -n ${BANNER:-} ]]; then
        conf_set banner "\"$BANNER\""
    fi
    if [[ -n ${PRE_LOGIN_BANNER:-} ]]; then
        conf_set pre-login-banner "\"$PRE_LOGIN_BANNER\""
    fi

    if [[ $SECURITY_HEADERS == true ]]; then
        conf_add included-http-headers "Strict-Transport-Security: max-age=31536000 ; includeSubDomains"
        conf_add included-http-headers "X-Frame-Options: deny"
        conf_add included-http-headers "X-Content-Type-Options: nosniff"
        conf_add included-http-headers "Content-Security-Policy: default-src 'none'"
        conf_add included-http-headers "Referrer-Policy: no-referrer"
        conf_add included-http-headers "Cache-Control: no-store"
    fi

    if [[ -d $CONFIG_DIR/config-per-user ]]; then
        conf_set config-per-user "$CONFIG_DIR/config-per-user/"
    fi
    if [[ -d $CONFIG_DIR/config-per-group ]]; then
        conf_set config-per-group "$CONFIG_DIR/config-per-group/"
    fi

    if [[ -f $EXTRA_CONFIG ]]; then
        conf_apply_file "$EXTRA_CONFIG"
    fi
    conf_apply_env
}

# Writes, for the admin panel's helper, one line per panel setting after
# conf_build: the variable, when a change reaches ocserv, where the value
# came from and the value the server uses, separated by tabs. The source is
# the file or OCSERV_CONF_* variable that overrides the ocserv option the
# setting becomes, or "environment", "panel" or "default". An overridden
# setting's value is left empty, since ocserv does not use it.
write_settings_state() {
    local out=$1 name when option source value
    {
        while read -r name when option; do
            [[ -n $name ]] || continue
            value=${!name:-}
            if [[ $option != - && -v CONF_OVERRIDDEN[$option] ]]; then
                source=${CONF_OVERRIDDEN[$option]}
                value=
            elif [[ -v ENV_SETTINGS[$name] ]]; then
                source=environment
            elif [[ -v PANEL_SET[$name] ]]; then
                source=panel
            else
                source=default
            fi
            printf '%s\t%s\t%s\t%s\n' "$name" "$when" "$source" "$value"
        done <<<"$PANEL_SETTINGS"
    } >"$out.new"
    mv -f "$out.new" "$out"
}

# The address pools of the groups, in CIDR form; filled by read_group_pools.
declare -a GROUP_POOLS=()

# Reads the address pools the group settings files in the directory give
# into GROUP_POOLS: ipv4-network with its prefix, or with ipv4-netmask. A
# pool that is not an IPv4 network is left out with a warning; ocserv
# refuses that group's sessions then anyway.
read_group_pools() {
    local dir=$1 file line net mask prefix
    GROUP_POOLS=()
    [[ -d $dir ]] || return 0
    for file in "$dir"/*; do
        [[ -f $file ]] || continue
        net=
        mask=
        while IFS= read -r line || [[ -n $line ]]; do
            line=${line%$'\r'}
            [[ $line =~ ^[[:space:]]*(ipv4-network|ipv4-netmask)[[:space:]]*=[[:space:]]*\"?([^\"[:space:]]+) ]] || continue
            case ${BASH_REMATCH[1]} in
                ipv4-network) net=${BASH_REMATCH[2]} ;;
                ipv4-netmask) mask=${BASH_REMATCH[2]} ;;
            esac
        done <"$file"
        [[ -n $net ]] || continue
        if [[ $net != */* && -n $mask ]] && prefix=$(netmask_to_prefix "$mask"); then
            net=$net/$prefix
        fi
        if is_ipv4_cidr "$net"; then
            GROUP_POOLS+=("$net")
        else
            warn "${file##*/}: the group's address pool '$net' is not an IPv4 network, so the firewall leaves it out"
        fi
    done
}

# Reads the tunnel networks from a finished ocserv.conf into CONF_V4_NET and
# CONF_V6_NET (CIDR, empty when absent). Only the global section is read.
read_tunnel_networks() {
    local file=$1 line key value net="" mask="" prefix
    CONF_V4_NET=
    CONF_V6_NET=
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*\[vhost: ]] && break
        [[ $line =~ ^[[:space:]]*([A-Za-z0-9_-]+)[[:space:]]*=[[:space:]]*\"?([^\"[:space:]]+) ]] || continue
        key=${BASH_REMATCH[1]}
        value=${BASH_REMATCH[2]}
        case $key in
            ipv4-network) [[ -z $net ]] && net=$value ;;
            ipv4-netmask) [[ -z $mask ]] && mask=$value ;;
            ipv6-network) [[ -z $CONF_V6_NET ]] && CONF_V6_NET=$value ;;
        esac
    done <"$file"

    if [[ $net == */* ]]; then
        CONF_V4_NET=$(normalize_route "$net") || die "$file: cannot read ipv4-network '$net'"
    elif [[ -n $net ]]; then
        [[ -n $mask ]] || die "$file: ipv4-network has no prefix and ipv4-netmask is missing"
        prefix=$(netmask_to_prefix "$mask") || die "$file: invalid ipv4-netmask '$mask'"
        CONF_V4_NET="$net/$prefix"
    fi
    return 0
}
