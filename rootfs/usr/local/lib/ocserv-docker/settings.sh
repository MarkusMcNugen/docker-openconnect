# shellcheck shell=bash
# Reads and validates every environment variable the container understands.
# load_settings normalizes each variable in place and is the only place
# defaults are applied. Requires common.sh.

readonly DEFAULT_TLS_PRIORITIES='NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2:-RSA:-DHE-RSA:-AES-128-CBC:-AES-256-CBC:-CAMELLIA-128-CBC:-CAMELLIA-256-CBC:-3DES-CBC:-ARCFOUR-128:-SHA1'

# Variables that map one-to-one onto a numeric ocserv option.
# Columns: variable, ocserv option, default ("-" leaves the option unset).
readonly NUMERIC_OPTIONS='
MAX_CLIENTS                 max-clients                 128
MAX_SAME_CLIENTS            max-same-clients            4
IDLE_TIMEOUT                idle-timeout                -
MOBILE_IDLE_TIMEOUT         mobile-idle-timeout         -
SESSION_TIMEOUT             session-timeout             -
RX_DATA_PER_SEC             rx-data-per-sec             -
TX_DATA_PER_SEC             tx-data-per-sec             -
AUTH_TIMEOUT                auth-timeout                240
COOKIE_TIMEOUT              cookie-timeout              300
MAX_BAN_SCORE               max-ban-score               80
BAN_TIME                    ban-time                    300
BAN_RESET_TIME              ban-reset-time              1200
BAN_POINTS_WRONG_PASSWORD   ban-points-wrong-password   10
RATE_LIMIT_MS               rate-limit-ms               100
KEEPALIVE                   keepalive                   32400
DPD                         dpd                         90
MOBILE_DPD                  mobile-dpd                  1800
SWITCH_TO_TCP_TIMEOUT       switch-to-tcp-timeout       25
MTU                         mtu                         -
SERVER_DRAIN_MS             server-drain-ms             -
LOG_LEVEL                   log-level                   2
'

# Settings an owner may change on the admin panel's Settings page while the
# environment leaves them unset, stored one per line in
# CONFIG_DIR/panel/settings.env as the variable, an equals sign and the
# value. Columns: variable; when a change reaches ocserv ("reload" keeps
# sessions, "start" waits for the next container start); the ocserv option
# it becomes ("-" for firewall settings).
readonly PANEL_SETTINGS='
DNS_SERVERS                 reload  dns
SPLIT_DNS_DOMAINS           reload  split-dns
DEFAULT_DOMAIN              reload  default-domain
TUNNEL_ALL_DNS              reload  tunnel-all-dns
BANNER                      reload  banner
PRE_LOGIN_BANNER            reload  pre-login-banner
MAX_CLIENTS                 reload  max-clients
MAX_SAME_CLIENTS            reload  max-same-clients
IDLE_TIMEOUT                reload  idle-timeout
MOBILE_IDLE_TIMEOUT         reload  mobile-idle-timeout
SESSION_TIMEOUT             reload  session-timeout
RX_DATA_PER_SEC             reload  rx-data-per-sec
TX_DATA_PER_SEC             reload  tx-data-per-sec
AUTH_TIMEOUT                reload  auth-timeout
COOKIE_TIMEOUT              reload  cookie-timeout
MAX_BAN_SCORE               reload  max-ban-score
BAN_TIME                    reload  ban-time
BAN_RESET_TIME              reload  ban-reset-time
BAN_POINTS_WRONG_PASSWORD   reload  ban-points-wrong-password
RATE_LIMIT_MS               reload  rate-limit-ms
KEEPALIVE                   reload  keepalive
DPD                         reload  dpd
MOBILE_DPD                  reload  mobile-dpd
SWITCH_TO_TCP_TIMEOUT       reload  switch-to-tcp-timeout
MTU                         reload  mtu
SERVER_DRAIN_MS             reload  server-drain-ms
PROXY_PROTOCOL              reload  listen-proxy-proto
AUTH_MODE                   start   auth
DTLS                        start   udp-port
TUNNEL_MODE                 start   route
TUNNEL_ROUTES               start   route
NO_ROUTES                   start   no-route
RESTRICT_TO_ROUTES          start   restrict-user-to-routes
NAT                         start   -
CLIENT_TO_CLIENT            start   -
CISCO_COMPAT                start   cisco-client-compat
LOG_LEVEL                   start   log-level
'

# The settings the environment set, and those the panel's file set because
# the environment did not; filled by load_panel_settings.
declare -A ENV_SETTINGS=()
declare -A PANEL_SET=()

# Whether the name is a row of PANEL_SETTINGS.
is_panel_setting() {
    local wanted=$1 name
    while read -r name _; do
        [[ $name == "$wanted" ]] && return 0
    done <<<"$PANEL_SETTINGS"
    return 1
}

# Notes which panel settings the environment set, then gives every other one
# the value stored by the panel, before load_settings applies the defaults
# and checks each value. A line naming anything else stops the start.
load_panel_settings() {
    local file=${CONFIG_DIR:-/config}/panel/settings.env line name value
    ENV_SETTINGS=()
    PANEL_SET=()
    while read -r name _; do
        [[ -n $name && -n ${!name:-} ]] && ENV_SETTINGS[$name]=1
    done <<<"$PANEL_SETTINGS"
    [[ -f $file ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line || $line == '#'* ]] && continue
        [[ $line =~ ^([A-Z0-9_]+)=(.*)$ ]] || die "$file: '$line' is not a setting and a value"
        name=${BASH_REMATCH[1]}
        value=${BASH_REMATCH[2]}
        is_panel_setting "$name" || die "$file: $name is not a setting the admin panel manages"
        if [[ -z ${!name:-} ]]; then
            printf -v "$name" '%s' "$value"
            PANEL_SET[$name]=1
        fi
    done <"$file"
    if ((${#PANEL_SET[@]} > 0)); then
        local -a names
        mapfile -t names < <(printf '%s\n' "${!PANEL_SET[@]}" | sort)
        info "settings from the admin panel: ${names[*]}"
    fi
}

# Normalizes a route given as CIDR or address/netmask to CIDR on stdout.
normalize_route() {
    local route=$1 prefix
    if is_ipv4_cidr "$route" || is_ipv6_cidr "$route"; then
        printf '%s\n' "$route"
    elif [[ $route == */*.*.*.* ]] && is_ipv4 "${route%%/*}" \
        && prefix=$(netmask_to_prefix "${route#*/}"); then
        printf '%s/%s\n' "${route%%/*}" "$prefix"
    else
        return 1
    fi
}

# Splits the comma-separated route variable into the named array of CIDRs.
load_route_list() {
    local var=$1
    local -n _routes=$2
    local raw normalized
    local -a items
    split_list items "${!var:-}"
    _routes=()
    for raw in "${items[@]}"; do
        normalized=$(normalize_route "$raw") || die "$var: '$raw' is not a route in CIDR or address/netmask form"
        _routes+=("$normalized")
    done
}

load_settings() {
    local var default item

    set_bool POWER_USER false
    set_bool PANEL_ENABLED false

    set_default LISTEN_PORT 4443
    require_port LISTEN_PORT
    set_default UDP_PORT "$LISTEN_PORT"
    require_port UDP_PORT
    set_bool DTLS true
    if [[ -n ${LISTEN_HOST:-} ]]; then
        require_plain_text LISTEN_HOST
    fi

    set_default TUNNEL_MODE all
    TUNNEL_MODE=${TUNNEL_MODE,,}
    require_choice TUNNEL_MODE all split-include
    load_route_list TUNNEL_ROUTES TUNNEL_ROUTE_LIST
    load_route_list NO_ROUTES NO_ROUTE_LIST
    if [[ $TUNNEL_MODE == split-include && ${#TUNNEL_ROUTE_LIST[@]} -eq 0 ]]; then
        die "TUNNEL_MODE=split-include needs at least one route in TUNNEL_ROUTES"
    fi

    set_default VPN_NETWORK 192.168.255.0/24
    is_ipv4_cidr "$VPN_NETWORK" || die "VPN_NETWORK must be an IPv4 network in CIDR form (got '$VPN_NETWORK')"

    set_default IPV6 auto
    IPV6=${IPV6,,}
    if [[ $IPV6 != auto ]]; then
        set_bool IPV6 auto
    fi
    set_default VPN_IPV6_NETWORK fd3e:7a0c:5b19::/48
    is_ipv6_cidr "$VPN_IPV6_NETWORK" || die "VPN_IPV6_NETWORK must be an IPv6 network in CIDR form (got '$VPN_IPV6_NETWORK')"

    set_default DNS_SERVERS 9.9.9.9,1.1.1.1
    split_list DNS_LIST "$DNS_SERVERS"
    for item in "${DNS_LIST[@]}"; do
        is_ipv4 "$item" || is_ipv6 "$item" || die "DNS_SERVERS: '$item' is not an IP address"
    done
    split_list SPLIT_DNS_LIST "${SPLIT_DNS_DOMAINS:-}"
    for item in "${SPLIT_DNS_LIST[@]}"; do
        [[ $item =~ ^[A-Za-z0-9.-]+$ ]] || die "SPLIT_DNS_DOMAINS: '$item' is not a domain name"
    done
    if [[ -n ${DEFAULT_DOMAIN:-} && ! $DEFAULT_DOMAIN =~ ^[A-Za-z0-9.\ -]+$ ]]; then
        die "DEFAULT_DOMAIN must be one or more space-separated domain names"
    fi
    set_bool TUNNEL_ALL_DNS true

    set_default RESTRICT_TO_ROUTES auto
    RESTRICT_TO_ROUTES=${RESTRICT_TO_ROUTES,,}
    if [[ $RESTRICT_TO_ROUTES != auto ]]; then
        set_bool RESTRICT_TO_ROUTES auto
    fi
    set_bool CLIENT_TO_CLIENT false
    set_bool NAT true
    set_default FIREWALL_BACKEND auto
    FIREWALL_BACKEND=${FIREWALL_BACKEND,,}
    require_choice FIREWALL_BACKEND auto nftables iptables
    # Unset, the country rules are the admin panel's, which ocpanel reads.
    if [[ -n ${COUNTRY_RULE:-} ]]; then
        COUNTRY_RULE=${COUNTRY_RULE,,}
        require_choice COUNTRY_RULE off block allow
    fi
    local countries=${COUNTRIES:-}
    local -a codes
    read -ra codes <<<"${countries//,/ }"
    for item in "${codes[@]}"; do
        [[ $item =~ ^[A-Za-z]{2}$ ]] || die "COUNTRIES: '$item' is not a two-letter country code"
    done
    if [[ -n ${MAXMIND_ACCOUNT_ID:-} || -n ${MAXMIND_LICENSE_KEY:-} ]]; then
        [[ ${MAXMIND_ACCOUNT_ID:-} =~ ^[0-9]{1,12}$ ]] ||
            die "MAXMIND_ACCOUNT_ID must be a MaxMind account's number, set with MAXMIND_LICENSE_KEY"
        [[ ${MAXMIND_LICENSE_KEY:-} =~ ^[A-Za-z0-9_]{6,128}$ ]] ||
            die "MAXMIND_LICENSE_KEY must be a MaxMind license key of letters, digits and underscores, set with MAXMIND_ACCOUNT_ID"
    fi
    # Unset, the mail server for email alerts is the one the admin panel
    # saved. No message here names the password.
    if [[ -n ${PANEL_SMTP_HOST:-} ]]; then
        [[ $PANEL_SMTP_HOST =~ ^[A-Za-z0-9.:-]+$ ]] ||
            die "PANEL_SMTP_HOST: '$PANEL_SMTP_HOST' is not a host name or IP address"
        set_default PANEL_SMTP_SECURITY starttls
        PANEL_SMTP_SECURITY=${PANEL_SMTP_SECURITY,,}
        require_choice PANEL_SMTP_SECURITY tls starttls plain
        if [[ -n ${PANEL_SMTP_PORT:-} ]]; then
            require_port PANEL_SMTP_PORT
        fi
        [[ ${PANEL_SMTP_FROM:-} =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]] ||
            die "PANEL_SMTP_FROM must be the address alerts come from, such as alerts@example.com, since PANEL_SMTP_HOST is set"
        if [[ -n ${PANEL_SMTP_USER:-} || -n ${PANEL_SMTP_PASSWORD:-} ]]; then
            [[ -n ${PANEL_SMTP_USER:-} && -n ${PANEL_SMTP_PASSWORD:-} ]] ||
                die "PANEL_SMTP_USER and PANEL_SMTP_PASSWORD go together: set both or neither"
            [[ $PANEL_SMTP_SECURITY != plain ]] ||
                die "PANEL_SMTP_SECURITY=plain would send PANEL_SMTP_PASSWORD unencrypted; use tls or starttls, or leave PANEL_SMTP_USER and PANEL_SMTP_PASSWORD unset for a relay that takes none"
        fi
    else
        for var in PANEL_SMTP_PORT PANEL_SMTP_SECURITY PANEL_SMTP_USER PANEL_SMTP_PASSWORD PANEL_SMTP_FROM; do
            [[ -z ${!var:-} ]] || die "$var is set without PANEL_SMTP_HOST"
        done
    fi
    # Unset, the location checks follow the admin panel's setting. The
    # panel's helper runs them, so turning them on here needs the panel.
    if [[ -n ${LOCATION_CHECKS:-} ]]; then
        set_bool LOCATION_CHECKS false
        if [[ $LOCATION_CHECKS == true && $PANEL_ENABLED != true ]]; then
            die "LOCATION_CHECKS=true needs the admin panel, which runs the checks: set PANEL_ENABLED=true"
        fi
    fi
    if [[ -n ${LOCATION_REFRESH_HOURS:-} ]]; then
        if [[ ! $LOCATION_REFRESH_HOURS =~ ^[0-9]{1,3}$ ]] ||
            ((10#$LOCATION_REFRESH_HOURS < 1 || 10#$LOCATION_REFRESH_HOURS > 168)); then
            die "LOCATION_REFRESH_HOURS must be a whole number of hours from 1 to 168 (got '$LOCATION_REFRESH_HOURS')"
        fi
    fi

    set_bool CISCO_COMPAT true
    set_bool PROXY_PROTOCOL false
    set_bool SECURITY_HEADERS true
    set_default TLS_PRIORITIES "$DEFAULT_TLS_PRIORITIES"
    require_plain_text TLS_PRIORITIES

    if [[ -n ${CAMOUFLAGE_SECRET:-} && ! $CAMOUFLAGE_SECRET =~ ^[A-Za-z0-9._~-]+$ ]]; then
        die "CAMOUFLAGE_SECRET may only contain letters, digits and . _ ~ -"
    fi
    for var in CAMOUFLAGE_REALM BANNER PRE_LOGIN_BANNER; do
        if [[ -n ${!var:-} ]]; then
            require_plain_text "$var"
        fi
    done

    while read -r var _ default; do
        [[ -n $var ]] || continue
        if [[ $default != - ]]; then
            set_default "$var" "$default"
        fi
        if [[ -n ${!var:-} ]]; then
            require_uint "$var"
        fi
    done <<<"$NUMERIC_OPTIONS"

    set_default CONFIG_DIR /config
    set_default RUNTIME_DIR /run/ocserv
    set_default EXTRA_CONFIG "$CONFIG_DIR/ocserv-extra.conf"
    set_default PASSWD_FILE "$CONFIG_DIR/ocpasswd"
    set_default OTP_FILE "$CONFIG_DIR/users.oath"
    set_default SERVER_CERT "$CONFIG_DIR/certs/server-cert.pem"
    set_default SERVER_KEY "$CONFIG_DIR/certs/server-key.pem"
    for var in CONFIG_DIR RUNTIME_DIR EXTRA_CONFIG PASSWD_FILE OTP_FILE SERVER_CERT SERVER_KEY; do
        [[ ${!var} == /* ]] || die "$var must be an absolute path (got '${!var}')"
        require_plain_text "$var"
    done

    set_default AUTH_MODE password
    AUTH_MODE=${AUTH_MODE,,}
    require_choice AUTH_MODE password certificate both either

    set_default CERT_KEY_TYPE ecdsa
    CERT_KEY_TYPE=${CERT_KEY_TYPE,,}
    require_choice CERT_KEY_TYPE ecdsa rsa
    set_default CA_CN "VPN CA"
    set_default CA_ORG OCSERV
    set_default CA_DAYS 3650
    set_default SRV_CN vpn.example.com
    set_default SRV_ORG OCSERV
    set_default SRV_DAYS 825
    for var in CA_CN CA_ORG SRV_CN SRV_ORG; do
        require_plain_text "$var"
    done
    require_uint CA_DAYS
    require_uint SRV_DAYS
    split_list SRV_SAN_LIST "${SRV_SAN:-}"
    for item in "${SRV_SAN_LIST[@]}"; do
        [[ $item =~ ^[A-Za-z0-9.:*-]+$ ]] || die "SRV_SAN: '$item' is not a host name or IP address"
    done

    if [[ -n ${PUID:-} || -n ${PGID:-} ]]; then
        set_default PUID 0
        set_default PGID 0
        require_uint PUID
        require_uint PGID
    fi
}
