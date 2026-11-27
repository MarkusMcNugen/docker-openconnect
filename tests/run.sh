#!/bin/bash
# Test runner for the image.
#
#   tests/run.sh unit              checks the entrypoint modules; needs only bash 5
#   tests/run.sh smoke <image>     runs the image with podman or docker, connects
#                                  real OpenConnect clients, and checks the tunnel,
#                                  the firewall, leak protection and the upgrade paths
#   tests/run.sh emulated <image>  checks an image for a platform that runs only
#                                  under QEMU emulation
#
# Prints one timestamped pass or fail line per check and a summary, and exits
# non-zero when any check fails.

# Single-quoted code passed to lib_run and sh -c expands in the child shell.
# shellcheck disable=SC2016
set -Eeuo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly REPO
readonly LIB=$REPO/rootfs/usr/local/lib/ocserv-docker
readonly FIXTURES=$REPO/tests/fixtures/legacy-1.x
PASSED=0
FAILED=0
T=$(mktemp -d)
readonly T

cleanup() {
    [[ -n ${SMOKE_CLEANUP:-} ]] && "$SMOKE_CLEANUP"
    [[ $T == /tmp/* || $T == "${TMPDIR:-/tmp}"/* ]] && rm -rf -- "$T"
    return 0
}
trap cleanup EXIT

stamp() { date -u +%H:%M:%S; }

note() { printf '%s      %s\n' "$(stamp)" "$*"; }

pass() {
    PASSED=$((PASSED + 1))
    printf '%s PASS %s\n' "$(stamp)" "$1"
}

# fail <name> [<detail>] counts a failure, prints it with its detail
# indented, and returns 1, so `check ... || return 1` ends a section.
fail() {
    local line
    FAILED=$((FAILED + 1))
    printf '%s FAIL %s\n' "$(stamp)" "$1"
    if [[ -n ${2:-} ]]; then
        while IFS= read -r line; do
            printf '         %s\n' "$line"
        done <<<"$2"
    fi
    return 1
}

# check <name> <command>... passes when the command succeeds.
check() {
    local name=$1 output
    shift
    if output=$("$@" 2>&1); then
        pass "$name"
    else
        fail "$name" "$output"
    fi
}

# check_fails <name> <command>... passes when the command fails.
check_fails() {
    local name=$1 output
    shift
    if output=$("$@" 2>&1); then
        fail "$name" "expected a failure, got success: $output"
    else
        pass "$name"
    fi
}

has_line() {
    local file=$1 want=$2 line
    while IFS= read -r line; do
        [[ $line == "$want" ]] && return 0
    done <"$file"
    printf 'missing line: %s\n' "$want"
    return 1
}

lacks_line() {
    local file=$1 unwanted=$2 line
    while IFS= read -r line; do
        if [[ $line == "$unwanted" ]]; then
            printf 'unexpected line: %s\n' "$unwanted"
            return 1
        fi
    done <"$file"
}

# key_count <file> <key> <expected> passes when the key appears that many times.
key_count() {
    local file=$1 key=$2 expected=$3 line n=0
    while IFS= read -r line; do
        [[ $line == "$key = "* ]] && n=$((n + 1))
    done <"$file"
    [[ $n == "$expected" ]] || {
        printf '%s appears %s times, expected %s\n' "$key" "$n" "$expected"
        return 1
    }
}

contains() {
    [[ $1 == *"$2"* ]] || {
        printf 'expected to find: %s\nin: %s\n' "$2" "$1"
        return 1
    }
}

lacks() {
    [[ $1 != *"$2"* ]] || {
        printf 'did not expect: %s\nin: %s\n' "$2" "$1"
        return 1
    }
}

matches() {
    [[ $1 =~ $2 ]] || {
        printf 'expected to match %s: %s\n' "$2" "$1"
        return 1
    }
}

# lib_run [<var>=<value>...] -- <code> runs the code in a clean environment
# with the entrypoint modules loaded.
lib_run() {
    local -a envs=()
    while [[ $1 != -- ]]; do
        envs+=("$1")
        shift
    done
    shift
    env -i PATH="$PATH" LIB="$LIB" LEGACY_HASHES="$LIB/legacy-defaults.sha256" \
        CONFIG_DIR="$T/config" RUNTIME_DIR="$T/run" IPV6_ENABLED=false \
        RESTRICT_ENABLED=false "${envs[@]}" bash -c '
        set -Eeuo pipefail
        for module in common settings legacy certs config system firewall; do
            source "$LIB/$module.sh"
        done
        '"$1"
}

# render <out> [<var>=<value>...] writes the configuration the settings produce.
render() {
    local out=$1
    shift
    lib_run OUT="$out" "$@" -- 'load_settings; conf_build; conf_write "$OUT" test'
}

copy_crlf() {
    local line
    while IFS= read -r line || [[ -n $line ]]; do
        printf '%s\r\n' "${line%$'\r'}"
    done <"$1" >"$2"
}

# replace_line <src> <dst> <old> <new> copies the file with one line replaced.
replace_line() {
    local line found=false
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        if [[ $line == "$3" ]]; then
            printf '%s\n' "$4"
            found=true
        else
            printf '%s\n' "$line"
        fi
    done <"$1" >"$2"
    $found || {
        printf 'line not found in %s: %s\n' "$1" "$3"
        return 1
    }
}

unit_render_defaults() {
    local c=$T/defaults.conf
    render "$c"
    check "defaults: plain auth on the config password file" has_line "$c" "auth = \"plain[passwd=$T/config/ocpasswd]\""
    check "defaults: TCP port 4443" has_line "$c" "tcp-port = 4443"
    check "defaults: UDP port 4443" has_line "$c" "udp-port = 4443"
    check "defaults: full tunnel" has_line "$c" "route = default"
    check "defaults: Quad9 DNS" has_line "$c" "dns = 9.9.9.9"
    check "defaults: Cloudflare DNS" has_line "$c" "dns = 1.1.1.1"
    check "defaults: two DNS servers" key_count "$c" dns 2
    check "defaults: 128 clients" has_line "$c" "max-clients = 128"
    check "defaults: 4 sessions per user" has_line "$c" "max-same-clients = 4"
    check "defaults: all DNS through the tunnel" has_line "$c" "tunnel-all-dns = true"
    check "defaults: camouflage off" has_line "$c" "camouflage = false"
    check "defaults: Cisco client compatibility" has_line "$c" "cisco-client-compat = true"
    check "defaults: worker isolation" has_line "$c" "isolate-workers = true"
    check "defaults: worker memory limit" has_line "$c" "limit-worker-memory = true"
    check "defaults: strict TLS priorities" has_line "$c" "tls-priorities = \"NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2:-RSA:-DHE-RSA:-AES-128-CBC:-AES-256-CBC:-CAMELLIA-128-CBC:-CAMELLIA-256-CBC:-3DES-CBC:-ARCFOUR-128:-SHA1\""
    check "defaults: IPv4 pool" has_line "$c" "ipv4-network = 192.168.255.0/24"
    check "defaults: no IPv6 pool without IPv6" key_count "$c" ipv6-network 0
    check "defaults: session hook as connect script" has_line "$c" "connect-script = /usr/local/libexec/ocserv-docker/session-hook"
    check "defaults: six security headers" key_count "$c" included-http-headers 6
    check "defaults: compression off" has_line "$c" "compression = false"
    check "defaults: no route restriction in full tunnel" has_line "$c" "restrict-user-to-routes = false"
    check "defaults: log level 2" has_line "$c" "log-level = 2"
    check "defaults: no idle timeout" key_count "$c" idle-timeout 0
    check "defaults: published networks are routed" has_line "$c" \
        'route-add-cmd = "ip route add %{RI} dev %{D}"'
    check "defaults: published networks are unrouted" has_line "$c" \
        'route-del-cmd = "ip route delete %{RI} dev %{D}"'
    check "defaults: no PROXY protocol" has_line "$c" "listen-proxy-proto = false"
    check "defaults: no drain time" key_count "$c" server-drain-ms 0
}

unit_render_ipv6() {
    local c=$T/ipv6.conf
    render "$c" IPV6_ENABLED=true
    check "ipv6: pool" has_line "$c" "ipv6-network = fd3e:7a0c:5b19::/48"
    check "ipv6: one address per client" has_line "$c" "ipv6-subnet-prefix = 128"
}

unit_render_split() {
    local c=$T/split.conf output
    render "$c" TUNNEL_MODE=split-include RESTRICT_ENABLED=true \
        "TUNNEL_ROUTES=192.168.1.0/24, 10.0.0.0/255.0.0.0" NO_ROUTES=192.168.1.128/25
    check "split: CIDR route kept" has_line "$c" "route = 192.168.1.0/24"
    check "split: netmask route converted" has_line "$c" "route = 10.0.0.0/8"
    check "split: two routes" key_count "$c" route 2
    check "split: no default route" lacks_line "$c" "route = default"
    check "split: excluded route" has_line "$c" "no-route = 192.168.1.128/25"
    check "split: route restriction" has_line "$c" "restrict-user-to-routes = true"
    check_fails "split: routes required" render "$T/x.conf" TUNNEL_MODE=split-include
    output=$(render "$T/x.conf" TUNNEL_MODE=split-include 2>&1) || true
    check "split: error names TUNNEL_ROUTES" contains "$output" "TUNNEL_ROUTES"
}

unit_render_overrides() {
    local c=$T/env.conf
    render "$c" MAX_CLIENTS=64 IDLE_TIMEOUT=1200 OCSERV_CONF_MAX_CLIENTS=500 \
        "OCSERV_CONF_ROUTE=10.1.0.0/16, 10.2.0.0/16" OCSERV_CONF_TRY_MTU_DISCOVERY= \
        'OCSERV_CONF_CAMOUFLAGE_REALM="Hidden"' "OCSERV_CONF_CUSTOM_HEADER=X-One: 1"$'\n'"X-Two: 2"
    check "env: OCSERV_CONF beats the named variable" has_line "$c" "max-clients = 500"
    check "env: option written once" key_count "$c" max-clients 1
    check "env: named variable sets an unset option" has_line "$c" "idle-timeout = 1200"
    check "env: list option split on commas" has_line "$c" "route = 10.2.0.0/16"
    check "env: list option replaces the default" key_count "$c" route 2
    check "env: empty value removes the option" key_count "$c" try-mtu-discovery 0
    check "env: underscore option name kept" has_line "$c" 'camouflage_realm = "Hidden"'
    check "env: newline-separated values" has_line "$c" "custom-header = X-Two: 2"
}

# AUTH_MODE: ocserv requires every auth line and accepts enable-auth alone;
# certificates come from the client CA, which names the user and groups.
unit_render_auth() {
    local c=$T/auth.conf plain="auth = \"plain[passwd=$T/config/ocpasswd]\""
    render "$c"
    check "auth: password by default" has_line "$c" "$plain"
    check "auth: no client CA by default" key_count "$c" ca-cert 0
    render "$c" AUTH_MODE=certificate
    check "auth: certificate alone" has_line "$c" 'auth = "certificate"'
    check "auth: certificate is the only method" key_count "$c" auth 1
    check "auth: the client CA verifies certificates" has_line "$c" "ca-cert = $T/config/certs/client-ca.pem"
    check "auth: the client CA's revocation list" has_line "$c" "crl = $T/config/certs/client-crl.pem"
    check "auth: the user is the certificate's user ID" has_line "$c" "cert-user-oid = 0.9.2342.19200300.100.1.1"
    check "auth: the groups are the certificate's units" has_line "$c" "cert-group-oid = 2.5.4.11"
    render "$c" AUTH_MODE=Both
    check "auth: both methods required" key_count "$c" auth 2
    check "auth: both includes the certificate" has_line "$c" 'auth = "certificate"'
    check "auth: both includes the password" has_line "$c" "$plain"
    check "auth: with both, the groups come from the password file" key_count "$c" cert-group-oid 0
    render "$c" AUTH_MODE=either
    check "auth: either signs in with the password" has_line "$c" "$plain"
    check "auth: either accepts a certificate alone" has_line "$c" 'enable-auth = "certificate"'
    check_fails "auth: an unknown mode stops the start" render "$T/x.conf" AUTH_MODE=sometimes
}

unit_render_extra_config() {
    local c=$T/extra.conf line n=0 vhost_at=0 last_global=0
    mkdir -p "$T/config"
    printf '%s\n' '# local additions' 'dns = 192.168.1.1' 'dns = 192.168.1.2' \
        'max-clients = 9' '[vhost:vpn2.example.com]' 'auth = "certificate"' >"$T/config/ocserv-extra.conf"
    render "$c"
    check "extra: replaces the DNS list" key_count "$c" dns 2
    check "extra: first DNS" has_line "$c" "dns = 192.168.1.1"
    check "extra: sets an option" has_line "$c" "max-clients = 9"
    check "extra: vhost section kept" has_line "$c" "[vhost:vpn2.example.com]"
    while IFS= read -r line; do
        n=$((n + 1))
        [[ $line == '[vhost:'* ]] && vhost_at=$n
        [[ $vhost_at == 0 && $line == *' = '* ]] && last_global=$n
    done <"$c"
    check "extra: vhost section after every global option" test "$vhost_at" -gt "$last_global"
    render "$c" OCSERV_CONF_MAX_CLIENTS=11
    check "extra: OCSERV_CONF beats the extra file" has_line "$c" "max-clients = 11"
    rm -f -- "$T/config/ocserv-extra.conf"
}

# The groups' own address pools are read from their settings files and
# translated by the firewall like the server's pool.
unit_group_pools() {
    local dir=$T/config/config-per-group out count
    mkdir -p "$dir"
    printf '%s\n' 'ipv4-network = 10.20.0.0' 'ipv4-netmask = 255.255.255.0' >"$dir/staff"
    printf '%s\n' 'ipv4-network = 10.30.0.0/25' >"$dir/lab"
    printf '%s\n' 'route = 10.0.0.0/8' >"$dir/plain"
    printf '%s\n' 'ipv4-network = nonsense' >"$dir/broken"
    out=$(lib_run NAT=true -- \
        'read_group_pools "$CONFIG_DIR/config-per-group" 2>/dev/null; nft_nat_ruleset ip 192.168.255.0/24 "${GROUP_POOLS[@]}"')
    check "group pools: the server's pool is translated" contains "$out" \
        'ip saddr 192.168.255.0/24 oifname != "vpns*" masquerade'
    check "group pools: a pool given with a netmask is translated" contains "$out" \
        'ip saddr 10.20.0.0/24 oifname != "vpns*" masquerade'
    check "group pools: a pool given with a prefix is translated" contains "$out" \
        'ip saddr 10.30.0.0/25 oifname != "vpns*" masquerade'
    count=$(printf '%s\n' "$out" | awk '/saddr [0-9][^ ]* oifname .* masquerade/{n++} END{print n+0}')
    check "group pools: a file without a pool and a broken pool add nothing" test "$count" == 3
    out=$(lib_run -- 'read_group_pools "$CONFIG_DIR/config-per-group"' 2>&1)
    check "group pools: a broken pool is named in a warning" contains "$out" "broken: the group's address pool 'nonsense'"
    rm -rf -- "$dir"
}

# The admin panel's stored settings fill what the environment leaves unset,
# and the state file names where each setting's value came from.
unit_panel_settings() {
    local c=$T/panel.conf s=$T/panel-settings
    mkdir -p "$T/config/panel"
    printf '%s\n' 'DNS_SERVERS=10.0.0.53' 'IDLE_TIMEOUT=900' 'MAX_CLIENTS=50' \
        'SERVER_DRAIN_MS=15000' 'PROXY_PROTOCOL=true' >"$T/config/panel/settings.env"
    lib_run OUT="$c" STATE="$s" MAX_CLIENTS=64 OCSERV_CONF_IDLE_TIMEOUT=600 -- \
        'load_panel_settings; load_settings; conf_build; conf_write "$OUT" test; write_settings_state "$STATE"'
    check "panel settings: a stored value fills an unset setting" has_line "$c" "dns = 10.0.0.53"
    check "panel settings: a stored drain time is written" has_line "$c" "server-drain-ms = 15000"
    check "panel settings: a stored PROXY protocol is written" has_line "$c" "listen-proxy-proto = true"
    check "panel settings: PROXY protocol changes with a reload" has_line "$s" \
        $'PROXY_PROTOCOL\treload\tpanel\ttrue'
    check "panel settings: the drain time changes with a reload" has_line "$s" \
        $'SERVER_DRAIN_MS\treload\tpanel\t15000'
    check "panel settings: the environment wins over a stored value" has_line "$c" "max-clients = 64"
    check "panel settings: OCSERV_CONF wins over a stored value" has_line "$c" "idle-timeout = 600"
    check "panel settings: state names the panel" has_line "$s" $'DNS_SERVERS\treload\tpanel\t10.0.0.53'
    check "panel settings: state names the environment" has_line "$s" $'MAX_CLIENTS\treload\tenvironment\t64'
    check "panel settings: state names the overriding variable" has_line "$s" \
        $'IDLE_TIMEOUT\treload\tOCSERV_CONF_IDLE_TIMEOUT\t'
    check "panel settings: state names the default" has_line "$s" $'NAT\tstart\tdefault\ttrue'
    printf '%s\n' 'LISTEN_PORT=1' >"$T/config/panel/settings.env"
    check_fails "panel settings: a setting the panel does not manage stops the start" \
        lib_run -- 'load_panel_settings'
    printf '%s\n' 'MAX_CLIENTS=lots' >"$T/config/panel/settings.env"
    check_fails "panel settings: stored values are checked like the environment" \
        lib_run -- 'load_panel_settings; load_settings'
    rm -rf -- "$T/config/panel"
}

unit_validation() {
    local x=$T/invalid.conf
    check_fails "validation: non-numeric limit" render "$x" MAX_CLIENTS=abc
    check_fails "validation: unknown boolean" render "$x" CLIENT_TO_CLIENT=maybe
    check_fails "validation: camouflage secret with a space" render "$x" "CAMOUFLAGE_SECRET=a b"
    check_fails "validation: network without prefix" render "$x" VPN_NETWORK=10.0.0.0
    check_fails "validation: port out of range" render "$x" LISTEN_PORT=70000
    check_fails "validation: DNS that is not an address" render "$x" DNS_SERVERS=dns.example.com
    check_fails "validation: route that is not a network" render "$x" TUNNEL_MODE=split-include TUNNEL_ROUTES=lan
    check_fails "validation: quote in a banner" render "$x" 'BANNER=say "hi"'
    check_fails "validation: unknown tunnel mode" render "$x" TUNNEL_MODE=split-exclude
    check_fails "validation: unknown key type" render "$x" CERT_KEY_TYPE=dsa
    check "validation: yes is a boolean" render "$x" CLIENT_TO_CLIENT=yes POWER_USER=No
}

unit_helpers() {
    check "helpers: netmask to prefix" lib_run -- '[[ $(netmask_to_prefix 255.255.255.0) == 24 ]]'
    check_fails "helpers: non-contiguous netmask" lib_run -- 'netmask_to_prefix 255.255.0.255'
    check "helpers: netmask route" lib_run -- '[[ $(normalize_route 10.0.0.0/255.0.0.0) == 10.0.0.0/8 ]]'
    check "helpers: IPv6 route" lib_run -- '[[ $(normalize_route fd00::/8) == fd00::/8 ]]'
    check "helpers: option name" lib_run -- '[[ $(env_to_option OCSERV_CONF_MAX_SAME_CLIENTS) == max-same-clients ]]'
    check "helpers: camouflage option name" lib_run -- '[[ $(env_to_option OCSERV_CONF_CAMOUFLAGE_SECRET) == camouflage_secret ]]'
    check "helpers: certificate names, deduplicated" lib_run "SRV_SAN=1.2.3.4, vpn2.example.com, vpn.example.com" -- '
        load_settings
        expected=$(printf "%s\n" "dns_name = \"vpn.example.com\"" "ip_address = \"1.2.3.4\"" "dns_name = \"vpn2.example.com\"")
        [[ $(san_lines) == "$expected" ]]'
    check "helpers: a stopped writer's lock and copy of the OTP file are removed" \
        lib_run OTP_FILE="$T/otp/users.oath" -- '
        mkdir -p "${OTP_FILE%/*}"
        printf "%s\n" "HOTP/T30 alex - 3132" >"$OTP_FILE"
        : >"$OTP_FILE.lock"
        : >"$OTP_FILE.new"
        out=$(clear_otp_leftovers 2>&1)
        [[ -s $OTP_FILE && ! -e $OTP_FILE.lock && ! -e $OTP_FILE.new && $out == *"removed $OTP_FILE.lock"* ]]'
}

unit_firewall() {
    local out
    out=$(lib_run -- 'load_settings; nft_filter_ruleset')
    check "firewall: forward policy drop" contains "$out" "type filter hook forward priority filter; policy drop;"
    check "firewall: clients isolated" contains "$out" 'iifname "vpns*" oifname "vpns*" drop'
    check "firewall: MSS clamp" contains "$out" "tcp option maxseg size set rt mtu"
    check "firewall: input limited to replies and ICMP" contains "$out" 'iifname "vpns*" drop'
    check "firewall: no rule names the panel's port while the panel is off" lacks "$out" "dport"
    out=$(lib_run -- 'load_settings
        PANEL_FW_PORT=8443 PANEL_FW_V4=(127.0.0.0/8 192.168.255.0/24) PANEL_FW_V6=(::1/128)
        nft_filter_ruleset')
    check "firewall: panel's port admits each network" contains "$out" "tcp dport 8443 ip saddr 192.168.255.0/24 accept"
    check "firewall: panel's port admits IPv6 networks" contains "$out" "tcp dport 8443 ip6 saddr ::1/128 accept"
    check "firewall: panel's port closed before the tunnel drop" matches "$out" 'tcp dport 8443 drop.*iifname "vpns\*" drop'
    check "firewall: panel networks split by family" lib_run PANEL_ENABLED=true -- '
        ocpanel() {
            case $1 in
                port) printf "8443\n" ;;
                allowed-networks) printf "%s\n" 127.0.0.0/8 ::1/128 172.17.0.1/32 fd00::/64 ;;
            esac
        }
        load_settings; read_panel_exposure
        [[ $PANEL_FW_PORT == 8443 && ${PANEL_FW_V4[*]} == "127.0.0.0/8 172.17.0.1/32" && ${PANEL_FW_V6[*]} == "::1/128 fd00::/64" ]]'
    check_fails "firewall: invalid panel settings stop the start" lib_run PANEL_ENABLED=true -- '
        ocpanel() { return 2; }
        load_settings; read_panel_exposure'
    out=$(lib_run -- 'load_settings
        fake_iptables() { printf "%s\n" "$*"; }
        PANEL_FW_PORT=8443; ipt_panel_rules fake_iptables 10.0.0.0/8')
    check "firewall: iptables admits each network to the panel's port" contains "$out" \
        "-w -A VPN_INPUT -p tcp --dport 8443 -s 10.0.0.0/8 -j ACCEPT"
    check "firewall: iptables closes the panel's port to the rest" contains "$out" \
        "-w -A VPN_INPUT -p tcp --dport 8443 -j DROP"
    out=$(lib_run -- 'load_settings
        PORTAL_FW_PORT=8444 PORTAL_FW_V4=(10.0.0.0/8) PORTAL_FW_V6=(fd00::/64)
        nft_filter_ruleset')
    check "firewall: a narrowed portal admits its networks" contains "$out" "tcp dport 8444 ip saddr 10.0.0.0/8 accept"
    check "firewall: a narrowed portal admits IPv6 networks" contains "$out" "tcp dport 8444 ip6 saddr fd00::/64 accept"
    check "firewall: a narrowed portal drops the rest" contains "$out" "tcp dport 8444 drop"
    check "firewall: an open portal gets no rule" lib_run PANEL_ENABLED=true -- '
        ocpanel() {
            case $1 in
                portal-port) printf "8444\n" ;;
                portal-networks) ;;
            esac
        }
        load_settings; read_portal_exposure
        [[ -z $PORTAL_FW_PORT ]]'
    out=$(lib_run -- 'load_settings
        ip6tables_fake() { printf "%s\n" "$*"; }
        PORTAL_FW_PORT=8444 PORTAL_FW_V4=(10.0.0.0/8) PORTAL_FW_V6=(fd00::/64)
        ipt_portal_rules ip6tables_fake')
    check "firewall: ip6tables admits the portal's IPv6 networks" contains "$out" \
        "-w -A VPN_INPUT -p tcp --dport 8444 -s fd00::/64 -j ACCEPT"
    check "firewall: ip6tables leaves out the portal's IPv4 networks" lacks "$out" "10.0.0.0/8"
    out=$(lib_run -- 'load_settings
        PANEL_FW_PORT=8443 PANEL_FW_V4=(127.0.0.0/8)
        BLOCKED_V4=(203.0.113.0/24 198.51.100.7/32) BLOCKED_V6=(2001:db8:4:2::/64)
        nft_filter_ruleset')
    check "firewall: blocked IPv4 networks fill their set" contains "$out" \
        "elements = { 203.0.113.0/24,198.51.100.7/32 }"
    check "firewall: blocked IPv6 networks fill their set" contains "$out" "elements = { 2001:db8:4:2::/64 }"
    check "firewall: blocked networks are dropped before the panel's port" matches "$out" \
        'ip saddr @blocked4 drop.*ip6 saddr @blocked6 drop.*tcp dport 8443'
    check "firewall: loopback is admitted before the blocklist" matches "$out" \
        'iifname "lo" accept.*ip saddr @blocked4 drop'
    out=$(lib_run -- 'load_settings; nft_filter_ruleset')
    check "firewall: an empty blocklist still declares its sets" contains "$out" "set blocked4 {"
    check "firewall: an empty set has no elements line" lacks "$out" "elements"
    check "firewall: the blocklist is split by family" lib_run PANEL_ENABLED=true -- '
        ocpanel() { [[ $1 == blocked-networks ]] && printf "%s\n" 203.0.113.0/24 2001:db8::/64 198.51.100.7/32; }
        load_settings; read_blocklist
        [[ ${BLOCKED_V4[*]} == "203.0.113.0/24 198.51.100.7/32" && ${BLOCKED_V6[*]} == "2001:db8::/64" ]]'
    check_fails "firewall: an unreadable blocklist stops the start" lib_run PANEL_ENABLED=true -- '
        ocpanel() { return 1; }
        load_settings; read_blocklist'
    out=$(lib_run -- 'load_settings
        fake_iptables() { printf "%s\n" "$*"; }
        BLOCKED_V4=(203.0.113.0/24) BLOCKED_V6=(2001:db8::/64)
        ipt_block_rules fake_iptables')
    check "firewall: iptables leaves loopback to the other rules" contains "$out" "-w -A VPN_BLOCK -i lo -j RETURN"
    check "firewall: iptables drops each blocked IPv4 network" contains "$out" \
        "-w -A VPN_BLOCK -s 203.0.113.0/24 -j DROP"
    check "firewall: iptables leaves IPv6 blocks to ip6tables" lacks "$out" "2001:db8::/64"
    out=$(lib_run -- 'load_settings
        ip6tables_fake() { printf "%s\n" "$*"; }
        BLOCKED_V4=(203.0.113.0/24) BLOCKED_V6=(2001:db8::/64)
        ipt_block_rules ip6tables_fake')
    check "firewall: ip6tables drops each blocked IPv6 network" contains "$out" \
        "-w -A VPN_BLOCK -s 2001:db8::/64 -j DROP"
    out=$(lib_run CLIENT_TO_CLIENT=true -- 'load_settings; nft_filter_ruleset')
    check "firewall: client to client allowed" contains "$out" 'iifname "vpns*" oifname "vpns*" accept'
    out=$(lib_run -- 'load_settings; nft_filter_ruleset')
    check "firewall: the site rules chain starts empty" contains "$out" "chain site_rules {"
    check "firewall: published networks have a set per family" contains "$out" "set site_closed6 {"
    check "firewall: site rules come before client isolation, closed sites before the rest" matches "$out" \
        'jump site_rules.*oifname "vpns\*" drop.*@site_closed4 drop.*@site_closed6 drop.*iifname "vpns\*" accept'
    check "firewall: no source check unless the kernel offers it" lacks "$out" "fib saddr"
    out=$(lib_run -- 'load_settings; SOURCE_CHECK=true; nft_filter_ruleset')
    check "firewall: forged tunnel sources are dropped before replies are admitted" matches "$out" \
        'ct state invalid drop.*iifname "vpns\*" fib saddr \. iif oif missing drop.*ct state established'
    check "firewall: the site part loads with the firewall and the source check" lib_run FW_BACKEND=iptables -- '
        ocpanel() { [[ $1 == site-sync && $PANEL_FIREWALL == iptables && $PANEL_SOURCE_CHECK == false ]]; }
        load_settings; load_site_rules'
    check_fails "firewall: a site part that cannot load stops the start" lib_run FW_BACKEND=nftables -- '
        ocpanel() { return 1; }
        load_settings; load_site_rules'
    check "firewall: the country rules guard the VPN's, the panel's and the portal's ports" lib_run \
        FW_BACKEND=nftables COUNTRY_RULE=Block "COUNTRIES=cn, ru" PANEL_LAN_NETWORKS=192.0.2.0/24 -- '
        ocpanel() {
            local -a ports
            read -ra ports <<<"$COUNTRY_PORTS"
            [[ $1 == country-sync && $COUNTRY_RULE == block && $COUNTRIES == "cn, ru" &&
                $COUNTRY_EXEMPT == 192.0.2.0/24 && ${ports[*]} == "4443 4443 8443 8444" ]]
        }
        load_settings; PANEL_FW_PORT=8443 PORTAL_FW_PORT=8444; load_country_rules'
    check "firewall: without COUNTRY_RULE ocpanel loads the panel's country rules" lib_run \
        FW_BACKEND=nftables -- '
        ocpanel() { [[ $1 == country-sync && -z ${COUNTRY_RULE:-} ]]; }
        load_settings; load_country_rules'
    check_fails "firewall: country rules that cannot load stop the start" lib_run \
        FW_BACKEND=nftables COUNTRY_RULE=block COUNTRIES=CN -- '
        ocpanel() { return 1; }
        load_settings; load_country_rules'
    out=$(lib_run FW_BACKEND=iptables COUNTRY_RULE=allow COUNTRIES=US -- '
        ocpanel() { echo "the country rules need nftables"; }
        load_settings; load_country_rules' 2>&1)
    check "firewall: what ocpanel says of country rules it cannot load is a warning" matches "$out" \
        '\[warn\] the country rules need nftables'
    out=$(lib_run -- '
        ocpanel() { [[ $1 == geoip-update ]] && echo "downloaded MaxMind GeoLite2 Country"; }
        load_settings; update_geoip' 2>&1)
    check "firewall: a GeoLite2 download at start is logged" matches "$out" \
        '\[info\] downloaded MaxMind GeoLite2 Country'
    out=$(lib_run -- '
        ocpanel() { echo "MaxMind GeoLite2 was not downloaded"; return 1; }
        load_settings; update_geoip' 2>&1)
    check "firewall: a GeoLite2 download that fails is a warning, not a stop" matches "$out" \
        '\[warn\] MaxMind GeoLite2 was not downloaded'
    check_fails "settings: a MaxMind license key without an account stops the start" lib_run \
        MAXMIND_LICENSE_KEY=abc_DEF_123 -- 'load_settings'
    out=$(lib_run MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY='not valid!' -- 'load_settings' 2>&1) || true
    check "settings: a refused MaxMind license key is not echoed" lacks "$out" "not valid!"
    check "settings: a mail server with TLS and a sign-in loads" lib_run \
        PANEL_SMTP_HOST=smtp.example.com PANEL_SMTP_SECURITY=TLS PANEL_SMTP_PORT=465 \
        PANEL_SMTP_USER=alerts@example.com PANEL_SMTP_PASSWORD=mail-secret-1 \
        PANEL_SMTP_FROM=alerts@example.com -- 'load_settings'
    check "settings: a plain relay without a password loads" lib_run \
        PANEL_SMTP_HOST=192.168.1.2 PANEL_SMTP_SECURITY=plain PANEL_SMTP_FROM=alerts@example.com \
        -- 'load_settings'
    check_fails "settings: a mail server variable without PANEL_SMTP_HOST stops the start" lib_run \
        PANEL_SMTP_FROM=alerts@example.com -- 'load_settings'
    check_fails "settings: a mail server without a From address stops the start" lib_run \
        PANEL_SMTP_HOST=smtp.example.com -- 'load_settings'
    check_fails "settings: an unknown mail server encryption stops the start" lib_run \
        PANEL_SMTP_HOST=smtp.example.com PANEL_SMTP_FROM=alerts@example.com \
        PANEL_SMTP_SECURITY=ssl -- 'load_settings'
    check_fails "settings: a mail server password without a user name stops the start" lib_run \
        PANEL_SMTP_HOST=smtp.example.com PANEL_SMTP_FROM=alerts@example.com \
        PANEL_SMTP_PASSWORD=mail-secret-1 -- 'load_settings'
    check_fails "settings: a mail server password over a plain connection stops the start" lib_run \
        PANEL_SMTP_HOST=192.168.1.2 PANEL_SMTP_SECURITY=plain PANEL_SMTP_FROM=alerts@example.com \
        PANEL_SMTP_USER=alerts PANEL_SMTP_PASSWORD=mail-secret-2 -- 'load_settings'
    out=$(lib_run PANEL_SMTP_HOST=192.168.1.2 PANEL_SMTP_SECURITY=plain \
        PANEL_SMTP_FROM=alerts@example.com PANEL_SMTP_USER=alerts PANEL_SMTP_PASSWORD=mail-secret-2 \
        -- 'load_settings' 2>&1) || true
    check "settings: a refused mail server password is not echoed" lacks "$out" "mail-secret-2"
    check_fails "settings: an unknown country rule stops the start" lib_run COUNTRY_RULE=deny -- 'load_settings'
    check_fails "settings: a country that is not a two-letter code stops the start" lib_run \
        COUNTRY_RULE=block COUNTRIES=CHN -- 'load_settings'
    check "settings: location checks turned on with the panel load" lib_run \
        PANEL_ENABLED=true LOCATION_CHECKS=Yes LOCATION_REFRESH_HOURS=012 -- '
        load_settings; [[ $LOCATION_CHECKS == true ]]'
    check "settings: location checks turned off load without the panel" lib_run \
        LOCATION_CHECKS=off -- 'load_settings; [[ $LOCATION_CHECKS == false ]]'
    check_fails "settings: location checks without the admin panel stop the start" lib_run \
        LOCATION_CHECKS=true -- 'load_settings'
    check_fails "settings: an unknown location checks value stops the start" lib_run \
        PANEL_ENABLED=true LOCATION_CHECKS=maybe -- 'load_settings'
    check_fails "settings: a location refresh beyond 168 hours stops the start" lib_run \
        LOCATION_REFRESH_HOURS=169 -- 'load_settings'
    check_fails "settings: a location refresh of no hours stops the start" lib_run \
        LOCATION_REFRESH_HOURS=0 -- 'load_settings'
    check_fails "settings: a location refresh with a unit stops the start" lib_run \
        LOCATION_REFRESH_HOURS=6h -- 'load_settings'
    out=$(lib_run -- 'load_settings
        fake_iptables() { printf "%s\n" "$*"; }
        GROUP_POOLS=(); ipt_family_rules fake_iptables icmp 192.168.255.0/24')
    check "firewall: iptables jumps to the site rules between tunnels" contains "$out" \
        "-w -A VPN_FORWARD -i vpns+ -o vpns+ -j VPN_SITES"
    check "firewall: iptables drops closed sites after isolation and before the rest" matches "$out" \
        'vpns\+ -o vpns\+ -j DROP.*-i vpns\+ -j VPN_SITES_CLOSED.*-i vpns\+ -j ACCEPT'
    check "firewall: iptables translates the sites let out" contains "$out" \
        "-w -t nat -A VPN_NAT -j VPN_SITES_NAT"
    out=$(lib_run -- 'load_settings
        fake_iptables() { printf "%s\n" "$*"; }
        ipt_source_check fake_iptables')
    check "firewall: iptables drops forged tunnel sources" contains "$out" \
        "-w -t raw -A VPN_SPOOF -i vpns+ -m rpfilter --invert -j DROP"
    out=$(lib_run -- 'load_settings; nft_nat_ruleset ip 192.168.255.0/24')
    check "firewall: IPv4 masquerade" contains "$out" 'ip saddr 192.168.255.0/24 oifname != "vpns*" masquerade'
    check "firewall: sites let out are translated" contains "$out" \
        'ip saddr @site_egress oifname != "vpns*" masquerade'
    out=$(lib_run -- 'load_settings; nft_nat_ruleset ip6 fd3e:7a0c:5b19::/48')
    check "firewall: the IPv6 egress set holds IPv6 networks" matches "$out" \
        'set site_egress \{[^}]*type ipv6_addr'
    out=$(lib_run NAT=false -- 'load_settings; nft_nat_ruleset ip 192.168.255.0/24')
    check "firewall: NAT off" lacks "$out" "masquerade"
    out=$(lib_run -- 'load_settings; nft_nat_ruleset ip6 ""')
    check "firewall: no IPv6 NAT without an IPv6 pool" lacks "$out" "masquerade"
    check "firewall: auto restriction in split mode" lib_run TUNNEL_MODE=split-include TUNNEL_ROUTES=10.0.0.0/8 FW_BACKEND=nftables -- '
        load_settings; resolve_route_restriction; [[ $RESTRICT_ENABLED == true ]]'
    check "firewall: no auto restriction in full tunnel" lib_run FW_BACKEND=nftables -- '
        load_settings; resolve_route_restriction; [[ $RESTRICT_ENABLED == false ]]'
    check_fails "firewall: restriction needs nftables" lib_run RESTRICT_TO_ROUTES=true FW_BACKEND=iptables -- '
        load_settings; resolve_route_restriction'
}

unit_networks() {
    check "networks: 1.x netmask form" lib_run CONF="$FIXTURES/ocserv.conf" -- '
        read_tunnel_networks "$CONF"; [[ $CONF_V4_NET == 192.168.255.0/24 && -z $CONF_V6_NET ]]'
    render "$T/net.conf" IPV6_ENABLED=true
    check "networks: rendered CIDR form" lib_run CONF="$T/net.conf" -- '
        read_tunnel_networks "$CONF"; [[ $CONF_V4_NET == 192.168.255.0/24 && $CONF_V6_NET == fd3e:7a0c:5b19::/48 ]]'
}

unit_legacy() {
    local d=$T/legacy i
    mkdir -p "$d"

    cp "$FIXTURES/ocserv.conf" "$d/rewritten.conf"
    printf '%s\n' 'dns = 8.8.8.8' 'route=192.168.1.0/255.255.255.0' 'split-dns = example.com' >>"$d/rewritten.conf"
    check "legacy: stock file plus rewritten lines is stock" lib_run F="$d/rewritten.conf" -- 'legacy_is_stock ocserv.conf "$F"'

    copy_crlf "$FIXTURES/ocserv.conf" "$d/crlf.conf"
    check "legacy: CRLF copy is stock" lib_run F="$d/crlf.conf" -- 'legacy_is_stock ocserv.conf "$F"'

    for i in 1 2 3; do printf 'tcp-port = 443\n'; done >"$d/mangled.conf"
    printf 'dns = 8.8.8.8\n' >>"$d/mangled.conf"
    check "legacy: file the 1.x port rewrite emptied is stock" lib_run F="$d/mangled.conf" -- 'legacy_is_stock ocserv.conf "$F"'

    replace_line "$FIXTURES/ocserv.conf" "$d/edited.conf" "max-clients = 0" "max-clients = 7"
    check_fails "legacy: edited file is not stock" lib_run F="$d/edited.conf" -- 'legacy_is_stock ocserv.conf "$F"'

    check "legacy: stock connect script" lib_run F="$FIXTURES/connect.sh" -- 'legacy_is_stock connect.sh "$F"'
    check_fails "legacy: kinds are not interchangeable" lib_run F="$FIXTURES/connect.sh" -- 'legacy_is_stock disconnect.sh "$F"'

    mkdir -p "$d/stock"
    cp "$FIXTURES/ocserv.conf" "$FIXTURES/connect.sh" "$d/stock/"
    printf '%s\n' '#!/bin/bash' 'logger custom' >"$d/stock/disconnect.sh"
    check "legacy: stock files retired, edited script kept" lib_run CONFIG_DIR="$d/stock" -- '
        load_settings; handle_legacy_files >/dev/null 2>&1
        [[ $LEGACY_CONFIG == false && -f $CONFIG_DIR/ocserv.conf.legacy && ! -e $CONFIG_DIR/ocserv.conf ]]
        [[ -f $CONFIG_DIR/connect.sh.legacy && -f $CONFIG_DIR/disconnect.sh ]]'

    mkdir -p "$d/edited"
    cp "$d/edited.conf" "$d/edited/ocserv.conf"
    cp "$FIXTURES/connect.sh" "$d/edited/"
    check "legacy: edited config honored and scripts left for it" lib_run CONFIG_DIR="$d/edited" -- '
        load_settings; handle_legacy_files >/dev/null 2>&1
        [[ $LEGACY_CONFIG == true && -f $CONFIG_DIR/ocserv.conf && -f $CONFIG_DIR/connect.sh ]]'

    mkdir -p "$d/power"
    cp "$FIXTURES/ocserv.conf" "$d/power/"
    check "legacy: POWER_USER leaves files alone" lib_run CONFIG_DIR="$d/power" POWER_USER=true -- '
        load_settings; handle_legacy_files; [[ -f $CONFIG_DIR/ocserv.conf && ! -e $CONFIG_DIR/ocserv.conf.legacy ]]'

    printf 'a\n' >"$d/twice"
    printf 'b\n' >"$d/twice.legacy"
    check "legacy: retire keeps an existing .legacy file" lib_run F="$d/twice" -- '
        legacy_retire "$F" >/dev/null; [[ -f $F.legacy.1 && $(<"$F.legacy") == b ]]'
}

# The session hook refuses a connecting client the admin panel's blocklist
# holds, and one whose address cannot be checked, before it logs the
# connection; without the panel it checks nothing. A stand-in ocpanel on
# PATH answers for the blocklist.
unit_session_hook() {
    local hook=$REPO/rootfs/usr/local/libexec/ocserv-docker/session-hook bin=$T/hook-bin out
    mkdir -p "$bin" "$T/hook-events"
    printf '%s\n' '#!/bin/sh' \
        'if [ "$1" = check-address ]; then' \
        '    case $2 in' \
        '        192.0.2.1) exit 0 ;;' \
        '        203.0.113.9) printf "%s\n" "the admin panel'"'"'s blocklist holds 203.0.113.0/24"; exit 1 ;;' \
        '    esac' \
        '    printf "%s\n" "ocpanel: the blocklist cannot be read" >&2' \
        '    exit 2' \
        'fi' \
        'if [ "$1" = check-user ] && [ "$2" = riley ]; then' \
        '    printf "%s\n" "riley is locked"' \
        '    exit 1' \
        'fi' \
        'if [ "$1" = check-location ]; then' \
        '    case $USERNAME in' \
        '        far) printf "%s\n" "the location checks scored the sign-in 80 of 100: a session is open 900 km away"; exit 1 ;;' \
        '        odd) printf "%s\n" "unusual for the location checks, scored 50 of 100: a network not used before (AS64500)" ;;' \
        '        broken) printf "%s\n" "the helper panicked" >&2; exit 101 ;;' \
        '    esac' \
        '    exit 0' \
        'fi' \
        'if [ "$1" = site-sync ]; then' \
        '    printf "%s\n" "$2" >>"$SYNC_LOG"' \
        '    [ -z "${SYNC_FAILS:-}" ]' \
        '    exit' \
        'fi' \
        'exit 0' >"$bin/ocpanel"
    chmod +x "$bin/ocpanel"
    local -a run=(env -i "PATH=$bin:$PATH" "CONFIG_DIR=$T/config" "PANEL_EVENTS_DIR=$T/hook-events"
        "SYNC_LOG=$T/hook-sync" REASON=connect USERNAME=alex)
    : >"$T/hook-sync"
    out=$("${run[@]}" IP_REAL=192.0.2.1 sh "$hook" 2>&1)
    check "session hook: an address off the blocklist connects" contains "$out" \
        "user alex connected from 192.0.2.1"
    check "session hook: a connect brings the site rules up to date" has_line "$T/hook-sync" connect
    check "session hook: a disconnect passes" "${run[@]}" REASON=disconnect sh "$hook"
    check "session hook: a disconnect brings the site rules up to date" has_line "$T/hook-sync" disconnect
    check "session hook: a failed site sync never refuses the session" \
        "${run[@]}" SYNC_FAILS=1 IP_REAL=192.0.2.1 sh "$hook"
    out=$("${run[@]}" SYNC_FAILS=1 IP_REAL=192.0.2.1 sh "$hook" 2>&1) || true
    check "session hook: a failed site sync is logged" contains "$out" \
        "the firewall did not take in this connect for the site-to-site rules"
    : >"$T/hook-sync"
    check_fails "session hook: an address on the blocklist is refused" \
        "${run[@]}" IP_REAL=203.0.113.9 sh "$hook"
    check "session hook: a refused client gets no site rules" lacks_line "$T/hook-sync" connect
    out=$("${run[@]}" IP_REAL=203.0.113.9 sh "$hook" 2>&1) || true
    check "session hook: the refusal names the block" contains "$out" \
        "refused user alex from 203.0.113.9: the admin panel's blocklist holds 203.0.113.0/24"
    check "session hook: a refused client is not logged as connected" lacks "$out" "connected from"
    check_fails "session hook: an address that cannot be checked is refused" \
        "${run[@]}" IP_REAL=198.51.100.7 sh "$hook"
    out=$("${run[@]}" USERNAME=riley IP_REAL=192.0.2.1 sh "$hook" 2>&1) || true
    check "session hook: a user the panel refuses is refused" contains "$out" \
        "refused user riley from 192.0.2.1: riley is locked"
    check_fails "session hook: a sign-in the location checks refuse is refused" \
        "${run[@]}" USERNAME=far IP_REAL=192.0.2.1 sh "$hook"
    out=$("${run[@]}" USERNAME=far IP_REAL=192.0.2.1 sh "$hook" 2>&1) || true
    check "session hook: the location refusal is logged with its reasons" contains "$out" \
        "refused user far from 192.0.2.1: the location checks scored the sign-in 80 of 100"
    check "session hook: a location refusal is not logged as connected" lacks "$out" \
        "connected from"
    out=$("${run[@]}" USERNAME=odd IP_REAL=192.0.2.1 sh "$hook" 2>&1)
    check "session hook: an unusual sign-in connects" contains "$out" \
        "user odd connected from 192.0.2.1"
    check "session hook: an unusual sign-in is logged with its reasons" contains "$out" \
        "user odd from 192.0.2.1: unusual for the location checks, scored 50 of 100"
    out=$("${run[@]}" USERNAME=broken IP_REAL=192.0.2.1 sh "$hook" 2>&1)
    check "session hook: a location check that fails lets the client in" contains "$out" \
        "user broken connected from 192.0.2.1"
    check "session hook: a location check that fails is logged" contains "$out" \
        "user broken from 192.0.2.1 was let in without a location check, which failed: the helper panicked"
    check "session hook: without the panel nothing is checked" env -i "PATH=$bin:$PATH" \
        "CONFIG_DIR=$T/config" REASON=connect USERNAME=alex IP_REAL=198.51.100.7 sh "$hook"
    rm -rf -- "$bin" "$T/hook-events"
}

run_unit() {
    local unit
    note "unit tests with $(bash --version | head -n 1)"
    for unit in unit_render_defaults unit_render_ipv6 unit_render_split unit_render_overrides \
        unit_render_auth unit_render_extra_config unit_panel_settings unit_group_pools \
        unit_session_hook unit_validation unit_helpers unit_firewall unit_networks unit_legacy; do
        section "$unit"
    done
}

readonly CLIENT_IMAGE=alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
readonly DEBIAN_CLIENT_IMAGE=debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
readonly SMOKE_ID=ocsmoke$$
readonly SMOKE_NET=$SMOKE_ID-net
# A documentation range of RFC 5737, which belongs to no country and to no
# private range, for a client the country rules judge. docker-sftp's tests
# take 198.51.100.0/24 on the same test host, and podman lets one network
# hold a subnet at a time.
readonly FAR_NET=$SMOKE_ID-far
readonly FAR_SUBNET=203.0.113.0/24
readonly SMOKE_USER=smoke
readonly SMOKE_PASS=smoke-password-1
readonly VPN_ADDRESS_RE='^192\.168\.255\.[0-9]+$'

select_engine() {
    if [[ -n ${CONTAINER_ENGINE:-} ]]; then
        ENGINE=$CONTAINER_ENGINE
    elif command -v podman >/dev/null 2>&1; then
        ENGINE=podman
    else
        ENGINE=docker
    fi
    command -v "$ENGINE" >/dev/null 2>&1 || {
        printf 'no container engine: %s not found\n' "$ENGINE" >&2
        exit 2
    }
}

# The flags docker-compose.yml uses, so the smoke test runs the documented
# hardened configuration. podman mounts tmpfs on /run and /tmp itself when
# the root file system is read-only.
server_flags() {
    SERVER_FLAGS=(
        --cap-drop ALL
        --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add KILL
        --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add NET_RAW
        --cap-add SETGID --cap-add SETUID
        --security-opt no-new-privileges:true
        --read-only
        --device /dev/net/tun
        --sysctl net.ipv4.ip_forward=1
        --sysctl net.ipv6.conf.all.forwarding=1
        --sysctl net.ipv6.conf.all.disable_ipv6=0
        --sysctl net.ipv6.conf.default.disable_ipv6=0
    )
    if [[ $ENGINE != podman ]]; then
        SERVER_FLAGS+=(--tmpfs /run --tmpfs /tmp)
    fi
}

smoke_cleanup() {
    local name
    for name in $("$ENGINE" ps -a --format '{{.Names}}' 2>/dev/null); do
        [[ $name == "$SMOKE_ID"-* ]] && "$ENGINE" rm -f "$name" >/dev/null 2>&1
    done
    for name in $("$ENGINE" volume ls --format '{{.Name}}' 2>/dev/null); do
        [[ $name == "$SMOKE_ID"-* ]] && "$ENGINE" volume rm -f "$name" >/dev/null 2>&1
    done
    "$ENGINE" network rm "$SMOKE_NET" >/dev/null 2>&1
    "$ENGINE" network inspect "$FAR_NET" >/dev/null 2>&1 && "$ENGINE" network rm "$FAR_NET" >/dev/null 2>&1
    return 0
}

# start_server <name> [<var>=<value>...] starts the image on a fresh config
# volume, unless the volume <name>-config already exists, which is then reused.
start_server() {
    local name=$SMOKE_ID-$1 var
    local -a envs=(-e "SRV_CN=$name")
    shift
    for var in "$@"; do
        envs+=(-e "$var")
    done
    "$ENGINE" volume inspect "$name-config" >/dev/null 2>&1 || "$ENGINE" volume create "$name-config" >/dev/null
    "$ENGINE" run -d --name "$name" --hostname "$name" --network "$SMOKE_NET" \
        "${SERVER_FLAGS[@]}" -v "$name-config:/config" "${envs[@]}" "$IMAGE" >/dev/null
}

stop_server() {
    "$ENGINE" rm -f "$SMOKE_ID-$1" >/dev/null 2>&1
    return 0
}

# Waits until occtl reaches the server, printing progress every 10 seconds.
wait_ready() {
    local name=$SMOKE_ID-$1 i state
    for i in $(seq 1 90); do
        if "$ENGINE" exec "$name" occtl show status >/dev/null 2>&1; then
            return 0
        fi
        state=$("$ENGINE" inspect -f '{{.State.Status}}' "$name" 2>/dev/null || printf 'missing')
        if [[ $state != running ]]; then
            printf 'container %s is %s\n' "$name" "$state"
            "$ENGINE" logs "$name" 2>&1
            return 1
        fi
        ((i % 10 == 0)) && note "waiting for $name: ${i} s, state $state" >&2
        sleep 1
    done
    printf '%s did not answer occtl within 90 s\n' "$name"
    "$ENGINE" logs "$name" 2>&1
    return 1
}

server_logs() { "$ENGINE" logs "$SMOKE_ID-$1" 2>&1; }

server_exec() {
    local name=$SMOKE_ID-$1
    shift
    "$ENGINE" exec "$name" "$@"
}

# add_user <server> creates the test user through ocpasswd's standard input.
add_user() {
    printf '%s\n' "$SMOKE_PASS" | "$ENGINE" exec -i "$SMOKE_ID-$1" ocpasswd -c /config/ocpasswd "$SMOKE_USER"
}

# add_named_user <server> <name> [<group>] creates a user with the test
# password, in the group when one is given.
add_named_user() {
    local -a group=()
    [[ -n ${3:-} ]] && group=(-g "$3")
    printf '%s\n' "$SMOKE_PASS" | "$ENGINE" exec -i "$SMOKE_ID-$1" ocpasswd -c /config/ocpasswd "${group[@]}" "$2"
}

# start_client <name> [debian] starts a client container: Alpine, whose
# openconnect is built with OpenSSL, or Debian, whose openconnect is built with
# GnuTLS like most distributions' packages.
start_client() {
    local name=$SMOKE_ID-$1 kind=${2:-alpine} image=$CLIENT_IMAGE
    [[ $kind == debian ]] && image=$DEBIAN_CLIENT_IMAGE
    "$ENGINE" run -d --name "$name" --network "$SMOKE_NET" --cap-add NET_ADMIN \
        --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        --sysctl net.ipv6.conf.default.disable_ipv6=0 "$image" sleep 3600 >/dev/null
    if [[ $kind == debian ]]; then
        "$ENGINE" exec -e DEBIAN_FRONTEND=noninteractive "$name" sh -c \
            'apt-get update -qq && apt-get install -y -qq --no-install-recommends openconnect openssl iproute2 procps ca-certificates >/dev/null'
    else
        "$ENGINE" exec "$name" apk add --no-cache --quiet openconnect openssl curl iproute2 oath-toolkit-oathtool
    fi
}

client_exec() {
    local name=$SMOKE_ID-$1
    shift
    "$ENGINE" exec "$name" "$@"
}

# start_far_client <name> <address> starts an Alpine client at the address on
# FAR_NET, which it creates when missing.
start_far_client() {
    local name=$SMOKE_ID-$1
    "$ENGINE" network inspect "$FAR_NET" >/dev/null 2>&1 ||
        "$ENGINE" network create --subnet "$FAR_SUBNET" "$FAR_NET" >/dev/null || return 1
    "$ENGINE" run -d --name "$name" --network "$FAR_NET" --ip "$2" --cap-add NET_ADMIN \
        --device /dev/net/tun "$CLIENT_IMAGE" sleep 3600 >/dev/null || return 1
    "$ENGINE" exec "$name" apk add --no-cache --quiet openconnect openssl curl iproute2
}

# attach_far <server> <address> attaches a running server to FAR_NET at the
# address.
attach_far() {
    "$ENGINE" network connect --ip "$2" "$FAR_NET" "$SMOKE_ID-$1"
}

# pin_of <server> <client> prints the server key's pin-sha256 value, computed
# by the client with openssl from the server's certificate.
pin_of() {
    "$ENGINE" exec "$SMOKE_ID-$1" cat /config/certs/server-cert.pem \
        | "$ENGINE" exec -i "$SMOKE_ID-$2" sh -c \
            'openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64'
}

# Prints a server container's address on the smoke network. Clients connect
# by address, so the checks do not depend on the engine's container DNS.
server_ip() {
    "$ENGINE" inspect -f "{{(index .NetworkSettings.Networks \"$SMOKE_NET\").IPAddress}}" "$SMOKE_ID-$1"
}

# connect <client> <server> [<url suffix> [<totp secret> [<user> [<password>]]]]
# starts openconnect in the client with the server's key pin, and prints the
# tunnel's IPv4 address once tun0 has one. With a secret, in hex or as
# "--base32 <key>", the client computes the current code with oathtool and
# sends it after the password. openconnect runs as a detached exec writing
# /tmp/openconnect.log, which is printed on failure. The client dials VIA
# when it is set, such as a load balancer in front of the server, and the
# tunnel's address must match ADDRESS_RE when it is set, else the pool's.
# With CLIENT_CERT set, the client presents CLIENT_CERT-cert.pem and its key
# CLIENT_CERT-key.pem; CLIENT_OPTIONS adds openconnect options as they stand.
connect() {
    local client=$1 server=$2 suffix=${3:-} secret=${4:-} user=${5:-$SMOKE_USER} pass=${6:-$SMOKE_PASS}
    local pin ip i line addr input pattern=${ADDRESS_RE:-$VPN_ADDRESS_RE} cert=""
    pin=$(pin_of "$server" "$client")
    ip=${VIA:-$(server_ip "$server")}
    input="printf '%s\n' '$pass'"
    if [[ -n $secret ]]; then
        input="printf '%s\n%s\n' '$pass' \"\$(oathtool --totp $secret)\""
    fi
    if [[ -n ${CLIENT_CERT:-} ]]; then
        cert="--certificate='$CLIENT_CERT-cert.pem' --sslkey='$CLIENT_CERT-key.pem'"
    fi
    "$ENGINE" exec -d "$SMOKE_ID-$client" sh -c "$input | openconnect --passwd-on-stdin \
        --user='$user' --servercert='pin-sha256:$pin' --interface=tun0 $cert ${CLIENT_OPTIONS:-} \
        'https://$ip:4443/$suffix' >/tmp/openconnect.log 2>&1" >/dev/null
    for i in $(seq 1 30); do
        if line=$(client_exec "$client" ip -4 -o addr show dev tun0 2>/dev/null) && [[ -n $line ]]; then
            read -r _ _ _ addr _ <<<"$line"
            addr=${addr%/*}
            if [[ $addr =~ $pattern ]]; then
                printf '%s\n' "$addr"
                return 0
            fi
        fi
        if ! client_exec "$client" pgrep -x openconnect >/dev/null 2>&1 && ((i > 2)); then
            break
        fi
        sleep 1
    done
    printf 'no tunnel to %s (%s) after %s s. openconnect log:\n' "$server" "$ip" "$i"
    client_exec "$client" cat /tmp/openconnect.log 2>&1
    return 1
}

# connect_expecting <pattern> <client> <server> connects the client to the
# server as connect does, waiting for a tunnel address that matches the
# pattern, such as one from a group's own pool.
connect_expecting() {
    local ADDRESS_RE=$1
    shift
    connect "$@"
}

# connect_with_cert <prefix> <client> <server> [...] connects as connect does,
# presenting the client's <prefix>-cert.pem and <prefix>-key.pem.
connect_with_cert() {
    local CLIENT_CERT=$1
    shift
    connect "$@"
}

# connect_with_options <options> <client> <server> [...] connects as connect
# does, with more openconnect options, such as a key file and its passphrase.
connect_with_options() {
    local CLIENT_OPTIONS=$1
    shift
    connect "$@"
}

# issue_client_cert <server> <client> <user> <prefix> issues a certificate for
# the user from the server's client CA with certtool in the server, keeps it
# as the server's /tmp/<user>-cert.pem, and copies it and its key into the
# client as <prefix>-cert.pem and <prefix>-key.pem.
issue_client_cert() {
    local server=$1 client=$2 user=$3 prefix=$4 part
    server_exec "$server" sh -c '
        set -e
        certtool --generate-privkey --key-type=ecdsa --curve=secp256r1 --outfile "/tmp/$0-key.pem" 2>/dev/null
        printf "uid = \"%s\"\ncn = \"%s\"\nexpiration_days = 1\nsigning_key\ntls_www_client\n" "$0" "$0" >"/tmp/$0.tmpl"
        certtool --generate-certificate --load-privkey "/tmp/$0-key.pem" \
            --load-ca-certificate /config/certs/client-ca.pem \
            --load-ca-privkey /config/certs/client-ca-key.pem \
            --template "/tmp/$0.tmpl" --outfile "/tmp/$0-cert.pem" >/dev/null 2>&1' "$user" || return 1
    for part in cert key; do
        server_exec "$server" cat "/tmp/$user-$part.pem" |
            "$ENGINE" exec -i "$SMOKE_ID-$client" sh -c "cat > '$prefix-$part.pem'" || return 1
    done
}

# revoke_client_cert <server> <user> revokes the certificate issue_client_cert
# last made for the user, writes the revocation list again and has ocserv
# load it.
revoke_client_cert() {
    server_exec "$1" sh -c 'cp "/tmp/$0-cert.pem" "/config/certs/client-revoked/$0.pem" &&
        /usr/local/libexec/ocserv-docker/client-crl /config/certs && occtl reload' "$2"
}

# connect_via <address> <client> <server> connects the client to the server
# through the address, as connect does.
connect_via() {
    local VIA=$1
    shift
    connect "$@"
}

# Ends the client's session and waits up to 20 s for tun0 to go away.
disconnect() {
    client_exec "$1" sh -c '
        pkill -x openconnect
        i=0
        while [ -e /sys/class/net/tun0 ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done
        [ ! -e /sys/class/net/tun0 ]'
}

# guess_until_banned <client> <server> signs in from the client with wrong
# passwords, up to 10 times, until the server's ban list holds the client's
# address. Each sign-in gives a wrong password at all three of ocserv's
# prompts, so ocserv refuses it and logs the refusal; a client that gives up
# after one wrong password adds ban points but leaves no line in the log.
guess_until_banned() {
    local client=$1 server=$2 pin ip address i bans
    pin=$(pin_of "$server" "$client")
    ip=$(server_ip "$server")
    address=$(server_ip "$client")
    for i in $(seq 1 10); do
        if client_exec "$client" sh -c "printf '%s\n' wrong-1 wrong-2 wrong-3 | timeout 20 openconnect \
            --passwd-on-stdin --user='$SMOKE_USER' --servercert='pin-sha256:$pin' \
            'https://$ip:4443/' >/dev/null 2>&1"; then
            printf 'a wrong password connected on attempt %s\n' "$i"
            return 1
        fi
        bans=$(server_exec "$server" occtl --json show ip bans 2>&1)
        if [[ $bans == *"\"$address\""* ]]; then
            return 0
        fi
    done
    printf 'no ban for %s after %s wrong passwords; occtl lists:\n%s\n' "$address" "$i" "$bans"
    return 1
}

# dtls_cipher <server> <vpn address> prints the DTLS cipher occtl reports for
# the session with that address, which is "(no-dtls)" while it has none.
dtls_cipher() {
    local vpn_ip cipher
    while read -r _ _ _ _ vpn_ip _ _ cipher _; do
        if [[ $vpn_ip == "$2" ]]; then
            printf '%s\n' "$cipher"
            return 0
        fi
    done < <(server_exec "$1" occtl show users 2>&1)
    printf 'no session with VPN address %s\n' "$2"
    return 1
}

# has_dtls <server> <vpn address> waits up to 20 s for the session to report
# a DTLS cipher, and prints it.
has_dtls() {
    local i cipher=""
    for i in $(seq 1 20); do
        if cipher=$(dtls_cipher "$1" "$2") && [[ $cipher != "(no-dtls)" ]]; then
            printf '%s\n' "$cipher"
            return 0
        fi
        sleep 1
    done
    printf 'no DTLS cipher after 20 s (last: %s)\n' "$cipher"
    server_exec "$1" occtl show users 2>&1
    return 1
}

# Prints how many lines of the text equal the wanted line.
count_lines() {
    local line n=0
    while IFS= read -r line; do
        [[ $line == "$2" ]] && n=$((n + 1))
    done <<<"$1"
    printf '%s\n' "$n"
}

# print_sample <title> <command>... prints the command's output, each line
# marked, for copying real output into the documentation.
print_sample() {
    local title=$1 line
    shift
    printf 'sample> %s\n' "$title"
    while IFS= read -r line; do
        printf 'sample| %s\n' "$line"
    done < <("$@" 2>&1)
}

route_dev() {
    local client=$1 family=$2 address=$3
    client_exec "$client" ip "$family" route get "$address" 2>&1
}

# holds_address <text> <address> passes when the text holds the address as a
# whole, not as the start of a longer one.
holds_address() {
    local whole="(^|[^0-9.])${2//./\\.}([^0-9]|$)"
    [[ $1 =~ $whole ]] || {
        printf 'no address %s in: %s\n' "$2" "$1"
        return 1
    }
}

smoke_tunnel() {
    local addr1 addr2 addr3 out
    start_server main
    check "server: starts with the hardened flags" wait_ready main
    check "server: ocpasswd adds a user from standard input" add_user main
    out=$(server_logs main)
    check "server: IPv6 leak protection on" contains "$out" "IPv6 on (fd3e:7a0c:5b19::/48)"
    check "server: nftables firewall" contains "$out" "firewall: nftables"
    out=$(server_exec main nft list table inet vpn_gateway 2>&1)
    check "server: forward policy drop loaded" contains "$out" "policy drop"
    out=$(server_exec main ocpanel check-config 2>&1)
    check "panel: passkeys bind to the server name" contains "$out" \
        "passkeys: available, bound to $SMOKE_ID-main"
    check_fails "panel: off by default, no ocpanel process" server_exec main pgrep -x ocpanel

    start_client c1
    start_client c2
    if addr1=$(connect c1 main); then
        pass "client: connects with a key pin"
    else
        fail "client: connects with a key pin" "$addr1$(printf '\n')$(server_logs main)"
        return 1
    fi
    check "client: VPN address from the pool" matches "$addr1" "$VPN_ADDRESS_RE"
    check "server: logs the key pin the client computes" contains "$(server_logs main)" \
        "server key pin for clients: pin-sha256:$(pin_of main c1)"
    out=$(client_exec c1 ip -6 -o addr show dev tun0 2>&1)
    check "client: IPv6 tunnel address" contains "$out" "fd3e:7a0c:5b19:"
    check "client: IPv4 internet routed into the tunnel" contains "$(route_dev c1 -4 1.1.1.1)" "dev tun0"
    check "client: IPv6 internet routed into the tunnel" contains "$(route_dev c1 -6 2606:4700:4700::1111)" "dev tun0"
    check "client: server tunnel address answers ping" client_exec c1 ping -c 2 -W 3 192.168.255.1
    out=$(server_exec main occtl show user "$SMOKE_USER" 2>&1)
    check "server: pushes Quad9 DNS" contains "$out" "9.9.9.9"
    check "server: logs the connection" contains "$(server_logs main)" "user $SMOKE_USER connected"
    if [[ ${SMOKE_INTERNET:-1} == 1 ]]; then
        check "client: HTTPS through the tunnel" client_exec c1 curl -fsS -m 20 -o /dev/null https://1.1.1.1/
        check "client: DNS through the tunnel" client_exec c1 nslookup example.com 9.9.9.9
    fi
    note "OpenSSL-built client's DTLS cipher: $(dtls_cipher main "$addr1" 2>&1)"

    if addr2=$(connect c2 main); then
        pass "client: second session for the same user"
    else
        fail "client: second session for the same user" "$addr2"
        return 1
    fi
    check "client: second session's VPN address from the pool" matches "$addr2" "$VPN_ADDRESS_RE"
    check "isolation: control, second client reaches the server" client_exec c2 ping -c 2 -W 3 192.168.255.1
    if [[ $addr1 =~ $VPN_ADDRESS_RE && $addr1 != "$addr2" ]]; then
        check_fails "isolation: second client cannot reach the first" client_exec c2 ping -c 2 -W 3 "$addr1"
    else
        fail "isolation: second client cannot reach the first" "no distinct VPN address to probe: '$addr1' and '$addr2'"
    fi

    start_client c3 debian
    if addr3=$(connect c3 main); then
        pass "client: GnuTLS-built openconnect connects"
        check "client: GnuTLS-built openconnect gets the UDP channel" has_dtls main "$addr3"
    else
        fail "client: GnuTLS-built openconnect connects" "$addr3"
    fi
    check "server: every worker sets up its signal stack" lacks "$(server_logs main)" "sigaltstack"
    check_fails "server: the image holds no package manager" server_exec main sh -c 'command -v apk'
    check_fails "server: the image holds no OpenSSL" server_exec main sh -c 'ls /usr/lib/libssl.so.3 /usr/lib/libcrypto.so.3'

    if [[ ${SMOKE_SAMPLES:-0} == 1 ]]; then
        print_sample "server log" server_logs main
        print_sample "occtl show status" server_exec main occtl show status
        print_sample "occtl show users" server_exec main occtl show users
        print_sample "occtl show user" server_exec main occtl show user "$SMOKE_USER"
        print_sample "occtl --json show users" server_exec main occtl --json show users
        print_sample "occtl show ip bans" server_exec main occtl show ip bans
    fi

    disconnect c3 >/dev/null 2>&1
    disconnect c2 >/dev/null
    sleep 2
    check "server: logs the disconnection" contains "$(server_logs main)" "user $SMOKE_USER disconnected after"
    disconnect c1 >/dev/null

    local before after
    before=$(server_exec main sha256sum /config/certs/server-cert.pem)
    "$ENGINE" restart "$SMOKE_ID-main" >/dev/null
    check "restart: server comes back" wait_ready main
    after=$(server_exec main sha256sum /config/certs/server-cert.pem)
    check "restart: certificate kept" test "$before" == "$after"
    out=$(server_exec main nft list tables 2>&1)
    check "restart: firewall table loaded once" test "$(count_lines "$out" "table inet vpn_gateway")" == 1
    stop_server main
}

smoke_split() {
    local out
    start_server split TUNNEL_MODE=split-include TUNNEL_ROUTES=10.99.0.0/16
    check "split: server starts" wait_ready split || return 1
    check "split: user added" add_user split
    if out=$(connect c1 split); then
        pass "split: client connects"
    else
        fail "split: client connects" "$out"
        return 1
    fi
    check "split: listed route goes into the tunnel" contains "$(route_dev c1 -4 10.99.1.1)" "dev tun0"
    check "split: DNS servers go into the tunnel" contains "$(route_dev c1 -4 9.9.9.9)" "dev tun0"
    check "split: other traffic stays outside" lacks "$(route_dev c1 -4 203.0.113.1)" "dev tun0"
    out=$(server_exec split nft list tables 2>&1)
    check "split: ocserv restricts the client to its routes" contains "$out" "table inet ocserv_vpns"
    disconnect c1 >/dev/null
    stop_server split
}

smoke_camouflage() {
    local code out
    start_server hidden CAMOUFLAGE_SECRET=smokesecret
    check "camouflage: server starts" wait_ready hidden || return 1
    check "camouflage: user added" add_user hidden
    code=$(client_exec c1 curl -sk -o /dev/null -w '%{http_code}' "https://$(server_ip hidden):4443/" 2>&1)
    check "camouflage: answers 404 without the secret" test "$code" == 404
    if out=$(connect c1 hidden "?smokesecret"); then
        pass "camouflage: client with the secret connects"
    else
        fail "camouflage: client with the secret connects" "$out"
    fi
    disconnect c1 >/dev/null
    stop_server hidden
}

# seed_volume <name> copies the files in the seed folder into the server's
# config volume.
seed_volume() {
    local volume=$SMOKE_ID-$1-config
    "$ENGINE" volume create "$volume" >/dev/null
    "$ENGINE" run --rm -v "$volume:/config" -v "$T/seed:/seed:ro" "$CLIENT_IMAGE" \
        sh -c 'cp /seed/* /config/' >/dev/null
}

smoke_upgrades() {
    local out
    mkdir -p "$T/seed"
    cp "$FIXTURES/ocserv.conf" "$FIXTURES/connect.sh" "$FIXTURES/disconnect.sh" "$T/seed/"
    printf '%s\n' 'dns = 8.8.8.8' 'dns = 8.8.4.4' >>"$T/seed/ocserv.conf"
    seed_volume stock
    start_server stock
    check "upgrade: stock 1.x config starts" wait_ready stock
    out=$(server_exec stock ls /config 2>&1)
    check "upgrade: stock ocserv.conf renamed" contains "$out" "ocserv.conf.legacy"
    check "upgrade: stock connect.sh renamed" contains "$out" "connect.sh.legacy"
    check "upgrade: environment configuration in use" contains "$(server_logs stock)" "configuration: /run/ocserv/ocserv.conf"
    stop_server stock

    rm -f -- "$T/seed/"*
    replace_line "$FIXTURES/ocserv.conf" "$T/seed/ocserv.conf" "max-clients = 0" "max-clients = 7"
    cp "$FIXTURES/connect.sh" "$FIXTURES/disconnect.sh" "$T/seed/"
    seed_volume edited
    start_server edited
    check "upgrade: hand-edited 1.x config starts" wait_ready edited
    out=$(server_logs edited)
    check "upgrade: hand-edited config used as it stands" contains "$out" "configuration: /config/ocserv.conf"
    check "upgrade: hand-edited config warned about" contains "$out" "edited by hand"
    stop_server edited

    start_server power POWER_USER=true
    check "upgrade: POWER_USER without a config starts" wait_ready power
    out=$(server_exec power head -n 1 /config/ocserv.conf 2>&1)
    check "upgrade: POWER_USER config written once" contains "$out" "POWER_USER=true"
    stop_server power
}

smoke_otp() {
    local out secret=3132333435363738393031323334353637383930
    mkdir -p "$T/seed"
    rm -f -- "$T/seed/"*
    printf 'HOTP/T30 %s - %s\n' "$SMOKE_USER" "$secret" >"$T/seed/users.oath"
    seed_volume otp
    start_server otp
    check "otp: server starts" wait_ready otp || return 1
    check "otp: user added" add_user otp
    out=$(server_exec otp cat /run/ocserv/ocserv.conf 2>&1)
    check "otp: one-time-password file in the login" contains "$out" "otp=/config/users.oath"
    check_fails "otp: a code from the wrong secret is refused" connect c1 otp "" 00112233445566778899aabbccddeeff00112233
    check "otp: the refusal came from the code check" contains "$(server_logs otp)" "OTP auth failed for '$SMOKE_USER'"
    disconnect c1 >/dev/null 2>&1
    if out=$(connect c1 otp "" "$secret"); then
        pass "otp: password and code accepted"
        disconnect c1 >/dev/null
    else
        fail "otp: password and code accepted" "$out"
    fi
    stop_server otp
}

# The panel while ocserv asks every user for a code: a user added there gets
# an authenticator key on the onboarding kit and connects with the password
# and a code from it, and resetting the key in the panel makes the old key
# fail and the new one work. The panel changes the one-time password file the
# way liboath does, so the file ocserv rewrites after each sign-in stays whole.
smoke_panel_codes() {
    local out i once csrf generated key old_key ip admitted base=https://$SMOKE_ID-codes:8443
    local new_password=smoke-codes-password-1 secret=3132333435363738393031323334353637383930
    admitted=$(server_ip c1)
    mkdir -p "$T/seed"
    rm -f -- "$T/seed/"*
    printf 'HOTP/T30 %s - %s\n' "$SMOKE_USER" "$secret" >"$T/seed/users.oath"
    seed_volume codes
    start_server codes PANEL_ENABLED=true "PANEL_LAN_NETWORKS=$admitted/32"
    check "codes: server starts with the panel on" wait_ready codes || return 1
    for i in $(seq 1 20); do
        out=$(server_logs codes)
        [[ $out == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    once=${out##*one-time password: }
    once=${once%% *}
    ip=$(server_ip codes)
    local -a web=(client_exec c1 curl -sS -m 20 --cacert /tmp/codes-ca.pem
        --resolve "$SMOKE_ID-codes:8443:$ip" -b /tmp/codes.jar -c /tmp/codes.jar)
    server_exec codes cat /config/certs/ca.pem | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'cat > /tmp/codes-ca.pem'
    client_exec c1 cp /dev/null /tmp/codes.jar
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode name=admin \
        --data-urlencode "password=$once" "$base/login" >/dev/null 2>&1
    out=$("${web[@]}" "$base/password" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode "csrf=$csrf" \
        --data-urlencode "current=$once" --data-urlencode "new=$new_password" \
        --data-urlencode "repeat=$new_password" "$base/password" >/dev/null 2>&1
    out=$("${web[@]}" "$base/users" 2>&1)
    check "codes: the VPN users page says new users get a key" contains "$out" \
        "so the new user also gets an authenticator key"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode change=add \
        --data-urlencode name=kit-user --data-urlencode password_choice=generate \
        --data-urlencode groups= "$base/users/change" 2>&1)
    check "codes: the kit gives a new user an authenticator key" contains "$out" "Or type this key"
    generated=${out#*id=\"kit-password\">}
    generated=${generated%%<*}
    key=${out#*class=\"mono key-text\">}
    key=${key%%<*}
    key=${key// /}
    if out=$(connect c1 codes "" "--base32 $key" kit-user "$generated"); then
        pass "codes: the new user connects with the password and a code from the kit's key"
    else
        fail "codes: the new user connects with the password and a code from the kit's key" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode change=reset_otp \
        --data-urlencode name=kit-user "$base/users/change" 2>&1)
    old_key=$key
    key=${out#*class=\"mono key-text\">}
    key=${key%%<*}
    key=${key// /}
    check "codes: resetting the authenticator gives a new key" test "$key" != "$old_key"
    check_fails "codes: the replaced key is refused" connect c1 codes "" "--base32 $old_key" kit-user "$generated"
    disconnect c1 >/dev/null 2>&1
    if out=$(connect c1 codes "" "--base32 $key" kit-user "$generated"); then
        pass "codes: the new key connects"
    else
        fail "codes: the new key connects" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    out=$(server_exec codes sh -c 'stat -c "%a" /config/users.oath; cat /config/users.oath; ls -A /config' 2>&1)
    check "codes: the one-time password file stays private" matches "$out" '^600'
    check "codes: the file keeps the other user's secret" contains "$out" "HOTP/T30 $SMOKE_USER - $secret"
    check "codes: no lock or half-written copy is left" lacks "$out" "users.oath."
    out=$(server_exec codes cat /config/panel/audit.log 2>&1)
    check "codes: audit log records the new key" contains "$out" "gave kit-user a new authenticator key"
    stop_server codes
}

# The VPN user portal while ocserv asks every user for a code: a user with a
# key signs in with the password and a code and sees how to connect; a user
# without one signs in to a session that can only set up a key, sets one up
# with a code from it, and connects to the VPN with it. Wrong passwords from
# an address lock it out of the portal.
smoke_portal() {
    local out i ip csrf key code base=https://$SMOKE_ID-portal:8444
    local secret=3132333435363738393031323334353637383930
    local new_user=portal-new new_pass=portal-new-password-1 changed_pass=smoke-portal-password-2
    mkdir -p "$T/seed"
    rm -f -- "$T/seed/"*
    printf 'HOTP/T30 %s - %s\n' "$SMOKE_USER" "$secret" >"$T/seed/users.oath"
    seed_volume portal
    start_server portal PANEL_ENABLED=true PANEL_PORTAL_ENABLED=true PANEL_LOGIN_MAX_FAILURES=3
    check "portal: server starts with the portal on" wait_ready portal || return 1
    for i in $(seq 1 20); do
        out=$(server_logs portal)
        [[ $out == *"panel: serving the VPN user portal on port 8444"* ]] && break
        sleep 1
    done
    check "portal: the web process serves the portal" contains "$out" \
        "panel: serving the VPN user portal on port 8444"
    check "portal: user added" add_user portal
    check "portal: ocpasswd stores a SHA-256-crypt hash" contains \
        "$(server_exec portal cat /config/ocpasswd 2>&1)" "$SMOKE_USER:*:\$5\$"
    printf '%s\n' "$new_pass" | "$ENGINE" exec -i "$SMOKE_ID-portal" ocpasswd -c /config/ocpasswd "$new_user"
    ip=$(server_ip portal)
    local -a web=(client_exec c1 curl -sS -m 20 --cacert /tmp/portal-ca.pem
        --resolve "$SMOKE_ID-portal:8444:$ip" -b /tmp/portal.jar -c /tmp/portal.jar)
    server_exec portal cat /config/certs/ca.pem | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'cat > /tmp/portal-ca.pem'
    client_exec c1 cp /dev/null /tmp/portal.jar
    out=$("${web[@]}" "$base/login" 2>&1)
    check "portal: sign-in page served over verified https" contains "$out" \
        "Use the same user name and password as for the VPN."
    out=$("${web[@]}" -o /dev/null -w '%{http_code}' -H "Host: elsewhere.example" "$base/login" 2>&1)
    check "portal: another host name refused" test "$out" == 421
    out=$("${web[@]}" -o /dev/null -w '%{http_code}' -H "Origin: https://elsewhere.example" \
        --data-urlencode "name=$SMOKE_USER" --data-urlencode "password=$SMOKE_PASS" "$base/login" 2>&1)
    check "portal: a sign-in posted from another site refused" test "$out" == 403
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "name=$SMOKE_USER" --data-urlencode "password=$SMOKE_PASS" "$base/login" 2>&1)
    check "portal: the password of a user with a key asks for a code" test "$out" == "303 $base/code"
    code=$(client_exec c1 oathtool --totp 00112233445566778899aabbccddeeff00112233)
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "code=$code" "$base/code" 2>&1)
    check "portal: a wrong code sends the user back to the password" contains "$out" \
        "That code did not sign in. Sign in again with your password."
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode "name=$SMOKE_USER" \
        --data-urlencode "password=$SMOKE_PASS" "$base/login" >/dev/null 2>&1
    code=$(client_exec c1 oathtool --totp "$secret")
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "code=$code" "$base/code" 2>&1)
    check "portal: the password and a code sign in" test "$out" == "303 $base/"
    out=$("${web[@]}" "$base/" 2>&1)
    check "portal: the home page shows how to connect" contains "$out" "Connect to the VPN"
    check "portal: the home page gives the server key's pin" contains "$out" "pin-sha256:$(pin_of portal c1)"
    out=$("${web[@]}" "$base/account" 2>&1)
    check "portal: the account page offers a password change" contains "$out" "Change password"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" \
        --data-urlencode "current=$SMOKE_PASS" --data-urlencode "new=short-pass" \
        --data-urlencode "repeat=short-pass" "$base/account/password" 2>&1)
    check "portal: a short new password is refused" contains "$out" "at least 12 characters"
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "current=$SMOKE_PASS" \
        --data-urlencode "new=$changed_pass" --data-urlencode "repeat=$changed_pass" \
        "$base/account/password" 2>&1)
    check "portal: the user changes their password" test "$out" == "303 $base/account?done=password"
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" -d '' "$base/logout" 2>&1)
    check "portal: sign out" test "$out" == "303 $base/login"
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' "$base/" 2>&1)
    check "portal: signed out, the home page sends to the sign-in page" test "$out" == "303 $base/login"
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "name=$SMOKE_USER" \
        --data-urlencode "password=$SMOKE_PASS" "$base/login" 2>&1)
    check "portal: the old password no longer signs in" contains "$out" \
        "That user name and password did not sign in."
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "name=$SMOKE_USER" --data-urlencode "password=$changed_pass" "$base/login" 2>&1)
    check "portal: the new password signs in" test "$out" == "303 $base/code"
    out=$(server_exec portal cat /config/panel/audit.log 2>&1)
    check "portal: audit log records the password change" contains "$out" \
        '"action":"portal.password","result":"allowed"'
    check "portal: the new password kept out of the audit log" lacks "$out" "$changed_pass"

    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "name=$new_user" --data-urlencode "password=$new_pass" "$base/login" 2>&1)
    check "portal: a user without a key signs in with the password alone" test "$out" == "303 $base/"
    out=$("${web[@]}" "$base/" 2>&1)
    check "portal: that session offers to set up a key" contains "$out" "Show the QR code"
    check "portal: that session shows no connection details" lacks "$out" "pin-sha256:"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" "$base/key" 2>&1)
    check "portal: a key is issued" contains "$out" "Or type this key"
    key=${out#*class=\"mono key-text\">}
    key=${key%%<*}
    key=${key// /}
    code=$(client_exec c1 oathtool --totp --base32 "$key")
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "code=$code" "$base/key/confirm" 2>&1)
    check "portal: a code from the new key saves it" test "$out" == "303 $base/?done=key"
    out=$("${web[@]}" "$base/?done=key" 2>&1)
    check "portal: the session then shows how to connect" contains "$out" "Your authenticator app is set up."
    if out=$(connect c1 portal "" "--base32 $key" "$new_user" "$new_pass"); then
        pass "portal: the user connects to the VPN with the key set up in the portal"
    else
        fail "portal: the user connects to the VPN with the key set up in the portal" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    out=$(server_exec portal sh -c 'stat -c "%a" /config/users.oath; cat /config/users.oath; ls -A /config' 2>&1)
    check "portal: the one-time password file stays private" matches "$out" '^600'
    # liboath rewrites the lines it records a code in with tabs between fields.
    check "portal: the file keeps the other user's key" matches "$out" \
        "HOTP/T30[[:space:]]+${SMOKE_USER}[[:space:]]+-[[:space:]]+$secret"
    check "portal: the file holds the new user's key" matches "$out" \
        "HOTP/T30[[:space:]]+${new_user}[[:space:]]+-[[:space:]]+[0-9a-f]{40}"
    check "portal: no lock or half-written copy is left" lacks "$out" "users.oath."
    out=$(server_exec portal cat /config/panel/audit.log 2>&1)
    check "portal: audit log records the key set up in the portal" contains "$out" \
        '"action":"portal.key.confirm","result":"allowed"'
    check "portal: VPN passwords kept out of the audit log" lacks "$out" "$new_pass"

    # c2 guesses passwords until its address is locked out of the portal.
    local -a other=(client_exec c2 curl -sS -m 20 --cacert /tmp/portal-ca.pem
        --resolve "$SMOKE_ID-portal:8444:$ip" -b /tmp/portal.jar -c /tmp/portal.jar)
    server_exec portal cat /config/certs/ca.pem | "$ENGINE" exec -i "$SMOKE_ID-c2" sh -c 'cat > /tmp/portal-ca.pem'
    client_exec c2 cp /dev/null /tmp/portal.jar
    for i in 1 2 3; do
        "${other[@]}" -o /dev/null -H "Origin: $base" --data-urlencode "name=$new_user" \
            --data-urlencode "password=wrong-$i" "$base/login" >/dev/null 2>&1
    done
    out=$("${other[@]}" -H "Origin: $base" --data-urlencode "name=$new_user" \
        --data-urlencode "password=$new_pass" "$base/login" 2>&1)
    check "portal: wrong passwords lock the portal for a while" contains "$out" "Too many failed sign-ins."
    stop_server portal
}

# tun_gone <client> waits up to 20 s for the client's tunnel to go away.
tun_gone() {
    client_exec "$1" sh -c '
        i=0
        while [ -e /sys/class/net/tun0 ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done
        [ ! -e /sys/class/net/tun0 ]'
}

# The firewall blocklist: an admin blocks a connected client's address on the
# Bans page, its tunnel ends, and the VPN's port and the panel's port refuse
# it; the block survives the container being recreated on its config volume,
# and lifting it lets the client connect again.
smoke_blocklist() {
    local out i once csrf ip admitted blocked base=https://$SMOKE_ID-block:8443
    local new_password=smoke-block-password-1
    admitted=$(server_ip c1)
    blocked=$(server_ip c2)
    start_server block PANEL_ENABLED=true "PANEL_LAN_NETWORKS=$admitted/32" \
        "PANEL_ALLOWED_NETWORKS=$blocked/32"
    check "block: server starts with the panel on" wait_ready block || return 1
    for i in $(seq 1 20); do
        out=$(server_logs block)
        [[ $out == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    check "block: user added" add_user block
    if out=$(connect c2 block); then
        pass "block: c2 connects before the block"
    else
        fail "block: c2 connects before the block" "$out"
    fi
    once=$(server_logs block)
    once=${once##*one-time password: }
    once=${once%% *}
    ip=$(server_ip block)
    local -a web=(client_exec c1 curl -sS -m 20 --cacert /tmp/block-ca.pem
        --resolve "$SMOKE_ID-block:8443:$ip" -b /tmp/block.jar -c /tmp/block.jar)
    server_exec block cat /config/certs/ca.pem | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'cat > /tmp/block-ca.pem'
    client_exec c1 cp /dev/null /tmp/block.jar
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode name=admin \
        --data-urlencode "password=$once" "$base/login" >/dev/null 2>&1
    out=$("${web[@]}" "$base/password" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode "csrf=$csrf" \
        --data-urlencode "current=$once" --data-urlencode "new=$new_password" \
        --data-urlencode "repeat=$new_password" "$base/password" >/dev/null 2>&1
    out=$("${web[@]}" "$base/bans" 2>&1)
    check "block: the Bans page explains automatic blocks" contains "$out" \
        "An address ocserv bans 3 times within 1 day is blocked at the firewall for 1 day"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "network=$admitted" \
        --data-urlencode duration=24 "$base/bans/block" 2>&1)
    check "block: an admin cannot block their own address" test "$out" == "200 "
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "network=$blocked" \
        --data-urlencode duration=lifted "$base/bans/block" 2>&1)
    check "block: an admin blocks c2 until lifted" test "$out" == "303 $base/bans?done=2"
    check "block: c2's tunnel ends" tun_gone c2
    disconnect c2 >/dev/null 2>&1
    out=$(server_exec block nft list set inet vpn_gateway blocked4 2>&1)
    check "block: the firewall's set holds c2" contains "$out" "$blocked"
    check_fails "block: the VPN refuses c2" connect c2 block
    disconnect c2 >/dev/null 2>&1
    check_fails "block: the panel refuses c2" client_exec c2 curl -sk -m 5 -o /dev/null "https://$ip:8443/login"
    out=$("${web[@]}" "$base/bans" 2>&1)
    check "block: the Bans page lists the block" contains "$out" "$blocked/32"

    stop_server block
    start_server block PANEL_ENABLED=true "PANEL_LAN_NETWORKS=$admitted/32" \
        "PANEL_ALLOWED_NETWORKS=$blocked/32"
    check "block: server starts again on its volume" wait_ready block || return 1
    for i in $(seq 1 20); do
        out=$(server_logs block)
        [[ $out == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    ip=$(server_ip block)
    local -a web=(client_exec c1 curl -sS -m 20 --cacert /tmp/block-ca.pem
        --resolve "$SMOKE_ID-block:8443:$ip" -b /tmp/block.jar -c /tmp/block.jar)
    out=$(server_exec block nft list set inet vpn_gateway blocked4 2>&1)
    check "block: the block survives the container being recreated" contains "$out" "$blocked"
    check_fails "block: the VPN still refuses c2" connect c2 block
    disconnect c2 >/dev/null 2>&1
    client_exec c1 cp /dev/null /tmp/block.jar
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode name=admin \
        --data-urlencode "password=$new_password" "$base/login" >/dev/null 2>&1
    out=$("${web[@]}" "$base/bans" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "network=$blocked/32" "$base/bans/unblock" 2>&1)
    check "block: an admin lifts the block" test "$out" == "303 $base/bans?done=3"
    if out=$(connect c2 block); then
        pass "block: c2 connects again once the block is lifted"
    else
        fail "block: c2 connects again once the block is lifted" "$out"
    fi
    disconnect c2 >/dev/null 2>&1
    out=$(server_exec block cat /config/panel/audit.log 2>&1)
    check "block: audit log records the block" contains "$out" "blocked $blocked/32 until lifted"
    check "block: audit log records the lifted block" contains "$out" "lifted the block of $blocked/32"
    stop_server block
}

# panel_sign_in <server> <client> <password> signs the panel's first admin in
# from the client: with the password once it is set, else with the one-time
# password in the server's log, which it replaces with the password. Each
# step must redirect where a signed-in admin goes, not back to the sign-in
# page. The cookie jar is the client's /tmp/<server>.jar and the CA
# /tmp/<server>-ca.pem.
panel_sign_in() {
    local server=$1 client=$2 password=$3 once out csrf ip base
    base=https://$SMOKE_ID-$server:8443
    ip=$(server_ip "$server")
    local -a web=(client_exec "$client" curl -sS -m 20 --cacert "/tmp/$server-ca.pem"
        --resolve "$SMOKE_ID-$server:8443:$ip" -b "/tmp/$server.jar" -c "/tmp/$server.jar")
    server_exec "$server" cat /config/certs/ca.pem |
        "$ENGINE" exec -i "$SMOKE_ID-$client" sh -c "cat > /tmp/$server-ca.pem"
    client_exec "$client" cp /dev/null "/tmp/$server.jar"
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode name=admin --data-urlencode "password=$password" "$base/login" 2>&1)
    [[ $out == "303 $base/" ]] && return 0
    once=$(server_logs "$server")
    if [[ $once != *"one-time password: "* ]]; then
        printf 'the password signed nobody in (%s), and the log holds no one-time password\n' "$out"
        return 1
    fi
    once=${once##*one-time password: }
    once=${once%% *}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode name=admin --data-urlencode "password=$once" "$base/login" 2>&1)
    if [[ $out != "303 $base/password" ]]; then
        printf 'the one-time password sign-in answered %s\n' "$out"
        return 1
    fi
    out=$("${web[@]}" "$base/password" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "current=$once" \
        --data-urlencode "new=$password" --data-urlencode "repeat=$password" "$base/password" 2>&1)
    if [[ $out != "303 $base/" ]]; then
        printf 'the password change answered %s\n' "$out"
        return 1
    fi
}

# Country rules, from the environment and from the panel, in the firewall's
# own table. The far client sits on FAR_NET, in no country and in no private
# range, so a block rule lets it in and an allow rule drops it, while c1's
# private address always passes.
smoke_countries() {
    local out csrf ip admin i base=https://$SMOKE_ID-countries:8443
    local far_ip=203.0.113.20 server_far=203.0.113.10 password=smoke-countries-password-1
    admin=$(server_ip c1)
    local -a envs=(PANEL_ENABLED=true "PANEL_LAN_NETWORKS=$admin/32")
    start_server countries "${envs[@]}" COUNTRY_RULE=Block "COUNTRIES=cn, RU"
    check "countries: server starts blocking the environment's countries" wait_ready countries || return 1
    check "countries: user added" add_user countries
    for i in $(seq 1 20); do
        [[ $(server_logs countries) == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    check "countries: the first owner sets a password" panel_sign_in countries c1 "$password" || return 1
    out=$(server_exec countries nft list set inet vpn_countries a_ports 2>&1)
    check "countries: the rules guard the VPN's port and the panel's" matches "$out" \
        'elements = \{ [^}]*4443[^}]*8443|elements = \{ [^}]*8443[^}]*4443'
    out=$(server_exec countries nft list set inet vpn_countries a_exempt4 2>&1)
    check "countries: the private ranges always pass" contains "$out" "10.0.0.0/8"
    out=$(server_exec countries nft list set inet vpn_countries a_listed4_0 2>&1)
    check "countries: the listed countries' networks are loaded" contains "$out" "elements = {"
    check "countries: the far client starts" start_far_client far "$far_ip" || return 1
    check "countries: the server joins the far network" attach_far countries "$server_far" || return 1
    if out=$(connect_via "$server_far" far countries); then
        pass "countries: a block rule lets in an address in no country"
    else
        fail "countries: a block rule lets in an address in no country" "$out"
    fi
    disconnect far >/dev/null 2>&1

    stop_server countries
    start_server countries "${envs[@]}" COUNTRY_RULE=allow COUNTRIES=US
    check "countries: server starts allowing only the environment's country" wait_ready countries || return 1
    check "countries: the server joins the far network again" attach_far countries "$server_far"
    out=$(server_exec countries nft list chain inet vpn_countries input 2>&1)
    check "countries: an allow rule drops what no listed set accepts" matches "$out" \
        'ip saddr @a_listed4_0 accept.*th dport @a_ports counter name "dropped" drop'
    local tried
    if tried=$(connect_via "$server_far" far countries 2>&1); then
        fail "countries: an allow rule drops an address in no country" "$tried"
    else
        pass "countries: an allow rule drops an address in no country"
    fi
    disconnect far >/dev/null 2>&1
    out=$(server_exec countries nft list counter inet vpn_countries dropped 2>&1)
    if [[ $out =~ packets\ [1-9][0-9]*\ bytes\ [1-9] ]]; then
        pass "countries: the drop counter counts what the rules drop"
    else
        fail "countries: the drop counter counts what the rules drop" \
            "$out"$'\n'"the far client's attempt: $tried"$'\n'"$(server_exec countries \
                nft list ruleset 2>&1 | awk '/^table|hook input|drop/')"
    fi
    if out=$(connect c1 countries); then
        pass "countries: a private address passes an allow rule"
    else
        fail "countries: a private address passes an allow rule" "$out"
    fi
    disconnect c1 >/dev/null 2>&1

    stop_server countries
    start_server countries "${envs[@]}"
    check "countries: server starts with the rules left to the panel" wait_ready countries || return 1
    attach_far countries "$server_far"
    check_fails "countries: with the panel's rule off there is no table" \
        server_exec countries nft list table inet vpn_countries
    for i in $(seq 1 20); do
        [[ $(server_logs countries) == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    check "countries: the owner signs in on the recreated container" \
        panel_sign_in countries c1 "$password" || return 1
    ip=$(server_ip countries)
    local -a web=(client_exec c1 curl -sS -m 30 --cacert /tmp/countries-ca.pem
        --resolve "$SMOKE_ID-countries:8443:$ip" -b /tmp/countries.jar -c /tmp/countries.jar)
    out=$("${web[@]}" "$base/bans" 2>&1)
    check "countries: the Bans page credits DB-IP" contains "$out" "IP Geolocation by DB-IP"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode list=1 --data-urlencode rule=allow \
        --data-urlencode country=US "$base/bans/countries" 2>&1)
    check "countries: an owner allows only the US from the panel" test "$out" == "303 $base/bans?done=5"
    check_fails "countries: the panel's allow rule drops an address in no country" \
        connect_via "$server_far" far countries
    disconnect far >/dev/null 2>&1
    out=$(server_exec countries cat /config/panel/country-rules.json 2>&1)
    check "countries: the panel keeps its rule" contains "$out" '"allow"'

    stop_server countries
    start_server countries "${envs[@]}"
    check "countries: server starts again on its volume" wait_ready countries || return 1
    attach_far countries "$server_far"
    check "countries: the panel's rule loads at start" server_exec countries nft list table inet vpn_countries
    check_fails "countries: the panel's rule still drops an address in no country" \
        connect_via "$server_far" far countries
    disconnect far >/dev/null 2>&1
    for i in $(seq 1 20); do
        [[ $(server_logs countries) == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    check "countries: the owner signs in again" panel_sign_in countries c1 "$password" || return 1
    ip=$(server_ip countries)
    local -a web=(client_exec c1 curl -sS -m 30 --cacert /tmp/countries-ca.pem
        --resolve "$SMOKE_ID-countries:8443:$ip" -b /tmp/countries.jar -c /tmp/countries.jar)
    out=$("${web[@]}" "$base/bans" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode list=1 --data-urlencode rule=off \
        "$base/bans/countries" 2>&1)
    check "countries: an owner turns the rule off" test "$out" == "303 $base/bans?done=5"
    check_fails "countries: the table goes with the rule" \
        server_exec countries nft list table inet vpn_countries
    if out=$(connect_via "$server_far" far countries); then
        pass "countries: the far client connects once the rule is off"
    else
        fail "countries: the far client connects once the rule is off" "$out"
    fi
    disconnect far >/dev/null 2>&1
    out=$(server_exec countries cat /config/panel/audit.log 2>&1)
    check "countries: the changes are audited" matches "$out" \
        'countries.change.*allowed only US at the firewall.*countries.change.*turned the country rules off'
    stop_server countries
    "$ENGINE" rm -f "$SMOKE_ID-far" >/dev/null 2>&1
    "$ENGINE" network inspect "$FAR_NET" >/dev/null 2>&1 && "$ENGINE" network rm "$FAR_NET" >/dev/null 2>&1
    return 0
}

# Alerts: an owner adds a webhook at c1's private address, where BusyBox's
# nc stands in for a service, and asks for a test; the helper posts the test
# there as JSON, audits the send without the URL's token, and keeps the URL
# in alerts.json, readable by root only. nc answers a few seconds late, so it
# has read the whole request before its input ends.
smoke_alerts() {
    local out csrf ip admin id i base=https://$SMOKE_ID-alerts:8443 password=smoke-alerts-password-1
    local token=smoke-hook-token-7f3k
    admin=$(server_ip c1)
    start_server alerts PANEL_ENABLED=true "PANEL_LAN_NETWORKS=$admin/32"
    check "alerts: server starts" wait_ready alerts || return 1
    for i in $(seq 1 20); do
        [[ $(server_logs alerts) == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    check "alerts: the first owner sets a password" panel_sign_in alerts c1 "$password" || return 1
    ip=$(server_ip alerts)
    local -a web=(client_exec c1 curl -sS -m 30 --cacert /tmp/alerts-ca.pem
        --resolve "$SMOKE_ID-alerts:8443:$ip" -b /tmp/alerts.jar -c /tmp/alerts.jar)
    "$ENGINE" exec -d "$SMOKE_ID-c1" sh -c \
        '(sleep 3; printf "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") | nc -l -p 8099 >/tmp/hook.txt 2>&1'
    out=$("${web[@]}" "$base/alerts" 2>&1)
    check "alerts: the Alerts page answers" contains "$out" "Where alerts go"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode kind=webhook \
        --data-urlencode "url=http://$admin:8099/hook/$token" "$base/alerts/channels" 2>&1)
    check "alerts: an owner adds a webhook on a private address" test "$out" == "303 $base/alerts?done=added"
    out=$("${web[@]}" "$base/alerts" 2>&1)
    check "alerts: the page marks the http webhook unencrypted" contains "$out" "Unencrypted"
    check "alerts: the page never shows the webhook's token" lacks "$out" "$token"
    id=${out#*action=\"/alerts/channels/test\"}
    id=${id#*name=\"id\" value=\"}
    id=${id%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "id=$id" "$base/alerts/channels/test" 2>&1)
    check "alerts: an owner asks for a test message" test "$out" == "303 $base/alerts?done=test"
    for i in $(seq 1 20); do
        out=$(client_exec c1 cat /tmp/hook.txt 2>&1)
        [[ $out == *'"title":'* ]] && break
        sleep 1
    done
    check "alerts: the helper posts to the webhook's path" contains "$out" "POST /hook/$token HTTP/1.1"
    check "alerts: the webhook gets the test message as JSON" matches "$out" '"title":"[^"]*: test message"'
    for i in $(seq 1 20); do
        out=$(server_exec alerts cat /config/panel/audit.log 2>&1)
        [[ $out == *'"alert.send"'* ]] && break
        sleep 1
    done
    check "alerts: the send is audited" contains "$out" "sent 1 alert to admin's webhook channel"
    check "alerts: the audit log never holds the webhook's token" lacks "$out" "$token"
    out=$(server_exec alerts stat -c '%a %U' /config/panel/alerts.json 2>&1)
    check "alerts: alerts.json is readable by root only" test "$out" == "600 root"
    stop_server alerts
    return 0
}

# A group with an address pool of its own: after a start that reads the
# group's settings file, the firewall translates the pool, and a member gets
# an address from it, reaches the server and, through the translation, the
# internet.
smoke_group_pool() {
    local out addr
    start_server gpool
    check "group pool: server starts" wait_ready gpool || return 1
    check "group pool: user added to a group" \
        sh -c 'printf "%s\n" "$1" | "$2" exec -i "$3" ocpasswd -c /config/ocpasswd -g pool-group "$4"' \
        _ "$SMOKE_PASS" "$ENGINE" "$SMOKE_ID-gpool" "$SMOKE_USER"
    server_exec gpool sh -c 'mkdir -p /config/config-per-group &&
        printf "ipv4-network = 10.77.0.0\nipv4-netmask = 255.255.255.0\n" >/config/config-per-group/pool-group'
    stop_server gpool
    start_server gpool
    check "group pool: server starts again with the group's pool" wait_ready gpool || return 1
    out=$(server_exec gpool nft list table ip vpn_gateway 2>&1)
    check "group pool: the firewall translates the group's pool" contains "$out" \
        'ip saddr 10.77.0.0/24 oifname != "vpns*" masquerade'
    if addr=$(connect_expecting '^10\.77\.0\.[0-9]+$' c1 gpool); then
        pass "group pool: a member connects"
    else
        fail "group pool: a member connects" "$addr"
        stop_server gpool
        return 0
    fi
    check "group pool: the member's address is from the group's pool" matches "$addr" '^10\.77\.0\.[0-9]+$'
    check "group pool: the member reaches the server" client_exec c1 ping -c 2 -W 3 10.77.0.1
    if [[ ${SMOKE_INTERNET:-1} == 1 ]]; then
        check "group pool: the member reaches the internet through the translation" \
            client_exec c1 nslookup example.com 9.9.9.9
    fi
    disconnect c1 >/dev/null 2>&1
    stop_server gpool
}

# Site-to-site networks: a user publishes 10.88.0.0/24, held by the client it
# connects from. No other client reaches the network without a rule; a rule
# from every client lets them in one way only; a rule back to the group staff
# lets the site reach staff's sessions and follows them as they connect and
# disconnect; the network leaves the VPN only once its egress is on; and a
# user an admin puts in staff on the VPN users page keeps their password and
# is reached by the site from their next connection.
smoke_sites() {
    local out once csrf ip admin site_vpn alice_vpn bob_vpn i base=https://$SMOKE_ID-sites:8443
    local new_password=smoke-sites-password-1
    admin=$(server_ip c1)
    "$ENGINE" volume create "$SMOKE_ID-sites-config" >/dev/null
    "$ENGINE" run --rm -v "$SMOKE_ID-sites-config:/config" "$CLIENT_IMAGE" sh -c \
        'mkdir -p /config/config-per-user && printf "iroute = 10.88.0.0/24\n" >/config/config-per-user/site1' >/dev/null
    start_server sites PANEL_ENABLED=true "PANEL_LAN_NETWORKS=$admin/32"
    check "sites: server starts with the panel on" wait_ready sites || return 1
    for i in $(seq 1 20); do
        out=$(server_logs sites)
        [[ $out == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    check "sites: the firewall checks where tunnel traffic comes from" \
        lacks "$out" "cannot check where tunnel traffic comes from"
    check "sites: the site's user added" add_named_user sites site1
    check "sites: a member of staff added" add_named_user sites alice staff
    check "sites: a user outside staff added" add_named_user sites bob
    if site_vpn=$(connect c2 sites "" "" site1); then
        pass "sites: the site's router connects"
    else
        fail "sites: the site's router connects" "$site_vpn"
        stop_server sites
        return 0
    fi
    out=$(server_exec sites ip route show 10.88.0.0/24 2>&1)
    check "sites: the server routes the site's network to its session" contains "$out" "dev vpns"
    check "sites: the site holds 10.88.0.1" client_exec c2 ip addr replace 10.88.0.1/32 dev lo
    if alice_vpn=$(connect c1 sites "" "" alice); then
        pass "sites: a member of staff connects"
    else
        fail "sites: a member of staff connects" "$alice_vpn"
        stop_server sites
        return 0
    fi
    check_fails "sites: without a rule a client does not reach the site" \
        client_exec c1 ping -c 2 -W 3 10.88.0.1

    once=$(server_logs sites)
    once=${once##*one-time password: }
    once=${once%% *}
    ip=$(server_ip sites)
    local -a web=(client_exec c1 curl -sS -m 20 --cacert /tmp/sites-ca.pem
        --resolve "$SMOKE_ID-sites:8443:$ip" -b /tmp/sites.jar -c /tmp/sites.jar)
    server_exec sites cat /config/certs/ca.pem | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'cat > /tmp/sites-ca.pem'
    client_exec c1 cp /dev/null /tmp/sites.jar
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode name=admin \
        --data-urlencode "password=$once" "$base/login" >/dev/null 2>&1
    out=$("${web[@]}" "$base/password" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode "csrf=$csrf" \
        --data-urlencode "current=$once" --data-urlencode "new=$new_password" \
        --data-urlencode "repeat=$new_password" "$base/password" >/dev/null 2>&1
    out=$("${web[@]}" "$base/sites" 2>&1)
    check "sites: the Sites page lists the site's network" contains "$out" "10.88.0.0/24"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode from=clients \
        --data-urlencode to=network:10.88.0.0/24 "$base/sites/rules/add" 2>&1)
    check "sites: an admin lets every client reach the site" test "$out" == "303 $base/sites?done=1"
    check "sites: a client reaches the site" client_exec c1 ping -c 2 -W 3 10.88.0.1
    check_fails "sites: the site does not reach the client without a rule back" \
        client_exec c2 ping -c 2 -W 3 -I 10.88.0.1 "$alice_vpn"
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode from=network:10.88.0.0/24 \
        --data-urlencode to=group:staff "$base/sites/rules/add" 2>&1)
    check "sites: an admin lets the site reach the group staff" test "$out" == "303 $base/sites?done=1"
    check "sites: the site reaches a member of staff" \
        client_exec c2 ping -c 2 -W 3 -I 10.88.0.1 "$alice_vpn"
    out=$(server_exec sites nft list table inet vpn_gateway 2>&1)
    check "sites: the firewall holds the member's address for the group" holds_address "$out" "$alice_vpn"
    disconnect c1 >/dev/null 2>&1
    for i in $(seq 1 10); do
        out=$(server_exec sites nft list table inet vpn_gateway 2>&1)
        holds_address "$out" "$alice_vpn" >/dev/null || break
        sleep 1
    done
    check_fails "sites: the address leaves the group when the member disconnects" \
        holds_address "$out" "$alice_vpn"
    if bob_vpn=$(connect c1 sites "" "" bob); then
        pass "sites: a user outside staff connects"
        check "sites: a user outside staff reaches the site by the rule for every client" \
            client_exec c1 ping -c 2 -W 3 10.88.0.1
        check_fails "sites: the site does not reach a user outside staff" \
            client_exec c2 ping -c 2 -W 3 -I 10.88.0.1 "$bob_vpn"
    else
        fail "sites: a user outside staff connects" "$bob_vpn"
    fi
    disconnect c1 >/dev/null 2>&1

    out=$(server_exec sites nft list set inet vpn_gateway site_closed4 2>&1)
    check "sites: the site's network stays inside the VPN" contains "$out" "10.88.0.0/24"
    if [[ ${SMOKE_INTERNET:-1} == 1 ]]; then
        check_fails "sites: the site does not reach the internet while its egress is off" \
            client_exec c2 curl -sS -m 10 -o /dev/null --interface 10.88.0.1 https://1.1.1.1/
    fi
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode user=site1 --data-urlencode on=on \
        "$base/sites/egress" 2>&1)
    check "sites: an admin lets the site's networks out" test "$out" == "303 $base/sites?done=3"
    out=$(server_exec sites nft list set ip vpn_gateway site_egress 2>&1)
    check "sites: the firewall translates the site's network on the way out" contains "$out" "10.88.0.0/24"
    if [[ ${SMOKE_INTERNET:-1} == 1 ]]; then
        check "sites: the site reaches the internet once its egress is on" \
            client_exec c2 curl -sS -m 10 -o /dev/null --interface 10.88.0.1 https://1.1.1.1/
    fi
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode change=groups --data-urlencode name=bob \
        --data-urlencode groups=staff "$base/users/change" 2>&1)
    check "sites: an admin puts bob in staff on the VPN users page" test "$out" == "303 $base/users?done=groups"
    out=$(server_exec sites cat /config/ocpasswd 2>&1)
    check "sites: the password file names bob's new group" contains "$out" "bob:staff:"
    check "sites: the password file's lock is gone" server_exec sites test ! -e /config/ocpasswd.tmp
    if bob_vpn=$(connect c1 sites "" "" bob); then
        pass "sites: bob signs in with the same password after the change"
        check "sites: the site reaches bob as a member of staff" \
            client_exec c2 ping -c 2 -W 3 -I 10.88.0.1 "$bob_vpn"
    else
        fail "sites: bob signs in with the same password after the change" "$bob_vpn"
    fi
    disconnect c1 >/dev/null 2>&1
    disconnect c2 >/dev/null 2>&1
    out=$(server_exec sites cat /config/panel/audit.log 2>&1)
    check "sites: the audit log records the rule from every client" contains "$out" \
        "let every VPN client reach 10.88.0.0/24"
    check "sites: the audit log records the rule back to staff" contains "$out" \
        "let 10.88.0.0/24 reach group staff"
    check "sites: the audit log records the egress" contains "$out" \
        "let the networks site1 publishes reach beyond the VPN"
    check "sites: the audit log records bob's new group" contains "$out" \
        "set the groups of bob to staff"
    stop_server sites
}

# Site-to-site rules with the panel off: a rule written by hand into
# /config/panel/site-rules.json loads at start, a client reaches the site's
# network, and the site does not reach the client.
smoke_sites_by_hand() {
    local out vpn
    "$ENGINE" volume create "$SMOKE_ID-siteshand-config" >/dev/null
    "$ENGINE" run --rm -v "$SMOKE_ID-siteshand-config:/config" "$CLIENT_IMAGE" sh -c '
        mkdir -p /config/config-per-user /config/panel &&
        printf "iroute = 10.88.0.0/24\n" >/config/config-per-user/site1 &&
        printf "%s\n" "$0" >/config/panel/site-rules.json' \
        '{"rules":[{"id":1,"from":"clients","to":{"network":"10.88.0.0/24"},"by":"smoke","created":0}],"egress":[]}' \
        >/dev/null
    start_server siteshand
    check "sites by hand: server starts with the panel off" wait_ready siteshand || return 1
    out=$(server_exec siteshand nft list chain inet vpn_gateway site_rules 2>&1)
    check "sites by hand: the firewall loads the rule written by hand" contains "$out" "10.88.0.0/24"
    check "sites by hand: the site's user added" add_named_user siteshand site1
    check "sites by hand: a client's user added" add_named_user siteshand alice
    if out=$(connect c2 siteshand "" "" site1); then
        pass "sites by hand: the site's router connects"
    else
        fail "sites by hand: the site's router connects" "$out"
        stop_server siteshand
        return 0
    fi
    check "sites by hand: the site holds 10.88.0.1" client_exec c2 ip addr replace 10.88.0.1/32 dev lo
    if vpn=$(connect c1 siteshand "" "" alice); then
        pass "sites by hand: a client connects"
        check "sites by hand: the client reaches the site" client_exec c1 ping -c 2 -W 3 10.88.0.1
        check_fails "sites by hand: the site does not reach the client" \
            client_exec c2 ping -c 2 -W 3 -I 10.88.0.1 "$vpn"
    else
        fail "sites by hand: a client connects" "$vpn"
    fi
    disconnect c1 >/dev/null 2>&1
    disconnect c2 >/dev/null 2>&1
    client_exec c2 ip addr del 10.88.0.1/32 dev lo >/dev/null 2>&1
    stop_server siteshand
}

# A server behind a load balancer: haproxy passes the VPN's port on with the
# PROXY protocol and health checks it, ocserv sees the client's own address,
# a block made on the Bans page refuses the client although its connections
# reach the server from the balancer, and a drain time saved on the Settings
# page reaches ocserv with a reload: a stop closes the port while sessions
# last for that time, with the panel's helper not started again meanwhile.
smoke_balancer() {
    local out i csrf once ip lb admin client started took stopper base=https://$SMOKE_ID-lb:8443
    local new_password=smoke-lb-password-1
    admin=$(server_ip c1)
    client=$(server_ip c2)
    start_server lb PANEL_ENABLED=true PROXY_PROTOCOL=true "PANEL_LAN_NETWORKS=$admin/32"
    check "balancer: server starts with the PROXY protocol on" wait_ready lb || return 1
    for i in $(seq 1 20); do
        out=$(server_logs lb)
        [[ $out == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    check "balancer: user added" add_user lb
    ip=$(server_ip lb)
    "$ENGINE" run -d --name "$SMOKE_ID-haproxy" --network "$SMOKE_NET" "$CLIENT_IMAGE" sleep 3600 >/dev/null
    check "balancer: haproxy installed" client_exec haproxy apk add --no-cache --quiet haproxy
    printf '%s\n' 'defaults' '    mode tcp' '    timeout connect 5s' '    timeout client 1h' \
        '    timeout server 1h' 'frontend vpn' '    bind :4443' '    default_backend ocserv' \
        'backend ocserv' "    server vpn1 $ip:4443 send-proxy-v2 check check-send-proxy inter 2s" \
        | "$ENGINE" exec -i "$SMOKE_ID-haproxy" sh -c 'cat > /etc/haproxy/haproxy.cfg'
    "$ENGINE" exec -d "$SMOKE_ID-haproxy" haproxy -f /etc/haproxy/haproxy.cfg
    for i in $(seq 1 20); do
        out=$(client_exec haproxy netstat -ltn 2>&1)
        [[ $out == *":4443 "* ]] && break
        sleep 1
    done
    lb=$(server_ip haproxy)
    if out=$(connect_via "$lb" c2 lb); then
        pass "balancer: c2 connects through the balancer"
    else
        fail "balancer: c2 connects through the balancer" "$out"
    fi
    out=$(server_logs lb)
    check "balancer: ocserv logs c2's own address, not the balancer's" contains "$out" \
        "connected from $client,"
    check "balancer: health checks with the PROXY protocol leave no errors" lacks "$out" \
        "could not parse proxy protocol header"
    out=$(server_exec lb occtl show users 2>&1)
    check "balancer: the session carries c2's own address" contains "$out" " $client "

    once=$(server_logs lb)
    once=${once##*one-time password: }
    once=${once%% *}
    local -a web=(client_exec c1 curl -sS -m 20 --cacert /tmp/lb-ca.pem
        --resolve "$SMOKE_ID-lb:8443:$ip" -b /tmp/lb.jar -c /tmp/lb.jar)
    server_exec lb cat /config/certs/ca.pem | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'cat > /tmp/lb-ca.pem'
    client_exec c1 cp /dev/null /tmp/lb.jar
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode name=admin \
        --data-urlencode "password=$once" "$base/login" >/dev/null 2>&1
    out=$("${web[@]}" "$base/password" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode "csrf=$csrf" \
        --data-urlencode "current=$once" --data-urlencode "new=$new_password" \
        --data-urlencode "repeat=$new_password" "$base/password" >/dev/null 2>&1
    out=$("${web[@]}" "$base/" 2>&1)
    check "balancer: the dashboard names the container" contains "$out" \
        "You are managing container $SMOKE_ID-lb at $SMOKE_ID-lb."
    out=$("${web[@]}" "$base/settings" 2>&1)
    check "balancer: the Settings page shows the load balancer settings" contains "$out" \
        "PROXY protocol from a load balancer"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode SERVER_DRAIN_MS=4000 "$base/settings" 2>&1)
    check "balancer: a drain time saved on the Settings page is applied with a reload" \
        test "$out" == "303 $base/settings?done=reloaded"
    out=$(server_exec lb cat /run/ocserv/ocserv.conf 2>&1)
    check "balancer: the running configuration has the drain time" contains "$out" "server-drain-ms = 4000"
    out=$("${web[@]}" "$base/bans" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "network=$client" \
        --data-urlencode duration=lifted "$base/bans/block" 2>&1)
    check "balancer: an admin blocks c2" test "$out" == "303 $base/bans?done=2"
    check "balancer: c2's session through the balancer ends" tun_gone c2
    disconnect c2 >/dev/null 2>&1
    check_fails "balancer: the VPN refuses c2 through the balancer" connect_via "$lb" c2 lb
    disconnect c2 >/dev/null 2>&1
    out=$(server_logs lb)
    check "balancer: the session script names the block" contains "$out" \
        "refused user $SMOKE_USER from $client: the admin panel's blocklist holds $client/32"
    out=$("${web[@]}" "$base/bans" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "network=$client/32" "$base/bans/unblock" 2>&1)
    check "balancer: an admin lifts the block" test "$out" == "303 $base/bans?done=3"
    if out=$(connect_via "$lb" c2 lb); then
        pass "balancer: c2 connects through the balancer again once the block is lifted"
    else
        fail "balancer: c2 connects through the balancer again once the block is lifted" "$out"
    fi

    started=$(date +%s)
    "$ENGINE" stop -t 30 "$SMOKE_ID-lb" >/dev/null 2>&1 &
    stopper=$!
    sleep 2
    check "balancer: a stop closes the VPN port at once" client_exec c1 sh -c \
        "curl -sk -m 3 -o /dev/null 'https://$ip:4443/'; [ \$? -eq 7 ]"
    check "balancer: c2's session lasts into the drain time" client_exec c2 test -e /sys/class/net/tun0
    wait "$stopper"
    took=$(($(date +%s) - started))
    check "balancer: the stop waits for the drain time" test "$took" -ge 4
    check "balancer: c2's session ends after the drain time" tun_gone c2
    disconnect c2 >/dev/null 2>&1
    out=$(server_logs lb)
    check "balancer: ocserv logs the drain time" contains "$out" \
        "termination request received; waiting 4000 ms"
    check "balancer: the panel's helper is not started again while the container stops" \
        lacks "$out" "starting it again"
    out=$("$ENGINE" inspect -f '{{.State.ExitCode}}' "$SMOKE_ID-lb" 2>&1)
    check "balancer: the container stops with status 0" test "$out" == 0
    "$ENGINE" rm -f "$SMOKE_ID-haproxy" >/dev/null 2>&1
    stop_server lb
}

# Certificate sign-in with AUTH_MODE. The first start creates the client CA
# and its revocation list. With certificate alone, a client signs in with a
# certificate from that CA and is refused without one, and a revoked
# certificate is refused once ocserv reloads. With either, the password or the
# certificate alone signs in. With both, the certificate needs the password.
smoke_certificates() {
    local out
    start_server certs AUTH_MODE=certificate
    check "certificates: server starts with certificate sign-in" wait_ready certs || return 1
    out=$(server_exec certs ls /config/certs 2>&1)
    check "certificates: the client CA is created" contains "$out" "client-ca.pem"
    check "certificates: its revocation list is created" contains "$out" "client-crl.pem"
    check "certificates: user added" add_user certs
    check "certificates: a certificate is issued from the client CA" \
        issue_client_cert certs c1 "$SMOKE_USER" /tmp/smoke
    if out=$(connect_with_cert /tmp/smoke c1 certs); then
        pass "certificates: a client signs in with its certificate"
    else
        fail "certificates: a client signs in with its certificate" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    check_fails "certificates: a client without a certificate is refused" connect c1 certs
    disconnect c1 >/dev/null 2>&1
    check "certificates: the certificate is revoked" revoke_client_cert certs "$SMOKE_USER"
    check_fails "certificates: a revoked certificate is refused" connect_with_cert /tmp/smoke c1 certs
    disconnect c1 >/dev/null 2>&1
    stop_server certs

    start_server certs AUTH_MODE=either
    check "certificates: server starts with either method" wait_ready certs || return 1
    if out=$(connect c1 certs); then
        pass "certificates: with either, the password alone signs in"
    else
        fail "certificates: with either, the password alone signs in" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    check "certificates: a second certificate is issued" issue_client_cert certs c1 "$SMOKE_USER" /tmp/smoke2
    if out=$(connect_with_cert /tmp/smoke2 c1 certs "" "" "$SMOKE_USER" wrong-password-1); then
        pass "certificates: with either, the certificate alone signs in"
    else
        fail "certificates: with either, the certificate alone signs in" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    stop_server certs

    start_server certs AUTH_MODE=both
    check "certificates: server starts with both methods" wait_ready certs || return 1
    if out=$(connect_with_cert /tmp/smoke2 c1 certs); then
        pass "certificates: with both, the certificate and the password sign in"
    else
        fail "certificates: with both, the certificate and the password sign in" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    check_fails "certificates: with both, the certificate and a wrong password are refused" \
        connect_with_cert /tmp/smoke2 c1 certs "" "" "$SMOKE_USER" wrong-password-1
    disconnect c1 >/dev/null 2>&1
    check_fails "certificates: with both, the password without a certificate is refused" connect c1 certs
    disconnect c1 >/dev/null 2>&1
    stop_server certs
}

# Client certificates from the panel: an admin issues a key file in each
# encryption and a certificate for a signing request, and a client signs in
# with each; a request with a weak key is refused; a revoked certificate and
# a locked user's certificate are refused, and unlocking lets the user in.
smoke_panel_certificates() {
    local out i csrf once ip admin phrase des_phrase p12 serial pem subject
    local base=https://$SMOKE_ID-pcerts:8443 new_password=smoke-pcerts-password-1
    admin=$(server_ip c1)
    start_server pcerts PANEL_ENABLED=true AUTH_MODE=certificate "PANEL_LAN_NETWORKS=$admin/32"
    check "panel certificates: server starts with certificate sign-in" wait_ready pcerts || return 1
    for i in $(seq 1 20); do
        out=$(server_logs pcerts)
        [[ $out == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    check "panel certificates: user added" add_user pcerts
    ip=$(server_ip pcerts)
    once=$(server_logs pcerts)
    once=${once##*one-time password: }
    once=${once%% *}
    local -a web=(client_exec c1 curl -sS -m 60 --cacert /tmp/pcerts-ca.pem
        --resolve "$SMOKE_ID-pcerts:8443:$ip" -b /tmp/pcerts.jar -c /tmp/pcerts.jar)
    server_exec pcerts cat /config/certs/ca.pem | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'cat > /tmp/pcerts-ca.pem'
    client_exec c1 cp /dev/null /tmp/pcerts.jar
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode name=admin \
        --data-urlencode "password=$once" "$base/login" >/dev/null 2>&1
    out=$("${web[@]}" "$base/password" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    "${web[@]}" -o /dev/null -H "Origin: $base" --data-urlencode "csrf=$csrf" \
        --data-urlencode "current=$once" --data-urlencode "new=$new_password" \
        --data-urlencode "repeat=$new_password" "$base/password" >/dev/null 2>&1
    out=$("${web[@]}" "$base/certificates" 2>&1)
    check "panel certificates: the Certificates page offers to issue one" contains "$out" "Issue a certificate"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}

    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode "user=$SMOKE_USER" \
        --data-urlencode how=key_file --data-urlencode cipher=aes256 "$base/certificates/issue" 2>&1)
    check "panel certificates: a key file is issued" contains "$out" "Download $SMOKE_USER.p12"
    phrase=${out#*id=\"key-passphrase\">}
    phrase=${phrase%%<*}
    serial=${out#*Serial number <span class=\"mono\">}
    serial=${serial%%<*}
    p12=${out#*data:application/x-pkcs12;base64,}
    p12=${p12%%\"*}
    printf '%s' "$p12" | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'base64 -d > /tmp/aes.p12'
    if out=$(connect_with_options "--certificate=/tmp/aes.p12 --key-password=$phrase" c1 pcerts); then
        pass "panel certificates: a client signs in with an AES-256 key file"
    else
        fail "panel certificates: a client signs in with an AES-256 key file" "$out"
    fi
    disconnect c1 >/dev/null 2>&1

    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode "user=$SMOKE_USER" \
        --data-urlencode how=key_file --data-urlencode cipher=triple_des "$base/certificates/issue" 2>&1)
    des_phrase=${out#*id=\"key-passphrase\">}
    des_phrase=${des_phrase%%<*}
    p12=${out#*data:application/x-pkcs12;base64,}
    p12=${p12%%\"*}
    printf '%s' "$p12" | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'base64 -d > /tmp/des.p12'
    if out=$(connect_with_options "--certificate=/tmp/des.p12 --key-password=$des_phrase" c1 pcerts); then
        pass "panel certificates: a client signs in with a 3DES key file"
    else
        fail "panel certificates: a client signs in with a 3DES key file" "$out"
    fi
    disconnect c1 >/dev/null 2>&1

    client_exec c1 sh -c 'openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout /tmp/req-key.pem -subj "/CN=someone-else" -out /tmp/req.pem 2>/dev/null'
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode "user=$SMOKE_USER" \
        --data-urlencode how=request --data-urlencode cipher=aes256 --data-urlencode request@/tmp/req.pem \
        "$base/certificates/issue" 2>&1)
    check "panel certificates: a signing request is signed" contains "$out" "Download $SMOKE_USER-cert.pem"
    pem=${out#*data:application/x-pem-file;base64,}
    pem=${pem%%\"*}
    printf '%s' "$pem" | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'base64 -d > /tmp/req-cert.pem'
    subject=$(client_exec c1 openssl x509 -in /tmp/req-cert.pem -noout -subject 2>&1)
    check "panel certificates: the certificate names the user" contains "$subject" "CN=$SMOKE_USER"
    check "panel certificates: the request's own name is dropped" lacks "$subject" "someone-else"
    if out=$(connect_with_options "--certificate=/tmp/req-cert.pem --sslkey=/tmp/req-key.pem" c1 pcerts); then
        pass "panel certificates: a client signs in with the key of its signing request"
    else
        fail "panel certificates: a client signs in with the key of its signing request" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    client_exec c1 sh -c 'openssl req -new -newkey rsa:1024 -nodes -keyout /tmp/weak-key.pem \
        -subj "/CN=weak" -out /tmp/weak.pem 2>/dev/null'
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode "user=$SMOKE_USER" \
        --data-urlencode how=request --data-urlencode cipher=aes256 --data-urlencode request@/tmp/weak.pem \
        "$base/certificates/issue" 2>&1)
    check "panel certificates: a request with an RSA 1024 key is refused" contains "$out" "is too weak"

    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "serial=$serial" "$base/certificates/revoke" 2>&1)
    check "panel certificates: the AES-256 key file's certificate is revoked" test "$out" == \
        "303 $base/certificates?done=revoked"
    check_fails "panel certificates: the revoked certificate is refused" \
        connect_with_options "--certificate=/tmp/aes.p12 --key-password=$phrase" c1 pcerts
    disconnect c1 >/dev/null 2>&1

    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode change=lock --data-urlencode "name=$SMOKE_USER" \
        "$base/users/change" 2>&1)
    check "panel certificates: the user is locked" test "$out" == "303 $base/users?done=lock"
    check_fails "panel certificates: a locked user's certificate is refused" \
        connect_with_options "--certificate=/tmp/des.p12 --key-password=$des_phrase" c1 pcerts
    disconnect c1 >/dev/null 2>&1
    out=$(server_logs pcerts)
    check "panel certificates: the session script names the lock" contains "$out" \
        "refused user $SMOKE_USER from $admin: $SMOKE_USER is locked"
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode change=unlock --data-urlencode "name=$SMOKE_USER" \
        "$base/users/change" 2>&1)
    check "panel certificates: the user is unlocked" test "$out" == "303 $base/users?done=unlock"
    if out=$(connect_with_options "--certificate=/tmp/des.p12 --key-password=$des_phrase" c1 pcerts); then
        pass "panel certificates: the unlocked user signs in with the certificate again"
    else
        fail "panel certificates: the unlocked user signs in with the certificate again" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    out=$(server_exec pcerts cat /config/panel/audit.log 2>&1)
    check "panel certificates: the audit log records the key file" contains "$out" \
        "issued a certificate for $SMOKE_USER in a key file encrypted with AES-256"
    check "panel certificates: the audit log records the revocation" contains "$out" \
        "revoked the certificate $serial of $SMOKE_USER"
    check "panel certificates: the audit log keeps no passphrase" lacks "$out" "$phrase"
    stop_server pcerts
}

# section <function> [<argument>...] runs one group of checks where -e does
# not apply, so a failed check reports and the run goes on. A group that
# returns non-zero after a failed check of its own has that failure
# counted already; one that returns non-zero without one counts as a
# failure of its own.
section() {
    local before=$FAILED
    note "section $1"
    if ! "$@"; then
        if ((FAILED == before)); then
            fail "$1 stopped early" || true
        else
            note "$1 stopped after a failed check"
        fi
    fi
}

run_smoke() {
    IMAGE=${1:?usage: tests/run.sh smoke <image>}
    select_engine
    server_flags
    SMOKE_CLEANUP=smoke_cleanup
    note "smoke tests of $IMAGE with $ENGINE $("$ENGINE" --version 2>&1)"
    "$ENGINE" network create "$SMOKE_NET" >/dev/null
    "$ENGINE" pull --quiet "$CLIENT_IMAGE" >/dev/null
    section smoke_tunnel
    section smoke_split
    section smoke_camouflage
    section smoke_upgrades
    section smoke_otp
    section smoke_panel
    section smoke_panel_codes
    section smoke_portal
    section smoke_blocklist
    section smoke_countries
    section smoke_alerts
    section smoke_group_pool
    section smoke_sites
    section smoke_sites_by_hand
    section smoke_balancer
    section smoke_certificates
    section smoke_panel_certificates
}

# panel_process <server> <mode> prints the uid and effective capabilities of
# the ocpanel process running in <mode> (helper or web), from /proc.
panel_process() {
    server_exec "$1" sh -c '
        for dir in /proc/[0-9]*; do
            command=$(tr "\0" " " < "$dir/cmdline" 2>/dev/null) || continue
            case $command in
                *"ocpanel $0"*) awk "/^Uid:/ { uid = \$2 } /^CapEff:/ { caps = \$2 } END { print uid, caps }" "$dir/status" ;;
            esac
        done' "$2"
}

smoke_panel() {
    local out uid i password admitted outside banned ip csrf key code id generated base=https://$SMOKE_ID-panel:8443
    local new_password=smoke-panel-password-1
    check "panel: client c1 is running" server_ip c1 || return 1
    check "panel: client c2 is running" server_ip c2 || return 1
    check "panel: client c3 is running" server_ip c3 || return 1
    admitted=$(server_ip c1)
    outside=$(server_ip c2)
    banned=$(server_ip c3)
    # A ban score of 40 bans c3 after four wrong passwords and stays above
    # what c1 gathers through its connections and its locked user's refusal.
    # The location checks are on and have no data yet, since the first
    # download waits five minutes, so every connect runs the check and goes
    # through.
    start_server panel PANEL_ENABLED=true "PANEL_LAN_NETWORKS=$admitted/32" \
        "PANEL_ALLOWED_NETWORKS=$outside/32" MAX_BAN_SCORE=40 LOCATION_CHECKS=true
    check "panel: server starts with the panel on" wait_ready panel || return 1
    for i in $(seq 1 20); do
        out=$(server_logs panel)
        [[ $out == *"panel: serving https on port 8443"* ]] && break
        sleep 1
    done
    check "panel: first admin created with a one-time password" contains "$out" \
        "first admin 'admin' created as owner; one-time password: "
    check "panel: web process connected to the helper" contains "$out" "web process running as uid"
    check "panel: web process serves HTTPS" contains "$out" "panel: serving https on port 8443"
    check "panel: the user portal stays off unless enabled" lacks "$out" "VPN user portal"
    out=$(panel_process panel helper)
    check "panel: helper runs as root" matches "$out" '^0 '
    uid=$(server_exec panel id -u ocpanel)
    out=$(panel_process panel web)
    check "panel: web process runs as ocpanel" matches "$out" "^$uid "
    check "panel: web process has no capabilities" matches "$out" ' 0000000000000000$'
    out=$(server_exec panel stat -c '%U %a' /run/ocpanel/helper.sock 2>&1)
    check "panel: helper socket is ocpanel's, mode 600" contains "$out" "ocpanel 600"
    out=$(server_exec panel stat -c '%U %a' /run/ocpanel/location.sock 2>&1)
    check "panel: location socket is root's, mode 600" contains "$out" "root 600"
    out=$(server_exec panel stat -c '%U %a' /config/panel/admins.json 2>&1)
    check "panel: admins file is root's, mode 600" contains "$out" "root 600"
    out=$(server_exec panel certtool --certificate-info --infile /config/panel/tls/cert.pem 2>&1)
    check "panel: own certificate issued for the server name" contains "$out" "DNSname: $SMOKE_ID-panel"
    out=$(server_exec panel sh -c 'cmp /config/panel/tls/key.pem /config/certs/server-key.pem' 2>&1)
    check "panel: own key, not the VPN server's" contains "$out" "differ"
    out=$(server_exec panel stat -c '%U %a' /config/panel/tls/key.pem 2>&1)
    check "panel: panel key is root's, mode 600" contains "$out" "root 600"
    out=$(server_exec panel cat /config/panel/audit.log 2>&1)
    check "panel: audit log records the first admin" contains "$out" '"action":"admin.bootstrap"'
    password=$(server_logs panel)
    password=${password##*one-time password: }
    password=${password%% *}
    check "panel: one-time password kept out of the audit log" lacks "$out" "$password"

    # c1 signs in, verifying the panel's certificate against the container's
    # ca.pem and keeping the panel's cookies in a jar of its own.
    ip=$(server_ip panel)
    local -a web=(client_exec c1 curl -sS -m 20 --cacert /tmp/panel-ca.pem
        --resolve "$SMOKE_ID-panel:8443:$ip" -b /tmp/panel.jar -c /tmp/panel.jar)
    server_exec panel cat /config/certs/ca.pem | "$ENGINE" exec -i "$SMOKE_ID-c1" sh -c 'cat > /tmp/panel-ca.pem'
    client_exec c1 cp /dev/null /tmp/panel.jar
    out=$("${web[@]}" -D - -o /dev/null "$base/login" 2>&1)
    check "panel: sign-in page served over verified https" contains "$out" "HTTP/1.1 200"
    check "panel: content security policy sent" contains "$out" "content-security-policy: default-src 'none'"
    check "panel: strict transport security sent" contains "$out" "strict-transport-security: max-age=31536000"
    check "panel: referrer policy lets browsers send the origin with forms" contains "$out" \
        "referrer-policy: same-origin"
    out=$("${web[@]}" -o /dev/null -w '%{http_code}' -H "Host: elsewhere.example" "$base/login" 2>&1)
    check "panel: another host name refused" test "$out" == 421
    out=$("${web[@]}" -o /dev/null -w '%{http_code}' -H "Origin: https://elsewhere.example" \
        --data-urlencode name=admin --data-urlencode "password=$password" "$base/login" 2>&1)
    check "panel: a sign-in posted from another site refused" test "$out" == 403
    out=$("${web[@]}" -o /dev/null -w '%{http_code}' \
        --data-urlencode name=admin --data-urlencode "password=$password" "$base/login" 2>&1)
    check "panel: a sign-in posted without an origin refused" test "$out" == 403
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode name=admin --data-urlencode "password=$password" "$base/login" 2>&1)
    check "panel: one-time password signs in and asks for a new one" test "$out" == "303 $base/password"
    out=$("${web[@]}" "$base/password" 2>&1)
    check "panel: password page asks to replace the one-time password" contains "$out" \
        "Replace your one-time password"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "current=$password" \
        --data-urlencode "new=$new_password" --data-urlencode "repeat=$new_password" "$base/password" 2>&1)
    check "panel: one-time password replaced" test "$out" == "303 $base/"
    out=$("${web[@]}" "$base/" 2>&1)
    check "panel: dashboard shown once signed in" contains "$out" '<h1 class="h1">Dashboard</h1>'
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" -d '' "$base/logout" 2>&1)
    check "panel: sign out" test "$out" == "303 $base/login"
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' "$base/" 2>&1)
    check "panel: signed out, the dashboard sends to the sign-in page" test "$out" == "303 $base/login"
    out=$("${web[@]}" -H "Origin: $base" \
        --data-urlencode name=admin --data-urlencode "password=$password" "$base/login" 2>&1)
    check "panel: one-time password works only once" contains "$out" "The admin name or password is wrong."
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode name=admin --data-urlencode "password=$new_password" "$base/login" 2>&1)
    check "panel: new password signs in" test "$out" == "303 $base/"
    out=$(server_exec panel cat /config/panel/audit.log 2>&1)
    check "panel: audit log records the password change" contains "$out" \
        '"action":"password.change","result":"allowed"'
    check "panel: new password kept out of the audit log" lacks "$out" "$new_password"

    # The owner adds an admin on the Admins page; the one-time password shown
    # there signs the new admin in, without the owner's cookies, to replace it.
    out=$("${web[@]}" "$base/admins" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode change=add \
        --data-urlencode name=smoke-viewer --data-urlencode role=viewer "$base/admins/change" 2>&1)
    check "panel: the Admins page shows a new admin's one-time password once" contains "$out" \
        "One-time password for smoke-viewer"
    local viewer_password=${out#*id=\"one-time-password\">}
    viewer_password=${viewer_password%%<*}
    out=$(client_exec c1 curl -sS -m 20 --cacert /tmp/panel-ca.pem --resolve "$SMOKE_ID-panel:8443:$ip" \
        -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode name=smoke-viewer --data-urlencode "password=$viewer_password" "$base/login" 2>&1)
    check "panel: the new admin's one-time password signs in and asks for a new one" \
        test "$out" == "303 $base/password"
    out=$(server_exec panel cat /config/panel/audit.log 2>&1)
    check "panel: audit log records the added admin" contains "$out" \
        "added smoke-viewer as a viewer with a one-time password"
    check "panel: the new admin's one-time password kept out of the audit log" lacks "$out" "$viewer_password"
    out=$("${web[@]}" "$base/account" 2>&1)
    check "panel: the account page shows the admin's own account" contains "$out" \
        '<h1 class="h1">Your account</h1>'
    out=$("${web[@]}" "$base/password" 2>&1)
    check "panel: a password change by choice offers the way back" contains "$out" "Back to your account"

    # A setting the environment leaves unset is changed on the Settings page
    # and reaches the running server with a reload.
    out=$("${web[@]}" "$base/settings" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "BANNER=Smoke banner" "$base/settings" 2>&1)
    check "panel: a reloadable setting is saved and reloaded" test "$out" == "303 $base/settings?done=reloaded"
    out=$(server_exec panel cat /run/ocserv/ocserv.conf 2>&1)
    check "panel: the running configuration has the new setting" contains "$out" 'banner = "Smoke banner"'
    out=$(server_exec panel cat /config/panel/settings.env 2>&1)
    check "panel: the setting is stored for the next start" contains "$out" "BANNER=Smoke banner"
    out=$(server_exec panel cat /config/panel/audit.log 2>&1)
    check "panel: audit log records the setting" contains "$out" \
        "set BANNER to Smoke banner; applied with a reload"
    out=$("${web[@]}" "$base/certificates" 2>&1)
    check "panel: the Certificates page shows the server's key pin" contains "$out" "pin-sha256:"
    check "panel: the Certificates page reads every certificate" lacks "$out" "could not be read"

    # c2 may reach the panel but is not on a trusted network: a password alone
    # opens only the page that sets up an authenticator app, and once one is
    # set up every sign-in from c2 also takes a code from it.
    local -a far=(client_exec c2 curl -sS -m 20 --cacert /tmp/panel-ca.pem
        --resolve "$SMOKE_ID-panel:8443:$ip" -b /tmp/panel.jar -c /tmp/panel.jar)
    server_exec panel cat /config/certs/ca.pem | "$ENGINE" exec -i "$SMOKE_ID-c2" sh -c 'cat > /tmp/panel-ca.pem'
    client_exec c2 cp /dev/null /tmp/panel.jar
    out=$("${far[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode name=admin --data-urlencode "password=$new_password" "$base/login" 2>&1)
    check "panel: off the trusted networks, a password alone leads to the authenticator setup" \
        test "$out" == "303 $base/enroll"
    out=$("${far[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' "$base/" 2>&1)
    check "panel: the setup session cannot open the dashboard" test "$out" == "303 $base/enroll"
    out=$("${far[@]}" "$base/enroll" 2>&1)
    check "panel: the setup page offers a passkey beside the app" contains "$out" "data-passkey-add"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${far[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" "$base/enroll/start" 2>&1)
    check "panel: an authenticator key is issued" test "$out" == "303 $base/enroll"
    out=$("${far[@]}" "$base/enroll" 2>&1)
    check "panel: the key is shown as a QR code" contains "$out" '<svg class="qr"'
    key=${out#*class=\"mono key-text\">}
    key=${key%%<*}
    key=${key// /}
    code=$(client_exec c2 oathtool --totp -b "$key" 2>&1)
    out=$("${far[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "code=$code" "$base/enroll" 2>&1)
    check "panel: a code from the app turns it on" test "$out" == "303 $base/"
    out=$("${far[@]}" "$base/" 2>&1)
    check "panel: dashboard shown once the app is on" contains "$out" '<h1 class="h1">Dashboard</h1>'
    out=$("${far[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" -d '' "$base/logout" 2>&1)
    check "panel: sign out off the trusted networks" test "$out" == "303 $base/login"
    out=$("${far[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode name=admin --data-urlencode "password=$new_password" "$base/login" 2>&1)
    check "panel: off the trusted networks, the password then asks for a code" \
        test "$out" == "303 $base/second-factor"
    code=$(client_exec c2 oathtool --totp -b -N "@$(($(date +%s) + 30))" "$key" 2>&1)
    out=$("${far[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "code=$code" "$base/second-factor" 2>&1)
    check "panel: password and code sign in" test "$out" == "303 $base/"
    out=$(server_exec panel cat /config/panel/audit.log 2>&1)
    check "panel: audit log records the authenticator setup" contains "$out" \
        '"action":"totp.confirm","result":"allowed"'
    check "panel: audit log records the sign-in with a code" contains "$out" '"detail":"password and TOTP code"'
    check "panel: authenticator key kept out of the audit log" lacks "$out" "$key"

    # A VPN client on c1 shows on the dashboard and the Sessions page, and
    # ending its session there drops its tunnel for good.
    check "panel: VPN user added" add_user panel
    if out=$(connect c1 panel); then
        pass "panel: a VPN client connects to the panel's server"
    else
        fail "panel: a VPN client connects to the panel's server" "$out"
    fi
    out=$("${web[@]}" "$base/" 2>&1)
    check "panel: the dashboard shows the VPN server running" contains "$out" '<div class="stat-v">Running</div>'
    out=$("${web[@]}" "$base/sessions" 2>&1)
    check "panel: the Sessions page lists the VPN user" contains "$out" "<div>$SMOKE_USER</div>"
    id=${out#*name=\"id\" value=\"}
    id=${id%%\"*}
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "id=$id" "$base/sessions/end" 2>&1)
    check "panel: ending the session is confirmed" test "$out" == "303 $base/sessions?ended=1"
    check "panel: the ended session's tunnel drops" client_exec c1 sh -c '
        i=0
        while [ -e /sys/class/net/tun0 ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done
        [ ! -e /sys/class/net/tun0 ]'
    check_fails "panel: the ended session does not reconnect" client_exec c1 pgrep -x openconnect
    out=$(server_exec panel cat /config/panel/audit.log 2>&1)
    check "panel: audit log records the ended session" contains "$out" "ended session $id of $SMOKE_USER"
    disconnect c1 >/dev/null 2>&1

    # A VPN user added in the panel gets an onboarding kit with the server's
    # key pin, as openssl computes it, and connects; a user given a generated
    # password connects with the password the kit shows; locked in the
    # panel, a user is refused.
    out=$("${web[@]}" "$base/users" 2>&1)
    check "panel: the VPN users page lists the user" contains "$out" \
        "<a class=\"name-link\" href=\"/users/$SMOKE_USER/settings\">$SMOKE_USER</a>"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode change=add \
        --data-urlencode name=panel-made --data-urlencode password_choice=type \
        --data-urlencode "password=$SMOKE_PASS" --data-urlencode groups= "$base/users/change" 2>&1)
    check "panel: a VPN user is added and gets an onboarding kit" contains "$out" "Onboarding kit for panel-made"
    check "panel: the kit gives the server's key pin" contains "$out" "pin-sha256:$(pin_of panel c1)"
    if out=$(connect c1 panel "" "" panel-made); then
        pass "panel: the user added in the panel connects"
    else
        fail "panel: the user added in the panel connects" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode change=add \
        --data-urlencode name=panel-kit --data-urlencode password_choice=generate \
        --data-urlencode groups= "$base/users/change" 2>&1)
    generated=${out#*id=\"kit-password\">}
    generated=${generated%%<*}
    check "panel: a generated password is words and a number" matches "$generated" '^[a-z0-9]+(-[a-z0-9]+){5,}$'
    if out=$(connect c1 panel "" "" panel-kit "$generated"); then
        pass "panel: the user with a generated password connects with it"
    else
        fail "panel: the user with a generated password connects with it" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode change=lock --data-urlencode name=panel-made \
        "$base/users/change" 2>&1)
    check "panel: the user is locked" test "$out" == "303 $base/users?done=lock"
    check_fails "panel: a locked user is refused" connect c1 panel "" "" panel-made
    disconnect c1 >/dev/null 2>&1
    out=$(server_exec panel sh -c 'stat -c "%a" /config/ocpasswd; cat /config/ocpasswd' 2>&1)
    check "panel: the password file stays private" matches "$out" '^600'
    check "panel: the locked user keeps a marked password" contains "$out" "panel-made:*:!"

    # A fixed address saved on a user's settings page is the one ocserv gives
    # them at their next connection, and a group made on the Groups page gets
    # a settings file ocserv reads.
    out=$("${web[@]}" "$base/users/$SMOKE_USER/settings" 2>&1)
    check "panel: the user's settings page is shown" contains "$out" "Settings for $SMOKE_USER"
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode action=save \
        --data-urlencode fixed_ipv4=192.168.255.77 "$base/users/$SMOKE_USER/settings" 2>&1)
    check "panel: a fixed VPN address is saved for the user" test "$out" == \
        "303 $base/users/$SMOKE_USER/settings?done=saved"
    out=$(server_exec panel cat "/config/config-per-user/$SMOKE_USER" 2>&1)
    check "panel: the user's settings file holds the address" contains "$out" "explicit-ipv4 = 192.168.255.77"
    if out=$(connect c1 panel); then
        check "panel: the user gets the fixed address at the next connection" test "$out" == 192.168.255.77
    else
        fail "panel: the user gets the fixed address at the next connection" "$out"
    fi
    disconnect c1 >/dev/null 2>&1
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode name=smoke-group "$base/groups" 2>&1)
    check "panel: a group is created" test "$out" == "303 $base/groups/smoke-group?done=created"
    check "panel: the group gets a settings file" server_exec panel test -f /config/config-per-group/smoke-group
    out=$("${web[@]}" "$base/groups/smoke-group" 2>&1)
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode action=save --data-urlencode extra-idle-timeout=900 \
        --data-urlencode extra-ipv4-network=10.77.0.0/24 "$base/groups/smoke-group" 2>&1)
    check "panel: a group's further settings are saved" test "$out" == "303 $base/groups/smoke-group?done=saved"
    out=$(server_exec panel cat /config/config-per-group/smoke-group 2>&1)
    check "panel: the group's file holds its idle timeout" contains "$out" "idle-timeout = 900"
    check "panel: the group's pool is written as a network and a netmask" contains "$out" \
        $'ipv4-network = 10.77.0.0\nipv4-netmask = 255.255.255.0'
    out=$("${web[@]}" -H "Origin: $base" --data-urlencode "csrf=$csrf" --data-urlencode action=save \
        --data-urlencode extra-ipv4-network=192.168.255.0/25 "$base/groups/smoke-group" 2>&1)
    check "panel: a group pool inside the server's pool is refused" contains "$out" "overlaps the VPN"
    out=$(server_exec panel cat /config/panel/audit.log 2>&1)
    check "panel: audit log records the user's settings" contains "$out" \
        "set the settings of user $SMOKE_USER: fixed address 192.168.255.77"
    out=$("${web[@]}" "$base/api/history" 2>&1)
    check "panel: the dashboard history holds samples" matches "$out" '"interval":10,"time":\[[0-9]'

    # Wrong passwords from c3 get its address banned; the Bans page shows the
    # ban with the running ban score, and lifting it there clears it in ocserv.
    check "panel: wrong passwords get an address banned" guess_until_banned c3 panel
    out=$("${web[@]}" "$base/bans" 2>&1)
    check "panel: the Bans page lists the banned address" contains "$out" "<td class=\"mono\">$banned</td>"
    check "panel: the Bans page states the running ban score" contains "$out" "when its points reach 40"
    csrf=${out#*name=\"csrf\" value=\"}
    csrf=${csrf%%\"*}
    out=$("${web[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $base" \
        --data-urlencode "csrf=$csrf" --data-urlencode "address=$banned" "$base/bans/unban" 2>&1)
    check "panel: lifting the ban is confirmed" test "$out" == "303 $base/bans?done=1"
    out=$(server_exec panel occtl --json show ip bans 2>&1)
    check "panel: ocserv no longer bans the address" lacks "$out" "\"$banned\""
    out=$(server_exec panel cat /config/panel/audit.log 2>&1)
    check "panel: audit log records the lifted ban" contains "$out" "lifted the ban on $banned"
    out=$("${web[@]}" "$base/audit" 2>&1)
    check "panel: the Audit log page shows the lifted ban" contains "$out" "Lifted the ban on $banned"

    # The live events hold the connects and disconnects the session script
    # recorded, and the refused sign-ins and the ban the log relay found in
    # ocserv's log, whose lines still reach the container log.
    for i in $(seq 1 15); do
        out=$("${web[@]}" "$base/api/events" 2>&1)
        [[ $out == *"Banned $banned"* ]] && break
        sleep 1
    done
    check "panel: the live events show a VPN user connecting" contains "$out" "$SMOKE_USER connected from "
    check "panel: the live events show a VPN user disconnecting" contains "$out" "$SMOKE_USER disconnected"
    check "panel: the live events show a refused sign-in and why" contains "$out" \
        "A sign-in as $SMOKE_USER was refused: the password was wrong"
    check "panel: the live events show the ban" contains "$out" "Banned $banned"
    out=$(server_logs panel)
    check "panel: with the location checks on, VPN users connect" contains "$out" \
        "user $SMOKE_USER connected from"
    check "panel: the helper answered every connect's location check" lacks "$out" \
        "without a location check"
    out=$(server_exec panel env USERNAME="$SMOKE_USER" IP_REAL=203.0.113.5 \
        ocpanel check-location 2>&1; echo "exit $?")
    check "panel: ocpanel check-location gets the helper's answer" test "$out" == "exit 0"
    out=$("${web[@]}" "$base/bans" 2>&1)
    check "panel: the Bans page shows the location checks waiting for data" contains "$out" \
        "Waiting for data"
    check "panel: the Bans page locks the setting LOCATION_CHECKS makes" contains "$out" \
        "LOCATION_CHECKS</span>. Set by the container's environment"
    out=$("${web[@]}" "$base/" 2>&1)
    check "panel: the dashboard lists recent events" contains "$out" '<li class="ev" data-kind="ban">'
    out=$(server_logs panel)
    check "panel: ocserv's log still reaches the container log" contains "$out" \
        "failed authentication for '$SMOKE_USER'"
    out=$(server_exec panel sh -c 'stat -c "%U %a" /run/ocserv/panel-events
        if [ -z "$(ls -A /run/ocserv/panel-events)" ]; then echo empty; else ls -A /run/ocserv/panel-events; fi' 2>&1)
    check "panel: the event spool is root's, mode 700, and emptied" test "$out" == "root 700
empty"

    out=$(server_exec panel nft list chain inet vpn_gateway input 2>&1)
    check "panel: firewall admits the LAN client to the panel's port" matches "$out" \
        "tcp dport 8443 ip saddr ${admitted//./\\.}(/32)? accept"
    check "panel: firewall admits PANEL_ALLOWED_NETWORKS to the panel's port" matches "$out" \
        "tcp dport 8443 ip saddr ${outside//./\\.}(/32)? accept"
    check "panel: firewall admits the VPN pool to the panel's port" contains "$out" \
        "tcp dport 8443 ip saddr 192.168.255.0/24 accept"
    check "panel: firewall drops the panel's port for everyone else" contains "$out" "tcp dport 8443 drop"
    out=$(client_exec c3 bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/$0/8443"; echo "exit $?"' "$ip" 2>&1)
    check "panel: an address not admitted cannot connect" contains "$out" "exit 124"
    stop_server panel
}

# Checks for a platform that runs only under emulation, where tunnels and
# netfilter are not available: every shipped program runs, the unit suite
# passes with the image's own bash and tools, and ocserv accepts a rendered
# configuration with certificates the image's certtool created.
run_emulated() {
    IMAGE=${1:?usage: tests/run.sh emulated <image>}
    select_engine
    local tool
    local -a platform=()
    if [[ -n ${TEST_PLATFORM:-} ]]; then
        platform=(--platform "$TEST_PLATFORM")
    fi
    note "emulated checks of $IMAGE (${TEST_PLATFORM:-host platform}) with $ENGINE"
    for tool in "ocserv --version" "occtl --version" "ocpasswd --version" "ocpanel --version" "certtool --version" \
        "iptables-legacy --version" "bash --version" "tini --version"; do
        # shellcheck disable=SC2086
        check "emulated: $tool" "$ENGINE" run --rm "${platform[@]}" --entrypoint ${tool%% *} "$IMAGE" ${tool#* }
    done
    # nft opens a netfilter netlink socket even for --version, which QEMU's
    # user-mode emulation does not support, so only its libraries are checked.
    check "emulated: nft and its libraries load" "$ENGINE" run --rm "${platform[@]}" \
        --entrypoint sh "$IMAGE" -c 'ldd /usr/sbin/nft'
    local panel
    panel=$("$ENGINE" run --rm "${platform[@]}" -e PANEL_HOSTNAME=vpn.example.com \
        --entrypoint ocpanel "$IMAGE" check-config 2>&1)
    check "emulated: ocpanel starts a passkey registration" contains "$panel" \
        "passkeys: available, bound to vpn.example.com"
    check "emulated: unit suite inside the image" "$ENGINE" run --rm "${platform[@]}" -v "$REPO:/src:ro" \
        --entrypoint bash "$IMAGE" /src/tests/run.sh unit
    check "emulated: ocserv accepts the rendered configuration" "$ENGINE" run --rm "${platform[@]}" \
        -e CONFIG_DIR=/tmp/config -e RUNTIME_DIR=/tmp/run --entrypoint bash "$IMAGE" -c '
        set -Eeuo pipefail
        for module in common settings legacy certs config system firewall; do
            source /usr/local/lib/ocserv-docker/$module.sh
        done
        load_settings; prepare_dirs; ensure_certificates; ensure_passwd_file
        IPV6_ENABLED=true RESTRICT_ENABLED=false
        conf_build; conf_write "$RUNTIME_DIR/ocserv.conf" test
        ocserv --test-config --config "$RUNTIME_DIR/ocserv.conf"'
}

summary() {
    printf '%s %s passed, %s failed\n' "$(stamp)" "$PASSED" "$FAILED"
    ((FAILED == 0))
}

case ${1:-} in
    unit)
        run_unit
        summary
        ;;
    smoke)
        run_smoke "${2:-}"
        summary
        ;;
    emulated)
        section run_emulated "${2:-}"
        summary
        ;;
    *)
        printf 'usage: %s unit | smoke <image> | emulated <image>\n' "$0" >&2
        exit 2
        ;;
esac
