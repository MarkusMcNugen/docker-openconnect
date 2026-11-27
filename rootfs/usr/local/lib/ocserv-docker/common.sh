# shellcheck shell=bash
# Logging and input validation shared by the entrypoint modules. Sourcing this
# file defines functions only.

log() {
    local level=$1
    shift
    printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$*"
}

info() { log info "$@"; }
warn() { log warn "$@" >&2; }

die() {
    log error "$@" >&2
    exit 1
}

# Normalizes the named variable to "true" or "false", using the default when
# it is unset or empty. Accepts true/false, yes/no, on/off and 1/0.
set_bool() {
    local name=$1 default=$2
    local raw=${!name:-$default}
    case ${raw,,} in
        1 | y | yes | true | on) printf -v "$name" '%s' true ;;
        0 | n | no | false | off) printf -v "$name" '%s' false ;;
        *) die "$name must be true or false (got '$raw')" ;;
    esac
}

# Sets the named variable to the default when it is unset or empty.
set_default() {
    local name=$1 default=$2
    if [[ -z ${!name:-} ]]; then
        printf -v "$name" '%s' "$default"
    fi
}

require_uint() {
    local name=$1
    [[ ${!name} =~ ^[0-9]+$ ]] || die "$name must be a non-negative integer (got '${!name}')"
}

require_port() {
    local name=$1
    require_uint "$name"
    ((${!name} >= 1 && ${!name} <= 65535)) || die "$name must be between 1 and 65535 (got '${!name}')"
}

require_choice() {
    local name=$1 choice
    shift
    for choice in "$@"; do
        [[ ${!name} == "$choice" ]] && return 0
    done
    die "$name must be one of: $* (got '${!name}')"
}

# Rejects characters that would break out of a double-quoted value in
# ocserv.conf or a certtool template.
require_plain_text() {
    local name=$1
    [[ ${!name} != *'"'* && ${!name} != *$'\n'* && ${!name} != *\\* ]] \
        || die "$name must not contain double quotes, backslashes or newlines"
}

is_ipv4_cidr() {
    local re='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/([0-9]|[12][0-9]|3[0-2])$'
    [[ $1 =~ $re ]]
}

is_ipv4() {
    local re='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    [[ $1 =~ $re ]]
}

is_ipv6_cidr() {
    [[ $1 =~ ^[0-9A-Fa-f:]+:[0-9A-Fa-f:]*/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$ ]]
}

is_ipv6() {
    [[ $1 =~ ^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*$ ]]
}

# Splits a comma- or newline-separated list into the named array, trimming
# whitespace and dropping empty items.
split_list() {
    local -n _out=$1
    local item
    _out=()
    while IFS= read -r item; do
        item=${item#"${item%%[![:space:]]*}"}
        item=${item%"${item##*[![:space:]]}"}
        [[ -n $item ]] && _out+=("$item")
    done < <(printf '%s\n' "$2" | tr ',' '\n')
    return 0
}

# Converts a dotted-decimal netmask to a prefix length on stdout.
netmask_to_prefix() {
    local mask=$1 octet bits=0 seen_partial=false count=0
    local IFS=.
    for octet in $mask; do
        count=$((count + 1))
        if $seen_partial && [[ $octet != 0 ]]; then
            return 1
        fi
        case $octet in
            255) bits=$((bits + 8)) ;;
            254) bits=$((bits + 7)) seen_partial=true ;;
            252) bits=$((bits + 6)) seen_partial=true ;;
            248) bits=$((bits + 5)) seen_partial=true ;;
            240) bits=$((bits + 4)) seen_partial=true ;;
            224) bits=$((bits + 3)) seen_partial=true ;;
            192) bits=$((bits + 2)) seen_partial=true ;;
            128) bits=$((bits + 1)) seen_partial=true ;;
            0) seen_partial=true ;;
            *) return 1 ;;
        esac
    done
    ((count == 4)) || return 1
    printf '%s\n' "$bits"
}
