# shellcheck shell=bash
# Recognizes the ocserv.conf, connect.sh and disconnect.sh files that the 1.x
# image copied into /config. Requires common.sh.
#
# A file is stock when its normalized form hashes to a value listed in
# legacy-defaults.sha256, which holds the hash of every version the 1.x image
# shipped. An ocserv.conf that normalizes to nothing is also stock: the 1.x
# entrypoint could replace every line with tcp-port lines.

readonly LEGACY_HASHES=${LEGACY_HASHES:-/usr/local/lib/ocserv-docker/legacy-defaults.sha256}

# Prints a 1.x file with carriage returns removed. For ocserv.conf it also
# drops the lines the 1.x entrypoint rewrote on every start: tcp-port,
# udp-port, route=, dns = and split-dns =.
legacy_normalize() {
    local kind=$1 file=$2 line
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        if [[ $kind == ocserv.conf ]]; then
            case $line in
                'tcp-port ='* | 'udp-port ='* | 'route='* | 'dns ='* | 'split-dns ='*) continue ;;
            esac
        fi
        printf '%s\n' "$line"
    done <"$file"
}

legacy_hash() {
    local hash _
    read -r hash _ < <(legacy_normalize "$1" "$2" | sha256sum)
    printf '%s\n' "$hash"
}

# Succeeds when the file is a stock 1.x file of the given kind.
legacy_is_stock() {
    local kind=$1 file=$2 hash listed listed_kind
    if [[ $kind == ocserv.conf && -z $(legacy_normalize "$kind" "$file") ]]; then
        return 0
    fi
    hash=$(legacy_hash "$kind" "$file")
    while read -r listed listed_kind; do
        [[ $listed == "$hash" && $listed_kind == "$kind" ]] && return 0
    done <"$LEGACY_HASHES"
    return 1
}

# Renames a file to <name>.legacy, or <name>.legacy.N when that name is taken.
legacy_retire() {
    local file=$1 target=$1.legacy n=1
    while [[ -e $target ]]; do
        target=$file.legacy.$n
        n=$((n + 1))
    done
    mv -- "$file" "$target"
    info "renamed the unmodified 1.x file $file to $target"
}

# Sets LEGACY_CONFIG to "true" when a hand-edited 1.x ocserv.conf is to be
# used as the whole configuration. Retires stock 1.x files. Does nothing when
# POWER_USER is true, since that configuration is used as it stands.
handle_legacy_files() {
    local conf=$CONFIG_DIR/ocserv.conf script
    LEGACY_CONFIG=false
    [[ $POWER_USER == true ]] && return 0

    if [[ -f $conf ]]; then
        if legacy_is_stock ocserv.conf "$conf"; then
            legacy_retire "$conf"
        else
            LEGACY_CONFIG=true
            warn "$conf was edited by hand under the 1.x image, so it is used as the whole configuration and the environment variables that shape ocserv.conf are not applied."
            warn "To switch to environment variables, rename $conf. To keep it and silence this warning, set POWER_USER=true."
            return 0
        fi
    fi

    for script in connect.sh disconnect.sh; do
        [[ -f $CONFIG_DIR/$script ]] || continue
        if legacy_is_stock "$script" "$CONFIG_DIR/$script"; then
            legacy_retire "$CONFIG_DIR/$script"
        else
            warn "$CONFIG_DIR/$script was edited by hand under the 1.x image and runs after the built-in session log. Move it to $CONFIG_DIR/hooks/$script to silence this warning."
        fi
    done
}
