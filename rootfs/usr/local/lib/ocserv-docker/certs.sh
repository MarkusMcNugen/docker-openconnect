# shellcheck shell=bash
# Creates a private CA and a server certificate when the default certificate
# files are missing, and reissues a server certificate this module created
# when it is within CERT_RENEW_DAYS of expiry or SRV_CN / SRV_SAN changed.
# A reissue keeps server-key.pem, so a client that pinned the key still
# connects. Requires common.sh and settings.sh.

readonly CERT_RENEW_DAYS=30

# Runs a command and prints its combined output only when it fails.
run_quiet() {
    local output
    if ! output=$("$@" 2>&1); then
        printf '%s\n' "$output" >&2
        die "command failed: $*"
    fi
}

file_sha256() {
    local hash _
    read -r hash _ < <(sha256sum "$1")
    printf '%s\n' "$hash"
}

generate_key() {
    local out=$1
    if [[ $CERT_KEY_TYPE == rsa ]]; then
        run_quiet certtool --generate-privkey --key-type=rsa --bits=3072 --outfile "$out"
    else
        run_quiet certtool --generate-privkey --key-type=ecdsa --curve=secp256r1 --outfile "$out"
    fi
    chmod 0600 "$out"
}

key_is_rsa() {
    local info
    info=$(certtool --key-info --infile "$1" 2>&1) || die "cannot read the private key $1"
    [[ $info == *"Algorithm: RSA"* ]]
}

# The certificate subject this configuration asks for, as stored in the marker.
cert_subject() {
    local IFS=,
    printf '%s\n' "$SRV_CN${SRV_SAN_LIST[*]:+,${SRV_SAN_LIST[*]}}"
}

san_lines() {
    local name
    local -A seen=()
    for name in "$SRV_CN" "${SRV_SAN_LIST[@]}"; do
        [[ -v seen[$name] ]] && continue
        seen[$name]=1
        if is_ipv4 "$name" || is_ipv6 "$name"; then
            printf 'ip_address = "%s"\n' "$name"
        else
            printf 'dns_name = "%s"\n' "$name"
        fi
    done
}

create_ca() {
    local dir=$1 tmpl=$RUNTIME_DIR/ca.tmpl
    generate_key "$dir/ca-key.pem"
    {
        printf 'cn = "%s"\n' "$CA_CN"
        printf 'organization = "%s"\n' "$CA_ORG"
        printf 'expiration_days = %s\n' "$CA_DAYS"
        printf 'ca\npath_len = 0\ncert_signing_key\ncrl_signing_key\n'
    } >"$tmpl"
    run_quiet certtool --generate-self-signed --load-privkey "$dir/ca-key.pem" \
        --template "$tmpl" --outfile "$dir/ca.pem"
    chmod 0644 "$dir/ca.pem"
}

# Issues server-cert.pem for server-key.pem and records it in the marker.
issue_server_cert() {
    local dir=$1 tmpl=$RUNTIME_DIR/server.tmpl expires
    {
        printf 'cn = "%s"\n' "$SRV_CN"
        printf 'organization = "%s"\n' "$SRV_ORG"
        printf 'expiration_days = %s\n' "$SRV_DAYS"
        san_lines
        printf 'signing_key\n'
        if key_is_rsa "$dir/server-key.pem"; then
            printf 'encryption_key\n'
        fi
        printf 'tls_www_server\n'
    } >"$tmpl"
    run_quiet certtool --generate-certificate --load-privkey "$dir/server-key.pem" \
        --load-ca-certificate "$dir/ca.pem" --load-ca-privkey "$dir/ca-key.pem" \
        --template "$tmpl" --outfile "$dir/server-cert.pem"
    chmod 0644 "$dir/server-cert.pem"

    expires=$(($(date +%s) + SRV_DAYS * 86400))
    {
        printf 'cert_sha256=%s\n' "$(file_sha256 "$dir/server-cert.pem")"
        printf 'expires=%s\n' "$expires"
        printf 'subject=%s\n' "$(cert_subject)"
    } >"$dir/.generated"
}

# Reissues a certificate this module created when it nears expiry or the
# requested names changed. Leaves any other certificate untouched.
renew_generated_cert() {
    local dir=$1 marker=$1/.generated key value
    local cert_sha256="" expires=0 subject="" reason=""
    [[ -f $marker && -f $dir/ca.pem && -f $dir/ca-key.pem ]] || return 0
    while IFS='=' read -r key value; do
        case $key in
            cert_sha256) cert_sha256=$value ;;
            expires) expires=$value ;;
            subject) subject=$value ;;
        esac
    done <"$marker"
    [[ $cert_sha256 == "$(file_sha256 "$dir/server-cert.pem")" ]] || return 0
    [[ $expires =~ ^[0-9]+$ ]] || expires=0

    if ((expires - $(date +%s) < CERT_RENEW_DAYS * 86400)); then
        reason="it expires within $CERT_RENEW_DAYS days"
    elif [[ $subject != "$(cert_subject)" ]]; then
        reason="SRV_CN or SRV_SAN changed"
    fi
    [[ -n $reason ]] || return 0

    issue_server_cert "$dir"
    info "reissued the self-signed server certificate because $reason; the server key is unchanged"
}

# The name browsers use for the admin panel: PANEL_HOSTNAME, else SRV_CN.
# ocpanel check-config validates it before any certificate is issued for it.
panel_hostname() {
    printf '%s\n' "${PANEL_HOSTNAME:-$SRV_CN}"
}

# Issues the admin panel's certificate, cert.pem for key.pem in $1, from the
# image's CA in $2, and records it in the directory's marker.
issue_panel_cert() {
    local dir=$1 ca_dir=$2 tmpl=$RUNTIME_DIR/panel.tmpl name expires
    name=$(panel_hostname)
    {
        printf 'cn = "%s"\n' "$name"
        printf 'organization = "%s"\n' "$SRV_ORG"
        printf 'expiration_days = %s\n' "$SRV_DAYS"
        if is_ipv4 "$name" || is_ipv6 "$name"; then
            printf 'ip_address = "%s"\n' "$name"
        else
            printf 'dns_name = "%s"\n' "$name"
        fi
        printf 'signing_key\ntls_www_server\n'
    } >"$tmpl"
    run_quiet certtool --generate-certificate --load-privkey "$dir/key.pem" \
        --load-ca-certificate "$ca_dir/ca.pem" --load-ca-privkey "$ca_dir/ca-key.pem" \
        --template "$tmpl" --outfile "$dir/cert.pem"
    chmod 0600 "$dir/cert.pem"
    expires=$(($(date +%s) + SRV_DAYS * 86400))
    {
        printf 'cert_sha256=%s\n' "$(file_sha256 "$dir/cert.pem")"
        printf 'expires=%s\n' "$expires"
        printf 'subject=%s\n' "$name"
    } >"$dir/.generated"
}

# Makes sure the admin panel has its own key and a certificate from the
# image's CA in $CONFIG_DIR/panel/tls. A certificate this module issued is
# reissued, with the same key, when it nears expiry or the panel's name
# changed; a certificate placed there by hand is left as it is.
ensure_panel_certificate() {
    local ca_dir=$CONFIG_DIR/certs dir=$CONFIG_DIR/panel/tls
    local marker=$CONFIG_DIR/panel/tls/.generated key value
    local cert_sha256="" expires=0 subject="" reason=""
    [[ -f $ca_dir/ca.pem && -f $ca_dir/ca-key.pem ]] ||
        die "the admin panel's certificate is issued by the image's CA, and $ca_dir has none (a custom SERVER_CERT and SERVER_KEY do not create one)"
    mkdir -p "$dir"
    chmod 0700 "$CONFIG_DIR/panel" "$dir"
    if [[ ! -f $dir/key.pem ]]; then
        generate_key "$dir/key.pem"
    fi
    chmod 0600 "$dir/key.pem"
    if [[ -f $dir/cert.pem ]]; then
        [[ -f $marker ]] || return 0
        while IFS='=' read -r key value; do
            case $key in
                cert_sha256) cert_sha256=$value ;;
                expires) expires=$value ;;
                subject) subject=$value ;;
            esac
        done <"$marker"
        [[ $cert_sha256 == "$(file_sha256 "$dir/cert.pem")" ]] || return 0
        [[ $expires =~ ^[0-9]+$ ]] || expires=0
        if ((expires - $(date +%s) < CERT_RENEW_DAYS * 86400)); then
            reason="it expires within $CERT_RENEW_DAYS days"
        elif [[ $subject != "$(panel_hostname)" ]]; then
            reason="the panel's name changed"
        fi
        [[ -n $reason ]] || return 0
    fi
    issue_panel_cert "$dir" "$ca_dir"
    info "issued the admin panel's certificate for $(panel_hostname) from $ca_dir/ca.pem${reason:+ because $reason}; the panel's key is its own"
}

# Writes the revocation list of the VPN users' client CA in $1: every
# certificate in $1/client-revoked, valid for a year. GnuTLS refuses every
# certificate once the list's next-update date passes, so the list is
# written again at every start, every revocation and once a day. It replaces
# the old list in one rename, so ocserv, which loads the list again when it
# changes, never reads half of one.
write_client_crl() {
    local dir=$1 work file output
    local -a revoked=()
    work=$(mktemp -d)
    printf 'crl_next_update = 365\ncrl_number = %s\n' "$(date +%s)" >"$work/crl.tmpl"
    for file in "$dir"/client-revoked/*.pem; do
        [[ -f $file ]] && revoked+=("$file")
    done
    if ((${#revoked[@]} > 0)); then
        cat -- "${revoked[@]}" >"$work/revoked.pem"
        revoked=(--load-certificate "$work/revoked.pem")
    fi
    if ! output=$(certtool --generate-crl --load-ca-privkey "$dir/client-ca-key.pem" \
        --load-ca-certificate "$dir/client-ca.pem" "${revoked[@]}" \
        --template "$work/crl.tmpl" --outfile "$work/crl.pem" 2>&1); then
        printf '%s\n' "$output" >&2
        rm -rf -- "$work"
        return 1
    fi
    chmod 0644 "$work/crl.pem"
    mv -f -- "$work/crl.pem" "$dir/client-crl.pem.new"
    mv -f -- "$dir/client-crl.pem.new" "$dir/client-crl.pem"
    rm -rf -- "$work"
}

# Makes sure the CA that signs VPN users' client certificates, and nothing
# else, exists with a fresh revocation list whenever certificates sign users
# in or the admin panel is on to issue them.
ensure_client_ca() {
    local dir=$CONFIG_DIR/certs tmpl=$RUNTIME_DIR/client-ca.tmpl
    [[ $AUTH_MODE != password || $PANEL_ENABLED == true ]] || return 0
    mkdir -p "$dir/client-revoked"
    chmod 0700 "$dir" "$dir/client-revoked"
    if [[ ! -f $dir/client-ca.pem || ! -f $dir/client-ca-key.pem ]]; then
        generate_key "$dir/client-ca-key.pem"
        chmod 0600 "$dir/client-ca-key.pem"
        {
            printf 'cn = "VPN client CA"\n'
            printf 'organization = "%s"\n' "$CA_ORG"
            printf 'expiration_days = %s\n' "$CA_DAYS"
            printf 'ca\npath_len = 0\ncert_signing_key\ncrl_signing_key\n'
        } >"$tmpl"
        run_quiet certtool --generate-self-signed --load-privkey "$dir/client-ca-key.pem" \
            --template "$tmpl" --outfile "$dir/client-ca.pem"
        chmod 0644 "$dir/client-ca.pem"
        info "created the CA for VPN users' client certificates in $dir/client-ca.pem"
    fi
    write_client_crl "$dir" || die "the revocation list of $dir/client-ca.pem could not be written"
}

ensure_certificates() {
    local dir=$CONFIG_DIR/certs
    if [[ -f $SERVER_CERT && -f $SERVER_KEY ]]; then
        if [[ $SERVER_CERT == "$dir/server-cert.pem" && $SERVER_KEY == "$dir/server-key.pem" ]]; then
            renew_generated_cert "$dir"
        fi
        return 0
    fi
    if [[ $SERVER_CERT != "$dir/server-cert.pem" || $SERVER_KEY != "$dir/server-key.pem" ]]; then
        die "SERVER_CERT ($SERVER_CERT) and SERVER_KEY ($SERVER_KEY) must both exist"
    fi

    mkdir -p "$dir"
    chmod 0700 "$dir"
    if [[ ! -f $dir/ca.pem || ! -f $dir/ca-key.pem ]]; then
        create_ca "$dir"
        info "created a private CA in $dir/ca.pem"
    fi
    if [[ ! -f $dir/server-key.pem ]]; then
        generate_key "$dir/server-key.pem"
    fi
    issue_server_cert "$dir"
    info "created a server certificate for $(cert_subject), valid $SRV_DAYS days; clients must trust $dir/ca.pem or pin the server key"
}
