role=$1
cd "$2"
umask 077

make_ca() {
    local ca=$1 subject=$2
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
        -days 2 -subj "/CN=$subject" -keyout "$ca.key" -out "$ca.pem" \
        -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign'
}

issue_certificate() {
    local ca=$1 subject=$2 name=$3 cert=$4
    shift 4
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
        -subj "/CN=$subject" -keyout "$name.key" -out "$name.csr"
    printf '%s\n' "$@" > "$name.ext"
    openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" \
        -CAcreateserial -days 1 -extfile "$name.ext" -out "$cert.pem"
}

case "$role" in
    mock)
        # The mock platform CA is separate from HTTPS trust.
        make_ca platform-ca 'Mock Platform CA'
        issue_certificate platform-ca 'Mock Platform Quote Signer' signing signing-cert \
            'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature'
        rm platform-ca.key
        ;;
    attester)
        # Both HTTPS certificates use the same name and CA but have separate keys.
        make_ca ca 'HTTPS Test CA'
        for cert in server rotated; do
            issue_certificate ca localhost "$cert" "$cert" \
                'subjectAltName=DNS:localhost' 'extendedKeyUsage=serverAuth'
        done
        rm ca.key
        ;;
    *)
        printf 'Usage: setup-certificate {mock|attester} STATE_DIRECTORY\n' >&2
        exit 2
        ;;
esac
