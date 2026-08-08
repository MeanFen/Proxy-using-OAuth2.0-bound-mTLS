#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT_DIR/infra/certs"
BFF_DIR="$CERT_DIR/bff"

CA_CERT="$CERT_DIR/root-ca.crt"
CA_KEY="$CERT_DIR/root-ca.key"
CA_SERIAL="$CERT_DIR/root-ca.srl"

mkdir -p "$BFF_DIR"
umask 077

for file in "$CA_CERT" "$CA_KEY"; do
    if [[ ! -f "$file" ]]; then
        echo "Thiếu file: $file"
        exit 1
    fi
done

sign_cert() {
    local csr="$1"
    local crt="$2"
    local ext="$3"

    if [[ -f "$CA_SERIAL" ]]; then
        openssl x509 -req \
            -in "$csr" \
            -CA "$CA_CERT" \
            -CAkey "$CA_KEY" \
            -CAserial "$CA_SERIAL" \
            -out "$crt" \
            -days 365 \
            -sha256 \
            -extfile "$ext"
    else
        openssl x509 -req \
            -in "$csr" \
            -CA "$CA_CERT" \
            -CAkey "$CA_KEY" \
            -CAcreateserial \
            -out "$crt" \
            -days 365 \
            -sha256 \
            -extfile "$ext"
    fi
}

echo "=== Sinh certificate BFF dùng để mTLS với Envoy ==="

cat > "$BFF_DIR/bff-client.ext" <<'EXT'
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=client-application-bff
EXT

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:3072 \
    -out "$BFF_DIR/bff-client.key"

openssl req -new \
    -key "$BFF_DIR/bff-client.key" \
    -out "$BFF_DIR/bff-client.csr" \
    -subj "/C=VN/ST=Khanh Hoa/L=Nha Trang/O=ZeroTrust Project/OU=Client Application/CN=client-application-bff"

sign_cert \
    "$BFF_DIR/bff-client.csr" \
    "$BFF_DIR/bff-client.crt" \
    "$BFF_DIR/bff-client.ext"

echo "=== Sinh certificate HTTPS cho Browser → BFF ==="

cat > "$BFF_DIR/bff-server.ext" <<'EXT'
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
DNS.2=client-application.local
IP.1=127.0.0.1
EXT

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:3072 \
    -out "$BFF_DIR/bff-server.key"

openssl req -new \
    -key "$BFF_DIR/bff-server.key" \
    -out "$BFF_DIR/bff-server.csr" \
    -subj "/C=VN/ST=Khanh Hoa/L=Nha Trang/O=ZeroTrust Project/OU=Client Application/CN=client-application-bff"

sign_cert \
    "$BFF_DIR/bff-server.csr" \
    "$BFF_DIR/bff-server.crt" \
    "$BFF_DIR/bff-server.ext"

chmod 600 \
    "$BFF_DIR/bff-client.key" \
    "$BFF_DIR/bff-server.key"

echo
echo "=== Xác minh BFF client certificate ==="

openssl verify \
    -CAfile "$CA_CERT" \
    -purpose sslclient \
    "$BFF_DIR/bff-client.crt"

echo
echo "=== Xác minh BFF server certificate ==="

openssl verify \
    -CAfile "$CA_CERT" \
    -purpose sslserver \
    -verify_hostname localhost \
    "$BFF_DIR/bff-server.crt"

rm -f \
    "$BFF_DIR/bff-client.csr" \
    "$BFF_DIR/bff-server.csr"

echo
echo "Hoàn thành sinh certificate BFF."
