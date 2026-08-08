#!/bin/bash
set -e

CLIENT_NAME=${1:-client}

if [ ! -f "certs/${CLIENT_NAME}.crt" ]; then
    echo "[-] Lỗi: Không tìm thấy file certs/${CLIENT_NAME}.crt"
    exit 1
fi

echo "[+] Đang tiến hành thu hồi chứng chỉ: certs/${CLIENT_NAME}.crt"
openssl ca -config certs/openssl.cnf -revoke certs/${CLIENT_NAME}.crt

echo "[+] Đang cập nhật danh sách thu hồi CRL (ca.crl) cho Envoy Gateway..."
openssl ca -config certs/openssl.cnf -gencrl -out certs/crl/ca.crl

echo "[+] Trích xuất thumbprint đưa vào danh sách đen revoked.txt của Auth Service..."
openssl x509 -in certs/${CLIENT_NAME}.crt -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A \
  | tr '+/' '-_' \
  | tr -d '=' >> certs/crl/revoked.txt

echo "[+] Đã thu hồi chứng chỉ thành công!"
echo "[+] File danh sách đen cập nhật tại: certs/crl/ca.crl và certs/crl/revoked.txt"
