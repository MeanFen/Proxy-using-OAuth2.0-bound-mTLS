#!/bin/bash
set -e

CLIENT_NAME=${1:-client}
BACKUP_DIR="certs/backup/${CLIENT_NAME}-$(date +%Y%m%d-%H%M%S)"

echo "[+] Khởi tạo thư mục sao lưu lưu trữ tại: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

echo "[+] Đang sao lưu chứng chỉ và khóa cũ..."
cp certs/${CLIENT_NAME}.crt "$BACKUP_DIR/" || true
cp certs/${CLIENT_NAME}.key "$BACKUP_DIR/" || true

echo "[+] Sinh cặp khóa Private Key 2048-bit mới..."
openssl genrsa -out certs/${CLIENT_NAME}.key 2048

echo "[+] Tạo yêu cầu ký số (CSR) mới..."
openssl req -new \
  -key certs/${CLIENT_NAME}.key \
  -out certs/${CLIENT_NAME}.csr \
  -subj "/CN=${CLIENT_NAME}"

# Đảm bảo có file ext để gán quyền clientAuth cho cert mới
if [ ! -f "certs/client.ext" ]; then
cat > certs/client.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
fi

echo "[+] Tiến hành ký cấp chứng chỉ client mới từ Root CA..."
openssl x509 -req \
  -in certs/${CLIENT_NAME}.csr \
  -CA certs/root-ca.crt \
  -CAkey certs/root-ca.key \
  -CAcreateserial \
  -out certs/${CLIENT_NAME}.crt \
  -days 365 \
  -sha256 \
  -extfile certs/client.ext

# Dọn dẹp file csr tạm
rm -f certs/${CLIENT_NAME}.csr

echo "[+] Cấp mới và xoay vòng chứng chỉ thành công!"
