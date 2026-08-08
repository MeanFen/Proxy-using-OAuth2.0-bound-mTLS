#!/bin/bash

# Thoát script ngay nếu có lệnh bị lỗi
set -e

# 1. CẤU HÌNH THƯ MỤC VÀ KHAI BÁO BIẾN
CERT_DIR="./certs"
mkdir -p "$CERT_DIR"

echo "========================================="
echo " KHỞI TẠO HẠ TẦNG PKI CHO ĐỒ ÁN ZERO-TRUST"
echo "========================================="

# 2. SINH ROOT CA (Chứng chỉ gốc của hệ thống)
echo -e "\n[1/3] Đang khởi tạo Root CA..."
# Sinh Private Key cho Root CA
openssl genrsa -out "$CERT_DIR/root-ca.key" 4096

# Tự ký Root Certificate (Thời hạn 10 năm)
openssl req -x509 -new -nodes \
    -key "$CERT_DIR/root-ca.key" \
    -sha256 -days 3650 \
    -out "$CERT_DIR/root-ca.crt" \
    -subj "/C=VN/ST=HoChiMinh/L=ThuDuc/O=UTE_ZeroTrust_Group/OU=PKI/CN=ZeroTrust Root CA"

# 3. SINH SERVER CERTIFICATE (Dành cho Envoy Proxy)
echo -e "\n[2/3] Đang khởi tạo Server Certificate cho Envoy..."
# Sinh Private Key cho Server
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Tạo Certificate Signing Request (CSR) cho Server
openssl req -new \
    -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=VN/ST=HoChiMinh/L=ThuDuc/O=UTE_ZeroTrust_Group/OU=Gateway/CN=zero-trust-gateway"

# Tạo file cấu hình phần mở rộng mở rộng (SAN - Subject Alternative Name)
# Cực kỳ quan trọng để Envoy nhận diện domain hợp lệ (localhost hoặc tên service trong docker)
cat > "$CERT_DIR/server.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = gateway.zero-trust.local
IP.1 = 127.0.0.1
EOF

# Ký Server Cert bằng Root CA (Thời hạn 1 năm)
openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/root-ca.crt" \
    -CAkey "$CERT_DIR/root-ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" \
    -days 365 -sha256 \
    -extfile "$CERT_DIR/server.ext"

# 4. SINH CLIENT CERTIFICATE (Dành cho Postman / Test Client)
echo -e "\n[3/3] Đang khởi tạo Client Certificate cho Test Client..."
# Sinh Private Key cho Client
openssl genrsa -out "$CERT_DIR/client.key" 2048

# Tạo CSR cho Client
openssl req -new \
    -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -subj "/C=VN/ST=HoChiMinh/L=ThuDuc/O=UTE_ZeroTrust_Group/OU=Client/CN=test-client"

# Cấu hình phần mở rộng cho Client (Bắt buộc phải có thuộc tính clientAuth)
cat > "$CERT_DIR/client.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

# Ký Client Cert bằng Root CA (Thời hạn 1 năm)
openssl x509 -req -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/root-ca.crt" \
    -CAkey "$CERT_DIR/root-ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/client.crt" \
    -days 365 -sha256 \
    -extfile "$CERT_DIR/client.ext"

# 5. DỌN DẸP FILE TẠM VÀ XUẤT THÔNG TIN CHO TRƯỜNG 'cnf' (RFC 8705)
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/server.ext" "$CERT_DIR/client.csr" "$CERT_DIR/client.ext"

echo -e "\n========================================="
echo " ĐÃ SINH THÀNH CÔNG TOÀN BỘ CHỨNG CHỈ!"
echo " Các file được lưu tại thư mục: $CERT_DIR"
echo "========================================="
ls -l "$CERT_DIR"

echo -e "\n-----------------------------------------"
echo " THÔNG TIN QUAN TRỌNG CHO PHAN PHƯỚC NGHĨA (AUTH SERVICE):"
echo " Để làm cấu hình claim 'cnf' (x5t#S256) trong JWT theo RFC 8705,"
echo " giá trị Base64URL SHA-256 thumbprint của Client Cert này là:"
echo "-----------------------------------------"

# Tính toán SHA-256 định dạng DER và mã hóa Base64URL theo RFC 8705
X5T_S256=$(openssl x509 -in "$CERT_DIR/client.crt" -outform DER | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
echo -e "\e[1;32m$X5T_S256\e[0m"
echo "-----------------------------------------"
