# Xây dựng gateway sử dụng OAuth 2.0 mTLS bound token
## **Thành viên:**
1. Phan Phước Nghĩa
2. Nguyễn Xuân Vinh
3. Nguyễn Bá Nam
## 1. Cài công cụ cần thiết

```bash
sudo apt update

sudo apt install -y \
  git \
  docker.io \
  docker-compose-v2 \
  openssl \
  python3 \
  python3-venv \
  python3-pip \
  curl
```

Kiểm tra phiên bản:

```bash
git --version
docker --version
docker compose version
openssl version
python3 --version
```

## 2. Sinh Root CA, Envoy server certificate và client certificate

```bash
cd ~/zero-trust-project/infra

chmod +x setup.sh
bash setup.sh
```

Kiểm tra các file đã sinh:

```bash
ls -l \
  certs/root-ca.crt \
  certs/root-ca.key \
  certs/server.crt \
  certs/server.key \
  certs/client.crt \
  certs/client.key
```
---

## 3. Tạo JWT signing key riêng trên máy

```bash
cd ~/zero-trust-project

mkdir -p auth_service/keys

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out auth_service/keys/private.pem

openssl pkey \
  -in auth_service/keys/private.pem \
  -pubout \
  -out auth_service/keys/public.pem

chmod 600 auth_service/keys/private.pem
chmod 644 auth_service/keys/public.pem
```

Kiểm tra cặp khóa:

```bash
openssl pkey \
  -in auth_service/keys/private.pem \
  -check \
  -noout

openssl pkey \
  -pubin \
  -in auth_service/keys/public.pem \
  -noout
```

Private key phải nằm tại:

```text
auth_service/keys/private.pem
```

---

## 4. Kiểm tra certificate nội bộ đã được tạo chưa

```bash
cd ~/zero-trust-project

for file in \
  infra/service-certs/envoy/envoy-upstream.crt \
  infra/service-certs/envoy/envoy-upstream.key \
  infra/service-certs/auth/auth-service.crt \
  infra/service-certs/auth/auth-service.key \
  infra/service-certs/resource/resource-api.crt \
  infra/service-certs/resource/resource-api.key
do
    if [ -f "$file" ]; then
        echo "[OK] $file"
    else
        echo "[MISSING] $file"
    fi
done
```

Nếu cả sáu file đều hiển thị `[OK]`, bỏ qua **Mục 6**.

---

## 5. Sinh certificate nội bộ khi đang bị thiếu

Chạy nguyên khối lệnh sau:

```bash
cd ~/zero-trust-project

mkdir -p \
  infra/service-certs/ca \
  infra/service-certs/envoy \
  infra/service-certs/auth \
  infra/service-certs/resource

CA_DIR="infra/service-certs/ca"

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out "$CA_DIR/service-ca.key"

openssl req \
  -x509 \
  -new \
  -sha256 \
  -days 3650 \
  -key "$CA_DIR/service-ca.key" \
  -out "$CA_DIR/service-ca.crt" \
  -subj "/C=VN/O=Zero Trust Project/OU=Internal PKI/CN=Zero Trust Internal Service CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

make_service_cert() {
    FILE_NAME="$1"
    COMMON_NAME="$2"
    EXTENDED_USAGE="$3"
    OUTPUT_DIR="$4"

    openssl genpkey \
      -algorithm RSA \
      -pkeyopt rsa_keygen_bits:2048 \
      -out "$OUTPUT_DIR/$FILE_NAME.key"

    openssl req \
      -new \
      -key "$OUTPUT_DIR/$FILE_NAME.key" \
      -out "$OUTPUT_DIR/$FILE_NAME.csr" \
      -subj "/C=VN/O=Zero Trust Project/OU=Internal Services/CN=$COMMON_NAME"

    cat > "$OUTPUT_DIR/$FILE_NAME.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=$EXTENDED_USAGE
subjectAltName=DNS:$COMMON_NAME
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

    if [ -f "$CA_DIR/service-ca.srl" ]; then
        SERIAL_ARGS=(
          -CAserial "$CA_DIR/service-ca.srl"
        )
    else
        SERIAL_ARGS=(
          -CAcreateserial
        )
    fi

    openssl x509 \
      -req \
      -sha256 \
      -days 825 \
      -in "$OUTPUT_DIR/$FILE_NAME.csr" \
      -CA "$CA_DIR/service-ca.crt" \
      -CAkey "$CA_DIR/service-ca.key" \
      "${SERIAL_ARGS[@]}" \
      -extfile "$OUTPUT_DIR/$FILE_NAME.ext" \
      -out "$OUTPUT_DIR/$FILE_NAME.crt"

    rm -f \
      "$OUTPUT_DIR/$FILE_NAME.csr" \
      "$OUTPUT_DIR/$FILE_NAME.ext"

    chmod 600 "$OUTPUT_DIR/$FILE_NAME.key"
    chmod 644 "$OUTPUT_DIR/$FILE_NAME.crt"
}

make_service_cert \
  "envoy-upstream" \
  "zero-trust-gateway" \
  "clientAuth" \
  "infra/service-certs/envoy"

make_service_cert \
  "auth-service" \
  "auth-service" \
  "serverAuth" \
  "infra/service-certs/auth"

make_service_cert \
  "resource-api" \
  "resource-api" \
  "serverAuth" \
  "infra/service-certs/resource"

cp "$CA_DIR/service-ca.crt" \
  infra/service-certs/envoy/service-ca.crt

cp "$CA_DIR/service-ca.crt" \
  infra/service-certs/auth/service-ca.crt

cp "$CA_DIR/service-ca.crt" \
  infra/service-certs/resource/service-ca.crt
```

### Kiểm tra chuỗi tin cậy và hostname

```bash
openssl verify \
  -CAfile infra/service-certs/ca/service-ca.crt \
  -purpose sslserver \
  -verify_hostname auth-service \
  infra/service-certs/auth/auth-service.crt

openssl verify \
  -CAfile infra/service-certs/ca/service-ca.crt \
  -purpose sslserver \
  -verify_hostname resource-api \
  infra/service-certs/resource/resource-api.crt

openssl verify \
  -CAfile infra/service-certs/ca/service-ca.crt \
  -purpose sslclient \
  infra/service-certs/envoy/envoy-upstream.crt
```

Cả ba lệnh phải trả về `OK`.

---

## 6. Sinh certificate cho BFF

```bash
cd ~/zero-trust-project

chmod +x client_app/generate_bff_certs.sh
bash client_app/generate_bff_certs.sh
```

Kiểm tra các file đã sinh:

```bash
ls -l \
  infra/certs/bff/bff-client.crt \
  infra/certs/bff/bff-client.key \
  infra/certs/bff/bff-server.crt \
  infra/certs/bff/bff-server.key
```

Kiểm tra certificate HTTPS của BFF:

```bash
openssl verify \
  -CAfile infra/certs/root-ca.crt \
  -verify_hostname localhost \
  infra/certs/bff/bff-server.crt
```

Kết quả mong đợi:

```text
infra/certs/bff/bff-server.crt: OK
```

---

## 7. Kiểm tra cấu hình Docker Compose

```bash
cd ~/zero-trust-project/infra

sudo docker compose config
```

Nếu không báo thiếu certificate hoặc private key thì tiếp tục.

---

## 8. Build và chạy hệ thống Docker

```bash
sudo docker compose down --remove-orphans

sudo docker compose up \
  -d \
  --build \
  --force-recreate
```

Kiểm tra trạng thái:

```bash
sudo docker compose ps
```

Cần thấy ba service:

```text
auth-service
resource-api
zero-trust-gateway
```

Chỉ Envoy được publish cổng `443`. Auth Service và Resource API chỉ dùng cổng nội bộ `8443`.

Xem log:

```bash
sudo docker compose logs \
  --tail=100 \
  envoy \
  auth-service \
  resource-api
```

---

## 9. Tạo môi trường Python để chạy BFF và test

```bash
cd ~/zero-trust-project

python3 -m venv .venv-bff

source .venv-bff/bin/activate

python3 -m pip install --upgrade pip

python3 -m pip install \
  -r client_app/requirements.txt \
  PyJWT \
  cryptography
```

---

## 10. Chạy BFF

Mở **Terminal 1**:

```bash
cd ~/zero-trust-project

source .venv-bff/bin/activate

export BFF_SECRET_KEY="$(openssl rand -hex 32)"

python3 client_app/app.py
```

Giữ Terminal 1 mở.

Kết quả mong đợi:

```text
Running on https://127.0.0.1:5001
```

---

## 11. Chạy bộ kiểm thử BFF

Mở **Terminal 2**:

```bash
cd ~/zero-trust-project

source .venv-bff/bin/activate

read -s -p "Nhập mật khẩu demo: " DEMO_PASSWORD
echo
```

Nhập mật khẩu demo của tài khoản `vinh`.

Chạy test:

```bash
BFF_TEST_USERNAME="vinh" \
BFF_TEST_PASSWORD="$DEMO_PASSWORD" \
python3 client_app/bff_security_test.py
```

Kết quả cần đạt:

```text
Passed : 7
Failed : 0
```

---

## 12. Chạy bộ kiểm thử hệ thống cũ

Vẫn ở Terminal 2:

```bash
SECURITY_TEST_USERNAME="vinh" \
SECURITY_TEST_PASSWORD="$DEMO_PASSWORD" \
AUTH_PRIVATE_KEY="$HOME/zero-trust-project/auth_service/keys/private.pem" \
python3 infra/security_test.py
```

Kết quả cần đạt:

```text
Passed : 4
Failed : 0
```

Sau đó xóa mật khẩu khỏi biến shell:

```bash
unset DEMO_PASSWORD
```

---

## 13. Mở giao diện BFF trên trình duyệt

### Cài Root CA vào Ubuntu

```bash
sudo cp \
  ~/zero-trust-project/infra/certs/root-ca.crt \
  /usr/local/share/ca-certificates/zero-trust-root-ca.crt

sudo update-ca-certificates
```

### Khởi động lại Chrome

```bash
pkill -f google-chrome || true
```

Truy cập:

```text
https://localhost:5001
```

Đăng nhập bằng tài khoản demo:

```text
Username: vinh
Password: mật khẩu demo đã được nhóm quy định
```

Sau khi đăng nhập:

- `Gọi Public API` phải trả `200`.
- `Gọi Protected API` phải trả `200`.
- Kết quả protected phải chứa:

```text
Verified via mTLS-bound token (RFC 8705)
```
---
# Benchmark Guide – Zero-Trust API Authentication qua BFF

Tài liệu này hướng dẫn chạy benchmark cho hệ thống **Zero-Trust API Authentication** theo flow mới:

```text
Browser / Benchmark Client
        ↓ HTTPS
Client Application / BFF - https://127.0.0.1:5001
        ↓ mTLS
Envoy Gateway - https://127.0.0.1:443
        ↓ ext_authz / mTLS
Auth Service + Resource API
```

Trong flow mới, Browser hoặc client benchmark **không giữ JWT** và **không giữ certificate/private key**. JWT được BFF lưu phía server trong `TOKEN_STORE`. Khi gọi protected API, BFF lấy JWT tương ứng với session cookie, gắn `Authorization: Bearer <token>` và dùng `bff-client.crt/key` để kết nối mTLS tới Envoy.

---

## 1. Công cụ sử dụng

Benchmark dùng 2 công cụ chính:

| Công cụ | Vai trò |
|---|---|
| Locust | Mô phỏng nhiều user thực tế đăng nhập, giữ session cookie và gọi `/public`, `/protected` qua BFF |
| wrk | Tạo tải HTTP cao vào từng endpoint riêng lẻ của BFF để đo throughput, average latency, P90/P99 latency |
| docker stats | Ghi nhận CPU, memory, network I/O của Envoy, Auth Service và Resource API |

Các chỉ số cần ghi nhận:

```text
Total Requests
Throughput / Requests per second
Average Latency
P95/P99 với Locust
P90/P99 với wrk
Failure / Timeout Rate
CPU Avg / CPU Max của từng container
```

---

## 2. Chuẩn bị môi trường

Chạy trong Ubuntu WSL.

```bash
cd /mnt/d/CODE/codecrypt/Project/zero-trust-project

source .venv-bff/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install locust requests urllib3

sudo apt update
sudo apt install -y wrk
```

Kiểm tra phiên bản công cụ:

```bash
docker --version
docker compose version
locust --version
wrk -v
python3 --version
```

---

## 3. Chạy backend Docker

Mở Terminal 1:

```bash
cd /mnt/d/CODE/codecrypt/Project/zero-trust-project/infra

docker compose up -d --build --force-recreate

docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Kết quả cần có các container đang `Up`:

```text
zero-trust-gateway
auth-service
resource-api hoặc zero-trust-resource-api
```

---

## 4. Chạy BFF

Mở Terminal 2:

```bash
cd /mnt/d/CODE/codecrypt/Project/zero-trust-project

source .venv-bff/bin/activate

export BFF_SECRET_KEY="$(openssl rand -hex 32)"

python3 -u client_app/app.py
```

Kết quả mong đợi:

```text
Running on https://127.0.0.1:5001
```

Giữ terminal này mở trong suốt quá trình benchmark.

---

## 5. Kiểm tra BFF trước khi benchmark

Mở Terminal 3:

```bash
cd /mnt/d/CODE/codecrypt/Project/zero-trust-project

curl -k -i \
  -w "\nBFF_HOME_CODE=%{http_code}\n" \
  https://127.0.0.1:5001/
```

Kết quả mong đợi:

```text
BFF_HOME_CODE=200
```

Kiểm tra public API qua BFF:

```bash
curl -k -i \
  -w "\nBFF_PUBLIC_CODE=%{http_code}\n" \
  https://127.0.0.1:5001/public
```

Kết quả mong đợi:

```text
BFF_PUBLIC_CODE=200
```

---

## 6. Cấu trúc thư mục kết quả

Tạo thư mục lưu kết quả benchmark:

```bash
cd /mnt/d/CODE/codecrypt/Project/zero-trust-project

mkdir -p benchmark/results
```

Sau khi benchmark, các file kết quả sẽ nằm tại:

```text
benchmark/results/
```

---

## 7. Chạy benchmark tự động bằng Python

Script chính:

```text
benchmark/run_benchmark_bff.py
```

Script này tự chạy:

```text
Locust 10 users
Locust 50 users
Locust 100 users
wrk /public 10 connections
wrk /public 50 connections
wrk /public 100 connections
wrk /protected 10 connections
wrk /protected 50 connections
wrk /protected 100 connections
docker stats cho từng bài đo
```

Chạy benchmark:

```bash
cd /mnt/d/CODE/codecrypt/Project/zero-trust-project

source .venv-bff/bin/activate

export BFF_TEST_USERNAME="vinh"
export BFF_TEST_PASSWORD='Vinh@123!'

python3 -u benchmark/run_benchmark_bff.py
```

> Lưu ý: nếu đổi mật khẩu demo, sửa giá trị `BFF_TEST_PASSWORD` tương ứng.

---

## 8. Benchmark Locust

### 8.1. Vai trò

Locust mô phỏng user giống Browser:

```text
Locust user → HTTPS → BFF → mTLS → Envoy → Auth Service / Resource API
```

Locust không giữ JWT. Sau khi login, Locust giữ session cookie. BFF là nơi lưu JWT và tự gắn Bearer Token khi gọi Envoy.

### 8.2. File cấu hình

File Locust:

```text
benchmark/locustfile_bff.py
```

Task chính:

```text
POST /login
GET /public
GET /protected
```

### 8.3. Chạy Locust 10 users

```bash
locust \
  -f benchmark/locustfile_bff.py \
  --headless \
  -u 10 \
  -r 2 \
  -t 60s \
  --host https://127.0.0.1:5001 \
  --csv benchmark/results/locust_10 \
  --html benchmark/results/locust_10_report.html \
  --print-stats
```

### 8.4. Chạy Locust 50 users

```bash
locust \
  -f benchmark/locustfile_bff.py \
  --headless \
  -u 50 \
  -r 5 \
  -t 60s \
  --host https://127.0.0.1:5001 \
  --csv benchmark/results/locust_50 \
  --html benchmark/results/locust_50_report.html \
  --print-stats
```

### 8.5. Chạy Locust 100 users

```bash
locust \
  -f benchmark/locustfile_bff.py \
  --headless \
  -u 100 \
  -r 10 \
  -t 60s \
  --host https://127.0.0.1:5001 \
  --csv benchmark/results/locust_100 \
  --html benchmark/results/locust_100_report.html \
  --print-stats
```

### 8.6. File kết quả Locust

```text
benchmark/results/locust_10_stats.csv
benchmark/results/locust_50_stats.csv
benchmark/results/locust_100_stats.csv

benchmark/results/locust_10_report.html
benchmark/results/locust_50_report.html
benchmark/results/locust_100_report.html
```

Dữ liệu cần lấy cho báo cáo:

```text
Total Requests
Throughput
Average Latency
P95 Latency
P99 Latency
Failure Rate
```

---

## 9. Benchmark wrk qua BFF

### 9.1. Vai trò

wrk tạo tải HTTP cao vào endpoint cụ thể của BFF:

```text
wrk → HTTPS → BFF → mTLS → Envoy → Auth Service / Resource API
```

Với `/public`, wrk gọi trực tiếp không cần login.

Với `/protected`, wrk cần session cookie sau khi login, vì JWT được BFF lưu phía server.

### 9.2. wrk /public 10 connections

```bash
wrk --latency -t4 -c10 -d60s \
  https://127.0.0.1:5001/public \
  | tee benchmark/results/wrk_public_10.log
```

### 9.3. wrk /public 50 connections

```bash
wrk --latency -t4 -c50 -d60s \
  https://127.0.0.1:5001/public \
  | tee benchmark/results/wrk_public_50.log
```

### 9.4. wrk /public 100 connections

```bash
wrk --latency -t4 -c100 -d60s \
  https://127.0.0.1:5001/public \
  | tee benchmark/results/wrk_public_100.log
```

### 9.5. Login lấy session cookie cho /protected

```bash
curl -sk -c /tmp/bff_cookie.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=vinh" \
  --data-urlencode "password=Vinh@123!" \
  https://127.0.0.1:5001/login \
  -o /tmp/bff_login_response.html

SESSION_VALUE=$(awk '$6=="session"{print $7}' /tmp/bff_cookie.txt)

echo "SESSION_VALUE length = ${#SESSION_VALUE}"
```

Nếu `SESSION_VALUE length` lớn hơn `0`, login thành công.

Test nhanh protected:

```bash
curl -k -i \
  -H "Cookie: session=$SESSION_VALUE" \
  -w "\nBFF_PROTECTED_CODE=%{http_code}\n" \
  https://127.0.0.1:5001/protected
```

Kết quả mong đợi:

```text
BFF_PROTECTED_CODE=200
```

### 9.6. wrk /protected 10 connections

```bash
wrk --latency -t4 -c10 -d60s \
  -H "Cookie: session=$SESSION_VALUE" \
  https://127.0.0.1:5001/protected \
  | tee benchmark/results/wrk_protected_10.log
```

### 9.7. wrk /protected 50 connections

```bash
wrk --latency -t4 -c50 -d60s \
  -H "Cookie: session=$SESSION_VALUE" \
  https://127.0.0.1:5001/protected \
  | tee benchmark/results/wrk_protected_50.log
```

### 9.8. wrk /protected 100 connections

```bash
wrk --latency -t4 -c100 -d60s \
  -H "Cookie: session=$SESSION_VALUE" \
  https://127.0.0.1:5001/protected \
  | tee benchmark/results/wrk_protected_100.log
```

### 9.9. File kết quả wrk

```text
benchmark/results/wrk_public_10.log
benchmark/results/wrk_public_50.log
benchmark/results/wrk_public_100.log

benchmark/results/wrk_protected_10.log
benchmark/results/wrk_protected_50.log
benchmark/results/wrk_protected_100.log

benchmark/results/wrk_summary.csv
```

Trong output wrk, lấy các dòng:

```text
Latency
Latency Distribution
50%
75%
90%
99%
Requests/sec
requests in ...
Socket errors / Non-2xx nếu có
```

---

## 10. Thu thập CPU bằng docker stats

Nếu dùng script `run_benchmark_bff.py`, docker stats sẽ được thu tự động.

Các file kết quả:

```text
benchmark/results/docker_stats_locust_10.csv
benchmark/results/docker_stats_locust_50.csv
benchmark/results/docker_stats_locust_100.csv

benchmark/results/docker_stats_wrk_public_10.csv
benchmark/results/docker_stats_wrk_public_50.csv
benchmark/results/docker_stats_wrk_public_100.csv

benchmark/results/docker_stats_wrk_protected_10.csv
benchmark/results/docker_stats_wrk_protected_50.csv
benchmark/results/docker_stats_wrk_protected_100.csv
```

Các chỉ số cần lấy:

```text
CPU Envoy Avg / Max
CPU Auth Service Avg / Max
CPU Resource API Avg / Max
Memory usage
Network I/O
```

---

## 11. Mở kết quả trên Windows

```bash
explorer.exe "$(wslpath -w benchmark/results)"
```

Nên mở các file HTML của Locust:

```text
locust_10_report.html
locust_50_report.html
locust_100_report.html
```

---

## 12. Nén kết quả gửi để hoàn thành báo cáo

```bash
cd /mnt/d/CODE/codecrypt/Project/zero-trust-project

zip -r benchmark_results_latency.zip benchmark/results
```

Gửi file:

```text
benchmark_results_latency.zip
```

---

## 13. Mapping kết quả vào Chương 7

| Mục báo cáo | File cần dùng |
|---|---|
| 7.4.3 Locust 10 users | `locust_10_stats.csv`, `docker_stats_locust_10.csv` |
| 7.4.4 Locust 50 users | `locust_50_stats.csv`, `docker_stats_locust_50.csv` |
| 7.4.5 Locust 100 users | `locust_100_stats.csv`, `docker_stats_locust_100.csv` |
| 7.5.2 wrk /public | `wrk_public_10.log`, `wrk_public_50.log`, `wrk_public_100.log` |
| 7.5.3 wrk /protected | `wrk_protected_10.log`, `wrk_protected_50.log`, `wrk_protected_100.log` |
| 7.6 docker stats | `docker_stats_*.csv` |
| 7.7 bảng tổng hợp | Tất cả file CSV/log trong `benchmark/results` |
| 7.8 biểu đồ | Dữ liệu từ Locust CSV, wrk log và docker stats |
| 7.9 phân tích | Dựa trên bảng tổng hợp và biểu đồ |

---

## 14. Ghi chú quan trọng

- Locust phù hợp để đo luồng người dùng thật qua BFF.
- wrk phù hợp để tạo tải lớn vào từng endpoint BFF.
- `/protected` khi đo bằng wrk phải có session cookie.
- Thêm `--latency` khi chạy wrk để có P90/P99.
- Không so sánh trực tiếp Locust và wrk như hai phép đo giống nhau, vì mục tiêu đo khác nhau.
- Nếu failure rate tăng hoặc latency tăng mạnh, cần xem CPU Auth Service, Envoy và Resource API bằng docker stats.
