#!/usr/bin/env python3
"""
=============================================================================
 ZERO-TRUST API GATEWAY — SECURITY TEST SUITE (Rút gọn theo SecurityTestReport.docx)
=============================================================================
"""

import requests
import urllib3
import jwt as pyjwt
import time
import sys
import os
import json
import base64
import hashlib
import uuid
import re
import tempfile
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------------- Đường dẫn certs ---------------------------------
def _find_certs_dir() -> Path:
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "certs",
        script_dir.parent / "infra" / "certs",
        script_dir.parent / "certs",
        script_dir / ".." / "infra" / "certs",
    ]
    for path in candidates:
        resolved = path.resolve()
        if resolved.exists() and (resolved / "root-ca.crt").exists():
            return resolved
    print(f"\n⚠ Không tìm thấy certs/ - hãy chạy bash infra/setup.sh")
    return script_dir.parent / "infra" / "certs"

CERTS_DIR = _find_certs_dir()
ENVOY_URL = "https://127.0.0.1:443"
CERT_FILE = str(CERTS_DIR / "client.crt")
KEY_FILE  = str(CERTS_DIR / "client.key")
CA_FILE   = str(CERTS_DIR / "root-ca.crt")

AUTH_PRIVATE_KEY_FILE = str((Path(__file__).resolve().parent.parent / "auth_service" / "keys" / "private.pem").resolve())

def _find_auth_private_key() -> Path:
    """
    Tìm private key thật dùng để ký JWT của Auth Service.

    Sửa lỗi:
    - Không trả về thư mục.
    - Chỉ chấp nhận đường dẫn là file thật bằng is_file().
    - Hỗ trợ các vị trí phổ biến:
      + infra/keys/private.pem
      + auth_service/keys/private.pem
      + auth_service/keys/private .pem
    - Có thể override bằng biến môi trường AUTH_PRIVATE_KEY.
    """
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent

    candidates = []

    env_key = os.environ.get("AUTH_PRIVATE_KEY")
    if env_key:
        candidates.append(Path(env_key))

    candidates.extend([
        # Trường hợp key nằm trong auth_service/keys/
        project_root / "auth_service" / "keys" / "private.pem",
        project_root / "auth_service" / "keys" / "private.pem",

        # Fallback theo vị trí certs
        CERTS_DIR.parent / "keys" / "private.pem",
        CERTS_DIR.parent / "keys" / "private.pem",
        CERTS_DIR.parent.parent / "auth_service" / "keys" / "private.pem",
        CERTS_DIR.parent.parent / "auth_service" / "keys" / "private.pem",
    ])

    checked = []

    for path in candidates:
        resolved = path.resolve()
        checked.append(str(resolved))

        if resolved.is_file():
            return resolved

    raise FileNotFoundError(
        "Không tìm thấy Auth Service private key. Đã kiểm tra các đường dẫn:\n"
        + "\n".join(f" - {p}" for p in checked)
        + "\n\nCách sửa: đặt private key tại infra/keys/private.pem "
          "hoặc auth_service/keys/private.pem, hoặc set AUTH_PRIVATE_KEY trỏ tới file private key."
    )

def _client_cert_x5t_s256() -> str:
    """
    Tính x5t#S256 hợp lệ từ client.crt hiện tại.
    """
    pem = Path(CERT_FILE).read_text(encoding="utf-8", errors="replace")
    pem_body = (
        pem
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
    )
    pem_body = re.sub(r"[^A-Za-z0-9+/=]", "", pem_body)

    padding = len(pem_body) % 4
    if padding:
        pem_body += "=" * (4 - padding)

    der = base64.b64decode(pem_body)
    digest = hashlib.sha256(der).digest()

    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

def _response_contains_expired(resp) -> bool:
    """
    TC-04 không chỉ kiểm tra HTTPS 403.
    Response phải có bằng chứng là lỗi expired/expiration.
    """
    try:
        body = json.dumps(resp.json(), ensure_ascii=False).lower()
    except Exception:
        body = getattr(resp, "text", "") or ""
        body = str(body).lower()

    return (
        "expired" in body
        or "expiration" in body
        or "signature has expired" in body
        or "token expired" in body
    )

# ----------------------------- Màu sắc terminal ---------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

results = []

TEST_USERNAME = os.getenv(
    "SECURITY_TEST_USERNAME",
    "vinh",
)

TEST_PASSWORD = os.getenv(
    "SECURITY_TEST_PASSWORD",
    "",
)

# ----------------------------- Helper functions ---------------------------------
def _make_request(method, path, headers=None, cert=None):
    url = ENVOY_URL + path
    try:
        resp = requests.request(method, url, headers=headers or {}, cert=cert, verify=False, timeout=5)
        return resp
    except requests.exceptions.SSLError as e:
        return _MockResponse(403, {"error": f"TLS Handshake Failed: {str(e)[:80]}"})
    except requests.exceptions.ConnectionError as e:
        return _MockResponse(503, {"error": f"Connection refused: {str(e)[:80]}"})

class _MockResponse:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self._data = data
        self.text = json.dumps(data, ensure_ascii=False)

    def json(self):
        return self._data

def _get_valid_jwt():
    print(f"\n[DEBUG] Cert dir: {CERTS_DIR}")
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[ERROR] Client cert missing. Run bash infra/setup.sh")
        return None
    try:
        if not TEST_PASSWORD:
            print(
                "[ERROR] Missing SECURITY_TEST_PASSWORD environment variable"
            )
            return None

        resp = requests.post(
            ENVOY_URL + "/auth/login",
            cert=(CERT_FILE, KEY_FILE),
            verify=False,
            json={
                "username": TEST_USERNAME,
                "password": TEST_PASSWORD,
            },
            timeout=5,
        )
        if resp.status_code == 200:
            token = resp.json().get("access_token")
            if token:
                print(f"\n{'='*60}\n{YELLOW}[JWT ACCESS TOKEN]{RESET}\n{'='*60}\n{token}\n{'='*60}\n")
                return token
            else:
                print("[ERROR] No access_token in response")
        else:
            print(f"[ERROR] Login failed: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[ERROR] {e}")
    return None

def _forge_invalid_jwt_rs256():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = fake_key.private_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PrivateFormat.TraditionalOpenSSL,
                                 encryption_algorithm=serialization.NoEncryption())
    now = int(time.time())
    payload = {
        "iss": "https://auth.zero-trust.local",
        "sub": "attacker",
        "aud": "https://api.resource.local",
        "exp": now + 3600,
        "scope": "read:resources",
        "cnf": {"x5t#S256": "FAKE_THUMBPRINT"}
    }
    return pyjwt.encode(payload, pem, algorithm="RS256")

def _expired_jwt():
    """
    Tạo JWT hết hạn nhưng hợp lệ về chữ ký và certificate binding.

    Điểm quan trọng:
    - Không dùng fake_key.
    - Ký bằng private key thật của Auth Service.
    - Giữ iss, aud hợp lệ.
    - Giữ cnf.x5t#S256 hợp lệ theo client.crt hiện tại.
    - Chỉ đặt exp về thời gian trong quá khứ.
    """
    private_key_path = _find_auth_private_key()
    private_key = private_key_path.read_text(encoding="utf-8")

    now = int(time.time())
    thumbprint = _client_cert_x5t_s256()

    payload = {
        "iss": "https://auth.zero-trust.local",
        "sub": TEST_USERNAME,
        "client_id": "test-client",
        "aud": "https://api.resource.local",

        # Chỉ claim này làm token hết hạn.
        "exp": now - 3600,

        # Các claim thời gian còn lại hợp lệ.
        "nbf": now - 7200,
        "iat": now - 7200,

        "jti": str(uuid.uuid4()),
        "scope": "read:resources write:resources",

        # Binding hợp lệ với client.crt đang dùng trong request.
        "cnf": {
            "x5t#S256": thumbprint
        }
    }

    headers = {
        "alg": "RS256",
        "typ": "at+jwt",
        "kid": "auth-service-key-2026"
    }

    print(f"[DEBUG] TC-04 signing expired JWT with: {private_key_path}")

    return pyjwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers=headers
    )

def _print_result(tc_id, name, threat_ref, expected, response, passed):
    status = f"{GREEN} PASS{RESET}" if passed else f"{RED} FAIL{RESET}"
    print(f"\n{'─'*65}")
    print(f"{BOLD}[{tc_id}] {name}{RESET}")
    print(f"  Threat Model Ref : {CYAN}{threat_ref}{RESET}")
    print(f"  Expected         : {expected}")
    print(f"  Got              : HTTPS {response.status_code} → {_safe_json(response)}")
    print(f"  Result           : {status}")
    results.append({"id": tc_id, "name": name, "passed": passed})

def _safe_json(resp):
    try:
        return resp.json()
    except:
        return "(non-JSON response)"

# ----------------------------- Test cases --------------------------------------
def tc01_valid_request():
    print(f"\n{'═'*65}\n{BOLD}{CYAN}TC-01: VALID REQUEST — Luồng hợp lệ hoàn chỉnh{RESET}")
    token = _get_valid_jwt()
    if not token:
        results.append({"id": "TC-01", "name": "Valid Request", "passed": False})
        return
    resp = _make_request("GET", "/api/protected", headers={"Authorization": f"Bearer {token}"}, cert=(CERT_FILE, KEY_FILE))
    passed = (resp.status_code == 200)
    _print_result("TC-01", "Valid Request", "N/A (Happy Path)", "HTTPS 200 OK", resp, passed)

def tc02_invalid_jwt_signature():
    print(f"\n{'═'*65}\n{BOLD}{CYAN}TC-02: INVALID JWT SIGNATURE — Forged token (RS256 wrong key){RESET}")
    forged = _forge_invalid_jwt_rs256()
    print(f"\n[FORGED JWT] {forged}\n")
    resp = _make_request("GET", "/api/protected", headers={"Authorization": f"Bearer {forged}"}, cert=(CERT_FILE, KEY_FILE))
    passed = (resp.status_code == 403)
    _print_result("TC-02", "Invalid JWT Signature", "Threat 4.5 — Privilege Escalation", "HTTPS 403 Forbidden", resp, passed)

def tc03_self_signed_cert():
    print(f"\n{'═'*65}\n{BOLD}{CYAN}TC-03: SELF-SIGNED CERTIFICATE — Impersonation (mTLS){RESET}")
    attacker_cert = CERTS_DIR / "attacker_selfsigned.crt"
    attacker_key = CERTS_DIR / "attacker_selfsigned.key"
    if attacker_cert.exists(): attacker_cert.unlink()
    if attacker_key.exists(): attacker_key.unlink()
    subj = "/CN=attacker-self-signed"
    cmd = f'openssl req -x509 -newkey rsa:2048 -nodes -keyout {attacker_key} -out {attacker_cert} -days 1 -subj "{subj}"'
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"\n[SELF-SIGNED CERT] {attacker_cert}")
    print(f"[SELF-SIGNED KEY]  {attacker_key}")
    result = subprocess.run(f'openssl x509 -in {attacker_cert} -noout -subject -issuer', shell=True, capture_output=True, text=True)
    print(result.stdout)
    print("[INFO] Self-signed → không được Envoy trust → TLS handshake fail.\n")
    resp = _make_request("GET", "/api/protected", headers={"Authorization": "Bearer dummy"}, cert=(str(attacker_cert), str(attacker_key)))
    passed = (resp.status_code in (401, 403))
    _print_result("TC-03", "Self-Signed Certificate", "Threat 4.3 — Impersonation", "TLS Handshake FAIL", resp, passed)

def tc04_replay_attack():
    print(f"\n{'═'*65}\n{BOLD}{CYAN}TC-04: REPLAY ATTACK — Expired token replayed{RESET}")
    print(f"  Threat Model Ref : {CYAN}Threat 4.2 + Residual Risk §5 (no replay cache){RESET}")
    print(f"  {YELLOW}⚠ Residual risk: Token còn hạn + cert lộ có thể replay đến hết exp{RESET}")
    print("  Mục tiêu TC-04: token được ký bằng key thật, binding hợp lệ, chỉ exp là hết hạn.")

    try:
        expired = _expired_jwt()
    except Exception as e:
        mock = _MockResponse(500, {"error": f"Cannot create expired JWT: {e}"})
        _print_result(
            "TC-04",
            "Replay Attack (Expired Token)",
            "Threat 4.2 + Residual Risk §5",
            "Create expired JWT with real Auth Service private key",
            mock,
            False
        )
        return

    all_pass = True
    last_resp = None

    for i in range(1, 4):
        resp = _make_request(
            "GET",
            "/api/protected",
            headers={"Authorization": f"Bearer {expired}"},
            cert=(CERT_FILE, KEY_FILE)
        )

        last_resp = resp
        expired_evidence = _response_contains_expired(resp)
        attempt_pass = (resp.status_code == 403 and expired_evidence)

        print(
            f"  Attempt {i} → HTTPS {resp.status_code} | "
            f"expired evidence: {expired_evidence} | "
            f"{'PASS' if attempt_pass else 'FAIL'}"
        )

        if not attempt_pass:
            all_pass = False

    _print_result(
        "TC-04",
        "Replay Attack (Expired Token)",
        "Threat 4.2 + Residual Risk §5",
        "HTTPS 403 Forbidden + error contains 'expired' (all 3 attempts)",
        last_resp,
        all_pass
    )

# ----------------------------- Main --------------------------------------------
def print_summary():
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    print(f"\n{'═'*65}\n{BOLD} KẾT QUẢ KIỂM THỬ BẢO MẬT{RESET}\n{'═'*65}")
    print(f"  Tổng số test case : {total}")
    print(f"  Passed            : {GREEN}{passed}{RESET}")
    print(f"  Failed            : {RED}{failed}{RESET}")
    print(f"{'─'*65}")
    for r in results:
        icon = f"{GREEN}{RESET}" if r["passed"] else f"{RED}{RESET}"
        print(f"  {icon}  {r['id']} — {r['name']}")
    print(f"{'═'*65}")
    if failed > 0:
        print(f"\n{YELLOW}⚠ Một số test chưa đạt.{RESET}")
        print("   Kiểm tra chi tiết các kết quả FAIL ở phía trên.")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    print(f"{BOLD}{'═'*65}{RESET}")
    print(f"{BOLD}{CYAN} ZERO-TRUST SECURITY TEST SUITE (RÚT GỌN){RESET}")
    print(f"{BOLD} Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{'═'*65}{RESET}")
    tc01_valid_request()
    tc02_invalid_jwt_signature()
    tc03_self_signed_cert()
    tc04_replay_attack()
    sys.exit(print_summary())