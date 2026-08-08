from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Callable

import requests


ROOT_DIR = Path(__file__).resolve().parent.parent

CA_CERT = ROOT_DIR / "infra/certs/root-ca.crt"

BFF_CERT = ROOT_DIR / "infra/certs/bff/bff-client.crt"
BFF_KEY = ROOT_DIR / "infra/certs/bff/bff-client.key"

OTHER_CERT = ROOT_DIR / "infra/certs/client.crt"
OTHER_KEY = ROOT_DIR / "infra/certs/client.key"

BFF_URL = "https://localhost:5001"
ENVOY_URL = "https://localhost"

USERNAME = os.getenv("BFF_TEST_USERNAME", "vinh")
PASSWORD = os.getenv("BFF_TEST_PASSWORD", "")

passed = 0
failed = 0


def print_result(
    test_name: str,
    success: bool,
    detail: str,
) -> None:
    global passed, failed

    status = "PASS" if success else "FAIL"

    print()
    print("─" * 68)
    print(f"{test_name}")
    print(f"Result : {status}")
    print(f"Detail : {detail}")

    if success:
        passed += 1
    else:
        failed += 1


def request_with_bff_cert(
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
    token: str | None = None,
    certificate: tuple[Path, Path] | None = None,
) -> requests.Response:
    headers: dict[str, str] = {}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    cert_pair = certificate or (BFF_CERT, BFF_KEY)

    with requests.Session() as session:
        session.trust_env = False

        return session.request(
            method=method,
            url=f"{ENVOY_URL}{path}",
            verify=str(CA_CERT),
            cert=(
                str(cert_pair[0]),
                str(cert_pair[1]),
            ),
            headers=headers,
            json=json_body,
            timeout=10,
        )


def test_browser_to_bff() -> None:
    with requests.Session() as session:
        session.trust_env = False

        response = session.get(
            f"{BFF_URL}/",
            verify=str(CA_CERT),
            timeout=10,
        )

    print_result(
        "TC-BFF-01: Browser → BFF không dùng Client Certificate",
        response.status_code == 200,
        f"HTTP {response.status_code}",
    )


def test_protected_without_login() -> None:
    with requests.Session() as session:
        session.trust_env = False

        response = session.get(
            f"{BFF_URL}/protected",
            verify=str(CA_CERT),
            allow_redirects=False,
            timeout=10,
        )

    success = (
        response.status_code == 302
        and response.headers.get("Location") == "/"
    )

    print_result(
        "TC-BFF-02: Chưa đăng nhập không được gọi Protected API qua BFF",
        success,
        (
            f"HTTP {response.status_code}, "
            f"Location={response.headers.get('Location')}"
        ),
    )


def test_wrong_password() -> None:
    response = request_with_bff_cert(
        "POST",
        "/auth/login",
        json_body={
            "username": USERNAME,
            "password": "sai-mat-khau",
        },
    )

    success = (
        response.status_code == 401
        and "Invalid username or password" in response.text
    )

    print_result(
        "TC-BFF-03: Sai mật khẩu",
        success,
        f"HTTP {response.status_code} → {response.text}",
    )


def login_and_get_token() -> str:
    response = request_with_bff_cert(
        "POST",
        "/auth/login",
        json_body={
            "username": USERNAME,
            "password": PASSWORD,
        },
    )

    try:
        payload = response.json()
    except ValueError:
        payload = {}

    token = payload.get("access_token")

    success = (
        response.status_code == 200
        and isinstance(token, str)
        and bool(token)
        and payload.get("authenticated_user") == USERNAME
        and payload.get("authenticated_client")
        == "client-application-bff"
    )

    print_result(
        "TC-BFF-04: Đăng nhập đúng và cấp mTLS-bound JWT",
        success,
        (
            f"HTTP {response.status_code}, "
            f"user={payload.get('authenticated_user')}, "
            f"client={payload.get('authenticated_client')}, "
            f"JWT length={len(token) if isinstance(token, str) else 0}"
        ),
    )

    if not success:
        raise RuntimeError(
            "Không lấy được access token hợp lệ, dừng các test tiếp theo."
        )

    return token


def test_correct_binding(token: str) -> None:
    response = request_with_bff_cert(
        "GET",
        "/api/protected",
        token=token,
    )

    success = (
        response.status_code == 200
        and "Verified via mTLS-bound token" in response.text
    )

    print_result(
        "TC-BFF-05: JWT và BFF Certificate khớp nhau",
        success,
        f"HTTP {response.status_code} → {response.text}",
    )


def test_binding_mismatch(token: str) -> None:
    response = request_with_bff_cert(
        "GET",
        "/api/protected",
        token=token,
        certificate=(OTHER_CERT, OTHER_KEY),
    )

    success = (
        response.status_code == 403
        and "certificate binding failed" in response.text
    )

    print_result(
        "TC-BFF-06: Token bị dùng với certificate khác",
        success,
        f"HTTP {response.status_code} → {response.text}",
    )


def test_direct_envoy_without_certificate() -> None:
    try:
        with requests.Session() as session:
            session.trust_env = False

            response = session.get(
                f"{ENVOY_URL}/api/public",
                verify=str(CA_CERT),
                timeout=10,
            )

        print_result(
            "TC-BFF-07: Browser gọi trực tiếp Envoy không có certificate",
            False,
            f"Không xảy ra TLS error, nhận HTTP {response.status_code}",
        )

    except requests.exceptions.SSLError as exc:
        print_result(
            "TC-BFF-07: Browser gọi trực tiếp Envoy không có certificate",
            True,
            f"TLS handshake bị từ chối: {exc}",
        )


def check_required_files() -> None:
    required_files = (
        CA_CERT,
        BFF_CERT,
        BFF_KEY,
        OTHER_CERT,
        OTHER_KEY,
    )

    missing = [
        str(path)
        for path in required_files
        if not path.is_file()
    ]

    if missing:
        raise FileNotFoundError(
            "Thiếu các file sau:\n" + "\n".join(missing)
        )


def main() -> int:
    if not PASSWORD:
        raise RuntimeError(
            "Thiếu BFF_TEST_PASSWORD. "
            "Hãy đặt biến môi trường trước khi chạy test."
        )

    print("=" * 68)
    print("ZERO-TRUST BFF SECURITY TEST SUITE")
    print("=" * 68)

    check_required_files()

    tests_before_login: list[Callable[[], None]] = [
        test_browser_to_bff,
        test_protected_without_login,
        test_wrong_password,
    ]

    for test in tests_before_login:
        test()

    token = login_and_get_token()

    test_correct_binding(token)
    test_binding_mismatch(token)
    test_direct_envoy_without_certificate()

    print()
    print("=" * 68)
    print("KẾT QUẢ KIỂM THỬ")
    print("=" * 68)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")
    print("=" * 68)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print()
        print(f"FATAL ERROR: {exc}")
        sys.exit(1)
