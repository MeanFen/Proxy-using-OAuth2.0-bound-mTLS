from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

import requests
from flask import (
    Flask,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)


BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent

ENVOY_URL = os.getenv(
    "ENVOY_URL",
    "https://localhost",
).rstrip("/")

ROOT_CA = ROOT_DIR / "infra/certs/root-ca.crt"

BFF_CLIENT_CERT = (
    ROOT_DIR / "infra/certs/bff/bff-client.crt"
)
BFF_CLIENT_KEY = (
    ROOT_DIR / "infra/certs/bff/bff-client.key"
)

BFF_SERVER_CERT = (
    ROOT_DIR / "infra/certs/bff/bff-server.crt"
)
BFF_SERVER_KEY = (
    ROOT_DIR / "infra/certs/bff/bff-server.key"
)

for required_file in (
    ROOT_CA,
    BFF_CLIENT_CERT,
    BFF_CLIENT_KEY,
    BFF_SERVER_CERT,
    BFF_SERVER_KEY,
):
    if not required_file.is_file():
        raise FileNotFoundError(
            f"Không tìm thấy file: {required_file}"
        )


app = Flask(__name__)

app.secret_key = os.getenv(
    "BFF_SECRET_KEY",
    secrets.token_hex(32),
)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Demo: JWT được lưu phía BFF, không lưu trong browser.
TOKEN_STORE: dict[str, str] = {}


PAGE = """
<!doctype html>
<html lang="vi">
<head>
    <meta charset="utf-8">
    <title>Zero-Trust Client Application / BFF</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 35px auto;
            line-height: 1.5;
        }

        input, button {
            padding: 9px;
            margin: 4px 0;
        }

        input {
            width: 300px;
        }

        pre {
            background: #eeeeee;
            padding: 15px;
            white-space: pre-wrap;
        }

        .message {
            background: #fff4cc;
            padding: 10px;
            margin: 10px 0;
        }

        .ok {
            color: green;
        }
    </style>
</head>
<body>
    <h1>Zero-Trust Client Application / BFF</h1>

    <p>
        Browser sử dụng HTTPS một chiều với BFF.
        Certificate mTLS và JWT chỉ được lưu tại BFF.
    </p>

    <p>
        Trạng thái:
        {% if logged_in %}
            <strong class="ok">Đã đăng nhập</strong>
        {% else %}
            <strong>Chưa đăng nhập</strong>
        {% endif %}
    </p>

    {% with messages = get_flashed_messages() %}
        {% for message in messages %}
            <div class="message">{{ message }}</div>
        {% endfor %}
    {% endwith %}

    <h2>Đăng nhập</h2>

    <form method="post" action="{{ url_for('login') }}">
        <div>
            <input
                name="username"
                placeholder="Username"
                required
            >
        </div>

        <div>
            <input
                name="password"
                type="password"
                placeholder="Password"
                required
            >
        </div>

        <button type="submit">Login</button>
    </form>

    <h2>API</h2>

    <form method="get" action="{{ url_for('public_api') }}">
        <button type="submit">Gọi Public API</button>
    </form>

    <form method="get" action="{{ url_for('protected_api') }}">
        <button type="submit">Gọi Protected API</button>
    </form>

    <form method="post" action="{{ url_for('logout') }}">
        <button type="submit">Logout</button>
    </form>

    {% if result %}
        <h2>Kết quả</h2>
        <pre>{{ result }}</pre>
    {% endif %}
</body>
</html>
"""


def get_session_id() -> str:
    session_id = session.get("session_id")

    if not session_id:
        session_id = secrets.token_urlsafe(32)
        session["session_id"] = session_id

    return session_id


def call_envoy(
    method: str,
    path: str,
    token: str | None = None,
    json_body: dict[str, Any] | None = None,
) -> requests.Response:
    headers: dict[str, str] = {}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    with requests.Session() as http:
        # Không sử dụng proxy từ biến môi trường.
        http.trust_env = False

        return http.request(
            method=method,
            url=f"{ENVOY_URL}{path}",
            cert=(
                str(BFF_CLIENT_CERT),
                str(BFF_CLIENT_KEY),
            ),
            verify=str(ROOT_CA),
            headers=headers,
            json=json_body,
            timeout=10,
        )


def render_home(
    result: dict[str, Any] | None = None,
):
    session_id = get_session_id()

    result_text = None

    if result is not None:
        result_text = json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        )

    return render_template_string(
        PAGE,
        logged_in=session_id in TOKEN_STORE,
        result=result_text,
    )


def parse_response(
    response: requests.Response,
) -> dict[str, Any]:
    try:
        body: Any = response.json()
    except ValueError:
        body = response.text

    return {
        "upstream_status": response.status_code,
        "body": body,
    }


@app.get("/")
def index():
    return render_home()


@app.post("/login")
def login():
    username = request.form.get(
        "username",
        "",
    ).strip()

    password = request.form.get(
        "password",
        "",
    )

    if not username or not password:
        flash("Username và password là bắt buộc.")
        return redirect(url_for("index"))

    try:
        response = call_envoy(
            method="POST",
            path="/auth/login",
            json_body={
                "username": username,
                "password": password,
            },
        )
    except requests.RequestException as exc:
        flash(f"Không thể kết nối Envoy: {exc}")
        return redirect(url_for("index"))

    try:
        payload = response.json()
    except ValueError:
        flash(
            f"Auth Service trả dữ liệu không hợp lệ. "
            f"HTTP {response.status_code}"
        )
        return redirect(url_for("index"))

    access_token = payload.get("access_token")

    if response.status_code != 200 or not access_token:
        error = payload.get(
            "error",
            "Login failed",
        )

        flash(
            f"Đăng nhập thất bại: {error} "
            f"(HTTP {response.status_code})"
        )

        return redirect(url_for("index"))

    TOKEN_STORE[get_session_id()] = access_token

    flash(
        "Đăng nhập thành công. "
        f"User={payload.get('authenticated_user')}, "
        f"Client={payload.get('authenticated_client')}. "
        "JWT được lưu tại BFF."
    )

    return redirect(url_for("index"))


@app.get("/public")
def public_api():
    try:
        response = call_envoy(
            method="GET",
            path="/api/public",
        )
    except requests.RequestException as exc:
        return render_home({
            "error": str(exc),
        })

    return render_home(
        parse_response(response)
    )


@app.get("/protected")
def protected_api():
    token = TOKEN_STORE.get(
        get_session_id()
    )

    if not token:
        flash("Bạn phải đăng nhập trước.")
        return redirect(url_for("index"))

    try:
        response = call_envoy(
            method="GET",
            path="/api/protected",
            token=token,
        )
    except requests.RequestException as exc:
        return render_home({
            "error": str(exc),
        })

    return render_home(
        parse_response(response)
    )


@app.post("/logout")
def logout():
    TOKEN_STORE.pop(
        get_session_id(),
        None,
    )

    flash("Đã đăng xuất và xóa JWT khỏi BFF.")

    return redirect(url_for("index"))


@app.get("/health")
def health():
    return {
        "status": "ok",
        "component": "client-application-bff",
    }


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        ssl_context=(
            str(BFF_SERVER_CERT),
            str(BFF_SERVER_KEY),
        ),
        debug=False,
    )
