from __future__ import annotations

import ssl

import jwt
from flask import Flask, jsonify, request

from cert_utils import (
    extract_cn_from_xfcc,
    extract_thumbprint_from_xfcc,
)
from jwt_service import (
    generate_access_token,
    verify_access_token,
)
from user_store import authenticate_user


app = Flask(__name__)


@app.route("/auth/login", methods=["POST"])
def login():
    # Certificate này thuộc confidential client/BFF,
    # không thuộc người dùng trình duyệt.
    xfcc = request.headers.get(
        "x-forwarded-client-cert"
    )

    if not xfcc:
        return jsonify({
            "error": "Missing XFCC header"
        }), 400

    credentials = request.get_json(
        silent=True
    ) or {}

    username = credentials.get("username")
    password = credentials.get("password")

    if (
        not isinstance(username, str)
        or not username.strip()
        or not isinstance(password, str)
        or not password
    ):
        return jsonify({
            "error": "Username and password are required"
        }), 400

    username = username.strip()

    user = authenticate_user(
        username,
        password,
    )

    if user is None:
        # Không thông báo username hay password sai
        # để tránh làm lộ tài khoản tồn tại.
        return jsonify({
            "error": "Invalid username or password"
        }), 401

    try:
        thumbprint = extract_thumbprint_from_xfcc(
            xfcc
        )

        client_id = extract_cn_from_xfcc(
            xfcc
        )

    except ValueError as exc:
        return jsonify({
            "error": str(exc)
        }), 400

    token = generate_access_token(
        username=user["username"],
        client_id=client_id,
        thumbprint=thumbprint,
        role=user["role"],
        scope=user["scope"],
    )

    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "authenticated_user": user["username"],
        "authenticated_client": client_id,
        "role": user["role"],
        "scope": user["scope"],
    }), 200


VERIFY_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
]


@app.route(
    "/verify",
    defaults={"original_path": ""},
    methods=VERIFY_METHODS,
)
@app.route(
    "/verify/<path:original_path>",
    methods=VERIFY_METHODS,
)
def verify(original_path=""):
    auth_header = request.headers.get(
        "Authorization"
    )

    if not auth_header:
        return jsonify({
            "error": "Missing Authorization header"
        }), 401

    if not auth_header.startswith("Bearer "):
        return jsonify({
            "error": "Invalid Authorization header"
        }), 401

    token = auth_header.split(" ", 1)[1]

    xfcc = request.headers.get(
        "x-forwarded-client-cert"
    )

    if not xfcc:
        return jsonify({
            "error": "Missing XFCC header"
        }), 400

    try:
        payload = verify_access_token(token)

        jwt_thumbprint = (
            payload
            .get("cnf", {})
            .get("x5t#S256")
        )

        if not jwt_thumbprint:
            return jsonify({
                "error": "Missing cnf thumbprint"
            }), 403

        current_thumbprint = (
            extract_thumbprint_from_xfcc(
                xfcc
            )
        )

        if jwt_thumbprint != current_thumbprint:
            return jsonify({
                "error": "certificate binding failed"
            }), 403

        token_client_id = payload.get(
            "client_id"
        )

        current_client_id = extract_cn_from_xfcc(
            xfcc
        )

        if token_client_id != current_client_id:
            return jsonify({
                "error": "client identity mismatch"
            }), 403

        return jsonify({
            "status": "ok",
            "subject": payload.get("sub"),
            "client_id": token_client_id,
            "role": payload.get("role"),
            "scope": payload.get("scope"),
        }), 200

    except jwt.InvalidTokenError as exc:
        return jsonify({
            "error": str(exc)
        }), 403

    except ValueError as exc:
        return jsonify({
            "error": str(exc)
        }), 400


if __name__ == "__main__":
    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH
    )

    context.load_cert_chain(
        certfile="/app/tls/auth-service.crt",
        keyfile="/app/tls/auth-service.key",
    )

    context.load_verify_locations(
        cafile="/app/tls/service-ca.crt"
    )

    context.verify_mode = ssl.CERT_REQUIRED

    app.run(
        host="0.0.0.0",
        port=8443,
        ssl_context=context,
        debug=False,
    )
