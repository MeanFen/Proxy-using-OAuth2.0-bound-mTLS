from __future__ import annotations

import time
import uuid
from pathlib import Path

import jwt


BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_FILE = BASE_DIR / "keys" / "private.pem"
PUBLIC_KEY_FILE = BASE_DIR / "keys" / "public.pem"


def get_private_key() -> str:
    return PRIVATE_KEY_FILE.read_text(
        encoding="utf-8"
    )


def get_public_key() -> str:
    return PUBLIC_KEY_FILE.read_text(
        encoding="utf-8"
    )


def generate_access_token(
    username: str,
    client_id: str,
    thumbprint: str,
    role: str,
    scope: str,
) -> str:
    now = int(time.time())

    payload = {
        "iss": "https://auth.zero-trust.local",

        # Danh tính người dùng đã được xác thực.
        "sub": username,

        # Danh tính OAuth confidential client/BFF.
        "client_id": client_id,

        "aud": "https://api.resource.local",

        "exp": now + 3600,
        "nbf": now,
        "iat": now,
        "jti": str(uuid.uuid4()),

        "role": role,
        "scope": scope,

        # Ràng buộc token với certificate của BFF.
        "cnf": {
            "x5t#S256": thumbprint
        },
    }

    headers = {
        "alg": "RS256",
        "typ": "at+jwt",
        "kid": "auth-service-key-2026",
    }

    return jwt.encode(
        payload,
        get_private_key(),
        algorithm="RS256",
        headers=headers,
    )


def verify_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        get_public_key(),
        algorithms=["RS256"],
        audience="https://api.resource.local",
        issuer="https://auth.zero-trust.local",
        options={
            "require": [
                "iss",
                "sub",
                "aud",
                "exp",
                "nbf",
                "iat",
                "jti",
                "client_id",
                "cnf",
            ]
        },
    )
