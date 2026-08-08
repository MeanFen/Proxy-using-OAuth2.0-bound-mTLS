from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from werkzeug.security import check_password_hash


USERS_FILE = Path(__file__).resolve().with_name("users.json")


def load_users() -> dict[str, dict[str, Any]]:
    if not USERS_FILE.is_file():
        raise RuntimeError(
            f"User database was not found: {USERS_FILE}"
        )

    try:
        data = json.loads(
            USERS_FILE.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Unable to load user database: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError(
            "User database must contain a JSON object"
        )

    return data


def authenticate_user(
    username: str,
    password: str,
) -> dict[str, str] | None:
    users = load_users()
    record = users.get(username)

    if not isinstance(record, dict):
        return None

    password_hash = record.get("password_hash")

    if not isinstance(password_hash, str):
        return None

    if not check_password_hash(
        password_hash,
        password,
    ):
        return None

    return {
        "username": username,
        "role": str(record.get("role", "user")),
        "scope": str(
            record.get("scope", "read:resources")
        ),
    }
