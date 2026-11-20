"""Server-side refresh sessions with one-time rotation and reuse detection.

Access JWTs remain short-lived bearer credentials. Refresh credentials are opaque,
random, hashed before storage, bound to the user and device metadata, and marked
used atomically. Reusing a rotated token revokes the whole session family.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status

from .database.main_db import _db

REFRESH_TTL_DAYS = 30
_refresh_sessions = _db.get_collection("auth_refresh_sessions")


def ensure_indexes() -> None:
    _refresh_sessions.create_index("token_hash", unique=True)
    _refresh_sessions.create_index([("family_id", 1), ("status", 1)])
    _refresh_sessions.create_index([("auth_id", 1), ("expires_at", 1)])
    _refresh_sessions.create_index("expires_at", expireAfterSeconds=0)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_refresh_token(
    *, auth_id: str, user_id: str, laundry_id: str | None, user_agent: str | None = None,
    ip_address: str | None = None, family_id: str | None = None,
) -> str:
    ensure_indexes()
    token = secrets.token_urlsafe(64)
    now = _now()
    _refresh_sessions.insert_one({
        "token_hash": _hash(token),
        "family_id": family_id or secrets.token_urlsafe(24),
        "auth_id": auth_id,
        "user_id": str(user_id),
        "laundry_id": laundry_id,
        "status": "active",
        "created_at": now,
        "expires_at": now + timedelta(days=REFRESH_TTL_DAYS),
        "user_agent_hash": _hash(user_agent or "") if user_agent else None,
        "ip_hash": _hash(ip_address or "") if ip_address else None,
    })
    return token


def rotate_refresh_token(
    token: str, *, user_agent: str | None = None, ip_address: str | None = None,
) -> dict[str, Any]:
    """Atomically consume a refresh token and issue its replacement.

    A used/revoked token indicates reuse. The complete family is revoked to
    contain a stolen token, and the caller receives a generic unauthorized error.
    """
    if not token or len(token) < 40:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    current = _refresh_sessions.find_one_and_update(
        {"token_hash": _hash(token), "status": "active", "expires_at": {"$gt": _now()}},
        {"$set": {"status": "used", "used_at": _now()}},
    )
    if not current:
        previous = _refresh_sessions.find_one({"token_hash": _hash(token)})
        if previous and previous.get("status") == "used":
            _refresh_sessions.update_many(
                {"family_id": previous.get("family_id")},
                {"$set": {"status": "revoked", "revoked_reason": "refresh_reuse"}},
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    replacement = issue_refresh_token(
        auth_id=current["auth_id"],
        user_id=current["user_id"],
        laundry_id=current.get("laundry_id"),
        user_agent=user_agent,
        ip_address=ip_address,
        family_id=current["family_id"],
    )
    return {"session": current, "refresh_token": replacement}


def revoke_user_sessions(auth_id: str, *, reason: str = "logout") -> int:
    result = _refresh_sessions.update_many(
        {"auth_id": auth_id, "status": "active"},
        {"$set": {"status": "revoked", "revoked_at": _now(), "revoked_reason": reason}},
    )
    return int(result.modified_count)


def revoke_family(family_id: str, *, reason: str = "logout") -> int:
    result = _refresh_sessions.update_many(
        {"family_id": family_id, "status": {"$ne": "revoked"}},
        {"$set": {"status": "revoked", "revoked_at": _now(), "revoked_reason": reason}},
    )
    return int(result.modified_count)
