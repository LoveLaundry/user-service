"""Hotel client accounts — external customers of one laundry.

Why this module exists
----------------------
A hotel is not an entity in this system: hotels appear only as the ``client_name``
string carried by gate passes, deliveries, bills and quotations (see
``quotations-ui/src/context/HotelContext.tsx``). Staff accounts, by contrast, are
``users`` rows belonging to a laundry membership. A hotel therefore had no
identity it could sign in with, which is what this module adds.

The isolation rule that makes this safe
---------------------------------------
A client session token deliberately carries **no** ``laundry_id`` and **no**
``laundries`` membership snapshot. It carries ``client_scope`` instead:

    {"laundry_id": "<slug>", "client_name": "<hotel>"}

Every resource service resolves its tenant from those two claims and fails
closed when they are missing (``bill_service/tenancy.py`` →
``resolve_laundry_id`` raises 400 "No active laundry in this session"). This
means the whole existing API surface keeps rejecting client tokens **without a
single change to any existing endpoint** — the safety comes from the token
shape, not from remembering to add a check.

Only endpoints written specifically for the client portal read
``client_scope``, and they must filter every query by both the laundry and the
client name. A client token must never be able to reach a staff endpoint.

Consistent with the rest of the tenant registry (``routers/laundries.py``), this
collection is MongoDB-backed; the Postgres repository covers the ``users`` table
only.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import bcrypt
from bson import ObjectId
from fastapi import HTTPException, Security

# Import order is load-bearing, do not "tidy" it. ``auth_helper`` calls
# ``load_dotenv()`` at import time, and ``config`` resolves MONGODB_MAIN_URI once
# at import. If auth_helper is imported first, config reads the .env URI and a
# test run would open a connection to the production cluster instead of the
# local/mocked one. Importing the database handle first makes config resolve the
# same URI the application itself would use.
from .database.main_db import client_accounts_collection

from .auth_helper import DISABLED_STATUSES, create_access_token, security, verify_token
from .memberships import ACTIVE, ARCHIVED, SUSPENDED, VALID_STATUSES, normalize_laundry_id

# Roles a hotel-side client may hold. Managers see money and invoices; the
# admin role additionally manages other client users of the same hotel.
CLIENT_ROLES = {"HOTEL_ADMIN", "HOTEL_MANAGER"}

CLIENT_NAME_MAX = 120
_AUTH_ID_RE = re.compile(r"^[A-Za-z0-9._@-]{3,64}$")

# Verifying an unknown account against this hash keeps response timing
# indistinguishable from a wrong password, so the endpoint cannot be used to
# enumerate which hotels have accounts.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"client-timing-equalizer", bcrypt.gensalt()).decode("utf-8")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_blocked(doc: Dict[str, Any]) -> bool:
    return str(doc.get("status") or "unset").strip().lower() in DISABLED_STATUSES


def normalize_client_name(value: Any) -> str:
    """Validate a hotel name. Raises 400 rather than silently coercing.

    The value must match the ``client_name`` already stored on operational
    records exactly (after trimming), otherwise a client would sign in and see
    an empty portal because its own documents were stamped differently.
    """
    name = str(value or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="client_name is required")
    if len(name) > CLIENT_NAME_MAX:
        raise HTTPException(
            status_code=400,
            detail=f"client_name must be at most {CLIENT_NAME_MAX} characters",
        )
    if any(ord(ch) < 32 for ch in name):
        raise HTTPException(status_code=400, detail="client_name contains control characters")
    return name


def normalize_auth_id(value: Any) -> str:
    auth_id = str(value or "").strip()
    if not _AUTH_ID_RE.match(auth_id):
        raise HTTPException(
            status_code=400,
            detail="auth_id must be 3-64 characters of letters, digits, '.', '_', '@' or '-'",
        )
    return auth_id


def normalize_role(value: Any) -> str:
    role = str(value or "").strip().upper()
    if role not in CLIENT_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"role must be one of {sorted(CLIENT_ROLES)}",
        )
    return role


def normalize_status(value: Any) -> str:
    status = str(value or "").strip().upper()
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
    return status


def hash_password(password: str) -> str:
    raw = str(password or "")
    if len(raw) < 8:
        raise HTTPException(status_code=400, detail="password must be at least 8 characters")
    encoded = raw.encode("utf-8")
    # bcrypt silently truncates beyond 72 bytes; refuse instead of accepting a
    # password whose tail would be ignored.
    if len(encoded) > 72:
        raise HTTPException(status_code=400, detail="password must be at most 72 bytes")
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("utf-8")


def create_client_account(
    *,
    laundry_id: Any,
    client_name: Any,
    auth_id: Any,
    user_name: Any,
    password: str,
    email: Optional[str] = None,
    role: Any = "HOTEL_MANAGER",
    status: Any = ACTIVE,
) -> Dict[str, Any]:
    """Create one hotel client login. Idempotent-safe: duplicates raise 409."""
    slug = normalize_laundry_id(laundry_id)
    name = normalize_client_name(client_name)
    login = normalize_auth_id(auth_id)
    display = str(user_name or "").strip() or login
    normalized_role = normalize_role(role)
    normalized_status = normalize_status(status)

    if client_accounts_collection.find_one({"laundry_id": slug, "auth_id": login}):
        raise HTTPException(
            status_code=409,
            detail="That login already exists for this laundry",
        )

    doc = {
        "laundry_id": slug,
        "client_name": name,
        "auth_id": login,
        "user_name": display[:120],
        "email": str(email).strip() if email else None,
        "password": hash_password(password),
        "role_id": normalized_role,
        "status": normalized_status,
        "created_at": _now(),
        "updated_at": _now(),
    }
    result = client_accounts_collection.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


def authenticate(
    auth_id: Any, password: str, laundry_id: Any | None = None
) -> Optional[Dict[str, Any]]:
    """Return the matching client account, or None.

    ``laundry_id`` narrows the lookup when the same hotel-brand login is serviced
    by more than one laundry business. Callers must treat None and a wrong
    password identically.
    """
    login = str(auth_id or "").strip()
    if not login:
        return None

    query: Dict[str, Any] = {"auth_id": login}
    if laundry_id:
        query["laundry_id"] = normalize_laundry_id(laundry_id)

    doc = client_accounts_collection.find_one(query)

    if not doc or "password" not in doc:
        try:
            bcrypt.checkpw(str(password or "").encode("utf-8"), _DUMMY_PASSWORD_HASH.encode("utf-8"))
        except ValueError:
            pass
        return None

    try:
        if not bcrypt.checkpw(
            str(password or "").encode("utf-8"), str(doc["password"]).encode("utf-8")
        ):
            return None
    except ValueError:
        return None

    if _is_blocked(doc):
        raise HTTPException(
            status_code=403,
            detail="This hotel account is inactive. Contact your laundry provider.",
        )
    return doc


def build_client_token(doc: Dict[str, Any]) -> str:
    """Issue a client session token.

    No ``laundry_id`` / ``laundries`` claim: that absence is the isolation
    mechanism described in the module docstring. Do not "helpfully" add them.
    """
    claims = {
        "user_id": str(doc.get("_id") or ""),
        "auth_id": doc["auth_id"],
        "user_name": doc.get("user_name") or doc["auth_id"],
        "role": normalize_role(doc.get("role_id")),
        # False by construction: a client is never a platform administrator.
        "platform_admin": False,
        "token_kind": "client",
        "client_scope": {
            "laundry_id": normalize_laundry_id(doc.get("laundry_id")),
            "client_name": normalize_client_name(doc.get("client_name")),
        },
    }
    # Hotel staff sign in from shared front-desk machines, so the session is
    # deliberately shorter than the 24h staff default.
    return create_access_token(claims, expires_in_hours=12)


def public_view(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Client-safe representation: never leaks the password hash."""
    return {
        "id": str(doc.get("_id") or doc.get("id") or ""),
        "laundry_id": doc.get("laundry_id"),
        "client_name": doc.get("client_name"),
        "auth_id": doc.get("auth_id"),
        "user_name": doc.get("user_name"),
        "email": doc.get("email"),
        "role_id": doc.get("role_id"),
        "status": doc.get("status"),
        "created_at": doc.get("created_at"),
    }


def get_client_session(credentials=Security(security)) -> Dict[str, Any]:
    """FastAPI dependency: a verified **client** session.

    Reloads the account so a disabled hotel user loses access immediately
    instead of riding out the token's lifetime, exactly like ``get_current_user``
    does for staff. A staff token is rejected here, and a client token is
    rejected by ``get_current_user`` — the two session kinds never overlap.
    """
    payload = verify_token(credentials.credentials)
    scope = payload.get("client_scope")
    if payload.get("token_kind") != "client" or not isinstance(scope, dict):
        raise HTTPException(status_code=403, detail="This endpoint requires a hotel account")

    doc = client_accounts_collection.find_one({"auth_id": payload.get("auth_id")})
    if not doc:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    if _is_blocked(doc):
        raise HTTPException(
            status_code=403,
            detail="This hotel account is inactive. Contact your laundry provider.",
        )

    # Live values win over the token snapshot, so a revoked/reassigned hotel
    # takes effect on the next request.
    payload["role"] = normalize_role(doc.get("role_id"))
    payload["status"] = doc.get("status")
    payload["user_name"] = doc.get("user_name") or payload.get("user_name")
    payload["client_scope"] = {
        "laundry_id": normalize_laundry_id(doc.get("laundry_id")),
        "client_name": normalize_client_name(doc.get("client_name")),
    }
    return payload


def client_scope_of(session: Dict[str, Any]) -> Dict[str, str]:
    """Extract the (laundry, hotel) pair a client request may read."""
    scope = session.get("client_scope") or {}
    return {
        "laundry_id": normalize_laundry_id(scope.get("laundry_id")),
        "client_name": normalize_client_name(scope.get("client_name")),
    }


def list_for_laundry(laundry_id: Any) -> List[Dict[str, Any]]:
    slug = normalize_laundry_id(laundry_id)
    cursor = client_accounts_collection.find({"laundry_id": slug}).sort("client_name", 1)
    return [public_view(doc) for doc in cursor]


def set_status(account_id: str, status: Any) -> Dict[str, Any]:
    normalized = normalize_status(status)
    try:
        oid = ObjectId(str(account_id))
    except Exception:
        raise HTTPException(status_code=404, detail="Client account not found")
    result = client_accounts_collection.find_one_and_update(
        {"_id": oid},
        {"$set": {"status": normalized, "updated_at": _now()}},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Client account not found")
    return public_view(result)
