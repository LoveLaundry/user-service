"""Hotel client accounts — external customers of one laundry.

Why this module exists
----------------------
Hotels and shops are first-class entities (``hotels`` / ``shops`` collections, see
``architecture/MULTI_TENANT_ENTITY_ARCHITECTURE.md``). A client account is the
login that entity signs in with, so every account carries the entity it belongs
to — ``hotel_id`` for a hotel login, ``shop_id`` for a shop login — in addition
to the ``client_name`` display string kept for reporting on older records.

An account may be created without an entity id (legacy rows, and laundries that
have not yet migrated their customer list into the registry). In that case the
association is resolved from ``client_name`` when a matching entity exists in
the same laundry. When both are present they must agree: an account is never
allowed to name one hotel while pointing at another.

The isolation rule that makes this safe
---------------------------------------
A client session token deliberately carries **no** ``laundry_id`` and **no**
``laundries`` membership snapshot. It carries ``client_scope`` instead:

    {"laundry_id": "<slug>", "client_type": "HOTEL",
     "hotel_id": "<slug>", "client_name": "<name>"}

Exactly one of ``hotel_id`` / ``shop_id`` is populated, chosen by
``client_type``. Every resource service resolves its tenant from those claims and fails
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
from .database.main_db import (
    client_accounts_collection,
    hotels_collection,
    laundries_collection,
    shops_collection,
)

from .auth_helper import DISABLED_STATUSES, create_access_token, security, verify_token
from .entity_memberships import normalize_entity_id
from .memberships import ACTIVE, ARCHIVED, SUSPENDED, VALID_STATUSES, normalize_laundry_id

# A client account belongs to one of two sides of the business, and the side is
# part of the identity rather than a UI concern: it decides which portal the
# token may read. A shop login must never resolve to hotel data, and vice versa.
CLIENT_TYPES = {"HOTEL": "SHOP", "SHOP": "HOTEL"}  # value is the opposite side

# Roles a client may hold, per side. There is deliberately no role that spans
# both sides: cross-side access is not expressible, so it cannot be granted by
# accident through a role string.
CLIENT_ROLES = {
    "HOTEL": {"HOTEL_ADMIN", "HOTEL_MANAGER"},
    "SHOP": {"SHOP_ADMIN", "SHOP_STAFF"},
}

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


def normalize_client_type(value: Any, default: str = "HOTEL") -> str:
    """Validate the side of the business a client account belongs to.

    Accounts created before this field existed are hotels, so ``HOTEL`` is the
    default. That default is why the field can be added without a data
    migration.
    """
    client_type = str(value or default).strip().upper()
    if client_type not in CLIENT_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"client_type must be one of {sorted(CLIENT_ROLES)}",
        )
    return client_type


def normalize_role(value: Any, client_type: str = "HOTEL") -> str:
    allowed = CLIENT_ROLES[normalize_client_type(client_type)]
    role = str(value or "").strip().upper()
    if role not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"role for a {client_type} account must be one of {sorted(allowed)}",
        )
    return role


def normalize_status(value: Any) -> str:
    status = str(value or "").strip().upper()
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
    return status


ENTITY_COLLECTIONS = {"HOTEL": "hotels", "SHOP": "shops"}


def _entity_collection(side: str):
    return hotels_collection if side == "HOTEL" else shops_collection


def _entity_id_field(side: str) -> str:
    return "hotel_id" if side == "HOTEL" else "shop_id"


def resolve_client_entity(
    *,
    client_type: Any,
    laundry_id: Any,
    client_name: Any = None,
    hotel_id: Any = None,
    shop_id: Any = None,
) -> Dict[str, Any]:
    """Bind a client account to its hotel or shop entity inside one laundry.

    Returns ``{"hotel_id": ..., "shop_id": ..., "client_name": ...}``.

    Rules, in order:
    - An id supplied for the *other* side is rejected: a hotel login can never
      point at a shop.
    - An explicit id must exist, belong to this laundry, and be ACTIVE.
    - With no id, a unique entity whose name matches ``client_name`` in this
      laundry is adopted, so existing customer lists migrate on first login
      instead of requiring a manual backfill.
    - With neither, the account stays name-only (legacy behaviour) rather than
      being rejected, so a laundry can keep trading while it migrates.

    All reads are scoped by ``associated_laundry_id``: an id belonging to a
    different laundry is reported as "not found" so the response cannot be used
    to probe another tenant's entity ids.
    """
    side = normalize_client_type(client_type)
    slug = normalize_laundry_id(laundry_id)
    if not slug:
        raise HTTPException(status_code=400, detail="A laundry is required")

    foreign = shop_id if side == "HOTEL" else hotel_id
    if str(foreign or "").strip():
        raise HTTPException(
            status_code=400,
            detail=f"A {side} account cannot be associated with a {ENTITY_COLLECTIONS[CLIENT_TYPES[side]]} entity",
        )

    explicit = hotel_id if side == "HOTEL" else shop_id
    collection = _entity_collection(side)
    id_field = _entity_id_field(side)
    name = normalize_client_name(client_name) if client_name else ""

    doc = None
    if str(explicit or "").strip():
        wanted = normalize_entity_id(explicit)
        try:
            doc = collection.find_one(
                {id_field: wanted, "associated_laundry_id": slug}
            )
        except Exception:
            doc = None
        if not doc:
            raise HTTPException(status_code=404, detail="No such entity in this laundry")
    elif name:
        try:
            matches = list(
                collection.find(
                    {"associated_laundry_id": slug, "name": name}
                ).limit(2)
            )
        except Exception:
            matches = []
        # Only adopt an unambiguous name match; two hotels sharing a name must
        # be disambiguated by id, never by guessing.
        if len(matches) == 1:
            doc = matches[0]

    if not doc:
        return {"hotel_id": None, "shop_id": None, "client_name": name}

    if str(doc.get("status") or "").strip().upper() != ACTIVE:
        raise HTTPException(status_code=403, detail="That entity is not active")

    entity_id = normalize_entity_id(doc.get(id_field))
    entity_name = str(doc.get("name") or "").strip()
    if name and entity_name and name != entity_name:
        raise HTTPException(
            status_code=409,
            detail="client_name does not match the associated entity",
        )

    return {
        "hotel_id": entity_id if side == "HOTEL" else None,
        "shop_id": entity_id if side == "SHOP" else None,
        "client_name": entity_name or name,
    }


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
    role: Any = None,
    client_type: Any = "HOTEL",
    status: Any = ACTIVE,
    hotel_id: Any = None,
    shop_id: Any = None,
) -> Dict[str, Any]:
    """Create one client login for one laundry.

    The same login may be registered under several laundry businesses — that is
    the multi-tenant association we need — but never twice inside one laundry,
    because a token resolves to exactly one (laundry, side, client) triple.
    """
    slug = normalize_laundry_id(laundry_id)
    login = normalize_auth_id(auth_id)
    display = str(user_name or "").strip() or login
    side = normalize_client_type(client_type)
    default_role = "HOTEL_MANAGER" if side == "HOTEL" else "SHOP_STAFF"
    normalized_role = normalize_role(role or default_role, side)
    normalized_status = normalize_status(status)

    association = resolve_client_entity(
        client_type=side,
        laundry_id=slug,
        client_name=client_name,
        hotel_id=hotel_id,
        shop_id=shop_id,
    )
    name = association["client_name"]
    if not name:
        raise HTTPException(status_code=400, detail="A client name is required")

    if client_accounts_collection.find_one({"laundry_id": slug, "auth_id": login}):
        raise HTTPException(
            status_code=409,
            detail="That login already exists for this laundry",
        )

    doc = {
        "laundry_id": slug,
        "client_type": side,
        "hotel_id": association["hotel_id"],
        "shop_id": association["shop_id"],
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


def _password_ok(doc: Dict[str, Any], password: str) -> bool:
    if "password" not in doc:
        return False
    try:
        return bcrypt.checkpw(
            str(password or "").encode("utf-8"), str(doc["password"]).encode("utf-8")
        )
    except ValueError:
        return False


def _laundry_label(slug: str) -> str:
    """Display name for a laundry, falling back to its slug."""
    try:
        found = laundries_collection.find_one({"laundry_id": slug})
    except Exception:
        found = None
    name = str((found or {}).get("name") or "").strip()
    return name or slug


def authenticate(
    auth_id: Any,
    password: str,
    laundry_id: Any | None = None,
    client_type: Any | None = None,
) -> Optional[Dict[str, Any]]:
    """Return the client account this attempt may open, or None.

    One login can be registered under several laundries. When it is, this
    refuses to guess: the caller must say which laundry, and a 409 carries the
    choices. Picking the first match silently would sign a user into another
    company's books, which is exactly the failure this guards against.

    Callers must treat ``None`` and a wrong password identically.
    """
    login = str(auth_id or "").strip()
    if not login:
        return None

    query: Dict[str, Any] = {"auth_id": login}
    if laundry_id:
        query["laundry_id"] = normalize_laundry_id(laundry_id)
    if client_type:
        query["client_type"] = normalize_client_type(client_type)

    candidates = list(client_accounts_collection.find(query).limit(50))
    if not candidates:
        # Burn a comparison so an unknown login costs the same as a wrong
        # password and cannot be used to enumerate accounts.
        try:
            bcrypt.checkpw(str(password or "").encode("utf-8"), _DUMMY_PASSWORD_HASH.encode("utf-8"))
        except ValueError:
            pass
        return None

    verified = [doc for doc in candidates if _password_ok(doc, password)]
    if not verified:
        return None

    if len(verified) > 1:
        options = [
            {
                "laundry_id": doc.get("laundry_id"),
                "laundry_name": _laundry_label(str(doc.get("laundry_id") or "")),
                "client_type": normalize_client_type(doc.get("client_type")),
                "client_name": doc.get("client_name"),
            }
            for doc in verified
        ]
        raise HTTPException(
            status_code=409,
            detail={
                "code": "laundry_required",
                "message": "This login is registered with more than one laundry. Choose one to continue.",
                "laundries": options,
            },
        )

    doc = verified[0]
    if _is_blocked(doc):
        side = normalize_client_type(doc.get("client_type")).lower()
        raise HTTPException(
            status_code=403,
            detail=f"This {side} account is inactive. Contact your laundry provider.",
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
        "role": normalize_role(doc.get("role_id"), doc.get("client_type") or "HOTEL"),
        # False by construction: a client is never a platform administrator.
        "platform_admin": False,
        "token_kind": "client",
        "client_scope": {
            "laundry_id": normalize_laundry_id(doc.get("laundry_id")),
            "client_name": normalize_client_name(doc.get("client_name")),
            "client_type": normalize_client_type(doc.get("client_type")),
            # Exactly one of these is set, matching client_type. Carried in the
            # token so downstream services scope by entity without a lookup.
            "hotel_id": (doc.get("hotel_id") or None),
            "shop_id": (doc.get("shop_id") or None),
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
        "client_type": normalize_client_type(doc.get("client_type")),
        "client_name": doc.get("client_name"),
        "hotel_id": doc.get("hotel_id") or None,
        "shop_id": doc.get("shop_id") or None,
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

    # Resolve the exact account, not merely the login: the same auth_id may
    # exist under several laundries, and loading the wrong one would apply the
    # wrong status and scope.
    lookup = {"laundry_id": scope.get("laundry_id"), "auth_id": payload.get("auth_id")}
    doc = client_accounts_collection.find_one(lookup)
    if not doc:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    if _is_blocked(doc):
        raise HTTPException(
            status_code=403,
            detail="This hotel account is inactive. Contact your laundry provider.",
        )

    # Live values win over the token snapshot, so a revoked/reassigned hotel
    # takes effect on the next request.
    # The side must come from the stored account: validating a shop role
    # against the hotel role set rejected every shop session with a 400.
    payload["role"] = normalize_role(doc.get("role_id"), doc.get("client_type"))
    payload["status"] = doc.get("status")
    payload["user_name"] = doc.get("user_name") or payload.get("user_name")
    payload["client_scope"] = {
        "laundry_id": normalize_laundry_id(doc.get("laundry_id")),
        "client_name": normalize_client_name(doc.get("client_name")),
        "client_type": normalize_client_type(doc.get("client_type")),
        # Rebuilt from the stored account, not copied from the token: an
        # association added or corrected by an administrator must take effect
        # on the next request. Omitting these here silently dropped the entity
        # from every authenticated call.
        "hotel_id": doc.get("hotel_id") or None,
        "shop_id": doc.get("shop_id") or None,
    }
    return payload


def client_scope_of(session: Dict[str, Any]) -> Dict[str, str]:
    """Extract the (laundry, hotel) pair a client request may read."""
    scope = session.get("client_scope") or {}
    side = normalize_client_type(scope.get("client_type"))
    # Only the id for this account's own side is ever returned, so a hotel
    # token cannot read a shop id even if one were somehow present.
    hotel_id = str(scope.get("hotel_id") or "").strip().lower() if side == "HOTEL" else ""
    shop_id = str(scope.get("shop_id") or "").strip().lower() if side == "SHOP" else ""
    return {
        "laundry_id": normalize_laundry_id(scope.get("laundry_id")),
        "client_name": normalize_client_name(scope.get("client_name")),
        "client_type": side,
        "hotel_id": hotel_id or None,
        "shop_id": shop_id or None,
    }


def list_for_laundry(laundry_id: Any, client_type: Any | None = None) -> List[Dict[str, Any]]:
    """Every client login a laundry owns, optionally filtered to one side.

    A laundry's shop logins and hotel logins are listed together but never
    mixed in the portal: the type is carried on each account, not inferred.
    """
    slug = normalize_laundry_id(laundry_id)
    query: Dict[str, Any] = {"laundry_id": slug}
    if client_type:
        query["client_type"] = normalize_client_type(client_type)
    cursor = client_accounts_collection.find(query).sort("client_name", 1)
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
