"""Shop entity registry — platform-managed shop entities.

Each shop is one operational entity that can have its own administrators.
This router owns its lifecycle (register, edit, suspend, archive), its membership
roster, and the support-entry hand-off that lets a platform administrator open
a shop session.

Access is restricted to platform administrators. Shop administrators can only
manage their own shop's operations, not other shops.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..auth_helper import create_access_token, get_current_user
from ..database.main_db import shops_collection, laundries_collection, users_collection
from ..memberships import ACTIVE, VALID_STATUSES, normalize_laundry_id

router = APIRouter(tags=["shops"])

MAX_SEARCH_LENGTH = 100
EDITABLE_FIELDS = (
    "name",
    "shop_code",
    "location",
    "address",
    "contact_number",
    "email",
    "logo_url",
    "icon",
    "description",
    "subscription_plan",
    "plan_limits",
)


def _slug(value: str) -> str:
    """Validate a shop id, mapping bad input to 400 instead of a 500."""
    slug = str(value or "").strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9_-]{0,31}$", slug):
        raise HTTPException(
            status_code=400,
            detail="Invalid shop id — use 1-32 lowercase letters, digits, '-' or '_'",
        )
    return slug


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _escape(term: str) -> str:
    """Literal, bounded substring search — never an operator or a ReDoS vector."""
    return re.escape(term.strip()[:MAX_SEARCH_LENGTH])


def _serialize(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(doc)
    out["id"] = str(out.pop("_id"))
    return out


def require_platform_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Gate for the platform surface: users and shops.

    A platform administrator is an explicitly designated account — the
    ``platform_admin`` flag, or the ``PLATFORM_ADMIN`` role. Being ``ADMIN`` is
    not enough: that role runs one laundry's operations, and must never be able
    to register or enter other businesses.
    """
    role = str(current_user.get("role") or "").upper()
    if current_user.get("platform_admin") or role == "PLATFORM_ADMIN":
        return current_user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Platform administrator access required",
    )


def _get_shop(shop_id: str) -> Dict[str, Any]:
    slug = _slug(shop_id)
    doc = shops_collection.find_one({"shop_id": slug})
    if not doc:
        raise HTTPException(status_code=404, detail="Shop not found")
    return doc


class ShopCreate(BaseModel):
    shop_id: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=120)
    shop_code: Optional[str] = Field(default=None, max_length=64)
    location: Optional[str] = Field(default=None, max_length=120)
    address: Optional[str] = Field(default=None, max_length=255)
    contact_number: Optional[str] = Field(default=None, max_length=40)
    email: Optional[str] = Field(default=None, max_length=120)
    logo_url: Optional[str] = Field(default=None, max_length=500)
    icon: Optional[str] = Field(default=None, max_length=16)
    description: Optional[str] = Field(default=None, max_length=500)
    subscription_plan: Optional[str] = Field(default=None, max_length=40)
    plan_limits: Optional[str] = Field(default=None, max_length=255)
    associated_laundry_id: str = Field(min_length=1, max_length=32)
    # Optional initial administrator
    admin_auth_id: Optional[str] = Field(default=None, max_length=64)
    admin_user_name: Optional[str] = Field(default=None, max_length=120)
    admin_password: Optional[str] = Field(default=None, max_length=128)
    admin_email: Optional[str] = Field(default=None, max_length=120)


class ShopUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    shop_code: Optional[str] = Field(default=None, max_length=64)
    location: Optional[str] = Field(default=None, max_length=120)
    address: Optional[str] = Field(default=None, max_length=255)
    contact_number: Optional[str] = Field(default=None, max_length=40)
    email: Optional[str] = Field(default=None, max_length=120)
    logo_url: Optional[str] = Field(default=None, max_length=500)
    icon: Optional[str] = Field(default=None, max_length=16)
    description: Optional[str] = Field(default=None, max_length=500)
    subscription_plan: Optional[str] = Field(default=None, max_length=40)
    plan_limits: Optional[str] = Field(default=None, max_length=255)


class StatusPayload(BaseModel):
    status: str


class MemberPayload(BaseModel):
    auth_id: str = Field(min_length=1, max_length=64)
    role: Optional[str] = Field(default=None, max_length=32)


def _user_response(user: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in user.items() if k not in ("password", "_id", "_encrypted")}
    out["id"] = str(user.get("id") or user.get("_id"))
    out["role_id"] = str(user.get("role_id") or "").upper()
    return out


# ── registry ──────────────────────────────────────────────────────────────────

@router.get("/shops")
def list_shops(
    search: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    laundry_id: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(require_platform_admin),
):
    query: Dict[str, Any] = {}
    if search:
        pattern = _escape(search)
        query["$or"] = [
            {"shop_id": {"$regex": pattern, "$options": "i"}},
            {"name": {"$regex": pattern, "$options": "i"}},
            {"location": {"$regex": pattern, "$options": "i"}},
        ]
    if status_filter:
        wanted = status_filter.strip().upper()
        if wanted not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
        query["status"] = wanted
    if laundry_id:
        query["associated_laundry_id"] = normalize_laundry_id(laundry_id)

    total = shops_collection.count_documents(query)
    cursor = (
        shops_collection.find(query)
        .sort([("created_at", -1), ("_id", -1)])
        .skip(offset)
        .limit(limit)
    )
    return {"items": [_serialize(d) for d in cursor], "total": total}


@router.get("/shops/{shop_id}")
def get_shop(shop_id: str, _admin: dict = Depends(require_platform_admin)):
    return _serialize(_get_shop(shop_id))


@router.post("/shops", status_code=201)
def create_shop(payload: ShopCreate, admin: dict = Depends(require_platform_admin)):
    slug = _slug(payload.shop_id)
    if shops_collection.find_one({"shop_id": slug}):
        raise HTTPException(status_code=409, detail="That shop id is already registered")

    # Validate that the associated laundry exists
    laundry_slug = normalize_laundry_id(payload.associated_laundry_id)
    laundry = laundries_collection.find_one({"laundry_id": laundry_slug})
    if not laundry:
        raise HTTPException(status_code=400, detail="Associated laundry does not exist")
    if laundry.get("status") != ACTIVE:
        raise HTTPException(status_code=400, detail="Associated laundry is not active")

    now = _now()
    document: Dict[str, Any] = {
        "shop_id": slug,
        "name": payload.name.strip(),
        "associated_laundry_id": laundry_slug,
        "status": ACTIVE,
        "created_by": admin.get("auth_id"),
        "created_at": now,
        "updated_at": now,
    }
    for field in EDITABLE_FIELDS[1:]:
        value = getattr(payload, field, None)
        if value is not None:
            document[field] = value.strip() if isinstance(value, str) else value

    result = shops_collection.insert_one(document)
    document["_id"] = result.inserted_id

    if payload.admin_auth_id and payload.admin_password:
        import bcrypt
        from ..crypto_helper import encrypt_dict, get_search_token
        from ..mongodb_repository import SENSITIVE_FIELDS
        auth_id_clean = payload.admin_auth_id.strip()
        user_name_clean = (payload.admin_user_name or auth_id_clean).strip()
        shop_membership = {
            "id": slug,
            "name": payload.name.strip(),
            "role": "SHOP_ADMIN",
            "status": ACTIVE,
        }
        existing = users_collection.find_one({"auth_id": auth_id_clean})
        if existing:
            shops_list = existing.get("shops") or []
            updated_shops = [s for s in shops_list if s.get("id") != slug] + [shop_membership]
            users_collection.update_one({"_id": existing["_id"]}, {"$set": {"shops": updated_shops, "updated_at": now}})
        else:
            hashed_pw = bcrypt.hashpw(payload.admin_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            user_doc = {
                "auth_id": auth_id_clean,
                "user_name": user_name_clean,
                "password": hashed_pw,
                "role_id": "SHOP_ADMIN",
                "status": "active",
                "shops": [shop_membership],
                "created_at": now,
                "updated_at": now,
            }
            if payload.admin_email:
                user_doc["email"] = payload.admin_email.strip()
                user_doc["email_search"] = get_search_token(payload.admin_email.strip())
            users_collection.insert_one(encrypt_dict(user_doc, SENSITIVE_FIELDS))

    return _serialize(document)


@router.put("/shops/{shop_id}")
def update_shop(
    shop_id: str,
    payload: ShopUpdate,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_shop(shop_id)
    updates: Dict[str, Any] = {}
    for field in EDITABLE_FIELDS:
        value = getattr(payload, field, None)
        if value is not None:
            updates[field] = value.strip() if isinstance(value, str) else value
    if not updates:
        return _serialize(doc)

    updates["updated_at"] = _now()
    shops_collection.update_one({"_id": doc["_id"]}, {"$set": updates})
    doc.update(updates)
    return _serialize(doc)


@router.post("/shops/{shop_id}/status")
def set_status(
    shop_id: str,
    payload: StatusPayload,
    _admin: dict = Depends(require_platform_admin),
):
    wanted = (payload.status or "").strip().upper()
    if wanted not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")

    doc = _get_shop(shop_id)
    slug = doc["shop_id"]
    now = _now()
    shops_collection.update_one(
        {"_id": doc["_id"]}, {"$set": {"status": wanted, "updated_at": now}}
    )

    # Membership status must also be suspended
    for member in users_collection.find({"shops.id": slug}):
        entries = [
            {**entry, "status": wanted} if entry.get("id") == slug else entry
            for entry in (member.get("shops") or [])
        ]
        users_collection.update_one(
            {"_id": member["_id"]},
            {"$set": {"shops": entries, "updated_at": now}},
        )

    doc["status"] = wanted
    doc["updated_at"] = now
    return _serialize(doc)


# ── membership roster ─────────────────────────────────────────────────────────

@router.get("/shops/{shop_id}/members")
def list_members(shop_id: str, _admin: dict = Depends(require_platform_admin)):
    doc = _get_shop(shop_id)
    slug = doc["shop_id"]
    members: List[Dict[str, Any]] = []
    for user in users_collection.find({"shops.id": slug}):
        for entry in (user.get("shops") or []):
            if entry.get("id") != slug:
                continue
            members.append(
                {
                    "id": str(user["_id"]),
                    "auth_id": user.get("auth_id"),
                    "user_name": user.get("user_name"),
                    "shop_id": slug,
                    "role": entry.get("role") or str(user.get("role_id") or "").upper(),
                    "status": entry.get("status"),
                    "created_at": user.get("created_at"),
                }
            )
    return members


@router.post("/shops/{shop_id}/members", status_code=201)
def add_member(
    shop_id: str,
    payload: MemberPayload,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_shop(shop_id)
    slug = doc["shop_id"]
    user = users_collection.find_one({"auth_id": payload.auth_id.strip()})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Add or update shop membership
    existing_shops = user.get("shops") or []
    updated = [
        {**entry, "role": payload.role, "status": ACTIVE} if entry.get("id") == slug else entry
        for entry in existing_shops
    ]
    if not any(entry.get("id") == slug for entry in updated):
        updated.append({
            "id": slug,
            "name": doc.get("name"),
            "role": payload.role,
            "status": ACTIVE,
        })

    users_collection.update_one({"_id": user["_id"]}, {"$set": {"shops": updated}})
    return {
        "id": str(user["_id"]),
        "auth_id": user.get("auth_id"),
        "user_name": user.get("user_name"),
        "shop_id": slug,
        "role": payload.role or str(user.get("role_id") or "").upper(),
        "status": ACTIVE,
    }


@router.delete("/shops/{shop_id}/members/{auth_id}")
def remove_member(
    shop_id: str,
    auth_id: str,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_shop(shop_id)
    slug = doc["shop_id"]
    user = users_collection.find_one({"auth_id": auth_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    entries = [entry for entry in (user.get("shops") or []) if entry.get("id") != slug]
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"shops": entries}})
    return {"message": "Membership revoked", "auth_id": auth_id, "shop_id": slug}


class AdminUserCreate(BaseModel):
    auth_id: str = Field(min_length=1, max_length=64)
    user_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=128)
    email: Optional[str] = Field(default=None, max_length=120)
    role: Optional[str] = Field(default="SHOP_ADMIN", max_length=32)


@router.post("/shops/{shop_id}/admins", status_code=201)
def create_shop_admin(
    shop_id: str,
    payload: AdminUserCreate,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_shop(shop_id)
    slug = doc["shop_id"]
    auth_id_clean = payload.auth_id.strip()
    user_name_clean = payload.user_name.strip()
    role_clean = str(payload.role or "SHOP_ADMIN").strip().upper()

    existing = users_collection.find_one({"auth_id": auth_id_clean})
    if existing:
        raise HTTPException(status_code=400, detail="Auth ID already exists")

    import bcrypt
    from ..crypto_helper import encrypt_dict, get_search_token
    from ..mongodb_repository import SENSITIVE_FIELDS
    hashed_pw = bcrypt.hashpw(payload.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    now = _now()
    shop_membership = {
        "id": slug,
        "name": doc.get("name"),
        "role": role_clean,
        "status": ACTIVE,
    }
    user_doc = {
        "auth_id": auth_id_clean,
        "user_name": user_name_clean,
        "password": hashed_pw,
        "role_id": role_clean,
        "status": "active",
        "shops": [shop_membership],
        "created_at": now,
        "updated_at": now,
    }
    if payload.email:
        user_doc["email"] = payload.email.strip()
        user_doc["email_search"] = get_search_token(payload.email.strip())

    result = users_collection.insert_one(encrypt_dict(user_doc, SENSITIVE_FIELDS))
    return {
        "id": str(result.inserted_id),
        "auth_id": auth_id_clean,
        "user_name": user_name_clean,
        "shop_id": slug,
        "role": role_clean,
        "status": ACTIVE,
    }


# ── session hand-off ──────────────────────────────────────────────────────────

@router.post("/shops/{shop_id}/enter")
def enter_shop(shop_id: str, admin: dict = Depends(require_platform_admin)):
    """Issue a short-lived, audited support session inside one shop."""
    doc = _get_shop(shop_id)
    if doc.get("status") != ACTIVE:
        raise HTTPException(status_code=403, detail="This shop is not active")

    token_data = {
        "user_id": admin.get("user_id"),
        "auth_id": admin.get("auth_id"),
        "user_name": admin.get("user_name"),
        "role": str(admin.get("role") or "").upper(),
        "status": admin.get("status"),
        "platform_admin": True,
        "support_entry": True,
        "shop_id": doc["shop_id"],
        "shops": [
            {
                "id": doc["shop_id"],
                "name": doc.get("name") or doc["shop_id"],
                "role": "SUPPORT",
                "status": ACTIVE,
            }
        ],
    }
    user = users_collection.find_one({"_id": admin.get("user_id")})
    return {
        "access_token": create_access_token(token_data, expires_in_hours=1),
        "token_type": "bearer",
        "user": _user_response(user) if user else {
            "auth_id": admin.get("auth_id"),
            "user_name": admin.get("user_name"),
            "role_id": str(admin.get("role") or "").upper(),
            "platform_admin": True,
            "shops": token_data["shops"],
        },
    }
