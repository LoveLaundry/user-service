"""Hotel entity registry — platform-managed hotel entities.

Each hotel is one operational entity that can have its own administrators.
This router owns its lifecycle (register, edit, suspend, archive), its membership
roster, and the support-entry hand-off that lets a platform administrator open
a hotel session.

Access is restricted to platform administrators. Hotel administrators can only
manage their own hotel's operations, not other hotels.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..auth_helper import create_access_token, get_current_user
from ..database.main_db import hotels_collection, laundries_collection, users_collection
from ..memberships import ACTIVE, VALID_STATUSES, normalize_laundry_id

router = APIRouter(tags=["hotels"])

MAX_SEARCH_LENGTH = 100
EDITABLE_FIELDS = (
    "name",
    "hotel_code",
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
    """Validate a hotel id, mapping bad input to 400 instead of a 500."""
    slug = str(value or "").strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9_-]{0,31}$", slug):
        raise HTTPException(
            status_code=400,
            detail="Invalid hotel id — use 1-32 lowercase letters, digits, '-' or '_'",
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
    """Gate for the platform surface: users and hotels.

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


def _get_hotel(hotel_id: str) -> Dict[str, Any]:
    slug = _slug(hotel_id)
    doc = hotels_collection.find_one({"hotel_id": slug})
    if not doc:
        raise HTTPException(status_code=404, detail="Hotel not found")
    return doc


class HotelCreate(BaseModel):
    hotel_id: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=120)
    hotel_code: Optional[str] = Field(default=None, max_length=64)
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


class HotelUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    hotel_code: Optional[str] = Field(default=None, max_length=64)
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

@router.get("/hotels")
def list_hotels(
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
            {"hotel_id": {"$regex": pattern, "$options": "i"}},
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

    total = hotels_collection.count_documents(query)
    cursor = (
        hotels_collection.find(query)
        .sort([("created_at", -1), ("_id", -1)])
        .skip(offset)
        .limit(limit)
    )
    return {"items": [_serialize(d) for d in cursor], "total": total}


@router.get("/hotels/{hotel_id}")
def get_hotel(hotel_id: str, _admin: dict = Depends(require_platform_admin)):
    return _serialize(_get_hotel(hotel_id))


@router.post("/hotels", status_code=201)
def create_hotel(payload: HotelCreate, admin: dict = Depends(require_platform_admin)):
    slug = _slug(payload.hotel_id)
    if hotels_collection.find_one({"hotel_id": slug}):
        raise HTTPException(status_code=409, detail="That hotel id is already registered")

    # Validate that the associated laundry exists
    laundry_slug = normalize_laundry_id(payload.associated_laundry_id)
    laundry = laundries_collection.find_one({"laundry_id": laundry_slug})
    if not laundry:
        raise HTTPException(status_code=400, detail="Associated laundry does not exist")
    if laundry.get("status") != ACTIVE:
        raise HTTPException(status_code=400, detail="Associated laundry is not active")

    now = _now()
    document: Dict[str, Any] = {
        "hotel_id": slug,
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

    result = hotels_collection.insert_one(document)
    document["_id"] = result.inserted_id

    return _serialize(document)


@router.put("/hotels/{hotel_id}")
def update_hotel(
    hotel_id: str,
    payload: HotelUpdate,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_hotel(hotel_id)
    updates: Dict[str, Any] = {}
    for field in EDITABLE_FIELDS:
        value = getattr(payload, field, None)
        if value is not None:
            updates[field] = value.strip() if isinstance(value, str) else value
    if not updates:
        return _serialize(doc)

    updates["updated_at"] = _now()
    hotels_collection.update_one({"_id": doc["_id"]}, {"$set": updates})
    doc.update(updates)
    return _serialize(doc)


@router.post("/hotels/{hotel_id}/status")
def set_status(
    hotel_id: str,
    payload: StatusPayload,
    _admin: dict = Depends(require_platform_admin),
):
    wanted = (payload.status or "").strip().upper()
    if wanted not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")

    doc = _get_hotel(hotel_id)
    slug = doc["hotel_id"]
    now = _now()
    hotels_collection.update_one(
        {"_id": doc["_id"]}, {"$set": {"status": wanted, "updated_at": now}}
    )

    # Membership status must also be suspended
    for member in users_collection.find({"hotels.id": slug}):
        entries = [
            {**entry, "status": wanted} if entry.get("id") == slug else entry
            for entry in (member.get("hotels") or [])
        ]
        users_collection.update_one(
            {"_id": member["_id"]},
            {"$set": {"hotels": entries, "updated_at": now}},
        )

    doc["status"] = wanted
    doc["updated_at"] = now
    return _serialize(doc)


# ── membership roster ─────────────────────────────────────────────────────────

@router.get("/hotels/{hotel_id}/members")
def list_members(hotel_id: str, _admin: dict = Depends(require_platform_admin)):
    doc = _get_hotel(hotel_id)
    slug = doc["hotel_id"]
    members: List[Dict[str, Any]] = []
    for user in users_collection.find({"hotels.id": slug}):
        for entry in (user.get("hotels") or []):
            if entry.get("id") != slug:
                continue
            members.append(
                {
                    "id": str(user["_id"]),
                    "auth_id": user.get("auth_id"),
                    "user_name": user.get("user_name"),
                    "hotel_id": slug,
                    "role": entry.get("role") or str(user.get("role_id") or "").upper(),
                    "status": entry.get("status"),
                    "created_at": user.get("created_at"),
                }
            )
    return members


@router.post("/hotels/{hotel_id}/members", status_code=201)
def add_member(
    hotel_id: str,
    payload: MemberPayload,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_hotel(hotel_id)
    slug = doc["hotel_id"]
    user = users_collection.find_one({"auth_id": payload.auth_id.strip()})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Add or update hotel membership
    existing_hotels = user.get("hotels") or []
    updated = [
        {**entry, "role": payload.role, "status": ACTIVE} if entry.get("id") == slug else entry
        for entry in existing_hotels
    ]
    if not any(entry.get("id") == slug for entry in updated):
        updated.append({
            "id": slug,
            "name": doc.get("name"),
            "role": payload.role,
            "status": ACTIVE,
        })

    users_collection.update_one({"_id": user["_id"]}, {"$set": {"hotels": updated}})
    return {
        "id": str(user["_id"]),
        "auth_id": user.get("auth_id"),
        "user_name": user.get("user_name"),
        "hotel_id": slug,
        "role": payload.role or str(user.get("role_id") or "").upper(),
        "status": ACTIVE,
    }


@router.delete("/hotels/{hotel_id}/members/{auth_id}")
def remove_member(
    hotel_id: str,
    auth_id: str,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_hotel(hotel_id)
    slug = doc["hotel_id"]
    user = users_collection.find_one({"auth_id": auth_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    entries = [entry for entry in (user.get("hotels") or []) if entry.get("id") != slug]
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"hotels": entries}})
    return {"message": "Membership revoked", "auth_id": auth_id, "hotel_id": slug}


# ── session hand-off ──────────────────────────────────────────────────────────

@router.post("/hotels/{hotel_id}/enter")
def enter_hotel(hotel_id: str, admin: dict = Depends(require_platform_admin)):
    """Issue a short-lived, audited support session inside one hotel."""
    doc = _get_hotel(hotel_id)
    if doc.get("status") != ACTIVE:
        raise HTTPException(status_code=403, detail="This hotel is not active")

    token_data = {
        "user_id": admin.get("user_id"),
        "auth_id": admin.get("auth_id"),
        "user_name": admin.get("user_name"),
        "role": str(admin.get("role") or "").upper(),
        "status": admin.get("status"),
        "platform_admin": True,
        "support_entry": True,
        "hotel_id": doc["hotel_id"],
        "hotels": [
            {
                "id": doc["hotel_id"],
                "name": doc.get("name") or doc["hotel_id"],
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
            "hotels": token_data["hotels"],
        },
    }
