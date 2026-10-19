"""Laundry registry (tenants) — the platform's view of independent businesses.

Each laundry is one isolated operational environment. This router owns its
lifecycle (register, edit, suspend, archive), its membership roster, and the
support-entry hand-off that lets a platform administrator open a tenant session.

Access is restricted to platform administrators. That flag is deliberately
separate from ``role_id``: the owner of a laundry is an ``ADMIN`` inside their
own tenant and must not be able to create or enter other tenants.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..auth_helper import create_access_token, get_current_user
from ..database.main_db import laundries_collection, users_collection
from ..memberships import (
    ACTIVE,
    VALID_STATUSES,
    build_claims,
    effective_memberships,
    grant,
    normalize_laundry_id,
    revoke,
)

router = APIRouter(tags=["laundries"])

MAX_SEARCH_LENGTH = 100
EDITABLE_FIELDS = (
    "name",
    "br_number",
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
    """Validate a laundry id, mapping bad input to 400 instead of a 500."""
    try:
        return normalize_laundry_id(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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
    """Gate for the platform surface: users and laundries.

    A platform administrator is an explicitly designated account — the
    ``platform_admin`` flag, or the ``PLATFORM_ADMIN`` role. Being ``ADMIN`` is
    not enough: that role runs one laundry's operations, and must never be able
    to register or enter another business.
    """
    role = str(current_user.get("role") or "").upper()
    if current_user.get("platform_admin") or role == "PLATFORM_ADMIN":
        return current_user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Platform administrator access required",
    )


def _get_laundry(laundry_id: str) -> Dict[str, Any]:
    slug = _slug(laundry_id)
    doc = laundries_collection.find_one({"laundry_id": slug})
    if not doc:
        raise HTTPException(status_code=404, detail="Laundry not found")
    return doc


class LaundryCreate(BaseModel):
    laundry_id: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=120)
    br_number: Optional[str] = Field(default=None, max_length=64)
    location: Optional[str] = Field(default=None, max_length=120)
    address: Optional[str] = Field(default=None, max_length=255)
    contact_number: Optional[str] = Field(default=None, max_length=40)
    email: Optional[str] = Field(default=None, max_length=120)
    logo_url: Optional[str] = Field(default=None, max_length=500)
    icon: Optional[str] = Field(default=None, max_length=16)
    description: Optional[str] = Field(default=None, max_length=500)
    subscription_plan: Optional[str] = Field(default=None, max_length=40)
    plan_limits: Optional[str] = Field(default=None, max_length=255)


class LaundryUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    br_number: Optional[str] = Field(default=None, max_length=64)
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


class SwitchPayload(BaseModel):
    laundry_id: str = Field(min_length=1, max_length=32)


def _user_response(user: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in user.items() if k not in ("password", "_id", "_encrypted")}
    out["id"] = str(user.get("id") or user.get("_id"))
    out["role_id"] = str(user.get("role_id") or "").upper()
    out["laundries"] = effective_memberships(user)
    return out


# ── registry ──────────────────────────────────────────────────────────────────

@router.get("/laundries")
def list_laundries(
    search: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(require_platform_admin),
):
    query: Dict[str, Any] = {}
    if search:
        pattern = _escape(search)
        query["$or"] = [
            {"laundry_id": {"$regex": pattern, "$options": "i"}},
            {"name": {"$regex": pattern, "$options": "i"}},
            {"location": {"$regex": pattern, "$options": "i"}},
        ]
    if status_filter:
        wanted = status_filter.strip().upper()
        if wanted not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
        query["status"] = wanted

    total = laundries_collection.count_documents(query)
    cursor = (
        laundries_collection.find(query)
        .sort([("created_at", -1), ("_id", -1)])
        .skip(offset)
        .limit(limit)
    )
    return {"items": [_serialize(d) for d in cursor], "total": total}


@router.get("/laundries/{laundry_id}")
def get_laundry(laundry_id: str, _admin: dict = Depends(require_platform_admin)):
    return _serialize(_get_laundry(laundry_id))


@router.post("/laundries", status_code=201)
def create_laundry(payload: LaundryCreate, admin: dict = Depends(require_platform_admin)):
    slug = _slug(payload.laundry_id)
    if laundries_collection.find_one({"laundry_id": slug}):
        raise HTTPException(status_code=409, detail="That laundry id is already registered")

    now = _now()
    document: Dict[str, Any] = {
        "laundry_id": slug,
        "name": payload.name.strip(),
        "status": ACTIVE,
        "created_by": admin.get("auth_id"),
        "created_at": now,
        "updated_at": now,
    }
    for field in EDITABLE_FIELDS[1:]:
        value = getattr(payload, field, None)
        if value is not None:
            document[field] = value.strip() if isinstance(value, str) else value

    result = laundries_collection.insert_one(document)
    document["_id"] = result.inserted_id

    # The creator gets an ACTIVE membership, otherwise they could register a
    # laundry they are unable to enter or hand over.
    if admin.get("user_id"):
        try:
            user = users_collection.find_one({"_id": _as_object_id(admin.get("user_id"))})
            if user:
                entries = grant(user, slug, name=document["name"], role="ADMIN", status=ACTIVE)
                users_collection.update_one({"_id": user["_id"]}, {"$set": {"laundries": entries}})
        except Exception:
            # Membership is a convenience here; the registry row must still stand.
            pass

    return _serialize(document)


@router.put("/laundries/{laundry_id}")
def update_laundry(
    laundry_id: str,
    payload: LaundryUpdate,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_laundry(laundry_id)
    updates: Dict[str, Any] = {}
    for field in EDITABLE_FIELDS:
        value = getattr(payload, field, None)
        if value is not None:
            updates[field] = value.strip() if isinstance(value, str) else value
    if not updates:
        return _serialize(doc)

    updates["updated_at"] = _now()
    laundries_collection.update_one({"_id": doc["_id"]}, {"$set": updates})
    doc.update(updates)
    return _serialize(doc)


@router.post("/laundries/{laundry_id}/status")
def set_status(
    laundry_id: str,
    payload: StatusPayload,
    _admin: dict = Depends(require_platform_admin),
):
    wanted = (payload.status or "").strip().upper()
    if wanted not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")

    doc = _get_laundry(laundry_id)
    slug = doc["laundry_id"]
    now = _now()
    laundries_collection.update_one(
        {"_id": doc["_id"]}, {"$set": {"status": wanted, "updated_at": now}}
    )

    # Membership status is what resource services actually check, so a suspended
    # laundry must also suspend every member's entry — otherwise an existing
    # session keeps working until its token expires.
    for member in users_collection.find({"laundries.id": slug}):
        entries = [
            {**entry, "status": wanted} if entry.get("id") == slug else entry
            for entry in (member.get("laundries") or [])
        ]
        users_collection.update_one(
            {"_id": member["_id"]},
            {"$set": {"laundries": entries, "updated_at": now}},
        )

    doc["status"] = wanted
    doc["updated_at"] = now
    return _serialize(doc)


# ── membership roster ─────────────────────────────────────────────────────────

@router.get("/laundries/{laundry_id}/members")
def list_members(laundry_id: str, _admin: dict = Depends(require_platform_admin)):
    doc = _get_laundry(laundry_id)
    slug = doc["laundry_id"]
    members: List[Dict[str, Any]] = []
    for user in users_collection.find({"laundries.id": slug}):
        for entry in effective_memberships(user):
            if entry["id"] != slug:
                continue
            members.append(
                {
                    "id": str(user["_id"]),
                    "auth_id": user.get("auth_id"),
                    "user_name": user.get("user_name"),
                    "laundry_id": slug,
                    "role": entry.get("role") or str(user.get("role_id") or "").upper(),
                    "status": entry.get("status"),
                    "created_at": user.get("created_at"),
                }
            )
    return members


@router.post("/laundries/{laundry_id}/members", status_code=201)
def add_member(
    laundry_id: str,
    payload: MemberPayload,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_laundry(laundry_id)
    slug = doc["laundry_id"]
    user = users_collection.find_one({"auth_id": payload.auth_id.strip()})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    entries = grant(user, slug, name=doc.get("name"), role=payload.role, status=ACTIVE)
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"laundries": entries}})
    return {
        "id": str(user["_id"]),
        "auth_id": user.get("auth_id"),
        "user_name": user.get("user_name"),
        "laundry_id": slug,
        "role": payload.role or str(user.get("role_id") or "").upper(),
        "status": ACTIVE,
    }


@router.delete("/laundries/{laundry_id}/members/{auth_id}")
def remove_member(
    laundry_id: str,
    auth_id: str,
    _admin: dict = Depends(require_platform_admin),
):
    doc = _get_laundry(laundry_id)
    slug = doc["laundry_id"]
    user = users_collection.find_one({"auth_id": auth_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    entries = revoke(user, slug)
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"laundries": entries}})
    return {"message": "Membership revoked", "auth_id": auth_id, "laundry_id": slug}


# ── session hand-off ──────────────────────────────────────────────────────────

@router.post("/laundries/{laundry_id}/enter")
def enter_laundry(laundry_id: str, admin: dict = Depends(require_platform_admin)):
    """Issue a short-lived, audited support session inside one tenant."""
    doc = _get_laundry(laundry_id)
    if doc.get("status") != ACTIVE:
        raise HTTPException(status_code=403, detail="This laundry is not active")

    token_data = {
        "user_id": admin.get("user_id"),
        "auth_id": admin.get("auth_id"),
        "user_name": admin.get("user_name"),
        "role": str(admin.get("role") or "").upper(),
        "status": admin.get("status"),
        "platform_admin": True,
        "support_entry": True,
        "laundry_id": doc["laundry_id"],
        "laundries": [
            {
                "id": doc["laundry_id"],
                "name": doc.get("name") or doc["laundry_id"],
                "role": "SUPPORT",
                "status": ACTIVE,
            }
        ],
    }
    user = users_collection.find_one({"_id": _as_object_id(admin.get("user_id"))})
    return {
        "access_token": create_access_token(token_data, expires_in_hours=1),
        "token_type": "bearer",
        "user": _user_response(user) if user else {
            "auth_id": admin.get("auth_id"),
            "user_name": admin.get("user_name"),
            "role_id": str(admin.get("role") or "").upper(),
            "platform_admin": True,
            "laundries": token_data["laundries"],
        },
    }


@router.post("/auth/laundry")
def switch_laundry(
    payload: SwitchPayload,
    current_user: dict = Depends(get_current_user),
):
    """Re-issue this session's token for another laundry the user belongs to."""
    slug = _slug(payload.laundry_id)
    doc = laundries_collection.find_one({"laundry_id": slug})
    if not doc or doc.get("status") != ACTIVE:
        raise HTTPException(status_code=403, detail="This laundry is not active")

    user = users_collection.find_one({"_id": _as_object_id(current_user.get("user_id"))})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    claims = build_claims(user, slug)
    token_data = {
        "user_id": user.get("id") or str(user["_id"]),
        "auth_id": user.get("auth_id"),
        "user_name": user.get("user_name"),
        "role": str(user.get("role_id") or "").upper(),
        "status": user.get("status"),
    }
    token_data.update(claims)
    return {
        "access_token": create_access_token(token_data),
        "token_type": "bearer",
        "user": _user_response(user),
    }


def _as_object_id(value: Union[str, None]):
    from bson import ObjectId

    try:
        return ObjectId(str(value))
    except Exception:
        return value
