"""Laundry membership claims and management.

Resource services trust exactly two JWT claims:

``laundry_id``
    The single laundry this session may operate on.
``laundries``
    The membership snapshot, so a resource service can re-check ACTIVE status
    without calling back into user-service on every request.

This module is the only place that builds them, so login, laundry switching and
the membership endpoints cannot drift apart.

Backward compatibility
----------------------
Accounts created before multi-tenancy have no memberships. They are treated as
ACTIVE members of the historical laundry (``DEFAULT_TENANT``, which defaults to
``lovelaundry``) so existing deployments keep working after the upgrade. That
synthesized entry is never persisted; only an explicit grant is written.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

LOVE_LAUNDRY_ID = "lovelaundry"
DEFAULT_HISTORICAL_NAME = "Love Laundry"

ACTIVE = "ACTIVE"
SUSPENDED = "SUSPENDED"
ARCHIVED = "ARCHIVED"
VALID_STATUSES = {ACTIVE, SUSPENDED, ARCHIVED}

_LAUNDRY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def normalize_laundry_id(value: Any) -> str:
    """Validate a laundry slug. Raises 400 rather than silently coercing."""
    slug = str(value or "").strip().lower()
    if not _LAUNDRY_ID_RE.match(slug):
        raise HTTPException(
            status_code=400,
            detail="Invalid laundry id — use 1-32 lowercase letters, digits, '-' or '_'",
        )
    return slug


def historical_laundry_id() -> str:
    """Laundry that owns all pre-multi-tenancy data."""
    raw = (os.getenv("DEFAULT_TENANT") or LOVE_LAUNDRY_ID).strip().lower()
    return raw if _LAUNDRY_ID_RE.match(raw) else LOVE_LAUNDRY_ID


def _normalize_status(value: Any) -> str:
    status = str(value or "").strip().upper()
    return status if status in VALID_STATUSES else SUSPENDED


def _normalize_entry(entry: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        return None
    try:
        laundry_id = normalize_laundry_id(entry.get("id"))
    except HTTPException:
        # A malformed stored entry must never become a usable claim.
        return None
    return {
        "id": laundry_id,
        "name": str(entry.get("name") or laundry_id).strip()[:120],
        "role": str(entry.get("role") or "").strip().upper() or None,
        "status": _normalize_status(entry.get("status")),
    }


def stored_memberships(user: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = user.get("laundries") if isinstance(user, dict) else None
    if not isinstance(raw, list):
        return []
    entries = [e for e in (_normalize_entry(x) for x in raw) if e]
    # De-duplicate on id, last write wins.
    by_id: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        by_id[entry["id"]] = entry
    return list(by_id.values())


def effective_memberships(user: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Stored memberships, or the legacy single-tenant grant for old accounts."""
    entries = stored_memberships(user)
    if entries:
        return entries
    return [
        {
            "id": historical_laundry_id(),
            "name": DEFAULT_HISTORICAL_NAME,
            "role": str(user.get("role_id") or "").strip().upper() or None,
            "status": ACTIVE,
        }
    ]


def build_claims(user: Dict[str, Any], requested_laundry_id: Optional[str] = None) -> Dict[str, Any]:
    """Return the ``laundry_id`` / ``laundries`` claims for a session.

    ``requested_laundry_id`` is honoured only when the user holds an ACTIVE
    membership for it; anything else fails closed with 403. With no request, a
    user with exactly one active membership is signed into it, while a user with
    several gets no active laundry and must call the switch endpoint.
    """
    entries = effective_memberships(user)

    if requested_laundry_id:
        wanted = normalize_laundry_id(requested_laundry_id)
        for entry in entries:
            if entry["id"] != wanted:
                continue
            if entry["status"] != ACTIVE:
                raise HTTPException(
                    status_code=403,
                    detail="This laundry is not active — contact an administrator",
                )
            return {"laundries": entries, "laundry_id": wanted}
        raise HTTPException(status_code=403, detail="No active assignment in that laundry")

    active = [e for e in entries if e["status"] == ACTIVE]
    laundry_id = active[0]["id"] if len(active) == 1 else ""
    return {"laundries": entries, "laundry_id": laundry_id}


def grant(
    user: Dict[str, Any],
    laundry_id: Any,
    *,
    name: Optional[str] = None,
    role: Optional[str] = None,
    status: str = ACTIVE,
) -> List[Dict[str, Any]]:
    """Add or update one membership. Returns the full list to persist."""
    slug = normalize_laundry_id(laundry_id)
    normalized_status = _normalize_status(status)
    entries = effective_memberships(user)
    updated: List[Dict[str, Any]] = []
    replaced = False
    for entry in entries:
        if entry["id"] == slug:
            updated.append(
                {
                    "id": slug,
                    "name": str(name or entry.get("name") or slug).strip()[:120],
                    "role": str(role or entry.get("role") or "").strip().upper() or None,
                    "status": normalized_status,
                }
            )
            replaced = True
        else:
            updated.append(entry)
    if not replaced:
        updated.append(
            {
                "id": slug,
                "name": str(name or slug).strip()[:120],
                "role": str(role or "").strip().upper() or None,
                "status": normalized_status,
            }
        )
    return updated


def revoke(user: Dict[str, Any], laundry_id: Any) -> List[Dict[str, Any]]:
    slug = normalize_laundry_id(laundry_id)
    entries = effective_memberships(user)
    remaining = [e for e in entries if e["id"] != slug]
    if len(remaining) == len(entries):
        raise HTTPException(status_code=404, detail="Membership not found")
    return remaining
