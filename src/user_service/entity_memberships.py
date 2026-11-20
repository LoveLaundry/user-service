"""Hotel and Shop membership claims and management.

This module handles membership claims for hotels and shops, mirroring the
laundry membership system. It provides functions to:
- Build JWT claims for hotel and shop sessions
- Grant/revoke entity memberships
- Validate entity membership status

The pattern is identical to memberships.py but for hotel and shop entities.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

ACTIVE = "ACTIVE"
SUSPENDED = "SUSPENDED"
ARCHIVED = "ARCHIVED"
VALID_STATUSES = {ACTIVE, SUSPENDED, ARCHIVED}

_ENTITY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def normalize_entity_id(value: Any) -> str:
    """Validate an entity (hotel/shop) id. Raises 400 rather than silently coercing."""
    slug = str(value or "").strip().lower()
    if not _ENTITY_ID_RE.match(slug):
        raise HTTPException(
            status_code=400,
            detail="Invalid entity id — use 1-32 lowercase letters, digits, '-' or '_'",
        )
    return slug


def _normalize_status(value: Any) -> str:
    status = str(value or "").strip().upper()
    return status if status in VALID_STATUSES else SUSPENDED


def _normalize_entry(entry: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        return None
    try:
        entity_id = normalize_entity_id(entry.get("id"))
    except HTTPException:
        return None
    return {
        "id": entity_id,
        "name": str(entry.get("name") or entity_id).strip()[:120],
        "role": str(entry.get("role") or "").strip().upper() or None,
        "status": _normalize_status(entry.get("status")),
    }


def stored_entity_memberships(user: Dict[str, Any], entity_type: str) -> List[Dict[str, Any]]:
    """Return stored memberships for a specific entity type (hotels or shops)."""
    raw = user.get(entity_type) if isinstance(user, dict) else None
    if not isinstance(raw, list):
        return []
    entries = [e for e in (_normalize_entry(x) for x in raw) if e]
    by_id: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        by_id[entry["id"]] = entry
    return list(by_id.values())


def effective_entity_memberships(user: Dict[str, Any], entity_type: str) -> List[Dict[str, Any]]:
    """Stored entity memberships (no legacy fallback for hotels/shops)."""
    return stored_entity_memberships(user, entity_type)


def build_entity_claims(
    user: Dict[str, Any],
    entity_type: str,
    requested_entity_id: Optional[str] = None
) -> Dict[str, Any]:
    """Return the entity_id / entity memberships claims for a session.

    For hotels: entity_type = "hotels", returns {"hotel_id": "...", "hotels": [...]}
    For shops: entity_type = "shops", returns {"shop_id": "...", "shops": [...]}
    """
    entries = effective_entity_memberships(user, entity_type)

    if requested_entity_id:
        wanted = normalize_entity_id(requested_entity_id)
        for entry in entries:
            if entry["id"] != wanted:
                continue
            if entry["status"] != ACTIVE:
                raise HTTPException(
                    status_code=403,
                    detail=f"This {entity_type[:-1]} is not active — contact an administrator",
                )
            claim_key = entity_type[:-1] + "_id"  # hotels -> hotel_id, shops -> shop_id
            return {entity_type: entries, claim_key: wanted}
        raise HTTPException(status_code=403, detail=f"No active assignment in that {entity_type[:-1]}")

    active = [e for e in entries if e["status"] == ACTIVE]
    claim_key = entity_type[:-1] + "_id"
    entity_id = active[0]["id"] if len(active) == 1 else ""
    return {entity_type: entries, claim_key: entity_id}


def grant_entity_membership(
    user: Dict[str, Any],
    entity_id: Any,
    entity_type: str,
    *,
    name: Optional[str] = None,
    role: Optional[str] = None,
    status: str = ACTIVE,
) -> List[Dict[str, Any]]:
    """Add or update one entity membership. Returns the full list to persist."""
    slug = normalize_entity_id(entity_id)
    normalized_status = _normalize_status(status)
    entries = effective_entity_memberships(user, entity_type)
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


def revoke_entity_membership(
    user: Dict[str, Any],
    entity_id: Any,
    entity_type: str
) -> List[Dict[str, Any]]:
    """Remove an entity membership. Returns the full list to persist."""
    slug = normalize_entity_id(entity_id)
    entries = effective_entity_memberships(user, entity_type)
    remaining = [e for e in entries if e["id"] != slug]
    if len(remaining) == len(entries):
        raise HTTPException(status_code=404, detail="Membership not found")
    return remaining
