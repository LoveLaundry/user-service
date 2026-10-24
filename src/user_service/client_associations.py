"""Which laundries a client login belongs to, and moving between them.

One person may be registered as a shop — or a hotel — under several laundries.
The accounts are separate documents keyed by ``(laundry_id, auth_id)``, never a
single row with a list of tenants: a shared row would make it possible for a
query to return one client's records while the session belongs to another.

The token, however, carries exactly one scope. Switching laundries therefore
re-issues the token rather than widening it, so an accidental cross-tenant read
stays impossible.
"""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import HTTPException

from .client_accounts import (
    ACTIVE,
    client_accounts_collection,
    client_scope_of,
    normalize_client_type,
)
from .database.main_db import laundries_collection
from .memberships import normalize_laundry_id


def _laundry_label(laundry_id: Any) -> str:
    """Display name for a laundry, falling back to its slug."""
    slug = normalize_laundry_id(laundry_id)
    try:
        doc = laundries_collection.find_one({"laundry_id": slug})
    except Exception:
        doc = None
    name = (doc or {}).get("name")
    return str(name).strip() if name else slug


def list_associations(auth_id: Any, client_type: Any = None) -> List[Dict[str, Any]]:
    """Every laundry this login may enter, for one side of the business.

    Side matters: a shop login and a hotel login are different accounts even
    when they share a username, so the list never offers to cross over.
    """
    login = str(auth_id or "").strip()
    if not login:
        return []

    query: Dict[str, Any] = {"auth_id": login}
    if client_type:
        query["client_type"] = normalize_client_type(client_type)

    try:
        docs = list(client_accounts_collection.find(query))
    except Exception:
        return []

    items = [
        {
            "laundry_id": normalize_laundry_id(doc.get("laundry_id")),
            "laundry_name": _laundry_label(doc.get("laundry_id")),
            "client_name": doc.get("client_name"),
            "client_type": normalize_client_type(doc.get("client_type"), client_type or "HOTEL"),
            "role_id": doc.get("role_id"),
            "status": doc.get("status"),
        }
        for doc in docs
    ]
    items.sort(key=lambda item: (item["laundry_name"] or "", item["laundry_id"] or ""))
    return items


def switch_to(session: Dict[str, Any], laundry_id: Any) -> Dict[str, Any]:
    """Load the same login's account in another laundry.

    Only an account that exists, matches the current side, and is ACTIVE may be
    switched to. Anything else is a 403 rather than a silent fallback to the
    current laundry, so the UI cannot end up showing one tenant's name over
    another tenant's data.
    """
    scope = client_scope_of(session)
    target = normalize_laundry_id(laundry_id)
    if not target:
        raise HTTPException(status_code=400, detail="A laundry is required")

    login = str(session.get("auth_id") or "").strip()
    try:
        doc = client_accounts_collection.find_one(
            {
                "auth_id": login,
                "laundry_id": target,
                "client_type": scope["client_type"],
            }
        )
    except Exception:
        doc = None

    if not doc:
        raise HTTPException(status_code=403, detail="No account for that laundry")
    if str(doc.get("status") or "").strip().upper() != ACTIVE:
        raise HTTPException(status_code=403, detail="That account is not active")

    return doc
