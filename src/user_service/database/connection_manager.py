"""
Three-database connection manager (synchronous pymongo).

Every database role (MAIN / SECONDARY / LOCAL) gets its own independent
pymongo client. Business code must select a role explicitly — it is
impossible to accidentally read the wrong database because each role
exposes only its own collections.

Roles:
    MAIN      production source of truth
    SECONDARY verification replica (written only by the sync worker)
    LOCAL     admin-triggered replica
"""
from __future__ import annotations

from pymongo import MongoClient

from ..config import (
    resolve_local_db,
    resolve_local_uri,
    resolve_main_db,
    resolve_main_uri,
    resolve_secondary_db,
    resolve_secondary_uri,
)

# Role names are the source of truth for database selection.
ROLE_MAIN = "MAIN"
ROLE_SECONDARY = "SECONDARY"
ROLE_LOCAL = "LOCAL"

_clients: dict[str, MongoClient] = {}
_databases: dict = {}


def _resolve(role: str) -> tuple[str, str]:
    """Return (uri, db_name) for the given role."""
    if role == ROLE_MAIN:
        return resolve_main_uri(), resolve_main_db()
    if role == ROLE_SECONDARY:
        return resolve_secondary_uri(), resolve_secondary_db()
    if role == ROLE_LOCAL:
        return resolve_local_uri(), resolve_local_db()
    raise ValueError(f"Unknown database role: {role}")


def get_client(role: str) -> MongoClient:
    """Return the role-specific pymongo client, creating it once."""
    role = role.upper()
    if role not in _clients:
        uri, _ = _resolve(role)
        _clients[role] = MongoClient(
            uri,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )
    return _clients[role]


def get_database(role: str):
    """Return the role-specific database object. NEVER cross roles."""
    role = role.upper()
    if role not in _databases:
        uri, db_name = _resolve(role)
        _databases[role] = get_client(role)[db_name]
    return _databases[role]


def ping(role: str) -> bool:
    """Ping a database role. Returns True when reachable."""
    try:
        get_client(role).admin.command("ping")
        return True
    except Exception:
        return False


def close_all() -> None:
    """Close all role clients. Call on application shutdown."""
    for client in _clients.values():
        try:
            client.close()
        except Exception:
            pass
    _clients.clear()
    _databases.clear()