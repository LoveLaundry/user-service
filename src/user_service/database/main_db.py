"""
MAIN database — production source of truth.

All normal application reads and writes MUST go through these
collections. Never read or write the Secondary/Local databases
from business logic.
"""
from pymongo.collection import Collection

from .connection_manager import ROLE_MAIN, get_database

_db = get_database(ROLE_MAIN)

users_collection: Collection = _db.get_collection("users")

# Multi-tenant identity: laundry registry + user memberships.
laundries_collection: Collection = _db.get_collection("laundries")
memberships_collection: Collection = _db.get_collection("memberships")

# Sync infrastructure collections live alongside business data in MAIN.
sync_status_collection: Collection = _db.get_collection("sync_status")
sync_queue_collection: Collection = _db.get_collection("sync_queue")
sync_logs_collection: Collection = _db.get_collection("sync_logs")


def ensure_indexes():
    """Create all required indexes on the MAIN database."""
    # Users indexes
    users_collection.create_index("user_name")
    users_collection.create_index("auth_id", unique=True)
    users_collection.create_index("email_search", unique=True, sparse=True)
    users_collection.create_index("mobile_number_search", sparse=True)
    users_collection.create_index("employee_id", sparse=True)
    users_collection.create_index("created_at")

    # Laundry registry + membership indexes.
    laundries_collection.create_index("laundry_id", unique=True)
    laundries_collection.create_index("name_search")
    laundries_collection.create_index("br_number", unique=True, sparse=True)
    laundries_collection.create_index("status")
    laundries_collection.create_index("created_at")
    memberships_collection.create_index([("auth_id", 1), ("laundry_id", 1)], unique=True)
    memberships_collection.create_index("laundry_id")
    memberships_collection.create_index("auth_id")
    memberships_collection.create_index("created_at")

    # Sync infrastructure indexes
    sync_status_collection.create_index([("entity", 1), ("record_id", 1)], unique=True)
    sync_queue_collection.create_index([("status", 1), ("next_attempt_at", 1)])
    sync_queue_collection.create_index([("entity", 1), ("record_id", 1)], unique=True)
    sync_logs_collection.create_index([("operation", 1), ("started_at", -1)])