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

    # Sync infrastructure indexes
    sync_status_collection.create_index([("entity", 1), ("record_id", 1)], unique=True)
    sync_queue_collection.create_index([("status", 1), ("next_attempt_at", 1)])
    sync_queue_collection.create_index([("entity", 1), ("record_id", 1)], unique=True)
    sync_logs_collection.create_index([("operation", 1), ("started_at", -1)])