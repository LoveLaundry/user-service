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
# Laundry registry (tenants). One document per independent business.
laundries_collection: Collection = _db.get_collection("laundries")

# External hotel logins. Deliberately separate from `users`: a hotel is a
# customer of a laundry, not a member of its staff, and its session must never
# receive a laundry membership claim (see client_accounts.py).
client_accounts_collection: Collection = _db.get_collection("client_accounts")

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
    laundries_collection.create_index("laundry_id", unique=True)
    laundries_collection.create_index("status")
    laundries_collection.create_index("name")

    # Client logins are scoped per laundry: the same hotel-brand login may exist
    # under two different laundry businesses, but never twice inside one.
    client_accounts_collection.create_index(
        [("laundry_id", 1), ("auth_id", 1)], unique=True
    )
    client_accounts_collection.create_index([("laundry_id", 1), ("client_name", 1)])
    client_accounts_collection.create_index("status")

    # Sync infrastructure indexes
    sync_status_collection.create_index([("entity", 1), ("record_id", 1)], unique=True)
    sync_queue_collection.create_index([("status", 1), ("next_attempt_at", 1)])
    sync_queue_collection.create_index([("entity", 1), ("record_id", 1)], unique=True)
    sync_logs_collection.create_index([("operation", 1), ("started_at", -1)])