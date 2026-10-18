"""Shared harness for user-service tests.

No real MongoDB instance is required. A ``mongomock`` database stands in for
every MAIN / SECONDARY / LOCAL collection, patched onto the database modules
BEFORE the repositories/services/router are (re)loaded, so their module-level
bindings (``from ..database.main_db import users_collection``) resolve to the
mock.
"""
import importlib
import os

import pytest
from mongomock import MongoClient

# Must be set before user_service.config is imported: DB_TYPE is derived from
# DATABASE_URL at import time and these tests exercise the MongoDB backend.
os.environ.setdefault("DATABASE_URL", "mongodb://localhost:27017")
os.environ.setdefault("JWT_SECRET", "test-secret-not-a-real-credential")
os.environ.setdefault("MASTER_KEY", "test-master-key-not-real")

MOCK_DB_NAME = "mock_user"

COLLECTION_NAMES = [
    "users_collection",
    "sync_queue_collection",
    "sync_status_collection",
    "sync_logs_collection",
]

# Modules whose module-level collection bindings must point at the mock.
# Anything that does `from ..database.main_db import <collection>` caches the
# handle at import time, so it must be reloaded after patching.
DEPENDENT_MODULES = [
    "user_service.repositories.entity_registry",
    "user_service.repositories.main_repository",
    "user_service.repositories.secondary_repository",
    "user_service.services.verification_service",
    "user_service.services.synchronization_service",
    "user_service.mongodb_repository",
    "user_service.main",
]

# (module, attribute) pairs that must all resolve to the mock database.
GUARDED_HANDLES = [
    ("user_service.mongodb_repository", "users_collection"),
    ("user_service.repositories.main_repository", "sync_queue_collection"),
    ("user_service.repositories.main_repository", "sync_status_collection"),
    ("user_service.services.synchronization_service", "sync_queue_collection"),
    ("user_service.services.synchronization_service", "sync_logs_collection"),
    ("user_service.repositories.secondary_repository", "sync_status_collection"),
    ("user_service.services.verification_service", "sync_status_collection"),
]


@pytest.fixture(scope="session")
def mock_client():
    return MongoClient()


@pytest.fixture(scope="session", autouse=True)
def mocked_db(mock_client):
    """Swap every database collection for a mongomock stand-in."""
    db = mock_client[MOCK_DB_NAME]

    import user_service.database.main_db as main_db
    import user_service.database.secondary_db as secondary_db
    import user_service.database.local_db as local_db

    for name in COLLECTION_NAMES:
        coll = db.get_collection(name)
        setattr(main_db, name, coll)
        setattr(secondary_db, name, coll)
        setattr(local_db, name, coll)

    for module_name in DEPENDENT_MODULES:
        importlib.reload(importlib.import_module(module_name))

    _assert_no_live_clients()
    return db


def _assert_no_live_clients() -> None:
    """Fail loudly if any module still holds a real MongoDB collection.

    A stale handle points at whatever ``.env`` names, which in development is
    the PRODUCTION Atlas cluster — a stray write in a test would mutate live
    data. Assert every cached handle belongs to the mongomock database.
    """
    prefix = f"{MOCK_DB_NAME}."
    leaked = []
    for module_name, attr in GUARDED_HANDLES:
        module = importlib.import_module(module_name)
        collection = getattr(module, attr, None)
        full_name = getattr(collection, "full_name", None)
        if full_name is None or not str(full_name).startswith(prefix):
            leaked.append(f"{module_name}.{attr} -> {full_name}")

    if leaked:
        pytest.fail(
            "Refusing to run: modules still hold live MongoDB collection(s) "
            f"[{'; '.join(leaked)}]. Tests would mutate a real database. "
            "Add the owning module to DEPENDENT_MODULES."
        )


@pytest.fixture(autouse=True)
def clean_db(mocked_db):
    """Isolate tests: every mocked collection starts empty."""
    for name in COLLECTION_NAMES:
        mocked_db[name].delete_many({})
    yield
