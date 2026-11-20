"""Regression tests for user updates.

`decrypt_dict` keeps the document's ``_id``, so re-serialising the decrypted
document into a ``$set`` payload used to smuggle ``_id`` back into MongoDB.
MongoDB rejects any change (even an equal one) to the immutable ``_id`` field,
so the update threw and the repository's blanket ``except`` reported "User not
found" (404) while nothing changed. These tests pin a working round-trip and
that the stored ``_id`` is never rewritten.
"""
import pytest
from bson import ObjectId

from user_service.mongodb_repository import MongoDBUserRepository


@pytest.fixture
def repo(mocked_db):
    return MongoDBUserRepository()


def test_update_round_trips_and_preserves_id(repo, mocked_db):
    created = repo.create({
        "user_name": "Alice",
        "email": "alice@example.com",
        "password": "secret-password",
        "auth_id": "auth-alice",
        "employee_id": "EMP-9",
        "role_id": "STAFF",
        "mobile_number": "0770000000",
    })
    uid = created["id"]

    updated = repo.update(uid, {"user_name": "Alice B", "email": "alice.b@example.com"})

    assert updated is not None, "update must not silently fail"
    assert updated["id"] == uid
    assert updated["user_name"] == "Alice B"
    assert updated["email"] == "alice.b@example.com"

    # The row still has exactly one _id and it is the original one.
    raw = mocked_db["users_collection"].find_one({"_id": ObjectId(uid)})
    assert raw is not None
    assert raw["_id"] == ObjectId(uid)


def test_update_missing_user_returns_none(repo):
    assert repo.update(str(ObjectId()), {"user_name": "Ghost"}) is None
