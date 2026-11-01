"""Refresh-token rotation and reuse-detection tests."""
from __future__ import annotations

import pytest

mongomock = pytest.importorskip("mongomock")


def _module(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-only-secret-please-change")
    monkeypatch.setenv("MONGODB_MAIN_URI", "mongodb://localhost")
    monkeypatch.setenv("MONGODB_MAIN_DB", "test")
    import user_service.auth_sessions as sessions
    sessions._db = mongomock.MongoClient()["test"]
    sessions._refresh_sessions = sessions._db.get_collection("auth_refresh_sessions")
    return sessions


def test_refresh_token_rotates_once_and_reuse_revokes_family(monkeypatch):
    sessions = _module(monkeypatch)
    first = sessions.issue_refresh_token(
        auth_id="u-1", user_id="1", laundry_id="laundry-a"
    )
    rotated = sessions.rotate_refresh_token(first)
    second = rotated["refresh_token"]
    assert second != first

    with pytest.raises(Exception):
        sessions.rotate_refresh_token(first)

    row = sessions._refresh_sessions.find_one({"token_hash": sessions._hash(second)})
    assert row["status"] == "revoked"


def test_logout_revokes_active_user_sessions(monkeypatch):
    sessions = _module(monkeypatch)
    sessions.issue_refresh_token(auth_id="u-2", user_id="2", laundry_id="a")
    sessions.issue_refresh_token(auth_id="u-2", user_id="2", laundry_id="b")
    assert sessions.revoke_user_sessions("u-2", reason="logout") == 2
    assert sessions._refresh_sessions.count_documents({"status": "active"}) == 0
