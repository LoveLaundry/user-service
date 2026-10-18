"""The tenant claims contract.

Resource services (bill, laundry-management, quotation, worker) read
``laundry_id`` and ``laundries`` from the JWT and fail closed without them. These
tests pin the user-service side of that contract so a refactor cannot silently
stop issuing them — which is exactly the failure this module was written to fix.
"""
import os

import bcrypt
import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from user_service import memberships as m
from user_service.main import app
from user_service.repository_factory import get_repository

SECRET = os.environ["JWT_SECRET"]


def _user(**overrides):
    base = {
        "id": "507f1f77bcf86cd799439011",
        "auth_id": "asha",
        "user_name": "Asha",
        "role_id": "ADMIN",
        "status": "active",
    }
    base.update(overrides)
    return base


def _claims(token: str) -> dict:
    return jwt.decode(token, SECRET, algorithms=["HS256"])


# ── unit: claim construction ───────────────────────────────────────────────────

def test_legacy_account_keeps_working():
    """Accounts predating multi-tenancy must still receive a usable tenant."""
    claims = m.build_claims(_user())
    assert claims["laundry_id"] == m.historical_laundry_id()
    assert claims["laundries"] == [
        {
            "id": m.historical_laundry_id(),
            "name": m.DEFAULT_HISTORICAL_NAME,
            "role": "ADMIN",
            "status": m.ACTIVE,
        }
    ]


def test_single_active_membership_is_selected():
    user = _user(laundries=[{"id": "acme", "name": "Acme", "status": "ACTIVE"}])
    assert m.build_claims(user)["laundry_id"] == "acme"


def test_several_active_memberships_require_an_explicit_switch():
    user = _user(
        laundries=[
            {"id": "acme", "status": "ACTIVE"},
            {"id": "globex", "status": "ACTIVE"},
        ]
    )
    claims = m.build_claims(user)
    assert claims["laundry_id"] == ""
    assert len(claims["laundries"]) == 2


def test_foreign_laundry_is_rejected():
    user = _user(laundries=[{"id": "acme", "status": "ACTIVE"}])
    with pytest.raises(HTTPException) as err:
        m.build_claims(user, "globex")
    assert err.value.status_code == 403


def test_suspended_membership_cannot_be_entered():
    user = _user(laundries=[{"id": "acme", "status": "SUSPENDED"}])
    with pytest.raises(HTTPException) as err:
        m.build_claims(user, "acme")
    assert err.value.status_code == 403


def test_only_active_membership_is_not_auto_selected():
    user = _user(laundries=[{"id": "acme", "status": "SUSPENDED"}])
    assert m.build_claims(user)["laundry_id"] == ""


def test_grant_then_revoke_roundtrip():
    user = _user()
    entries = m.grant(user, "acme", name="Acme Ltd")
    assert {"id": "acme", "name": "Acme Ltd", "role": None, "status": m.ACTIVE} in entries
    assert m.build_claims({**user, "laundries": entries}, "acme")["laundry_id"] == "acme"

    remaining = m.revoke({**user, "laundries": entries}, "acme")
    assert [e["id"] for e in remaining] == [m.historical_laundry_id()]


def test_grant_rejects_path_traversal_slug():
    with pytest.raises(HTTPException) as err:
        m.grant(_user(), "../../etc/passwd")
    assert err.value.status_code == 400


def test_malformed_stored_entries_never_become_claims():
    user = _user(laundries=[{"id": "BAD SLUG"}, "nonsense", {"id": "acme", "status": "ACTIVE"}])
    claims = m.build_claims(user)
    assert [e["id"] for e in claims["laundries"]] == ["acme"]


# ── endpoint: login must emit the claims ──────────────────────────────────────

class _FakeRepo:
    def __init__(self, user):
        self.user = user

    def get_by_auth_id(self, value):
        return self.user if value == self.user["auth_id"] else None

    def get_by_email(self, value):
        return None

    def get_by_id(self, user_id):
        return self.user

    def update(self, user_id, data):
        self.user.update(data)
        return self.user


@pytest.fixture
def client_factory():
    def build(user):
        repo = _FakeRepo(user)
        app.dependency_overrides[get_repository] = lambda: repo
        return TestClient(app), repo

    yield build
    app.dependency_overrides.pop(get_repository, None)


def _with_password(user, password="correct-horse-battery"):
    user["password"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return user, password


def test_login_token_contains_laundry_claims(client_factory):
    user, password = _with_password(_user())
    client, _ = client_factory(user)

    response = client.post("/auth/login", json={"username": "asha", "password": password})
    assert response.status_code == 200
    payload = _claims(response.json()["access_token"])
    assert payload["laundry_id"] == m.historical_laundry_id()
    assert payload["laundries"][0]["status"] == "ACTIVE"


def test_login_can_target_one_of_several_memberships(client_factory):
    user, password = _with_password(
        _user(
            laundries=[
                {"id": "acme", "status": "ACTIVE"},
                {"id": "globex", "status": "ACTIVE"},
            ]
        )
    )
    client, _ = client_factory(user)

    ok = client.post(
        "/auth/login",
        json={"username": "asha", "password": password, "laundry_id": "globex"},
    )
    assert ok.status_code == 200
    assert _claims(ok.json()["access_token"])["laundry_id"] == "globex"

    denied = client.post(
        "/auth/login",
        json={"username": "asha", "password": password, "laundry_id": "initech"},
    )
    assert denied.status_code == 403


def test_switch_laundry_issues_a_new_scoped_token(client_factory, monkeypatch):
    user, password = _with_password(
        _user(
            laundries=[
                {"id": "acme", "status": "ACTIVE"},
                {"id": "globex", "status": "ACTIVE"},
            ]
        )
    )
    # get_current_user reloads the account straight from the repository (to catch
    # revoked users); point that lookup at this test's fixture.
    from user_service import auth_helper

    monkeypatch.setattr(auth_helper, "_fresh_user", lambda auth_id: user)
    client, _ = client_factory(user)
    login = client.post("/auth/login", json={"username": "asha", "password": password})
    token = login.json()["access_token"]
    assert _claims(token)["laundry_id"] == ""

    switched = client.post(
        "/auth/switch-laundry",
        json={"laundry_id": "acme"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert switched.status_code == 200
    assert _claims(switched.json()["access_token"])["laundry_id"] == "acme"


def test_membership_grant_requires_admin(client_factory):
    user, _ = _with_password(_user(role_id="CASHIER"))
    client, _ = client_factory(user)
    response = client.post(
        f"/users/{user['id']}/laundries",
        json={"laundry_id": "acme"},
    )
    assert response.status_code in (401, 403)
