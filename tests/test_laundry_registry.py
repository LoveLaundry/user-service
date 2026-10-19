"""Laundry registry — the tenant lifecycle, end to end.

The React `/laundries` page was shipped against this contract but the endpoints
never existed, so registration could not work. These tests pin the contract the
UI consumes: list/create/update/status/members/enter, plus the guard that keeps
tenant administrators out of the platform registry.
"""
import jwt
import pytest
from fastapi.testclient import TestClient

from user_service.auth_helper import JWT_ALGORITHM, JWT_SECRET, create_access_token
from user_service.crypto_helper import encrypt_dict
from user_service.main import app
from user_service.mongodb_repository import SENSITIVE_FIELDS


@pytest.fixture
def client(mocked_db):
    return TestClient(app)


def _seed_user(db, auth_id: str, *, platform_admin: bool = False, role: str = "ADMIN") -> tuple:
    result = db["users_collection"].insert_one(
        encrypt_dict(
        {
            "auth_id": auth_id,
            "user_name": auth_id.title(),
            "role_id": role,
            "status": "active",
            "platform_admin": platform_admin,
            "laundries": [],
        },
        SENSITIVE_FIELDS,
        )
    )
    token = create_access_token(
        {
            "user_id": str(result.inserted_id),
            "auth_id": auth_id,
            "user_name": auth_id.title(),
            "role": role,
            "status": "active",
            "platform_admin": platform_admin,
        }
    )
    return str(result.inserted_id), token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register(client, token, laundry_id="acme", name="Acme Laundry"):
    return client.post(
        "/laundries",
        json={"laundry_id": laundry_id, "name": name},
        headers=_auth(token),
    )


def test_tenant_manager_cannot_reach_the_registry(client, mocked_db):
    """A laundry-side manager must not create or list other laundries."""
    _, token = _seed_user(mocked_db, "tenantmanager", platform_admin=False, role="MANAGER")

    listed = client.get("/laundries", headers=_auth(token))
    created = _register(client, token, "rogue", "Rogue Laundry")

    assert listed.status_code == 403
    assert created.status_code == 403
    assert mocked_db["laundries_collection"].count_documents({}) == 0


def test_platform_admin_registers_a_laundry(client, mocked_db):
    _, token = _seed_user(mocked_db, "owner", platform_admin=True)

    created = _register(client, token, "acme", "Acme Laundry")

    assert created.status_code == 201, created.text
    body = created.json()
    assert body["laundry_id"] == "acme"
    assert body["name"] == "Acme Laundry"
    assert body["status"] == "ACTIVE"
    assert body["created_by"] == "owner"

    listed = client.get("/laundries", headers=_auth(token))
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["laundry_id"] == "acme"


def test_duplicate_laundry_id_is_rejected(client, mocked_db):
    _, token = _seed_user(mocked_db, "owner", platform_admin=True)
    assert _register(client, token, "acme", "Acme").status_code == 201

    duplicate = _register(client, token, "acme", "Acme Two")
    assert duplicate.status_code == 409


def test_malformed_laundry_id_is_a_400_not_a_500(client, mocked_db):
    _, token = _seed_user(mocked_db, "owner", platform_admin=True)

    bad = _register(client, token, "Bad Slug!", "Bad")
    assert bad.status_code == 400


def test_suspending_a_laundry_suspends_its_members(client, mocked_db):
    _, token = _seed_user(mocked_db, "owner", platform_admin=True)
    member_id, _ = _seed_user(mocked_db, "washer", platform_admin=False, role="CASHIER")
    assert _register(client, token, "acme", "Acme").status_code == 201

    added = client.post(
        "/laundries/acme/members",
        json={"auth_id": "washer", "role": "CASHIER"},
        headers=_auth(token),
    )
    assert added.status_code == 201, added.text

    suspended = client.post(
        "/laundries/acme/status", json={"status": "SUSPENDED"}, headers=_auth(token)
    )
    assert suspended.status_code == 200
    assert suspended.json()["status"] == "SUSPENDED"

    member = mocked_db["users_collection"].find_one({"auth_id": "washer"})
    entry = next(e for e in member["laundries"] if e["id"] == "acme")
    assert entry["status"] == "SUSPENDED", "a live membership would outlive the suspension"


def test_enter_issues_a_support_scoped_token(client, mocked_db):
    _, token = _seed_user(mocked_db, "owner", platform_admin=True)
    assert _register(client, token, "acme", "Acme").status_code == 201

    entered = client.post("/laundries/acme/enter", headers=_auth(token))
    assert entered.status_code == 200, entered.text

    claims = jwt.decode(entered.json()["access_token"], JWT_SECRET, algorithms=[JWT_ALGORITHM])
    assert claims["laundry_id"] == "acme"
    assert claims["support_entry"] is True
    assert claims["platform_admin"] is True
    assert [m["id"] for m in claims["laundries"]] == ["acme"]


def test_membership_listing_reports_the_roster(client, mocked_db):
    _, token = _seed_user(mocked_db, "owner", platform_admin=True)
    _seed_user(mocked_db, "washer", platform_admin=False)
    assert _register(client, token, "acme", "Acme").status_code == 201
    client.post(
        "/laundries/acme/members",
        json={"auth_id": "washer", "role": "CASHIER"},
        headers=_auth(token),
    )

    roster = client.get("/laundries/acme/members", headers=_auth(token))
    assert roster.status_code == 200
    auth_ids = {m["auth_id"] for m in roster.json()}
    assert "washer" in auth_ids
    assert all(m["laundry_id"] == "acme" for m in roster.json())


def test_admin_alone_does_not_grant_platform_scope(client, mocked_db):
    """An ADMIN runs one laundry; the registry must stay out of reach."""
    _, token = _seed_user(mocked_db, "legacyadmin", platform_admin=False, role="ADMIN")

    assert client.get("/laundries", headers=_auth(token)).status_code == 403
    assert _register(client, token, "acme", "Acme").status_code == 403


def test_flagged_admin_reaches_the_registry(client, mocked_db):
    _, token = _seed_user(mocked_db, "operator", platform_admin=True, role="ADMIN")

    assert client.get("/laundries", headers=_auth(token)).status_code == 200
    assert _register(client, token, "acme", "Acme").status_code == 201
