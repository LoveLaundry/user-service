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


def _seed_user(
    db,
    auth_id: str,
    *,
    platform_admin: bool = False,
    role: str = "ADMIN",
    laundries: list | None = None,
    laundry_id: str | None = None,
    support_entry: bool = False,
) -> tuple:
    result = db["users_collection"].insert_one(
        encrypt_dict(
        {
            "auth_id": auth_id,
            "user_name": auth_id.title(),
            "role_id": role,
            "status": "active",
            "platform_admin": platform_admin,
            "laundries": laundries or [],
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
            "laundries": laundries or [],
            "laundry_id": laundry_id or "",
            "support_entry": support_entry,
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


def test_platform_admin_role_can_list_users(client, mocked_db):
    """Reported in production: GET /users returned 403 for a PLATFORM_ADMIN.

    The role only satisfied platform routes, so the account could see the Users
    page but not load it.
    """
    _, token = _seed_user(mocked_db, "platadmin", platform_admin=False, role="PLATFORM_ADMIN")

    response = client.get("/users", headers=_auth(token))

    assert response.status_code == 200, response.text


def test_tenant_admin_membership_management_is_scoped_to_active_laundry(client, mocked_db):
    _, token = _seed_user(
        mocked_db,
        "acmeadmin",
        role="ADMIN",
        laundries=[{"id": "acme", "status": "ACTIVE"}],
        laundry_id="acme",
    )
    target_id, _ = _seed_user(
        mocked_db,
        "member",
        role="CASHIER",
        laundries=[
            {"id": "acme", "status": "ACTIVE"},
            {"id": "globex", "status": "ACTIVE"},
        ],
    )
    headers = _auth(token)

    listed = client.get(f"/users/{target_id}/laundries", headers=headers)
    assert listed.status_code == 200
    assert [entry["id"] for entry in listed.json()["laundries"]] == ["acme"]

    assert client.post(
        f"/users/{target_id}/laundries",
        json={"laundry_id": "globex"},
        headers=headers,
    ).status_code == 403
    assert client.patch(
        f"/users/{target_id}/laundries/globex",
        json={"status": "SUSPENDED"},
        headers=headers,
    ).status_code == 403
    assert client.delete(
        f"/users/{target_id}/laundries/globex",
        headers=headers,
    ).status_code == 403

    stored = mocked_db["users_collection"].find_one({"auth_id": "member"})
    assert [entry["id"] for entry in stored["laundries"]] == ["acme", "globex"]


def test_platform_admin_can_manage_memberships_across_laundries(client, mocked_db):
    _, token = _seed_user(mocked_db, "platformadmin", platform_admin=True)
    target_id, _ = _seed_user(
        mocked_db,
        "member",
        role="CASHIER",
        laundries=[
            {"id": "acme", "status": "ACTIVE"},
            {"id": "globex", "status": "ACTIVE"},
        ],
    )

    listed = client.get(f"/users/{target_id}/laundries", headers=_auth(token))
    assert listed.status_code == 200
    assert {entry["id"] for entry in listed.json()["laundries"]} == {"acme", "globex"}

    granted = client.post(
        f"/users/{target_id}/laundries",
        json={"laundry_id": "initech"},
        headers=_auth(token),
    )
    assert granted.status_code == 201, granted.text
    assert {entry["id"] for entry in granted.json()["laundries"]} == {
        "acme", "globex", "initech"
    }


def test_support_entry_membership_management_is_limited_to_selected_laundry(client, mocked_db):
    _, token = _seed_user(
        mocked_db,
        "supportadmin",
        platform_admin=True,
        laundries=[{"id": "acme", "status": "ACTIVE"}],
        laundry_id="acme",
        support_entry=True,
    )
    target_id, _ = _seed_user(
        mocked_db,
        "member",
        role="CASHIER",
        laundries=[
            {"id": "acme", "status": "ACTIVE"},
            {"id": "globex", "status": "ACTIVE"},
        ],
    )
    headers = _auth(token)

    listed = client.get(f"/users/{target_id}/laundries", headers=headers)
    assert listed.status_code == 200
    assert [entry["id"] for entry in listed.json()["laundries"]] == ["acme"]

    assert client.post(
        f"/users/{target_id}/laundries",
        json={"laundry_id": "globex"},
        headers=headers,
    ).status_code == 403
    assert client.patch(
        f"/users/{target_id}/laundries/globex",
        json={"status": "SUSPENDED"},
        headers=headers,
    ).status_code == 403
    assert client.delete(
        f"/users/{target_id}/laundries/globex",
        headers=headers,
    ).status_code == 403
