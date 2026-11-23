"""Cross-tenant isolation regressions for user-service staff routes.

The staff directory is administered per tenant: a laundry admin may manage its
own staff but must not read, change, create or enumerate users belonging to
another laundry. Session claims must also be rebuilt from the live record so a
revoked membership stops working without waiting for token expiry.
"""
import os

import jwt
import pytest
from fastapi.testclient import TestClient

from user_service.auth_helper import ACCESS_TOKEN_TTL_HOURS, create_access_token
from user_service.crypto_helper import encrypt_dict, get_search_token
from user_service.mongodb_repository import SENSITIVE_FIELDS

SECRET = os.environ["JWT_SECRET"]
PASSWORD = "cross-tenant-passphrase-1"
NEW_PASSWORD = "another-safe-passphrase-2"


@pytest.fixture
def client(mocked_db):
    from user_service.main import app

    return TestClient(app)


def _membership(tenant, role="STAFF", status="ACTIVE"):
    return {"id": tenant, "name": tenant.title(), "role": role, "status": status}


def _seed(
    db,
    auth_id,
    *,
    role="ADMIN",
    laundry=None,
    laundries=None,
    hotels=None,
    shops=None,
    platform_admin=False,
    status="active",
    support_entry=False,
):
    """Insert a user and issue a token shaped like a real staff login."""
    if laundries is None:
        laundries = [_membership(laundry, role)] if laundry else []
    hotels = hotels or []
    shops = shops or []
    doc = {
        "auth_id": auth_id,
        "user_name": auth_id.title().replace("-", " "),
        "role_id": role,
        "status": status,
        "platform_admin": platform_admin,
        "laundries": laundries,
        "hotels": hotels,
        "shops": shops,
        "email": f"{auth_id}@example.com",
        "employee_id": f"EMP-{auth_id}",
    }
    doc["email_search"] = get_search_token(doc["email"])
    result = db["users_collection"].insert_one(encrypt_dict(doc, SENSITIVE_FIELDS))
    uid = str(result.inserted_id)
    claims = {
        "user_id": uid,
        "auth_id": auth_id,
        "user_name": doc["user_name"],
        "role": role,
        "status": status,
        "platform_admin": platform_admin,
        "laundries": laundries,
        "laundry_id": laundry or "",
        "hotels": hotels,
        "shops": shops,
        "support_entry": support_entry,
    }
    if role == "HOTEL_ADMIN" and hotels:
        claims["hotel_id"] = hotels[0]["id"]
    if role == "SHOP_ADMIN" and shops:
        claims["shop_id"] = shops[0]["id"]
    return uid, create_access_token(claims)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ── finding 1: per-account scope checks ─────────────────────────────────────────

def test_cross_tenant_password_change_is_denied(client, mocked_db):
    _, caller_token = _seed(mocked_db, "acme-admin", role="ADMIN", laundry="acme")
    rival_id, _ = _seed(mocked_db, "rival-staff", role="STAFF", laundry="rival")
    own_id, _ = _seed(mocked_db, "acme-staff", role="STAFF", laundry="acme")
    headers = _auth(caller_token)

    denied = client.patch(
        f"/users/{rival_id}/password",
        json={"password": NEW_PASSWORD},
        headers=headers,
    )
    assert denied.status_code == 403

    allowed = client.patch(
        f"/users/{own_id}/password",
        json={"password": NEW_PASSWORD},
        headers=headers,
    )
    assert allowed.status_code == 200


@pytest.mark.parametrize(
    "method,path,kwargs",
    [
        ("get", "/users/{uid}", {}),
        ("get", "/users/auth/rival-staff", {}),
        ("get", "/users/email/rival-staff@example.com", {}),
        ("get", "/users/employee/EMP-rival-staff", {}),
        ("put", "/users/{uid}", {"json": {"user_name": "Taken Over"}}),
        ("patch", "/users/{uid}/status", {"json": {"status": "disabled"}}),
        ("delete", "/users/{uid}", {}),
        ("patch", "/users/{uid}/profile", {"data": {"user_name": "Taken Over"}}),
    ],
)
def test_cross_tenant_user_access_is_denied_on_every_route(client, mocked_db, method, path, kwargs):
    _, caller_token = _seed(mocked_db, "scope-admin", role="ADMIN", laundry="acme")
    rival_id, _ = _seed(mocked_db, "rival-staff", role="STAFF", laundry="rival")
    response = getattr(client, method)(
        path.format(uid=rival_id), headers=_auth(caller_token), **kwargs
    )
    assert response.status_code == 403


def test_same_tenant_admin_still_manages_staff(client, mocked_db):
    _, caller_token = _seed(mocked_db, "good-admin", role="ADMIN", laundry="acme")
    staff_id, _ = _seed(mocked_db, "good-staff", role="STAFF", laundry="acme")
    headers = _auth(caller_token)

    assert client.get(f"/users/{staff_id}", headers=headers).status_code == 200
    assert client.put(
        f"/users/{staff_id}", json={"user_name": "Renamed"}, headers=headers
    ).status_code == 200
    assert client.get("/users", headers=headers).status_code == 200


def test_entity_admin_scope_honours_hotel_membership(client, mocked_db):
    hotel = _membership("grand", "HOTEL_ADMIN")
    _, caller_token = _seed(
        mocked_db, "hotel-boss", role="HOTEL_ADMIN", hotels=[hotel]
    )
    own_id, _ = _seed(
        mocked_db,
        "hotel-clerk",
        role="STAFF",
        hotels=[_membership("grand", "HOTEL_MANAGER")],
    )
    other_id, _ = _seed(
        mocked_db,
        "other-hotel-clerk",
        role="STAFF",
        hotels=[_membership("rival-hotel", "HOTEL_MANAGER")],
    )
    headers = _auth(caller_token)

    allowed = client.patch(
        f"/users/{own_id}/profile", data={"user_name": "Front Desk"}, headers=headers
    )
    denied = client.patch(
        f"/users/{other_id}/profile", data={"user_name": "Taken Over"}, headers=headers
    )
    assert allowed.status_code == 200
    assert denied.status_code == 403


# ── finding 2: directory enumeration ───────────────────────────────────────────

def test_cross_tenant_user_list_and_count_are_filtered(client, mocked_db):
    _, tenant_token = _seed(mocked_db, "tenant-admin", role="ADMIN", laundry="acme")
    _seed(mocked_db, "acme-staff", role="STAFF", laundry="acme")
    _seed(mocked_db, "acme-manager", role="MANAGER", laundry="acme")
    _seed(mocked_db, "rival-staff", role="STAFF", laundry="rival")
    _, platform_token = _seed(
        mocked_db, "platform-owner", role="PLATFORM_ADMIN", platform_admin=True
    )

    listed = client.get("/users", headers=_auth(tenant_token))
    assert listed.status_code == 200
    assert {user["auth_id"] for user in listed.json()} == {
        "tenant-admin",
        "acme-staff",
        "acme-manager",
    }

    counted = client.get("/users/count", headers=_auth(tenant_token))
    assert counted.status_code == 200
    assert counted.json() == {"count": 3}

    platform_list = client.get("/users", headers=_auth(platform_token))
    assert platform_list.status_code == 200
    assert len(platform_list.json()) == 5
    assert client.get("/users/count", headers=_auth(platform_token)).json() == {
        "count": 5
    }


# ── finding 3: membership injection ────────────────────────────────────────────

def test_non_platform_admin_cannot_grant_membership_in_another_tenant(client, mocked_db):
    _, tenant_token = _seed(mocked_db, "tenant-admin", role="ADMIN", laundry="acme")
    _, platform_token = _seed(
        mocked_db, "platform-owner", role="PLATFORM_ADMIN", platform_admin=True
    )
    headers = _auth(tenant_token)

    body = {
        "user_name": "Injected Staff",
        "auth_id": "injected",
        "password": PASSWORD,
        "role_id": "STAFF",
    }
    cross = client.post(
        "/users", json={**body, "laundry_id": "rival"}, headers=headers
    )
    assert cross.status_code == 403
    assert mocked_db["users_collection"].find_one({"auth_id": "injected"}) is None

    own = client.post(
        "/users", json={**body, "laundry_id": "acme"}, headers=headers
    )
    assert own.status_code == 201
    assert "acme" in [entry["id"] for entry in own.json()["laundries"]]

    hotel = client.post(
        "/users",
        json={**body, "auth_id": "injected-hotel", "hotel_id": "foreign-hotel"},
        headers=headers,
    )
    assert hotel.status_code == 403

    # Platform admins keep the existing behaviour of targeting any tenant.
    platform = client.post(
        "/users",
        json={**body, "auth_id": "platform-placed", "laundry_id": "rival"},
        headers=_auth(platform_token),
    )
    assert platform.status_code == 201
    assert "rival" in [entry["id"] for entry in platform.json()["laundries"]]


# ── finding 4: stale tenant claims ─────────────────────────────────────────────

def test_revoked_membership_is_removed_from_an_existing_token(client, mocked_db):
    _, token = _seed(mocked_db, "tenant-admin", role="ADMIN", laundry="acme")
    headers = _auth(token)
    assert client.get("/auth/status", headers=headers).status_code == 200

    mocked_db["users_collection"].update_one(
        {"auth_id": "tenant-admin"}, {"$set": {"laundries": []}}
    )

    # The legacy fallback means a user with no memberships reads as the
    # historical laundry, so an old acme-scoped token must be refused rather
    # than silently re-pointed at another tenant.
    rejected = client.get("/auth/status", headers=headers)
    assert rejected.status_code == 403


def test_suspended_membership_is_enforced_on_the_next_request(client, mocked_db):
    _, token = _seed(mocked_db, "tenant-admin", role="ADMIN", laundry="acme")
    mocked_db["users_collection"].update_one(
        {"auth_id": "tenant-admin"},
        {"$set": {"laundries": [_membership("acme", "ADMIN", "SUSPENDED")]}},
    )
    assert client.get("/auth/status", headers=_auth(token)).status_code == 403


def test_support_entry_scope_survives_claim_refresh(client, mocked_db):
    # Registry-issued support tokens carry an audited scope that is not stored
    # on the user row; rebuilding must not strip it.
    _, token = _seed(
        mocked_db,
        "platform-owner",
        role="PLATFORM_ADMIN",
        platform_admin=True,
        support_entry=True,
        laundry="support-tenant",
        laundries=[_membership("support-tenant", "SUPPORT")],
    )
    response = client.get("/auth/status", headers=_auth(token))
    assert response.status_code == 200
    assert response.json()["laundry_id"] == "support-tenant"


def test_client_session_scope_is_unchanged(client, mocked_db):
    from user_service import client_accounts as ca

    ca.create_client_account(
        laundry_id="lovelaundry",
        client_name="Cinnamon Grand",
        auth_id="cinnamon",
        user_name="Front Desk",
        password="hotel-pass-1",
        role="HOTEL_MANAGER",
        client_type="HOTEL",
    )
    login = client.post(
        "/client/auth/login",
        json={"auth_id": "cinnamon", "password": "hotel-pass-1"},
    )
    assert login.status_code == 200
    claims = jwt.decode(login.json()["access_token"], SECRET, algorithms=["HS256"])
    # Staff claim rebuild must not leak into the customer session shape.
    assert "laundry_id" not in claims
    assert claims["client_scope"]["laundry_id"] == "lovelaundry"
    assert client.get(
        "/client/auth/status", headers=_auth(login.json()["access_token"])
    ).status_code == 200


# ── cheaper hardening items ────────────────────────────────────────────────────

def test_access_token_default_ttl_comes_from_config_and_explicit_ttl_wins():
    default_claims = jwt.decode(
        create_access_token({"auth_id": "ttl-check"}), SECRET, algorithms=["HS256"]
    )
    assert default_claims["exp"] - default_claims["iat"] == int(
        ACCESS_TOKEN_TTL_HOURS * 3600
    )
    explicit_claims = jwt.decode(
        create_access_token({"auth_id": "ttl-check"}, expires_in_hours=12),
        SECRET,
        algorithms=["HS256"],
    )
    assert explicit_claims["exp"] - explicit_claims["iat"] == 12 * 3600


def test_staff_password_length_policy(client, mocked_db):
    _, token = _seed(mocked_db, "platform-owner", role="PLATFORM_ADMIN", platform_admin=True)
    headers = _auth(token)
    body = {
        "user_name": "Policy Staff",
        "auth_id": "policy-staff",
        "role_id": "STAFF",
    }

    assert client.post(
        "/users", json={**body, "password": "short123456"}, headers=headers
    ).status_code == 422
    assert client.post(
        "/users", json={**body, "password": PASSWORD}, headers=headers
    ).status_code == 201
    staff_id, _ = _seed(mocked_db, "policy-target", role="STAFF", laundry="acme")
    assert client.patch(
        f"/users/{staff_id}/password",
        json={"password": "short123456"},
        headers=headers,
    ).status_code == 422
