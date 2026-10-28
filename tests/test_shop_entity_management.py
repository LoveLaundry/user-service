"""Tests for shop entity management and access control.

Verifies that:
- Platform Admins can create shop entities
- Platform Admins can grant shop admin memberships
- Shop Admins can only access their own shop's data
- Cross-shop access is prevented
- Shop entity associations are immutable
"""
import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from user_service.auth_helper import create_access_token
from user_service.mongodb_repository import SENSITIVE_FIELDS
from user_service.crypto_helper import encrypt_dict


@pytest.fixture()
def client(mocked_db):
    from user_service.main import app
    return TestClient(app)


def _seed_user(
    db,
    auth_id: str,
    *,
    platform_admin: bool = False,
    role: str = "ADMIN",
    shops: list | None = None,
    shop_id: str | None = None,
) -> tuple[str, str]:
    if shops is None and shop_id:
        shops = [{"id": shop_id, "name": "Test Shop", "role": role, "status": "ACTIVE"}]
    doc = {
        "auth_id": auth_id,
        "user_name": auth_id.title(),
        "role_id": role,
        "status": "active",
        "platform_admin": platform_admin,
        "shops": shops or [],
    }
    result = db["users_collection"].insert_one(encrypt_dict(doc, SENSITIVE_FIELDS))
    uid = str(result.inserted_id)
    token = create_access_token(
        {
            "user_id": uid,
            "auth_id": auth_id,
            "user_name": auth_id.title(),
            "role": role,
            "status": "active",
            "platform_admin": platform_admin,
            "shops": shops or [],
            "shop_id": shop_id or "",
        }
    )
    return uid, token


def _seed_shop(db, shop_id: str, name: str, laundry_id: str = "lovelaundry"):
    doc = {
        "shop_id": shop_id,
        "name": name,
        "associated_laundry_id": laundry_id,
        "status": "ACTIVE",
        "created_by": "test",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }
    db["shops_collection"].insert_one(doc)
    return doc


def _seed_laundry(db, laundry_id: str, name: str):
    doc = {
        "laundry_id": laundry_id,
        "name": name,
        "status": "ACTIVE",
        "created_by": "test",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }
    db["laundries_collection"].insert_one(doc)
    return doc


# ── Shop Entity Creation ───────────────────────────────────────────────────────

def test_platform_admin_can_create_shop(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _, token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "shop_id": "city-express",
        "name": "City Express Shop",
        "associated_laundry_id": "lovelaundry",
    }
    response = client.post("/shops", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["shop_id"] == "city-express"
    assert data["name"] == "City Express Shop"
    assert data["associated_laundry_id"] == "lovelaundry"


def test_non_platform_admin_cannot_create_shop(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _, token = _seed_user(mocked_db, "regular-admin", role="ADMIN")
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "shop_id": "test-shop",
        "name": "Test Shop",
        "associated_laundry_id": "lovelaundry",
    }
    response = client.post("/shops", json=payload, headers=headers)
    assert response.status_code == 403


def test_shop_id_must_be_unique(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _, token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "shop_id": "city-express",
        "name": "Another City Express",
        "associated_laundry_id": "lovelaundry",
    }
    response = client.post("/shops", json=payload, headers=headers)
    assert response.status_code == 409


def test_shop_must_have_valid_laundry(client, mocked_db):
    _, token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "shop_id": "test-shop",
        "name": "Test Shop",
        "associated_laundry_id": "nonexistent-laundry",
    }
    response = client.post("/shops", json=payload, headers=headers)
    assert response.status_code == 400


# ── Shop Membership Management ─────────────────────────────────────────────────

def test_platform_admin_can_grant_shop_admin(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _, admin_token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)
    user_id, _ = _seed_user(mocked_db, "shop-staff", role="STAFF")

    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "shop_id": "city-express",
        "role": "SHOP_ADMIN",
    }
    response = client.post(f"/users/{user_id}/shops", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["shops"][0]["id"] == "city-express"
    assert data["shops"][0]["role"] == "SHOP_ADMIN"


def test_non_platform_admin_cannot_grant_shop_admin(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _, admin_token = _seed_user(mocked_db, "laundry-admin", role="ADMIN")
    user_id, _ = _seed_user(mocked_db, "shop-staff", role="STAFF")

    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "shop_id": "city-express",
        "role": "SHOP_ADMIN",
    }
    response = client.post(f"/users/{user_id}/shops", json=payload, headers=headers)
    assert response.status_code == 403


def test_shop_admin_can_grant_shop_staff(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _, admin_token = _seed_user(mocked_db, "shop-admin", role="SHOP_ADMIN", shop_id="city-express")
    user_id, _ = _seed_user(mocked_db, "shop-cashier", role="STAFF")

    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "shop_id": "city-express",
        "role": "SHOP_STAFF",
    }
    response = client.post(f"/users/{user_id}/shops", json=payload, headers=headers)
    assert response.status_code == 201


def test_cross_shop_access_prevented(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _seed_shop(mocked_db, "quickwash", "QuickWash Outlet")

    # Shop admin for City Express
    _, city_token = _seed_user(mocked_db, "city-admin", role="SHOP_ADMIN", shop_id="city-express")
    # Try to access QuickWash
    headers = {"Authorization": f"Bearer {city_token}"}

    # Should not be able to list QuickWash members
    response = client.get("/shops/quickwash/members", headers=headers)
    assert response.status_code == 403


# ── Shop Session Switching ─────────────────────────────────────────────────────

def test_user_can_switch_to_shop_they_belong_to(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _, token = _seed_user(mocked_db, "multi-shop-user", role="SHOP_STAFF", shops=[
        {"id": "city-express", "name": "City Express Shop", "role": "SHOP_STAFF", "status": "ACTIVE"}
    ])

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"shop_id": "city-express"}
    response = client.post("/auth/switch-shop", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["shop_id"] == "city-express"


def test_user_cannot_switch_to_shop_they_dont_belong_to(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _seed_shop(mocked_db, "quickwash", "QuickWash Outlet")
    _, token = _seed_user(mocked_db, "city-only-user", role="SHOP_STAFF", shops=[
        {"id": "city-express", "name": "City Express Shop", "role": "SHOP_STAFF", "status": "ACTIVE"}
    ])

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"shop_id": "quickwash"}
    response = client.post("/auth/switch-shop", json=payload, headers=headers)
    assert response.status_code == 403


def test_suspended_shop_cannot_be_switched_to(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _, token = _seed_user(mocked_db, "suspended-shop-user", role="SHOP_STAFF", shops=[
        {"id": "city-express", "name": "City Express Shop", "role": "SHOP_STAFF", "status": "SUSPENDED"}
    ])

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"shop_id": "city-express"}
    response = client.post("/auth/switch-shop", json=payload, headers=headers)
    assert response.status_code == 403


# ── Shop Status Management ─────────────────────────────────────────────────────

def test_platform_admin_can_suspend_shop(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _, token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"status": "SUSPENDED"}
    response = client.post("/shops/city-express/status", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUSPENDED"


def test_non_platform_admin_cannot_suspend_shop(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_shop(mocked_db, "city-express", "City Express Shop")
    _, token = _seed_user(mocked_db, "regular-admin", role="ADMIN")

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"status": "SUSPENDED"}
    response = client.post("/shops/city-express/status", json=payload, headers=headers)
    assert response.status_code == 403
