"""Tests ensuring laundry admins, shops admins, and hotels admin can ONLY be created by the platform admin."""
import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from user_service.auth_helper import create_access_token
from user_service.crypto_helper import encrypt_dict
from user_service.mongodb_repository import SENSITIVE_FIELDS


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
    laundries: list | None = None,
    laundry_id: str | None = None,
) -> tuple[str, str]:
    if laundries is None and laundry_id:
        laundries = [{"id": laundry_id, "name": "Love Laundry", "role": role, "status": "ACTIVE"}]
    doc = {
        "auth_id": auth_id,
        "user_name": auth_id.title(),
        "role_id": role,
        "status": "active",
        "platform_admin": platform_admin,
        "laundries": laundries or [],
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
            "laundries": laundries or [],
            "laundry_id": laundry_id or "",
        }
    )
    return uid, token


# ── Laundry Admin Creation & Protection ────────────────────────────────────────

def test_laundry_admin_cannot_create_another_laundry_admin(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-1", role="ADMIN", laundry_id="lovelaundry")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "user_name": "New Laundry Admin",
        "auth_id": "new.laundry.admin",
        "password": "password123",
        "role_id": "ADMIN",
    }
    response = client.post("/users", json=payload, headers=headers)
    assert response.status_code == 403
    assert "Only platform administrators can create laundry administrators" in response.json()["detail"]


def test_laundry_admin_cannot_create_platform_admin(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-2", role="ADMIN", laundry_id="lovelaundry")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "user_name": "New Platform Admin",
        "auth_id": "new.plat.admin",
        "password": "password123",
        "role_id": "PLATFORM_ADMIN",
    }
    response = client.post("/users", json=payload, headers=headers)
    assert response.status_code == 403


def test_platform_admin_can_create_laundry_admin(client, mocked_db):
    _, token = _seed_user(mocked_db, "platform-admin-root", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "user_name": "Brand New Laundry Admin",
        "auth_id": "brand.new.admin",
        "password": "password123",
        "role_id": "ADMIN",
        "laundry_id": "lovelaundry",
    }
    response = client.post("/users", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["auth_id"] == "brand.new.admin"
    assert data["role_id"] == "ADMIN"


def test_laundry_admin_can_create_staff_or_manager(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-3", role="ADMIN", laundry_id="lovelaundry")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "user_name": "Regular Staff",
        "auth_id": "regular.staff.1",
        "password": "password123",
        "role_id": "STAFF",
    }
    response = client.post("/users", json=payload, headers=headers)
    assert response.status_code == 201
    assert response.json()["role_id"] == "STAFF"


def test_laundry_admin_cannot_promote_user_to_admin(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-4", role="ADMIN", laundry_id="lovelaundry")
    staff_id, _ = _seed_user(mocked_db, "staff.worker.promote", role="STAFF", laundry_id="lovelaundry")

    headers = {"Authorization": f"Bearer {token}"}
    response = client.put(f"/users/{staff_id}", json={"role_id": "ADMIN"}, headers=headers)
    assert response.status_code == 403
    assert "Only platform administrators can promote users to administrator" in response.json()["detail"]


def test_laundry_admin_cannot_modify_admin_account(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-5", role="ADMIN", laundry_id="lovelaundry")
    target_admin_id, _ = _seed_user(mocked_db, "existing.admin.target", role="ADMIN", laundry_id="lovelaundry")

    headers = {"Authorization": f"Bearer {token}"}
    # Attempting to edit admin's username
    response = client.put(f"/users/{target_admin_id}", json={"user_name": "Hacked Name"}, headers=headers)
    assert response.status_code == 403
    assert "Only platform administrators can modify administrator accounts" in response.json()["detail"]

    # Attempting to disable admin
    status_resp = client.patch(f"/users/{target_admin_id}/status", json={"status": "inactive"}, headers=headers)
    assert status_resp.status_code == 403

    # Attempting to delete admin
    del_resp = client.delete(f"/users/{target_admin_id}", headers=headers)
    assert del_resp.status_code == 403


def test_laundry_admin_cannot_grant_admin_membership(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-6", role="ADMIN", laundry_id="lovelaundry")
    staff_id, _ = _seed_user(mocked_db, "staff.membership.grant", role="STAFF", laundry_id="lovelaundry")

    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        f"/users/{staff_id}/laundries",
        json={"laundry_id": "lovelaundry", "role": "ADMIN"},
        headers=headers,
    )
    assert response.status_code == 403
    assert "Only platform administrators can grant admin memberships" in response.json()["detail"]


# ── Hotel & Shop Admin Creation Via POST /clients ──────────────────────────────

def test_laundry_admin_cannot_create_hotel_admin(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-7", role="ADMIN", laundry_id="lovelaundry")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "client_type": "HOTEL",
        "role": "HOTEL_ADMIN",
        "client_name": "Hilton Colombo",
        "auth_id": "hilton.admin",
        "user_name": "Hilton Admin User",
        "password": "securepass123",
    }
    response = client.post("/clients", json=payload, headers=headers)
    assert response.status_code == 403
    assert "Only platform administrators can create hotel administrators" in response.json()["detail"]


def test_laundry_admin_cannot_create_shop_admin(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-8", role="ADMIN", laundry_id="lovelaundry")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "client_type": "SHOP",
        "role": "SHOP_ADMIN",
        "client_name": "City Express Shop",
        "auth_id": "city.shop.admin",
        "user_name": "City Shop Admin User",
        "password": "securepass123",
    }
    response = client.post("/clients", json=payload, headers=headers)
    assert response.status_code == 403
    assert "Only platform administrators can create shop administrators" in response.json()["detail"]


def test_platform_admin_can_create_hotel_admin(client, mocked_db):
    _, token = _seed_user(mocked_db, "platform-admin-clients", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "client_type": "HOTEL",
        "role": "HOTEL_ADMIN",
        "client_name": "Grand Oriental Hotel",
        "auth_id": "goh.admin",
        "user_name": "GOH Admin",
        "password": "securepass123",
        "laundry_id": "lovelaundry",
    }
    response = client.post("/clients", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["role_id"] == "HOTEL_ADMIN"
    assert data["client_name"] == "Grand Oriental Hotel"
    assert data["client_type"] == "HOTEL"


def test_platform_admin_can_create_shop_admin(client, mocked_db):
    _, token = _seed_user(mocked_db, "platform-admin-shop", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "client_type": "SHOP",
        "role": "SHOP_ADMIN",
        "client_name": "QuickWash Outlet",
        "auth_id": "quickwash.admin",
        "user_name": "QuickWash Admin",
        "password": "securepass123",
        "laundry_id": "lovelaundry",
    }
    response = client.post("/clients", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["role_id"] == "SHOP_ADMIN"
    assert data["client_name"] == "QuickWash Outlet"
    assert data["client_type"] == "SHOP"


def test_laundry_admin_can_create_hotel_manager_and_shop_staff(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-clients", role="ADMIN", laundry_id="lovelaundry")
    headers = {"Authorization": f"Bearer {token}"}

    # Hotel Manager
    hotel_resp = client.post(
        "/clients",
        json={
            "client_type": "HOTEL",
            "role": "HOTEL_MANAGER",
            "client_name": "Grand Oriental Hotel",
            "auth_id": "goh.manager.1",
            "user_name": "GOH Manager",
            "password": "securepass123",
        },
        headers=headers,
    )
    assert hotel_resp.status_code == 201
    assert hotel_resp.json()["role_id"] == "HOTEL_MANAGER"

    # Shop Staff
    shop_resp = client.post(
        "/clients",
        json={
            "client_type": "SHOP",
            "role": "SHOP_STAFF",
            "client_name": "QuickWash Outlet",
            "auth_id": "quickwash.staff.1",
            "user_name": "QuickWash Staff",
            "password": "securepass123",
        },
        headers=headers,
    )
    assert shop_resp.status_code == 201
    assert shop_resp.json()["role_id"] == "SHOP_STAFF"
