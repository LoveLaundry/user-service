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


# ── Hotel & Shop Admin Creation Via POST /users ────────────────────────────────

def test_laundry_admin_cannot_create_hotel_admin_via_users(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-u1", role="ADMIN", laundry_id="lovelaundry")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "user_name": "New Hotel Admin",
        "auth_id": "new.hotel.admin.u",
        "password": "password123",
        "role_id": "HOTEL_ADMIN",
        "hotel_id": "hilton",
    }
    response = client.post("/users", json=payload, headers=headers)
    assert response.status_code == 403
    assert "Only platform administrators can create hotel administrators" in response.json()["detail"]


def test_laundry_admin_cannot_create_shop_admin_via_users(client, mocked_db):
    _, token = _seed_user(mocked_db, "tenant-admin-u2", role="ADMIN", laundry_id="lovelaundry")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "user_name": "New Shop Admin",
        "auth_id": "new.shop.admin.u",
        "password": "password123",
        "role_id": "SHOP_ADMIN",
        "shop_id": "quickwash",
    }
    response = client.post("/users", json=payload, headers=headers)
    assert response.status_code == 403
    assert "Only platform administrators can create shop administrators" in response.json()["detail"]


def test_platform_admin_can_create_hotel_admin_via_users(client, mocked_db):
    _, token = _seed_user(mocked_db, "platform-admin-u3", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "user_name": "Hotel Admin User",
        "auth_id": "hotel.admin.direct",
        "password": "password123",
        "role_id": "HOTEL_ADMIN",
        "hotel_id": "cinnamon-grand",
    }
    response = client.post("/users", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["auth_id"] == "hotel.admin.direct"
    assert data["role_id"] == "HOTEL_ADMIN"
    assert any(h["id"] == "cinnamon-grand" and h["role"] == "HOTEL_ADMIN" for h in (data.get("hotels") or []))


def test_platform_admin_can_create_shop_admin_via_users(client, mocked_db):
    _, token = _seed_user(mocked_db, "platform-admin-u4", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "user_name": "Shop Admin User",
        "auth_id": "shop.admin.direct",
        "password": "password123",
        "role_id": "SHOP_ADMIN",
        "shop_id": "kandy-shop",
    }
    response = client.post("/users", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["auth_id"] == "shop.admin.direct"
    assert data["role_id"] == "SHOP_ADMIN"
    assert any(s["id"] == "kandy-shop" and s["role"] == "SHOP_ADMIN" for s in (data.get("shops") or []))


# ── Entity Registration with Initial Admin & Direct Admin Endpoint ─────────────

def test_platform_admin_can_create_hotel_with_initial_admin(client, mocked_db):
    mocked_db["laundries_collection"].insert_one({"laundry_id": "lovelaundry", "name": "Love Laundry", "status": "ACTIVE"})
    _, token = _seed_user(mocked_db, "platform-admin-hotel-init", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "hotel_id": "marino-beach",
        "name": "Marino Beach Hotel",
        "associated_laundry_id": "lovelaundry",
        "admin_auth_id": "marino.admin",
        "admin_user_name": "Marino Admin",
        "admin_password": "securepassword123",
        "admin_email": "admin@marinobeach.lk",
    }
    resp = client.post("/hotels", json=payload, headers=headers)
    assert resp.status_code == 201
    assert resp.json()["hotel_id"] == "marino-beach"

    # Verify admin user was created in users_collection
    user = mocked_db["users_collection"].find_one({"auth_id": "marino.admin"})
    assert user is not None
    assert user["role_id"] == "HOTEL_ADMIN"
    assert any(h["id"] == "marino-beach" for h in (user.get("hotels") or []))


def test_platform_admin_can_create_shop_with_initial_admin(client, mocked_db):
    mocked_db["laundries_collection"].insert_one({"laundry_id": "lovelaundry", "name": "Love Laundry", "status": "ACTIVE"})
    _, token = _seed_user(mocked_db, "platform-admin-shop-init", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "shop_id": "galle-outlet",
        "name": "Galle Express Outlet",
        "associated_laundry_id": "lovelaundry",
        "admin_auth_id": "galle.shop.admin",
        "admin_user_name": "Galle Shop Admin",
        "admin_password": "securepassword123",
    }
    resp = client.post("/shops", json=payload, headers=headers)
    assert resp.status_code == 201
    assert resp.json()["shop_id"] == "galle-outlet"

    user = mocked_db["users_collection"].find_one({"auth_id": "galle.shop.admin"})
    assert user is not None
    assert user["role_id"] == "SHOP_ADMIN"
    assert any(s["id"] == "galle-outlet" for s in (user.get("shops") or []))


def test_platform_admin_can_create_hotel_admin_via_admins_endpoint(client, mocked_db):
    mocked_db["hotels_collection"].insert_one({"hotel_id": "shangrila", "name": "Shangri-La", "status": "ACTIVE"})
    _, token = _seed_user(mocked_db, "platform-admin-hotel-endpoint", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "auth_id": "shangrila.admin",
        "user_name": "Shangri-La Admin",
        "password": "securepassword123",
        "role": "HOTEL_ADMIN",
    }
    resp = client.post("/hotels/shangrila/admins", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["auth_id"] == "shangrila.admin"
    assert data["role"] == "HOTEL_ADMIN"
    assert data["hotel_id"] == "shangrila"


def test_platform_admin_can_create_shop_admin_via_admins_endpoint(client, mocked_db):
    mocked_db["shops_collection"].insert_one({"shop_id": "colombo-07-shop", "name": "Colombo 07 Shop", "status": "ACTIVE"})
    _, token = _seed_user(mocked_db, "platform-admin-shop-endpoint", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "auth_id": "c7.shop.admin",
        "user_name": "Colombo 7 Admin",
        "password": "securepassword123",
        "role": "SHOP_ADMIN",
    }
    resp = client.post("/shops/colombo-07-shop/admins", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["auth_id"] == "c7.shop.admin"
    assert data["role"] == "SHOP_ADMIN"
    assert data["shop_id"] == "colombo-07-shop"

