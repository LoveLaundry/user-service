"""Tests for hotel entity management and access control.

Verifies that:
- Platform Admins can create hotel entities
- Platform Admins can grant hotel admin memberships
- Hotel Admins can only access their own hotel's data
- Cross-hotel access is prevented
- Hotel entity associations are immutable
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
    hotels: list | None = None,
    hotel_id: str | None = None,
) -> tuple[str, str]:
    if hotels is None and hotel_id:
        hotels = [{"id": hotel_id, "name": "Test Hotel", "role": role, "status": "ACTIVE"}]
    doc = {
        "auth_id": auth_id,
        "user_name": auth_id.title(),
        "role_id": role,
        "status": "active",
        "platform_admin": platform_admin,
        "hotels": hotels or [],
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
            "hotels": hotels or [],
            "hotel_id": hotel_id or "",
        }
    )
    return uid, token


def _seed_hotel(db, hotel_id: str, name: str, laundry_id: str = "lovelaundry"):
    doc = {
        "hotel_id": hotel_id,
        "name": name,
        "associated_laundry_id": laundry_id,
        "status": "ACTIVE",
        "created_by": "test",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }
    db["hotels_collection"].insert_one(doc)
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


# ── Hotel Entity Creation ───────────────────────────────────────────────────────

def test_platform_admin_can_create_hotel(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _, token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "hotel_id": "hilton-colombo",
        "name": "Hilton Colombo",
        "associated_laundry_id": "lovelaundry",
    }
    response = client.post("/hotels", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["hotel_id"] == "hilton-colombo"
    assert data["name"] == "Hilton Colombo"
    assert data["associated_laundry_id"] == "lovelaundry"


def test_non_platform_admin_cannot_create_hotel(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _, token = _seed_user(mocked_db, "regular-admin", role="ADMIN")
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "hotel_id": "test-hotel",
        "name": "Test Hotel",
        "associated_laundry_id": "lovelaundry",
    }
    response = client.post("/hotels", json=payload, headers=headers)
    assert response.status_code == 403


def test_hotel_id_must_be_unique(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _, token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "hotel_id": "hilton-colombo",
        "name": "Another Hilton",
        "associated_laundry_id": "lovelaundry",
    }
    response = client.post("/hotels", json=payload, headers=headers)
    assert response.status_code == 409


def test_hotel_must_have_valid_laundry(client, mocked_db):
    _, token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "hotel_id": "test-hotel",
        "name": "Test Hotel",
        "associated_laundry_id": "nonexistent-laundry",
    }
    response = client.post("/hotels", json=payload, headers=headers)
    assert response.status_code == 400


# ── Hotel Membership Management ─────────────────────────────────────────────────

def test_platform_admin_can_grant_hotel_admin(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _, admin_token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)
    user_id, _ = _seed_user(mocked_db, "hotel-staff", role="STAFF")

    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "hotel_id": "hilton-colombo",
        "role": "HOTEL_ADMIN",
    }
    response = client.post(f"/users/{user_id}/hotels", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["hotels"][0]["id"] == "hilton-colombo"
    assert data["hotels"][0]["role"] == "HOTEL_ADMIN"


def test_non_platform_admin_cannot_grant_hotel_admin(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _, admin_token = _seed_user(mocked_db, "laundry-admin", role="ADMIN")
    user_id, _ = _seed_user(mocked_db, "hotel-staff", role="STAFF")

    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "hotel_id": "hilton-colombo",
        "role": "HOTEL_ADMIN",
    }
    response = client.post(f"/users/{user_id}/hotels", json=payload, headers=headers)
    assert response.status_code == 403


def test_hotel_admin_can_grant_hotel_manager(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _, admin_token = _seed_user(mocked_db, "hotel-admin", role="HOTEL_ADMIN", hotel_id="hilton-colombo")
    user_id, _ = _seed_user(mocked_db, "hotel-staff", role="STAFF")

    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "hotel_id": "hilton-colombo",
        "role": "HOTEL_MANAGER",
    }
    response = client.post(f"/users/{user_id}/hotels", json=payload, headers=headers)
    assert response.status_code == 201


def test_cross_hotel_access_prevented(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _seed_hotel(mocked_db, "galadari", "Galadari Hotel")

    # Hotel admin for Hilton
    _, hilton_token = _seed_user(mocked_db, "hilton-admin", role="HOTEL_ADMIN", hotel_id="hilton-colombo")
    # Try to access Galadari
    headers = {"Authorization": f"Bearer {hilton_token}"}

    # Should not be able to list Galadari members
    response = client.get("/hotels/galadari/members", headers=headers)
    assert response.status_code == 403


# ── Hotel Session Switching ─────────────────────────────────────────────────────

def test_user_can_switch_to_hotel_they_belong_to(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _, token = _seed_user(mocked_db, "multi-hotel-user", role="HOTEL_MANAGER", hotels=[
        {"id": "hilton-colombo", "name": "Hilton Colombo", "role": "HOTEL_MANAGER", "status": "ACTIVE"}
    ])

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"hotel_id": "hilton-colombo"}
    response = client.post("/auth/switch-hotel", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["hotel_id"] == "hilton-colombo"


def test_user_cannot_switch_to_hotel_they_dont_belong_to(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _seed_hotel(mocked_db, "galadari", "Galadari Hotel")
    _, token = _seed_user(mocked_db, "hilton-only-user", role="HOTEL_MANAGER", hotels=[
        {"id": "hilton-colombo", "name": "Hilton Colombo", "role": "HOTEL_MANAGER", "status": "ACTIVE"}
    ])

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"hotel_id": "galadari"}
    response = client.post("/auth/switch-hotel", json=payload, headers=headers)
    assert response.status_code == 403


def test_suspended_hotel_cannot_be_switched_to(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _, token = _seed_user(mocked_db, "suspended-hotel-user", role="HOTEL_MANAGER", hotels=[
        {"id": "hilton-colombo", "name": "Hilton Colombo", "role": "HOTEL_MANAGER", "status": "SUSPENDED"}
    ])

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"hotel_id": "hilton-colombo"}
    response = client.post("/auth/switch-hotel", json=payload, headers=headers)
    assert response.status_code == 403


# ── Hotel Status Management ─────────────────────────────────────────────────────

def test_platform_admin_can_suspend_hotel(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _, token = _seed_user(mocked_db, "platform-admin", role="PLATFORM_ADMIN", platform_admin=True)

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"status": "SUSPENDED"}
    response = client.post("/hotels/hilton-colombo/status", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUSPENDED"


def test_non_platform_admin_cannot_suspend_hotel(client, mocked_db):
    _seed_laundry(mocked_db, "lovelaundry", "Love Laundry")
    _seed_hotel(mocked_db, "hilton-colombo", "Hilton Colombo")
    _, token = _seed_user(mocked_db, "regular-admin", role="ADMIN")

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"status": "SUSPENDED"}
    response = client.post("/hotels/hilton-colombo/status", json=payload, headers=headers)
    assert response.status_code == 403
