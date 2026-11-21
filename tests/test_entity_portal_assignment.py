"""Regression tests for hotel/shop assignment and entity support entry.

The original failure had two halves:

* the registry member dialog wrote a generic staff membership, while the
  standalone portals authenticate against ``client_accounts``;
* entity Enter returned a token with no ``laundry_id`` but the UI opened the
  laundry Today page with it.

These tests pin both contracts: assignment must create a usable portal login,
and Enter must stay entity-scoped.
"""
from fastapi.testclient import TestClient

from user_service.auth_helper import create_access_token, verify_token
from user_service.crypto_helper import encrypt_dict
from user_service.mongodb_repository import SENSITIVE_FIELDS


def _client(mocked_db) -> TestClient:
    from user_service.main import app

    return TestClient(app)


def _seed_platform_admin(db, auth_id: str = "platform-admin") -> tuple[str, str]:
    doc = {
        "auth_id": auth_id,
        "user_name": "Platform Admin",
        "role_id": "PLATFORM_ADMIN",
        "status": "active",
        "platform_admin": True,
    }
    result = db["users_collection"].insert_one(encrypt_dict(doc, SENSITIVE_FIELDS))
    uid = str(result.inserted_id)
    token = create_access_token(
        {
            "user_id": uid,
            "auth_id": auth_id,
            "user_name": "Platform Admin",
            "role": "PLATFORM_ADMIN",
            "status": "active",
            "platform_admin": True,
        }
    )
    return uid, token


def _seed_staff_user(db, auth_id: str) -> str:
    doc = {
        "auth_id": auth_id,
        "user_name": auth_id.title(),
        "role_id": "STAFF",
        "status": "active",
    }
    return str(db["users_collection"].insert_one(encrypt_dict(doc, SENSITIVE_FIELDS)).inserted_id)


def _seed_laundry(db, laundry_id: str = "lovelaundry") -> None:
    db["laundries_collection"].insert_one(
        {
            "laundry_id": laundry_id,
            "name": "Love Laundry",
            "status": "ACTIVE",
            "created_at": "2024-01-01T00:00:00Z",
        }
    )


def _seed_entity(db, kind: str, entity_id: str, name: str) -> None:
    id_field = "hotel_id" if kind == "hotels" else "shop_id"
    db[f"{kind}_collection"].insert_one(
        {
            id_field: entity_id,
            "name": name,
            "associated_laundry_id": "lovelaundry",
            "status": "ACTIVE",
            "created_at": "2024-01-01T00:00:00Z",
        }
    )


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_hotel_assignment_creates_portal_login(mocked_db):
    client = _client(mocked_db)
    _seed_laundry(mocked_db)
    _seed_entity(mocked_db, "hotels", "grand-hotel", "Grand Hotel")
    _, token = _seed_platform_admin(mocked_db)
    staff_id = _seed_staff_user(mocked_db, "hotel.manager")

    response = client.post(
        "/hotels/grand-hotel/members",
        headers=_headers(token),
        json={
            "auth_id": "hotel.manager",
            "role": "HOTEL_MANAGER",
            "user_name": "Grand Hotel Manager",
            "password": "securepass123",
        },
    )
    assert response.status_code == 201, response.text

    account = mocked_db["client_accounts_collection"].find_one({"auth_id": "hotel.manager"})
    assert account is not None
    assert account["client_type"] == "HOTEL"
    assert account["hotel_id"] == "grand-hotel"
    assert account.get("shop_id") is None
    assert account["role_id"] == "HOTEL_MANAGER"

    # The compatibility staff membership is still written.
    staff = mocked_db["users_collection"].find_one({"_id": mocked_db["users_collection"].find_one({"auth_id": "hotel.manager"})["_id"]})
    assert any(entry["id"] == "grand-hotel" and entry["role"] == "HOTEL_MANAGER" for entry in staff["hotels"])

    roster = client.get("/hotels/grand-hotel/members", headers=_headers(token))
    assert roster.status_code == 200
    assert any(
        row["auth_id"] == "hotel.manager" and row["source"] == "client"
        for row in roster.json()
    )

    login = client.post(
        "/client/auth/login",
        json={
            "auth_id": "hotel.manager",
            "password": "securepass123",
            "client_type": "HOTEL",
            "laundry_id": "lovelaundry",
        },
    )
    assert login.status_code == 200, login.text
    claims = verify_token(login.json()["access_token"])
    assert claims["client_scope"]["hotel_id"] == "grand-hotel"
    assert "laundry_id" not in claims
    assert "laundries" not in claims


def test_shop_assignment_creates_portal_login(mocked_db):
    client = _client(mocked_db)
    _seed_laundry(mocked_db)
    _seed_entity(mocked_db, "shops", "city-shop", "City Shop")
    _, token = _seed_platform_admin(mocked_db)
    _seed_staff_user(mocked_db, "shop.staff")

    response = client.post(
        "/shops/city-shop/members",
        headers=_headers(token),
        json={
            "auth_id": "shop.staff",
            "role": "SHOP_STAFF",
            "user_name": "City Shop Staff",
            "password": "securepass123",
        },
    )
    assert response.status_code == 201, response.text

    account = mocked_db["client_accounts_collection"].find_one({"auth_id": "shop.staff"})
    assert account is not None
    assert account["client_type"] == "SHOP"
    assert account["shop_id"] == "city-shop"
    assert account.get("hotel_id") is None
    assert account["role_id"] == "SHOP_STAFF"

    login = client.post(
        "/client/auth/login",
        json={
            "auth_id": "shop.staff",
            "password": "securepass123",
            "client_type": "SHOP",
            "laundry_id": "lovelaundry",
        },
    )
    assert login.status_code == 200, login.text
    claims = verify_token(login.json()["access_token"])
    assert claims["client_scope"]["shop_id"] == "city-shop"
    assert "laundry_id" not in claims


def test_generic_entity_roles_are_rejected(mocked_db):
    client = _client(mocked_db)
    _seed_laundry(mocked_db)
    _seed_entity(mocked_db, "hotels", "grand-hotel", "Grand Hotel")
    _seed_entity(mocked_db, "shops", "city-shop", "City Shop")
    _, token = _seed_platform_admin(mocked_db)
    staff_id = _seed_staff_user(mocked_db, "generic.roles")

    hotel_member = client.post(
        "/hotels/grand-hotel/members",
        headers=_headers(token),
        json={"auth_id": "generic.roles", "role": "ADMIN"},
    )
    assert hotel_member.status_code == 400

    shop_member = client.post(
        "/shops/city-shop/members",
        headers=_headers(token),
        json={"auth_id": "generic.roles", "role": "STAFF"},
    )
    assert shop_member.status_code == 400

    hotel_grant = client.post(
        f"/users/{staff_id}/hotels",
        headers=_headers(token),
        json={"hotel_id": "grand-hotel", "role": "MANAGER"},
    )
    assert hotel_grant.status_code == 400

    shop_grant = client.post(
        f"/users/{staff_id}/shops",
        headers=_headers(token),
        json={"shop_id": "city-shop", "role": "STAFF"},
    )
    assert shop_grant.status_code == 400

    assert mocked_db["client_accounts_collection"].count_documents({}) == 0


def test_entity_enter_returns_entity_scope_without_laundry(mocked_db):
    client = _client(mocked_db)
    _seed_laundry(mocked_db)
    _seed_entity(mocked_db, "hotels", "grand-hotel", "Grand Hotel")
    _seed_entity(mocked_db, "shops", "city-shop", "City Shop")
    _, token = _seed_platform_admin(mocked_db)

    hotel = client.post("/hotels/grand-hotel/enter", headers=_headers(token))
    assert hotel.status_code == 200, hotel.text
    hotel_claims = verify_token(hotel.json()["access_token"])
    assert hotel_claims["hotel_id"] == "grand-hotel"
    assert hotel_claims["hotels"][0]["id"] == "grand-hotel"
    assert hotel_claims["support_entry"] is True
    assert hotel_claims["platform_admin"] is True
    assert "laundry_id" not in hotel_claims
    assert "laundries" not in hotel_claims

    shop = client.post("/shops/city-shop/enter", headers=_headers(token))
    assert shop.status_code == 200, shop.text
    shop_claims = verify_token(shop.json()["access_token"])
    assert shop_claims["shop_id"] == "city-shop"
    assert shop_claims["shops"][0]["id"] == "city-shop"
    assert shop_claims["support_entry"] is True
    assert "laundry_id" not in shop_claims
    assert "laundries" not in shop_claims
