"""Frontend-facing auth and registry response contracts.

The operational apps authenticate through ``/api/user`` and the platform admin
reads the hotel registry through the same service. These tests lock the additive
response shapes without changing the canonical flat claims older clients use.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(mocked_db):
    from user_service.main import app

    return TestClient(app)


@pytest.fixture()
def repo(mocked_db):
    from user_service.repository_factory import get_repository

    return next(get_repository())


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def _make_user(repo, auth_id: str, role: str, **overrides) -> dict:
    payload = {
        "auth_id": auth_id,
        "user_name": auth_id.replace("-", " ").title(),
        "password": "secret-pass",
        "role_id": role,
        "status": "active",
    }
    payload.update(overrides)
    return repo.create(payload)


def test_staff_login_accepts_legacy_user_name_alias(client: TestClient, repo) -> None:
    _make_user(repo, "counter", "STAFF")
    response = client.post(
        "/auth/login", json={"user_name": "counter", "password": "secret-pass"}
    )
    assert response.status_code == 200, response.text
    assert response.json()["user"]["auth_id"] == "counter"


def test_staff_status_exposes_named_and_flat_shapes(client: TestClient, repo) -> None:
    _make_user(repo, "status-staff", "STAFF")
    token = _login(client, "status-staff", "secret-pass")["access_token"]

    response = client.get("/auth/status", headers=_headers(token))
    assert response.status_code == 200
    payload = response.json()
    assert payload["user"]["auth_id"] == "status-staff"
    assert payload["auth_id"] == payload["user"]["auth_id"]


def test_client_status_exposes_named_and_flat_shapes(client: TestClient, mocked_db) -> None:
    from user_service.client_accounts import create_client_account

    create_client_account(
        laundry_id="lovelaundry",
        client_name="Grand Hotel",
        auth_id="grand-hotel",
        user_name="Grand Hotel",
        password="secret-pass",
        role="HOTEL_ADMIN",
        client_type="HOTEL",
    )
    login = client.post(
        "/client/auth/login",
        json={"auth_id": "grand-hotel", "password": "secret-pass"},
    )
    assert login.status_code == 200, login.text

    response = client.get(
        "/client/auth/status", headers=_headers(login.json()["access_token"])
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["client"]["client_name"] == "Grand Hotel"
    assert payload["client_name"] == payload["client"]["client_name"]


def test_hotel_registry_uses_paged_envelope(client: TestClient, repo, mocked_db) -> None:
    mocked_db["laundries_collection"].insert_one(
        {"laundry_id": "lovelaundry", "name": "Love Laundry", "status": "ACTIVE"}
    )
    mocked_db["hotels_collection"].insert_one(
        {
            "hotel_id": "grand-hotel",
            "name": "Grand Hotel",
            "hotel_code": "GRAND",
            "associated_laundry_id": "lovelaundry",
            "status": "ACTIVE",
        }
    )
    _make_user(repo, "platform", "PLATFORM_ADMIN", platform_admin=True)
    token = _login(client, "platform", "secret-pass")["access_token"]

    response = client.get("/hotels?limit=20&offset=0", headers=_headers(token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) >= {"items", "total", "limit", "offset"}
    assert body["limit"] == 20
    assert body["offset"] == 0
    assert body["items"][0]["hotel_code"] == "GRAND"
