"""Refreshing a session must re-read the account, not just extend the clock.

If refresh simply re-signed the old claims, a disabled account or a revoked
membership would keep working until the original expiry — which is exactly the
hole the token-revocation tests were written to close.
"""
import jwt
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


def _make_user(repo, **overrides):
    base = {
        "user_name": "Refresh User",
        "email": "refresh@example.com",
        "password": "s3cret-pass",
        "auth_id": "auth-refresh",
        "employee_id": "EMP-RF1",
        "role_id": "STAFF",
        "mobile_number": "0771234999",
    }
    base.update(overrides)
    return repo.create(base)


def _staff_token(client):
    response = client.post(
        "/auth/login", json={"username": "auth-refresh", "password": "s3cret-pass"}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def test_refresh_issues_a_working_token(client, repo):
    _make_user(repo)
    token = _staff_token(client)

    response = client.post("/auth/refresh", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200, response.text
    renewed = response.json()["access_token"]
    claims = jwt.decode(renewed, options={"verify_signature": False})
    assert claims["auth_id"] == "auth-refresh"
    assert claims["role"] == "STAFF"


def test_refresh_rejects_a_disabled_account(client, repo):
    _make_user(repo)
    token = _staff_token(client)

    from user_service.database.main_db import users_collection

    users_collection.update_one({"auth_id": "auth-refresh"}, {"$set": {"status": "disabled"}})

    response = client.post("/auth/refresh", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_client_refresh_keeps_the_same_scope(client):
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
        json={"auth_id": "cinnamon", "password": "hotel-pass-1", "client_type": "HOTEL"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    response = client.post(
        "/client/auth/refresh", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200, response.text
    renewed = jwt.decode(response.json()["access_token"], options={"verify_signature": False})
    assert renewed["client_scope"]["laundry_id"] == "lovelaundry"
    assert renewed["client_scope"]["client_type"] == "HOTEL"
    # Still no tenant membership: a refreshed hotel token must not gain staff powers.
    assert "laundry_id" not in renewed
    assert "laundries" not in renewed


def test_client_refresh_rejects_a_suspended_account(client):
    from user_service import client_accounts as ca
    from user_service.database.main_db import client_accounts_collection

    ca.create_client_account(
        laundry_id="lovelaundry",
        client_name="Raman Stores",
        auth_id="raman",
        user_name="Raman",
        password="shop-pass-1",
        role="SHOP_ADMIN",
        client_type="SHOP",
    )

    login = client.post(
        "/client/auth/login",
        json={"auth_id": "raman", "password": "shop-pass-1", "client_type": "SHOP"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    client_accounts_collection.update_one(
        {"auth_id": "raman"}, {"$set": {"status": "SUSPENDED"}}
    )

    response = client.post(
        "/client/auth/refresh", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403
