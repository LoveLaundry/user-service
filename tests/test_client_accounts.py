"""Hotel client accounts and the isolation contract they rely on.

The critical property under test is negative: a hotel session must be unable to
touch staff endpoints. That is guaranteed by the token **lacking** ``laundry_id``
and ``laundries`` claims, so these tests pin that absence â€” adding either claim
would silently open the entire staff API to hotel customers.
"""
import os

import jwt
import pytest
from fastapi.testclient import TestClient

from user_service import client_accounts as ca

SECRET = os.environ["JWT_SECRET"]


def _claims(token: str) -> dict:
    return jwt.decode(token, SECRET, algorithms=["HS256"])


@pytest.fixture()
def client(mocked_db):
    """Build the app *after* the mock database has been wired in."""
    from user_service.main import app

    return TestClient(app)


def _make(laundry="lovelaundry", hotel="Cinnamon Grand", auth_id="cinnamon", password="hotelpass1", **kw):
    return ca.create_client_account(
        laundry_id=laundry,
        client_name=hotel,
        auth_id=auth_id,
        user_name=kw.pop("user_name", "Front Desk"),
        password=password,
        **kw,
    )


# â”€â”€ token shape: the isolation mechanism â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def test_client_token_carries_no_laundry_membership_claim():
    doc = _make()
    claims = _claims(ca.build_client_token(doc))

    assert claims["token_kind"] == "client"
    assert claims["client_scope"] == {
        "laundry_id": "lovelaundry",
        "client_name": "Cinnamon Grand",
        "client_type": "HOTEL",
    }
    # Absent, not empty: resource services fail closed on a missing claim.
    assert "laundry_id" not in claims
    assert "laundries" not in claims
    assert claims["platform_admin"] is False


def test_client_token_is_shorter_lived_than_a_staff_token():
    claims = _claims(ca.build_client_token(_make()))
    assert claims["exp"] - claims["iat"] == 12 * 3600


# â”€â”€ login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def test_login_returns_a_working_client_session(client):
    _make()
    response = client.post(
        "/client/auth/login", json={"auth_id": "cinnamon", "password": "hotelpass1"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["client"]["client_name"] == "Cinnamon Grand"
    assert "password" not in body["client"]

    status = client.get(
        "/client/auth/status",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert status.status_code == 200
    assert status.json()["client_name"] == "Cinnamon Grand"
    assert status.json()["laundry_id"] == "lovelaundry"


def test_unknown_and_wrong_password_are_indistinguishable(client):
    _make()
    unknown = client.post("/client/auth/login", json={"auth_id": "nobody", "password": "whatever1"})
    wrong = client.post("/client/auth/login", json={"auth_id": "cinnamon", "password": "wrongpass1"})

    assert unknown.status_code == wrong.status_code == 400
    assert unknown.json()["detail"] == wrong.json()["detail"]


def test_suspended_account_cannot_sign_in(client):
    _make(status="SUSPENDED")
    response = client.post(
        "/client/auth/login", json={"auth_id": "cinnamon", "password": "hotelpass1"}
    )
    assert response.status_code == 403


def test_session_dies_when_the_account_is_suspended(client):
    doc = _make()
    token = ca.build_client_token(doc)
    ca.set_status(str(doc["_id"]), "SUSPENDED")

    response = client.get("/client/auth/status", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


# â”€â”€ the negative contract: staff endpoints reject hotel sessions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def test_staff_endpoint_rejects_a_client_token(client):
    doc = _make()
    token = ca.build_client_token(doc)

    response = client.get("/auth/status", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_client_endpoint_rejects_a_staff_token(client):
    from user_service.auth_helper import create_access_token

    # A genuine staff token shape: tenant claims, no client_scope.
    staff_token = create_access_token(
        {
            "user_id": "507f1f77bcf86cd799439011",
            "auth_id": "asha",
            "user_name": "Asha",
            "role": "ADMIN",
            "laundry_id": "lovelaundry",
            "laundries": [
                {"id": "lovelaundry", "name": "Love Laundry", "role": "ADMIN", "status": "ACTIVE"}
            ],
        }
    )

    response = client.get(
        "/client/auth/status", headers={"Authorization": f"Bearer {staff_token}"}
    )
    assert response.status_code == 403



# â”€â”€ uniqueness and validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def test_same_login_twice_in_one_laundry_is_rejected():
    _make()
    with pytest.raises(Exception) as excinfo:
        _make()
    assert getattr(excinfo.value, "status_code", None) == 409


def test_same_login_is_allowed_in_another_laundry():
    _make()
    other = _make(laundry="rivalwash", hotel="Cinnamon Grand")
    assert other["laundry_id"] == "rivalwash"


def test_client_name_is_validated():
    with pytest.raises(Exception) as excinfo:
        _make(hotel="   ")
    assert getattr(excinfo.value, "status_code", None) == 400

    with pytest.raises(Exception) as excinfo:
        _make(hotel="Cinnamon\x00Grand")
    assert getattr(excinfo.value, "status_code", None) == 400


def test_role_must_be_a_hotel_role():
    with pytest.raises(Exception) as excinfo:
        _make(role="ADMIN")
    assert getattr(excinfo.value, "status_code", None) == 400


def test_password_hash_is_never_returned():
    doc = _make()
    assert "password" not in ca.public_view(doc)
    assert doc["password"].startswith("$2")
