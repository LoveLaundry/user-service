"""One login, several laundries — and the guarantee that they stay separate.

The dangerous failure here is not an error, it is a *successful* sign-in that
shows the wrong laundry's books. These tests pin the three defences:
an ambiguous login is refused, the association list never crosses sides, and
switching replaces the token instead of widening it.
"""
import pytest
from fastapi.testclient import TestClient

from user_service import client_accounts as ca


@pytest.fixture()
def client(mocked_db):
    from user_service.main import app

    return TestClient(app)


def make(laundry, login="raman", client_type="SHOP", name="Raman Stores", status="ACTIVE"):
    return ca.create_client_account(
        laundry_id=laundry,
        client_name=name,
        auth_id=login,
        user_name="Raman",
        password="shop-pass-1",
        role="SHOP_ADMIN" if client_type == "SHOP" else "HOTEL_MANAGER",
        client_type=client_type,
        status=status,
    )


def token_of(payload):
    return payload["access_token"]


def claims(token):
    from user_service.auth_helper import verify_token

    return verify_token(token)


def test_ambiguous_login_asks_instead_of_guessing(client):
    make("lovelaundry")
    make("coastallaundry", name="Raman Stores")

    response = client.post(
        "/client/auth/login",
        json={"auth_id": "raman", "password": "shop-pass-1", "client_type": "SHOP"},
    )

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "laundry_required"
    assert {item["laundry_id"] for item in detail["laundries"]} == {"lovelaundry", "coastallaundry"}


def test_choosing_a_laundry_scopes_the_session_to_it(client):
    make("lovelaundry")
    make("coastallaundry", name="Raman Stores")

    response = client.post(
        "/client/auth/login",
        json={
            "auth_id": "raman",
            "password": "shop-pass-1",
            "client_type": "SHOP",
            "laundry_id": "coastallaundry",
        },
    )

    assert response.status_code == 200
    payload = claims(token_of(response.json()))
    assert payload["client_scope"]["laundry_id"] == "coastallaundry"
    # The isolation claim: a client token must never carry a staff tenant claim.
    assert "laundry_id" not in payload
    assert "laundries" not in payload


def test_association_list_is_per_side_of_the_business(client):
    make("lovelaundry", client_type="SHOP")
    make("coastallaundry", client_type="SHOP", name="Raman Stores")
    # Same username on the other side, at a third laundry: a different account
    # that must never appear in a shop session's list. (One login per laundry
    # is enforced, so a shop and a hotel login cannot share a username inside
    # the same laundry in the first place.)
    make("harbourlaundry", client_type="HOTEL", name="Raman Hotel")

    login = client.post(
        "/client/auth/login",
        json={
            "auth_id": "raman",
            "password": "shop-pass-1",
            "client_type": "SHOP",
            "laundry_id": "lovelaundry",
        },
    )
    token = token_of(login.json())

    response = client.get("/client/auth/laundries", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert body["client_type"] == "SHOP"
    assert body["count"] == 2
    assert {item["laundry_id"] for item in body["items"]} == {"lovelaundry", "coastallaundry"}
    assert all(item["client_type"] == "SHOP" for item in body["items"])


def test_switching_replaces_the_scope_rather_than_widening_it(client):
    make("lovelaundry")
    make("coastallaundry", name="Raman Stores")

    login = client.post(
        "/client/auth/login",
        json={
            "auth_id": "raman",
            "password": "shop-pass-1",
            "client_type": "SHOP",
            "laundry_id": "lovelaundry",
        },
    )
    first = token_of(login.json())

    switched = client.post(
        "/client/auth/switch",
        json={"laundry_id": "coastallaundry"},
        headers={"Authorization": f"Bearer {first}"},
    )

    assert switched.status_code == 200
    second = token_of(switched.json())
    assert claims(second)["client_scope"]["laundry_id"] == "coastallaundry"
    # The original token is unchanged: it still sees only the first laundry.
    assert claims(first)["client_scope"]["laundry_id"] == "lovelaundry"


def test_cannot_switch_to_a_laundry_that_has_no_account(client):
    make("lovelaundry")

    login = client.post(
        "/client/auth/login",
        json={
            "auth_id": "raman",
            "password": "shop-pass-1",
            "client_type": "SHOP",
            "laundry_id": "lovelaundry",
        },
    )
    token = token_of(login.json())

    response = client.post(
        "/client/auth/switch",
        json={"laundry_id": "somebody-else"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_cannot_switch_across_sides(client):
    make("lovelaundry", client_type="SHOP")
    make("coastallaundry", client_type="HOTEL", name="Raman Hotel")

    login = client.post(
        "/client/auth/login",
        json={
            "auth_id": "raman",
            "password": "shop-pass-1",
            "client_type": "SHOP",
            "laundry_id": "lovelaundry",
        },
    )
    token = token_of(login.json())

    response = client.post(
        "/client/auth/switch",
        json={"laundry_id": "coastallaundry"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_cannot_switch_into_a_suspended_association(client):
    make("lovelaundry")
    make("coastallaundry", status="SUSPENDED", name="Raman Stores")

    login = client.post(
        "/client/auth/login",
        json={
            "auth_id": "raman",
            "password": "shop-pass-1",
            "client_type": "SHOP",
            "laundry_id": "lovelaundry",
        },
    )
    token = token_of(login.json())

    response = client.post(
        "/client/auth/switch",
        json={"laundry_id": "coastallaundry"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_staff_token_cannot_list_client_associations(client):
    from user_service.auth_helper import create_access_token

    staff = create_access_token(
        {
            "user_id": "507f1f77bcf86cd799439011",
            "auth_id": "asha",
            "user_name": "Asha",
            "role": "ADMIN",
            "laundry_id": "lovelaundry",
            "laundries": [{"id": "lovelaundry", "name": "Love Laundry", "role": "ADMIN",
                           "status": "ACTIVE"}],
        }
    )

    response = client.get("/client/auth/laundries", headers={"Authorization": f"Bearer {staff}"})
    assert response.status_code == 403
