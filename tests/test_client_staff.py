"""A hotel or shop administrator enrolling colleagues.

The two things that must not happen: an administrator enrolling staff into a
different hotel (by passing someone else's name), and an administrator minting
another administrator through this route.
"""
import pytest
from types import SimpleNamespace
from fastapi.testclient import TestClient


@pytest.fixture()
def client(mocked_db):
    from user_service.main import app

    return TestClient(app)


def _session(role, client_type="HOTEL", client_name="Cinnamon Grand", laundry="lovelaundry"):
    """A client-session claim set, shaped exactly as build_client_token emits."""
    return {
        "auth_id": "boss-1",
        "user_name": "Boss",
        "role": role,
        "token_kind": "client",
        "client_scope": {
            "laundry_id": laundry,
            "client_name": client_name,
            "client_type": client_type,
        },
    }


def _call(client, session, **payload):
    from user_service.main import create_client_staff

    body = {
        "auth_id": "front-desk-1",
        "user_name": "Front Desk",
        "password": "staff-pass-1",
    }
    body.update(payload)
    request = SimpleNamespace(
        auth_id=body["auth_id"],
        user_name=body["user_name"],
        password=body["password"],
        email=body.get("email"),
        role=body.get("role"),
    )
    return create_client_staff(request, session=session)


def test_hotel_admin_enrols_a_hotel_staff_member(client):
    created = _call(client, _session("HOTEL_ADMIN"))

    assert created["role_id"] == "HOTEL_MANAGER"
    assert created["client_name"] == "Cinnamon Grand"
    assert created["laundry_id"] == "lovelaundry"
    assert "password" not in created


def test_a_manager_cannot_enrol_anyone(client):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        _call(client, _session("HOTEL_MANAGER"))
    assert caught.value.status_code == 403


def test_an_admin_cannot_create_another_admin(client):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        _call(client, _session("HOTEL_ADMIN"), role="HOTEL_ADMIN")
    assert caught.value.status_code == 400


def test_the_new_account_is_pinned_to_the_callers_hotel(client):
    from user_service.database.main_db import client_accounts_collection

    _call(client, _session("HOTEL_ADMIN"))

    stored = client_accounts_collection.find_one({"auth_id": "front-desk-1"})
    # Whatever the payload said, the account belongs to the caller's hotel.
    assert stored["client_name"] == "Cinnamon Grand"
    assert stored["laundry_id"] == "lovelaundry"


def test_shop_admin_enrols_shop_staff(client):
    created = _call(
        client,
        _session("SHOP_ADMIN", client_type="SHOP", client_name="Raman Stores"),
    )

    assert created["role_id"] == "SHOP_STAFF"
    assert created["client_name"] == "Raman Stores"


def test_cross_side_role_is_refused(client):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        _call(client, _session("HOTEL_ADMIN"), role="SHOP_STAFF")
    assert caught.value.status_code == 400


def test_staff_list_shows_only_the_same_account(client):
    from user_service import client_accounts as ca
    from user_service.main import list_client_staff

    ca.create_client_account(
        laundry_id="lovelaundry",
        client_name="Cinnamon Grand",
        auth_id="boss-1",
        user_name="Boss",
        password="admin-pass-1",
        role="HOTEL_ADMIN",
        client_type="HOTEL",
    )
    _call(client, _session("HOTEL_ADMIN"))
    ca.create_client_account(
        laundry_id="lovelaundry",
        client_name="Other Hotel",
        auth_id="other-1",
        user_name="Other",
        password="other-pass-1",
        role="HOTEL_ADMIN",
        client_type="HOTEL",
    )

    listing = list_client_staff(session=_session("HOTEL_ADMIN"))

    names = {item["auth_id"] for item in listing["items"]}
    assert names == {"boss-1", "front-desk-1"}
    assert "other-1" not in names
