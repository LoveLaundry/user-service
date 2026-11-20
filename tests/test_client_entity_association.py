"""Client accounts bound to their hotel / shop entity.

``architecture/MULTI_TENANT_ENTITY_ARCHITECTURE.md`` requires that a hotel or
shop login is associated with exactly one entity, that the entity belongs to the
same laundry, and that the association is carried in the token so downstream
services can scope by entity rather than by a display-name string.

The negative properties are the ones that fail silently, so they are pinned
here: a hotel login must never resolve to a shop, an entity from another laundry
must be indistinguishable from a missing one, and a suspended entity must not be
enterable.
"""
import importlib
import os

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from user_service.crypto_helper import encrypt_dict
from user_service.mongodb_repository import SENSITIVE_FIELDS

SECRET = os.environ["JWT_SECRET"]
LAUNDRY = "lovelaundry"
OTHER_LAUNDRY = "rivalwash"

ENTITY_COLLECTION = {"HOTEL": "hotels_collection", "SHOP": "shops_collection"}
ENTITY_FIELD = {"HOTEL": "hotel_id", "SHOP": "shop_id"}


def _claims(token: str) -> dict:
    return jwt.decode(token, SECRET, algorithms=["HS256"])


@pytest.fixture()
def ca(mocked_db):
    """The module *after* the harness has re-bound its collection handles.

    Importing at module scope would keep the pre-patch module object, whose
    collections point at the real cluster — the very leak the harness guards.
    """
    return importlib.import_module("user_service.client_accounts")


@pytest.fixture()
def assoc(mocked_db):
    return importlib.import_module("user_service.client_associations")


@pytest.fixture()
def api(mocked_db):
    from user_service.main import app

    return TestClient(app)


def _seed_entity(db, kind, entity_id, *, laundry=LAUNDRY, name=None, status="ACTIVE"):
    db[ENTITY_COLLECTION[kind]].insert_one(
        {
            ENTITY_FIELD[kind]: entity_id,
            "name": name or entity_id.replace("-", " ").title(),
            "associated_laundry_id": laundry,
            "status": status,
        }
    )


def _make(ca, *, kind="HOTEL", name, login, password="secretpass1", **kw):
    return ca.create_client_account(
        laundry_id=LAUNDRY,
        client_name=name,
        auth_id=login,
        user_name="Front Desk",
        password=password,
        client_type=kind,
        **kw,
    )


# ── explicit association ──────────────────────────────────────────────────────


def test_hotel_account_stores_hotel_id_and_clears_shop_id(mocked_db, ca):
    _seed_entity(mocked_db, "HOTEL", "cinnamon-grand", name="Cinnamon Grand")

    doc = _make(ca, name="Cinnamon Grand", login="cinnamon", hotel_id="cinnamon-grand")

    assert doc["hotel_id"] == "cinnamon-grand"
    assert doc["shop_id"] is None
    assert doc["client_name"] == "Cinnamon Grand"


def test_shop_account_stores_shop_id_and_clears_hotel_id(mocked_db, ca):
    _seed_entity(mocked_db, "SHOP", "city-express", name="City Express")

    doc = _make(
        ca, kind="SHOP", name="City Express", login="city", shop_id="city-express"
    )

    assert doc["shop_id"] == "city-express"
    assert doc["hotel_id"] is None


def test_token_carries_the_entity_for_its_own_side_only(mocked_db, ca):
    _seed_entity(mocked_db, "HOTEL", "cinnamon-grand", name="Cinnamon Grand")
    doc = _make(ca, name="Cinnamon Grand", login="cinnamon", hotel_id="cinnamon-grand")

    claims = _claims(ca.build_client_token(doc))
    scope = claims["client_scope"]

    assert scope["hotel_id"] == "cinnamon-grand"
    assert scope["shop_id"] is None
    # The staff-membership claims must still be absent, entity or not.
    assert "laundries" not in claims
    assert "laundry_id" not in claims


# ── cross-side and cross-tenant rejection ─────────────────────────────────────


def test_hotel_account_cannot_be_linked_to_a_shop(mocked_db, ca):
    _seed_entity(mocked_db, "SHOP", "city-express", name="City Express")

    with pytest.raises(HTTPException) as err:
        _make(
            ca, name="Cinnamon Grand", login="cinnamon", shop_id="city-express"
        )
    assert err.value.status_code == 400


def test_unknown_entity_is_a_404(mocked_db, ca):
    with pytest.raises(HTTPException) as err:
        _make(ca, name="Ghost Hotel", login="ghost", hotel_id="does-not-exist")
    assert err.value.status_code == 404


def test_entity_owned_by_another_laundry_is_a_404_not_a_403(mocked_db, ca):
    """A foreign id must be indistinguishable from a missing one.

    A 403 here would confirm the id exists somewhere, which is a cross-tenant
    probing oracle.
    """
    _seed_entity(mocked_db, "HOTEL", "rival-hotel", laundry=OTHER_LAUNDRY)

    with pytest.raises(HTTPException) as err:
        _make(ca, name="Rival Hotel", login="rival", hotel_id="rival-hotel")
    assert err.value.status_code == 404


def test_suspended_entity_cannot_be_linked(mocked_db, ca):
    _seed_entity(mocked_db, "HOTEL", "closed-hotel", status="SUSPENDED")

    with pytest.raises(HTTPException) as err:
        _make(ca, name="Closed Hotel", login="closed", hotel_id="closed-hotel")
    assert err.value.status_code == 403


# ── name-based adoption (migration path) ──────────────────────────────────────


def test_unique_name_match_adopts_the_entity(mocked_db, ca):
    _seed_entity(mocked_db, "HOTEL", "cinnamon-grand", name="Cinnamon Grand")

    doc = _make(ca, name="Cinnamon Grand", login="cinnamon")

    assert doc["hotel_id"] == "cinnamon-grand"


def test_ambiguous_name_is_not_adopted(mocked_db, ca):
    """Two hotels sharing a name must be disambiguated by id, never guessed."""
    _seed_entity(mocked_db, "HOTEL", "grand-one", name="Grand")
    _seed_entity(mocked_db, "HOTEL", "grand-two", name="Grand")

    doc = _make(ca, name="Grand", login="grand")

    assert doc["hotel_id"] is None


def test_name_that_contradicts_the_entity_is_rejected(mocked_db, ca):
    _seed_entity(mocked_db, "HOTEL", "cinnamon-grand", name="Cinnamon Grand")

    with pytest.raises(HTTPException) as err:
        _make(
            ca,
            name="Some Other Hotel",
            login="mismatch",
            hotel_id="cinnamon-grand",
        )
    assert err.value.status_code == 409


def test_no_entity_keeps_legacy_name_only_account(mocked_db, ca):
    doc = _make(ca, name="Walk In Customer", login="walkin")

    assert doc["hotel_id"] is None
    assert doc["shop_id"] is None
    assert doc["client_name"] == "Walk In Customer"


# ── switching into a suspended entity ─────────────────────────────────────────


def test_switch_refuses_a_suspended_entity(mocked_db, ca, assoc):
    _seed_entity(mocked_db, "HOTEL", "cinnamon-grand", name="Cinnamon Grand")
    _make(ca, name="Cinnamon Grand", login="cinnamon", hotel_id="cinnamon-grand")

    mocked_db[ENTITY_COLLECTION["HOTEL"]].update_one(
        {"hotel_id": "cinnamon-grand"}, {"$set": {"status": "SUSPENDED"}}
    )

    session = {
        "auth_id": "cinnamon",
        "client_scope": {
            "laundry_id": LAUNDRY,
            "client_name": "Cinnamon Grand",
            "client_type": "HOTEL",
        },
    }
    with pytest.raises(HTTPException) as err:
        assoc.switch_to(session, LAUNDRY)
    assert err.value.status_code == 403


# ── API surface ───────────────────────────────────────────────────────────────


def _platform_admin_token(db) -> str:
    """Create a platform admin staff row and return a signed token for it."""
    from user_service.auth_helper import create_access_token

    auth_id = "platform-admin"
    doc = {
        "auth_id": auth_id,
        "user_name": "Platform Admin",
        "role_id": "ADMIN",
        "status": "active",
        "platform_admin": True,
        "laundries": [
            {"id": LAUNDRY, "name": "LoveLaundry", "role": "ADMIN", "status": "ACTIVE"}
        ],
    }
    result = db["users_collection"].insert_one(encrypt_dict(doc, SENSITIVE_FIELDS))
    return create_access_token(
        {
            "user_id": str(result.inserted_id),
            "auth_id": auth_id,
            "user_name": "Platform Admin",
            "role": "ADMIN",
            "status": "active",
            "platform_admin": True,
            "laundry_id": LAUNDRY,
            "laundries": doc["laundries"],
        }
    )


def test_platform_admin_can_pin_the_entity_via_api(mocked_db, api, ca):
    _seed_entity(mocked_db, "HOTEL", "cinnamon-grand", name="Cinnamon Grand")
    token = _platform_admin_token(mocked_db)

    resp = api.post(
        "/clients",
        json={
            "client_name": "Cinnamon Grand",
            "auth_id": "cinnamon",
            "user_name": "Front Desk",
            "password": "hotelpass1",
            "client_type": "HOTEL",
            "hotel_id": "cinnamon-grand",
            "laundry_id": LAUNDRY,
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 201, resp.text
    assert resp.json()["hotel_id"] == "cinnamon-grand"


def test_client_staff_inherit_the_admins_entity(mocked_db, api, ca):
    _seed_entity(mocked_db, "HOTEL", "cinnamon-grand", name="Cinnamon Grand")
    admin = _make(
        ca,
        name="Cinnamon Grand",
        login="cinnamon",
        hotel_id="cinnamon-grand",
        role="HOTEL_ADMIN",
    )
    token = ca.build_client_token(admin)

    resp = api.post(
        "/client/staff",
        json={
            "auth_id": "cinnamon-clerk",
            "user_name": "Clerk",
            "password": "clerkpass1",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 201, resp.text
    assert resp.json()["hotel_id"] == "cinnamon-grand"

    listing = api.get("/client/staff", headers={"Authorization": f"Bearer {token}"})
    assert listing.status_code == 200
    assert listing.json()["hotel_id"] == "cinnamon-grand"
    assert listing.json()["total"] == 2
