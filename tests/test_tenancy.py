"""Multi-tenant identity: registry, memberships, tenant JWT claims, isolation.

Covers the platform contract: laundry registration + lifecycle, membership
management with last-admin protection, tenant-scoped JWT claims at login and
switch, platform-admin superset, suspended/archived fail-closed behavior, and
cross-laundry denial on every user-admin read path.
"""
import pytest
from fastapi import HTTPException

from user_service import tenancy
from user_service.main import (
    add_laundry_member,
    bootstrap_first_admin,
    create_laundry,
    create_user,
    get_all_users,
    get_laundry,
    get_user_by_auth_id,
    list_laundries,
    list_laundry_members,
    login,
    remove_laundry_member,
    set_laundry_status,
    switch_laundry,
    enter_laundry,
    update_laundry,
    BootstrapPayload,
    LoginPayload,
    SwitchLaundryRequest,
)
from user_service.auth_helper import verify_token
from user_service.mongodb_repository import MongoDBUserRepository
from user_service.schemas import LaundryCreate, LaundryStatusUpdate, LaundryUpdate, MembershipCreate, UserCreate


@pytest.fixture
def repo(mocked_db):
    return MongoDBUserRepository()


@pytest.fixture
def stores(mocked_db):
    return (
        tenancy.MongoLaundryRepository(),
        tenancy.MongoMembershipRepository(),
    )


@pytest.fixture
def platform_caller():
    return {"auth_id": "root", "role": "PLATFORM_ADMIN"}


def _user(repo, auth_id, role_id="STAFF"):
    return repo.create(
        {
            "user_name": auth_id,
            "auth_id": auth_id,
            "password": "password-123",
            "role_id": role_id,
        }
    )


def _laundry_payload(laundry_id="acme", **overrides):
    data = {"laundry_id": laundry_id, "name": "Acme Laundry"}
    data.update(overrides)
    return LaundryCreate(**data)


def _create_laundry(caller, laundry_id="acme", **overrides):
    return create_laundry(_laundry_payload(laundry_id, **overrides), caller, None)


# ── Registry ──────────────────────────────────────────────────────────────


def test_registry_create_get_list_update(platform_caller):
    created = _create_laundry(platform_caller)
    assert created["laundry_id"] == "acme"
    assert created["status"] == "ACTIVE"

    fetched = get_laundry("acme", platform_caller, None)
    assert fetched["name"] == "Acme Laundry"

    listed = list_laundries("Acme Laundry", "", 100, 0, platform_caller, None)
    assert listed["total"] == 1
    assert listed["items"][0]["laundry_id"] == "acme"

    updated = update_laundry("acme", LaundryUpdate(location="Colombo"), platform_caller, None)
    assert updated["location"] == "Colombo"


def test_registry_rejects_bad_slug_and_duplicates(platform_caller):
    with pytest.raises(HTTPException) as exc:
        _create_laundry(platform_caller, laundry_id="AB")
    assert exc.value.status_code == 400

    _create_laundry(platform_caller, laundry_id="acme")
    with pytest.raises(HTTPException) as exc:
        _create_laundry(platform_caller, laundry_id="acme")
    assert exc.value.status_code == 400


def test_registry_requires_platform_admin(repo):
    _user(repo, "staff-1", "STAFF")
    caller = {"auth_id": "staff-1", "role": "STAFF"}
    with pytest.raises(HTTPException):
        get_laundry("acme", caller, None)


def test_registry_http_gates_end_to_end(mocked_db):
    """Depends() gates only apply over HTTP — prove them through TestClient."""
    from fastapi.testclient import TestClient

    from user_service.main import app
    from user_service.mongodb_repository import MongoDBUserRepository

    repo = MongoDBUserRepository()
    client = TestClient(app)
    boot = client.post(
        "/auth/bootstrap",
        json={"auth_id": "root", "user_name": "Root", "password": "password-123"},
    )
    assert boot.status_code == 201
    root_headers = {"Authorization": f"Bearer {boot.json()['access_token']}"}

    repo.create({
        "user_name": "Staff",
        "auth_id": "staff-http",
        "password": "password-123",
        "role_id": "STAFF",
    })
    staff_login = client.post("/auth/login", json={"username": "staff-http", "password": "password-123"})
    assert staff_login.status_code == 200
    staff_headers = {"Authorization": f"Bearer {staff_login.json()['access_token']}"}

    assert client.post(
        "/laundries", json={"laundry_id": "acme", "name": "Acme"}, headers=staff_headers
    ).status_code == 403
    assert client.get("/laundries", headers=staff_headers).status_code == 403
    assert client.post("/laundries/acme/enter", headers=staff_headers).status_code == 403

    created = client.post(
        "/laundries", json={"laundry_id": "acme", "name": "Acme"}, headers=root_headers
    )
    assert created.status_code == 201
    assert created.json()["laundry_id"] == "acme"
    listed = client.get("/laundries", headers=root_headers)
    assert listed.status_code == 200
    # Bootstrap seeds the lovelaundry tenant alongside the created one.
    assert {item["laundry_id"] for item in listed.json()["items"]} == {"lovelaundry", "acme"}


def test_laundry_lifecycle_suspend_reactivate(platform_caller):
    _create_laundry(platform_caller)
    suspended = set_laundry_status("acme", LaundryStatusUpdate(status="suspended"), platform_caller, None)
    assert suspended["status"] == "SUSPENDED"
    reactivated = set_laundry_status("acme", LaundryStatusUpdate(status="ACTIVE"), platform_caller, None)
    assert reactivated["status"] == "ACTIVE"
    archived = set_laundry_status("acme", LaundryStatusUpdate(status="archived"), platform_caller, None)
    assert archived["status"] == "ARCHIVED"
    with pytest.raises(HTTPException) as exc:
        set_laundry_status("acme", LaundryStatusUpdate(status="bogus"), platform_caller, None)
    assert exc.value.status_code == 400


# ── Memberships ───────────────────────────────────────────────────────────


def test_membership_crud_and_last_admin_guard(repo, platform_caller, stores):
    laundry_repo, membership_repo = stores
    _create_laundry(platform_caller)
    alice = _user(repo, "alice", "ADMIN")
    bob = _user(repo, "bob", "STAFF")

    added = add_laundry_member(
        "acme", MembershipCreate(auth_id="alice", role="ADMIN"), platform_caller, repo, None
    )
    assert added["role"] == "ADMIN"

    with pytest.raises(HTTPException) as exc:
        add_laundry_member(
            "acme", MembershipCreate(auth_id="alice", role="STAFF"), platform_caller, repo, None
        )
    assert exc.value.status_code == 400

    with pytest.raises(HTTPException) as exc:
        add_laundry_member(
            "acme", MembershipCreate(auth_id="ghost", role="STAFF"), platform_caller, repo, None
        )
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        add_laundry_member(
            "acme", MembershipCreate(auth_id="bob", role="OWNER"), platform_caller, repo, None
        )
    assert exc.value.status_code == 400

    members = list_laundry_members("acme", platform_caller, None)
    assert [m["auth_id"] for m in members] == ["alice"]

    # Last administrator cannot be removed.
    with pytest.raises(HTTPException) as exc:
        remove_laundry_member("acme", "alice", platform_caller, None)
    assert exc.value.status_code == 400

    add_laundry_member(
        "acme", MembershipCreate(auth_id="bob", role="ADMIN"), platform_caller, repo, None
    )
    assert remove_laundry_member("acme", "alice", platform_caller, None) == {"removed": True}


def test_laundry_admin_manages_own_members_only(repo, stores):
    laundry_repo, membership_repo = stores
    _create_laundry({"auth_id": "root", "role": "PLATFORM_ADMIN"}, laundry_id="acme")
    _create_laundry({"auth_id": "root", "role": "PLATFORM_ADMIN"}, laundry_id="other")
    _user(repo, "admin-a", "ADMIN")
    _user(repo, "staff-b", "STAFF")
    membership_repo.add("admin-a", "acme", "ADMIN")
    membership_repo.add("staff-b", "other", "STAFF")

    admin_a = {"auth_id": "admin-a", "role": "ADMIN"}
    # Own laundry: allowed.
    members = list_laundry_members("acme", admin_a, None)
    assert [m["auth_id"] for m in members] == ["admin-a"]
    # Other laundry: denied.
    with pytest.raises(HTTPException) as exc:
        list_laundry_members("other", admin_a, None)
    assert exc.value.status_code == 403
    # Staff role (not laundry admin): denied everywhere.
    staff_b = {"auth_id": "staff-b", "role": "STAFF"}
    with pytest.raises(HTTPException) as exc:
        list_laundry_members("other", staff_b, None)
    assert exc.value.status_code == 403


# ── Login claims, switch, entry ───────────────────────────────────────────


def test_login_embeds_active_laundry_claims(repo):
    _create_laundry({"auth_id": "root", "role": "PLATFORM_ADMIN"})
    _user(repo, "washer-1", "STAFF")
    add_laundry_member(
        "acme",
        MembershipCreate(auth_id="washer-1", role="STAFF"),
        {"auth_id": "root", "role": "PLATFORM_ADMIN"},
        repo,
        None,
    )
    result = login(LoginPayload(username="washer-1", password="password-123"), repo, None)
    payload = verify_token(result["access_token"])
    assert payload["laundry_id"] == "acme"
    assert payload["role"] == "STAFF"
    assert payload["laundries"] == [{"id": "acme", "role": "STAFF", "status": "ACTIVE"}]
    assert result["user"]["laundry_id"] == "acme"


def test_legacy_user_without_memberships_keeps_working(repo):
    _user(repo, "legacy-1", "ADMIN")
    result = login(LoginPayload(username="legacy-1", password="password-123"), repo, None)
    assert result["user"]["role_id"] == "ADMIN"
    assert result["user"].get("laundry_id") is None


def test_suspended_laundry_blocks_login_and_switch(repo, platform_caller):
    _create_laundry(platform_caller)
    _user(repo, "washer-2", "STAFF")
    add_laundry_member(
        "acme",
        MembershipCreate(auth_id="washer-2", role="STAFF"),
        platform_caller,
        repo,
        None,
    )
    set_laundry_status("acme", LaundryStatusUpdate(status="SUSPENDED"), platform_caller, None)

    with pytest.raises(HTTPException) as exc:
        login(LoginPayload(username="washer-2", password="password-123"), repo, None)
    assert exc.value.status_code == 403

    caller = {"auth_id": "washer-2", "role": "STAFF"}
    with pytest.raises(HTTPException) as exc:
        switch_laundry(SwitchLaundryRequest(laundry_id="acme"), caller, repo, None)
    assert exc.value.status_code == 403


def test_switch_moves_active_laundry(repo, platform_caller):
    _create_laundry(platform_caller, laundry_id="acme")
    _create_laundry(platform_caller, laundry_id="other")
    _user(repo, "rover", "STAFF")
    add_laundry_member("acme", MembershipCreate(auth_id="rover", role="STAFF"), platform_caller, repo, None)
    add_laundry_member("other", MembershipCreate(auth_id="rover", role="MANAGER"), platform_caller, repo, None)

    first = login(LoginPayload(username="rover", password="password-123"), repo, None)
    assert first["user"]["laundry_id"] is None  # multiple seats: no implicit default

    caller = {"auth_id": "rover", "role": "STAFF"}
    moved = switch_laundry(SwitchLaundryRequest(laundry_id="other"), caller, repo, None)
    assert moved["user"]["laundry_id"] == "other"
    assert moved["user"]["role_id"] == "MANAGER"
    assert verify_token(moved["access_token"])["laundry_id"] == "other"

    with pytest.raises(HTTPException) as exc:
        switch_laundry(SwitchLaundryRequest(laundry_id="unknown"), caller, repo, None)
    assert exc.value.status_code in (400, 403)


def test_platform_entry_is_short_lived_and_audited(repo, platform_caller):
    _user(repo, "root", "PLATFORM_ADMIN")
    _create_laundry(platform_caller)
    entered = enter_laundry("acme", platform_caller, repo, None)
    payload = verify_token(entered["access_token"])
    assert payload["laundry_id"] == "acme"
    assert payload["support_entry"] is True
    assert payload["exp"] - payload["iat"] == 3600
    assert entered["user"]["platform_admin"] is True


def test_bootstrap_seeds_platform_admin_and_lovelaundry(repo):
    result = bootstrap_first_admin(
        BootstrapPayload(auth_id="root", user_name="Root", password="password-123"), repo, None
    )
    assert result["user"]["role_id"] == "PLATFORM_ADMIN"
    payload = verify_token(result["access_token"])
    assert payload["platform_admin"] is True

    laundry = get_laundry("lovelaundry", {"auth_id": "root", "role": "PLATFORM_ADMIN"}, None)
    assert laundry["status"] == "ACTIVE"


# ── User-admin isolation ──────────────────────────────────────────────────


def test_laundry_admin_sees_only_shared_laundry_users(repo, platform_caller):
    _create_laundry(platform_caller, laundry_id="acme")
    _create_laundry(platform_caller, laundry_id="other")
    _user(repo, "admin-a", "ADMIN")
    _user(repo, "admin-b", "ADMIN")
    add_laundry_member("acme", MembershipCreate(auth_id="admin-a", role="ADMIN"), platform_caller, repo, None)
    add_laundry_member("other", MembershipCreate(auth_id="admin-b", role="ADMIN"), platform_caller, repo, None)

    admin_a = {"auth_id": "admin-a", "role": "ADMIN"}
    visible = get_all_users(repo, admin_a, None)
    assert {u["auth_id"] for u in visible} == {"admin-a"}

    with pytest.raises(HTTPException) as exc:
        get_user_by_auth_id("admin-b", repo, admin_a, None)
    assert exc.value.status_code == 404

    seen = get_user_by_auth_id("admin-a", repo, admin_a, None)
    assert seen["auth_id"] == "admin-a"


def test_create_user_enrolls_in_caller_laundry(repo, platform_caller):
    _create_laundry(platform_caller, laundry_id="acme")
    _user(repo, "admin-a", "ADMIN")
    add_laundry_member("acme", MembershipCreate(auth_id="admin-a", role="ADMIN"), platform_caller, repo, None)

    admin_a = {"auth_id": "admin-a", "role": "ADMIN", "laundry_id": "acme"}
    created = create_user(
        UserCreate(user_name="New Hire", auth_id="hire-1", password="password-123", role_id="STAFF"),
        repo,
        admin_a,
        None,
    )
    assert created["auth_id"] == "hire-1"

    members = list_laundry_members("acme", admin_a, None)
    assert "hire-1" in [m["auth_id"] for m in members]

    with pytest.raises(HTTPException) as exc:
        create_user(
            UserCreate(user_name="Sneaky", auth_id="sneaky-1", password="password-123", role_id="PLATFORM_ADMIN"),
            repo,
            admin_a,
            None,
        )
    assert exc.value.status_code == 400


def test_platform_admin_superset_passes_admin_gates(repo, platform_caller):
    _user(repo, "someone", "STAFF")
    visible = get_all_users(repo, platform_caller, None)
    assert {u["auth_id"] for u in visible} == {"someone"}
