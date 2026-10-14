"""First-admin bootstrap: a fresh database must be able to create its first login.

Without POST /auth/bootstrap the system deadlocks on a fresh DB — every user
route requires ADMIN, so no account could ever be created and nobody could
log in. The endpoint is fail-closed: it refuses once any user exists.
"""
import pytest
from fastapi import HTTPException

from user_service.main import BootstrapPayload, LoginPayload, bootstrap_first_admin, login
from user_service.mongodb_repository import MongoDBUserRepository


@pytest.fixture
def repo(mocked_db):
    return MongoDBUserRepository()


def _payload(**overrides):
    data = {"auth_id": "ceo-admin", "user_name": "CEO", "password": "change-me-immediately-1"}
    data.update(overrides)
    return BootstrapPayload(**data)


def test_bootstrap_creates_first_admin_and_token(repo):
    result = bootstrap_first_admin(_payload(), repo)

    assert result["token_type"] == "bearer"
    assert result["access_token"]
    assert result["user"]["auth_id"] == "ceo-admin"
    assert result["user"]["role_id"] == "ADMIN"
    assert "password" not in result["user"]

    # The new admin can sign in with the same credentials.
    signed_in = login(
        LoginPayload(username="ceo-admin", password="change-me-immediately-1"),
        repo,
    )
    assert signed_in["access_token"]
    assert signed_in["user"]["role_id"] == "ADMIN"

    repo.delete(result["user"]["id"])


def test_bootstrap_refuses_once_users_exist(repo):
    created = repo.create(
        {
            "user_name": "Existing",
            "auth_id": "existing-user",
            "password": "some-password-1",
            "role_id": "STAFF",
        }
    )
    try:
        with pytest.raises(HTTPException) as exc:
            bootstrap_first_admin(_payload(), repo)
        assert exc.value.status_code == 403
    finally:
        repo.delete(created["id"])


def test_bootstrap_rejects_weak_password(repo):
    with pytest.raises(Exception):
        BootstrapPayload(auth_id="ab", user_name="X", password="short")
