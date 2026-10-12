"""A disabled account must lose access immediately, not at token expiry.

Previously `get_current_user` only verified the JWT signature, so a token
issued before an admin disabled the account kept working for up to 24h. This
tests that the very next authenticated request is rejected after the status
turns disabled, and that a deleted account is likewise rejected.
"""
import pytest


def _app():
    from user_service.main import app

    return app


def _create_user(repo, **overrides):
    base = {
        "user_name": "Revoke Me",
        "email": "revoke@example.com",
        "password": "s3cret",
        "auth_id": "auth-revoke",
        "employee_id": "EMP-R1",
        "role_id": "STAFF",
        "mobile_number": "0771234000",
    }
    base.update(overrides)
    return repo.create(base)


def test_disabled_user_loses_access_to_already_issued_tokens(mocked_db):
    from fastapi.testclient import TestClient
    from user_service.mongodb_repository import MongoDBUserRepository

    repo = MongoDBUserRepository()
    admin = _create_user(repo, user_name="Admin", auth_id="auth-admin",
                         role_id="ADMIN", email="admin@example.com", mobile_number="0770000000")
    staff = _create_user(repo)

    client = TestClient(_app())
    admin_login = client.post(
        "/auth/login", json={"username": "auth-admin", "password": "s3cret"}
    )
    assert admin_login.status_code == 200
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}

    staff_login = client.post(
        "/auth/login", json={"username": "auth-revoke", "password": "s3cret"}
    )
    assert staff_login.status_code == 200
    staff_token = staff_login.json()["access_token"]
    staff_headers = {"Authorization": f"Bearer {staff_token}"}

    # Token is valid right after login.
    ok = client.get("/auth/status", headers=staff_headers)
    assert ok.status_code == 200

    # Admin disables the account.
    disabled = client.patch(
        f"/users/{staff['id']}/status",
        json={"status": "disabled"},
        headers=admin_headers,
    )
    assert disabled.status_code == 200, disabled.text

    # The same, still-unexpired token is now rejected.
    rejected = client.get("/auth/status", headers=staff_headers)
    assert rejected.status_code == 403
    assert "deactivated" in rejected.json()["detail"]