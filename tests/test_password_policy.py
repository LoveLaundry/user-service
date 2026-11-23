"""Regression tests for staff password length and bcrypt byte-limit policy."""

import pytest
from pydantic import ValidationError

from user_service.schemas import UserCreate, UserPasswordUpdate, UserUpdate


def _create_payload(password: str) -> dict:
    return {
        "user_name": "staff",
        "role_id": "STAFF",
        "auth_id": "auth-staff",
        "password": password,
    }


def test_staff_password_minimum_length_is_enforced() -> None:
    with pytest.raises(ValidationError):
        UserCreate(**_create_payload("short"))


def test_password_update_enforces_72_byte_limit() -> None:
    with pytest.raises(ValidationError):
        UserPasswordUpdate(password="a" * 73)


def test_multibyte_password_cannot_exceed_bcrypt_byte_limit() -> None:
    # 37 two-byte characters are 74 bytes even though they are only 37 chars.
    with pytest.raises(ValidationError):
        UserUpdate(password="ā" * 37)


def test_valid_staff_password_is_accepted() -> None:
    assert UserCreate(**_create_payload("password123456")).password == "password123456"
    assert UserUpdate(password="password123456").password == "password123456"
