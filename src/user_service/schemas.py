from .app_time import stamp
from datetime import datetime
from typing import Union
from pydantic import BaseModel, EmailStr, Field, field_serializer, field_validator


class _PasswordPolicy(BaseModel):
    """Shared staff-password rules; bcrypt silently truncates past 72 bytes."""

    @field_validator("password", check_fields=False)
    @classmethod
    def _enforce_byte_limit(cls, value: str | None) -> str | None:
        if value is not None and len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 bytes")
        return value


class UserCreate(_PasswordPolicy):
    user_name: str
    bio_data: str | None = None
    user_dp: str | None = None
    mobile_number: str | None = None
    email: EmailStr | None = None
    role_id: str
    employee_id: str | None = None
    auth_id: str
    # bcrypt silently truncates past 72 bytes; reject longer secrets instead.
    password: str = Field(min_length=12, max_length=72)
    status: str = "unset"
    tenant: str | None = None
    public_key: str | None = None
    key_version: int | None = 1
    permissions: str | None = None
    laundry_id: str | None = None
    hotel_id: str | None = None
    shop_id: str | None = None


class UserUpdate(_PasswordPolicy):
    user_name: str | None = None
    bio_data: str | None = None
    user_dp: str | None = None
    mobile_number: str | None = None
    email: EmailStr | None = None
    role_id: str | None = None
    employee_id: str | None = None
    auth_id: str | None = None
    password: str | None = Field(default=None, min_length=12, max_length=72)
    status: str | None = None
    public_key: str | None = None
    key_version: int | None = None
    permissions: str | None = None


class UserPasswordUpdate(_PasswordPolicy):
    password: str = Field(min_length=12, max_length=72)


class UserStatusUpdate(BaseModel):
    status: str


class UserResponse(BaseModel):
    id: Union[int, str]
    user_name: str
    bio_data: str | None = None
    user_dp: str | None = None
    mobile_number: str | None = None
    email: str | None = None
    role_id: str
    employee_id: str | None = None
    auth_id: str
    status: str
    tenant: str | None = None
    public_key: str | None = None
    key_version: int | None = None
    permissions: str | None = None
    platform_admin: bool | None = None
    laundry_id: str | None = None
    laundries: list | None = None
    hotels: list | None = None
    shops: list | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_serializer("created_at", "updated_at")
    def serialize_datetime(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        return stamp(value)

    model_config = {"from_attributes": True}


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

    user: UserResponse