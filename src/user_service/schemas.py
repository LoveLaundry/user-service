from .app_time import stamp
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, EmailStr, field_serializer


class UserCreate(BaseModel):
    user_name: str
    bio_data: str | None = None
    user_dp: str | None = None
    mobile_number: str | None = None
    email: EmailStr | None = None
    role_id: str
    employee_id: str | None = None
    auth_id: str
    password: str
    status: str = "unset"
    public_key: str | None = None
    key_version: int | None = 1
    permissions: str | None = None
    # Optional enrollment target. Platform callers may pass any ACTIVE laundry;
    # laundry admins are always enrolled in their own active laundry.
    laundry_id: str | None = None


class UserUpdate(BaseModel):
    user_name: str | None = None
    bio_data: str | None = None
    user_dp: str | None = None
    mobile_number: str | None = None
    email: EmailStr | None = None
    role_id: str | None = None
    employee_id: str | None = None
    auth_id: str | None = None
    password: str | None = None
    status: str | None = None
    public_key: str | None = None
    key_version: int | None = None
    permissions: str | None = None


class UserPasswordUpdate(BaseModel):
    password: str


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
    public_key: str | None = None
    key_version: int | None = None
    permissions: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    # Multi-tenant context (absent for legacy callers, populated at login).
    laundry_id: str | None = None
    laundries: Optional[List[Dict[str, Any]]] = None
    platform_admin: bool | None = None

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

class LaundryCreate(BaseModel):
    laundry_id: str
    name: str
    br_number: str | None = None
    location: str | None = None
    address: str | None = None
    contact_number: str | None = None
    email: str | None = None
    logo_url: str | None = None
    icon: str | None = None
    description: str | None = None
    subscription_plan: str | None = None
    plan_limits: str | None = None


class LaundryUpdate(BaseModel):
    name: str | None = None
    br_number: str | None = None
    location: str | None = None
    address: str | None = None
    contact_number: str | None = None
    email: str | None = None
    logo_url: str | None = None
    icon: str | None = None
    description: str | None = None
    subscription_plan: str | None = None
    plan_limits: str | None = None


class LaundryResponse(BaseModel):
    id: int | str
    laundry_id: str
    name: str
    br_number: str | None = None
    location: str | None = None
    address: str | None = None
    contact_number: str | None = None
    email: str | None = None
    logo_url: str | None = None
    icon: str | None = None
    description: str | None = None
    status: str
    subscription_plan: str | None = None
    plan_limits: str | None = None
    created_by: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_serializer("created_at", "updated_at")
    def serialize_datetime(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        return stamp(value)

    model_config = {"from_attributes": True}


class LaundryStatusUpdate(BaseModel):
    status: str


class MembershipCreate(BaseModel):
    auth_id: str
    role: str


class MembershipResponse(BaseModel):
    id: int | str
    auth_id: str
    laundry_id: str
    role: str
    status: str
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_serializer("created_at", "updated_at")
    def serialize_datetime(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        return stamp(value)

    model_config = {"from_attributes": True}


class SwitchLaundryRequest(BaseModel):
    laundry_id: str
