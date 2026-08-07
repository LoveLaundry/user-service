from datetime import datetime
from typing import Union

from pydantic import BaseModel, EmailStr, Field, field_serializer


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
    email: EmailStr | None = None
    role_id: str
    employee_id: str | None = None
    auth_id: str
    status: str
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_serializer("created_at", "updated_at")
    def serialize_datetime(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        return value.isoformat()

    model_config = {"from_attributes": True}