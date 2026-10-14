from datetime import datetime

from sqlalchemy import String, Integer, DateTime, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    user_name: Mapped[str] = mapped_column(
        String,
        nullable=False,
        index=True
    )

    bio_data: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    user_dp: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    mobile_number: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    email: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    role_id: Mapped[str] = mapped_column(
        String,
        nullable=False
    )

    employee_id: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    auth_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
        index=True,
        unique=True
    )

    password: Mapped[str] = mapped_column(
        String,
        nullable=False
    )

    status: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default="unset"
    )

    permissions: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

class Laundry(Base):
    """Platform laundry registry entry. One row per independent business."""

    __tablename__ = "laundries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    laundry_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
        unique=True,
        index=True,
    )

    name: Mapped[str] = mapped_column(String, nullable=False)
    br_number: Mapped[str | None] = mapped_column(String, nullable=True, unique=True)
    location: Mapped[str | None] = mapped_column(String, nullable=True)
    address: Mapped[str | None] = mapped_column(String, nullable=True)
    contact_number: Mapped[str | None] = mapped_column(String, nullable=True)
    email: Mapped[str | None] = mapped_column(String, nullable=True)
    logo_url: Mapped[str | None] = mapped_column(String, nullable=True)
    icon: Mapped[str | None] = mapped_column(String, nullable=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="ACTIVE")
    subscription_plan: Mapped[str | None] = mapped_column(String, nullable=True)
    plan_limits: Mapped[str | None] = mapped_column(String, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Membership(Base):
    """A user's role inside one laundry. Platform access is separate."""

    __tablename__ = "memberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    auth_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    laundry_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    role: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("auth_id", "laundry_id", name="uq_membership_auth_laundry"),
    )
