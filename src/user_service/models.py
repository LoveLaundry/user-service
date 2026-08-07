from datetime import datetime

from sqlalchemy import String, Integer, DateTime, func
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