from typing import List, Optional, Dict, Any

from sqlalchemy.orm import Session

from .models import User
from .repository import UserRepository


class PostgreSQLUserRepository(UserRepository):
    def __init__(self, db: Session):
        self.db = db

    def _model_to_dict(self, user: User) -> Dict[str, Any]:
        return {
            "id": user.id,
            "user_name": user.user_name,
            "bio_data": user.bio_data,
            "user_dp": user.user_dp,
            "mobile_number": user.mobile_number,
            "email": user.email,
            "role_id": user.role_id,
            "employee_id": user.employee_id,
            "auth_id": user.auth_id,
            "password": user.password,
            "status": user.status,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        }

    def get_all(self) -> List[Dict[str, Any]]:
        users = self.db.query(User).order_by(User.created_at.desc()).all()
        return [self._model_to_dict(user) for user in users]

    def get_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        user = self.db.query(User).filter(User.id == user_id).first()
        return self._model_to_dict(user) if user else None

    def get_by_auth_id(self, auth_id: str) -> Optional[Dict[str, Any]]:
        user = self.db.query(User).filter(User.auth_id == auth_id).first()
        return self._model_to_dict(user) if user else None

    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        user = self.db.query(User).filter(User.email == email).first()
        return self._model_to_dict(user) if user else None

    def get_by_mobile_number(self, mobile_number: str) -> Optional[Dict[str, Any]]:
        user = self.db.query(User).filter(User.mobile_number == mobile_number).first()
        return self._model_to_dict(user) if user else None

    def get_by_employee_id(self, employee_id: str) -> Optional[Dict[str, Any]]:
        user = self.db.query(User).filter(User.employee_id == employee_id).first()
        return self._model_to_dict(user) if user else None

    def create(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        user = User(
            user_name=user_data["user_name"],
            bio_data=user_data.get("bio_data"),
            user_dp=user_data.get("user_dp"),
            mobile_number=user_data.get("mobile_number"),
            email=user_data.get("email"),
            role_id=user_data["role_id"],
            employee_id=user_data.get("employee_id"),
            auth_id=user_data["auth_id"],
            password=user_data["password"],
            status=user_data.get("status", "unset"),
        )

        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        return self._model_to_dict(user)

    def update(self, user_id: int, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        user = self.db.query(User).filter(User.id == user_id).first()

        if not user:
            return None

        for key, value in update_data.items():
            if hasattr(user, key):
                setattr(user, key, value)

        self.db.commit()
        self.db.refresh(user)

        return self._model_to_dict(user)

    def update_password(self, user_id: int, password: str) -> bool:
        user = self.db.query(User).filter(User.id == user_id).first()

        if not user:
            return False

        user.password = password
        self.db.commit()

        return True

    def update_status(self, user_id: int, status: str) -> bool:
        user = self.db.query(User).filter(User.id == user_id).first()

        if not user:
            return False

        user.status = status
        self.db.commit()

        return True

    def delete(self, user_id: int) -> bool:
        user = self.db.query(User).filter(User.id == user_id).first()

        if not user:
            return False

        self.db.delete(user)
        self.db.commit()

        return True

    def exists_by_auth_id(self, auth_id: str) -> bool:
        return self.db.query(User).filter(User.auth_id == auth_id).first() is not None

    def exists_by_email(self, email: str) -> bool:
        return self.db.query(User).filter(User.email == email).first() is not None

    def exists_by_employee_id(self, employee_id: str) -> bool:
        return self.db.query(User).filter(User.employee_id == employee_id).first() is not None

    def count(self) -> int:
        return self.db.query(User).count()