from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any


class UserRepository(ABC):

    @abstractmethod
    def get_all(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_by_id(self, user_id: Any) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_by_auth_id(self, auth_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_by_mobile_number(self, mobile_number: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_by_employee_id(self, employee_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def create(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def update(self, user_id: Any, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def update_password(self, user_id: Any, password: str) -> bool:
        pass

    @abstractmethod
    def update_status(self, user_id: Any, status: str) -> bool:
        pass

    @abstractmethod
    def delete(self, user_id: Any) -> bool:
        pass

    @abstractmethod
    def exists_by_auth_id(self, auth_id: str) -> bool:
        pass

    @abstractmethod
    def exists_by_email(self, email: str) -> bool:
        pass

    @abstractmethod
    def exists_by_employee_id(self, employee_id: str) -> bool:
        pass

    @abstractmethod
    def count(self) -> int:
        pass