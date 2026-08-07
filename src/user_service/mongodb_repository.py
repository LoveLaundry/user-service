from datetime import datetime
from typing import List, Optional, Dict, Any

from bson import ObjectId
from pymongo import MongoClient

from .config import DATABASE_URL, MONGODB_DB_NAME
from .repository import UserRepository


USERS_COLLECTION = "users"


class MongoDBUserRepository(UserRepository):
    def __init__(self):
        self.client = MongoClient(DATABASE_URL)
        self.db = self.client[MONGODB_DB_NAME]
        self.collection = self.db[USERS_COLLECTION]

        self.collection.create_index("user_name")
        self.collection.create_index("auth_id", unique=True)
        self.collection.create_index("email", unique=True, sparse=True)
        self.collection.create_index("mobile_number", sparse=True)
        self.collection.create_index("employee_id", sparse=True)
        self.collection.create_index("created_at")

    def _serialize_document(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not doc:
            return None

        doc["id"] = str(doc["_id"])
        del doc["_id"]
        return doc

    def get_all(self) -> List[Dict[str, Any]]:
        documents = self.collection.find().sort("created_at", -1)
        return [self._serialize_document(doc) for doc in documents]

    def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        try:
            doc = self.collection.find_one({"_id": ObjectId(user_id)})
            return self._serialize_document(doc)
        except Exception:
            return None

    def get_by_auth_id(self, auth_id: str) -> Optional[Dict[str, Any]]:
        doc = self.collection.find_one({"auth_id": auth_id})
        return self._serialize_document(doc)

    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        doc = self.collection.find_one({"email": email})
        return self._serialize_document(doc)

    def get_by_mobile_number(self, mobile_number: str) -> Optional[Dict[str, Any]]:
        doc = self.collection.find_one({"mobile_number": mobile_number})
        return self._serialize_document(doc)

    def get_by_employee_id(self, employee_id: str) -> Optional[Dict[str, Any]]:
        doc = self.collection.find_one({"employee_id": employee_id})
        return self._serialize_document(doc)

    def create(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.utcnow()

        document = {
            "user_name": user_data["user_name"],
            "bio_data": user_data.get("bio_data"),
            "user_dp": user_data.get("user_dp"),
            "mobile_number": user_data.get("mobile_number"),
            "email": user_data.get("email"),
            "role_id": user_data["role_id"],
            "employee_id": user_data.get("employee_id"),
            "auth_id": user_data["auth_id"],
            "password": user_data["password"],
            "status": user_data.get("status", "unset"),
            "created_at": now,
            "updated_at": now,
        }

        result = self.collection.insert_one(document)
        document["_id"] = result.inserted_id

        return self._serialize_document(document)

    def update(self, user_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            update_data["updated_at"] = datetime.utcnow()

            result = self.collection.find_one_and_update(
                {"_id": ObjectId(user_id)},
                {"$set": update_data},
                return_document=True,
            )

            return self._serialize_document(result)
        except Exception:
            return None

    def update_password(self, user_id: str, password: str) -> bool:
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {
                        "password": password,
                        "updated_at": datetime.utcnow(),
                    }
                },
            )
            return result.modified_count > 0
        except Exception:
            return False

    def update_status(self, user_id: str, status: str) -> bool:
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {
                        "status": status,
                        "updated_at": datetime.utcnow(),
                    }
                },
            )
            return result.modified_count > 0
        except Exception:
            return False

    def delete(self, user_id: str) -> bool:
        try:
            result = self.collection.delete_one({"_id": ObjectId(user_id)})
            return result.deleted_count > 0
        except Exception:
            return False

    def exists_by_auth_id(self, auth_id: str) -> bool:
        return self.collection.count_documents({"auth_id": auth_id}, limit=1) > 0

    def exists_by_email(self, email: str) -> bool:
        return self.collection.count_documents({"email": email}, limit=1) > 0

    def exists_by_employee_id(self, employee_id: str) -> bool:
        return self.collection.count_documents({"employee_id": employee_id}, limit=1) > 0

    def count(self) -> int:
        return self.collection.count_documents({})

    def close(self):
        self.client.close()