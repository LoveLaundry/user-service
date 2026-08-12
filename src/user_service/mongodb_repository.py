from datetime import datetime
from typing import List, Optional, Dict, Any
import bcrypt

from bson import ObjectId

from .repository import UserRepository
from .crypto_helper import encrypt_dict, decrypt_dict, get_search_token
from .database.main_db import users_collection
from .repositories.main_repository import bump_version, enqueue_sync
from .services.verification_service import attach_verification_to

USERS_COLLECTION = "users"
SENSITIVE_FIELDS = ["mobile_number", "email", "bio_data", "user_dp"]


class MongoDBUserRepository(UserRepository):
    def __init__(self):
        self.collection = users_collection

        self.collection.create_index("user_name")
        self.collection.create_index("auth_id", unique=True)
        self.collection.create_index("email_search", unique=True, sparse=True)
        self.collection.create_index("mobile_number_search", sparse=True)
        self.collection.create_index("employee_id", sparse=True)
        self.collection.create_index("created_at")

    def _serialize_document(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not doc:
            return None

        try:
            doc = decrypt_dict(doc, SENSITIVE_FIELDS)
        except Exception as e:
            raise ValueError(f"Failed to decrypt user: {str(e)}")

        doc["id"] = str(doc["_id"])
        del doc["_id"]
        return doc

    def get_all(self) -> List[Dict[str, Any]]:
        documents = self.collection.find().sort("created_at", -1)
        results = []
        for doc in documents:
            try:
                serialized = self._serialize_document(doc)
                results.append(attach_verification_to("user", doc["_id"], serialized))
            except ValueError:
                pass
        return results

    def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        try:
            doc = self.collection.find_one({"_id": ObjectId(user_id)})
            if not doc:
                return None
            serialized = self._serialize_document(doc)
            return attach_verification_to("user", doc["_id"], serialized)
        except Exception:
            return None

    def get_by_auth_id(self, auth_id: str) -> Optional[Dict[str, Any]]:
        doc = self.collection.find_one({"auth_id": auth_id})
        if not doc:
            return None
        serialized = self._serialize_document(doc)
        return attach_verification_to("user", doc["_id"], serialized)

    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        doc = self.collection.find_one({"email_search": get_search_token(email)})
        if not doc:
            return None
        serialized = self._serialize_document(doc)
        return attach_verification_to("user", doc["_id"], serialized)

    def get_by_mobile_number(self, mobile_number: str) -> Optional[Dict[str, Any]]:
        doc = self.collection.find_one(
            {"mobile_number_search": get_search_token(mobile_number)}
        )
        if not doc:
            return None
        serialized = self._serialize_document(doc)
        return attach_verification_to("user", doc["_id"], serialized)

    def get_by_employee_id(self, employee_id: str) -> Optional[Dict[str, Any]]:
        doc = self.collection.find_one({"employee_id": employee_id})
        if not doc:
            return None
        serialized = self._serialize_document(doc)
        return attach_verification_to("user", doc["_id"], serialized)

    def create(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.utcnow()

        raw_password = user_data.get("password", "")
        hashed_password = ""
        if raw_password:
            hashed_password = bcrypt.hashpw(
                raw_password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

        document = {
            "user_name": user_data["user_name"],
            "bio_data": user_data.get("bio_data"),
            "user_dp": user_data.get("user_dp"),
            "mobile_number": user_data.get("mobile_number"),
            "email": user_data.get("email"),
            "role_id": user_data["role_id"],
            "employee_id": user_data.get("employee_id"),
            "auth_id": user_data["auth_id"],
            "password": hashed_password,
            "status": user_data.get("status", "unset"),
            "public_key": user_data.get("public_key"),
            "key_version": user_data.get("key_version", 1),
            "created_at": now,
            "updated_at": now,
        }

        encrypted_document = encrypt_dict(document, SENSITIVE_FIELDS)

        result = self.collection.insert_one(encrypted_document)
        encrypted_document["_id"] = result.inserted_id

        # Main DB write succeeded -> bump version and enqueue replication
        new_version = bump_version("user", result.inserted_id)
        enqueue_sync("user", result.inserted_id, new_version)

        serialized = self._serialize_document(encrypted_document)
        return attach_verification_to("user", result.inserted_id, serialized)

    def update(
        self, user_id: str, update_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        try:
            update_data["updated_at"] = datetime.utcnow()

            if "password" in update_data and update_data["password"]:
                raw_password = update_data["password"]
                update_data["password"] = bcrypt.hashpw(
                    raw_password.encode("utf-8"), bcrypt.gensalt()
                ).decode("utf-8")

            original = self.collection.find_one({"_id": ObjectId(user_id)})
            if not original:
                return None

            try:
                decrypted_original = self.decrypt_document_full(original)
            except Exception:
                return None

            decrypted_original.update(update_data)
            decrypted_original.pop("created_at", None)
            decrypted_original["updated_at"] = datetime.utcnow()

            encrypted_new = encrypt_dict(decrypted_original, SENSITIVE_FIELDS)

            result = self.collection.find_one_and_update(
                {"_id": ObjectId(user_id)},
                {"$set": encrypted_new},
                return_document=True,
            )

            if not result:
                return None

            # Main DB write succeeded -> bump version and enqueue replication
            new_version = bump_version("user", ObjectId(user_id))
            enqueue_sync("user", ObjectId(user_id), new_version)

            serialized = self._serialize_document(result)
            return attach_verification_to("user", ObjectId(user_id), serialized)
        except Exception:
            return None

    def decrypt_document_full(self, doc: dict) -> dict:
        meta = doc.get("encryption_metadata")
        if not meta:
            return doc
        return decrypt_dict(doc, SENSITIVE_FIELDS)

    def update_password(self, user_id: str, password: str) -> bool:
        try:
            hashed_password = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
            result = self.collection.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {
                        "password": hashed_password,
                        "updated_at": datetime.utcnow(),
                    }
                },
            )
            if result.modified_count > 0:
                new_version = bump_version("user", ObjectId(user_id))
                enqueue_sync("user", ObjectId(user_id), new_version)
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
            if result.modified_count > 0:
                new_version = bump_version("user", ObjectId(user_id))
                enqueue_sync("user", ObjectId(user_id), new_version)
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
        token = get_search_token(email)
        return self.collection.count_documents({"email_search": token}, limit=1) > 0

    def exists_by_employee_id(self, employee_id: str) -> bool:
        return self.collection.count_documents({"employee_id": employee_id}, limit=1) > 0

    def count(self) -> int:
        return self.collection.count_documents({})

    def close(self):
        pass