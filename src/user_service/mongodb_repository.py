from datetime import datetime
from typing import List, Optional, Dict, Any
from pymongo import MongoClient
from bson import ObjectId

from .repository import QuotationRepository
from .config import DATABASE_URL, MONGODB_DB_NAME, MONGODB_COLLECTION


class MongoDBQuotationRepository(QuotationRepository):
    """MongoDB implementation of QuotationRepository"""
    
    def __init__(self):
        self.client = MongoClient(DATABASE_URL)
        self.db = self.client[MONGODB_DB_NAME]
        self.collection = self.db[MONGODB_COLLECTION]
        
        # Create indexes
        self.collection.create_index("client_name")
        self.collection.create_index("created_at")
    
    def _serialize_document(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Convert MongoDB document to API response format"""
        if not doc:
            return None
        
        # Convert ObjectId to string
        if "_id" in doc:
            doc["id"] = str(doc["_id"])
            del doc["_id"]
        
        # Ensure datetime objects are present
        if "created_at" in doc and isinstance(doc["created_at"], datetime):
            doc["created_at"] = doc["created_at"]
        if "updated_at" in doc and isinstance(doc["updated_at"], datetime):
            doc["updated_at"] = doc["updated_at"]
        
        return doc
    
    def get_all(self) -> List[Dict[str, Any]]:
        """Get all quotations, sorted by created_at descending"""
        documents = self.collection.find().sort("created_at", -1)
        return [self._serialize_document(doc) for doc in documents]
    
    def get_by_id(self, quotation_id: str) -> Optional[Dict[str, Any]]:
        """Get a quotation by ID"""
        try:
            doc = self.collection.find_one({"_id": ObjectId(quotation_id)})
            return self._serialize_document(doc) if doc else None
        except Exception:
            return None
    
    def create(self, quotation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new quotation"""
        now = datetime.utcnow()
        
        document = {
            "client_name": quotation_data["client_name"],
            "quotation_title": quotation_data.get("quotation_title"),
            "line_items": quotation_data.get("line_items", []),
            "status": quotation_data.get("status", "draft"),
            "created_at": now,
            "updated_at": now,
        }
        
        result = self.collection.insert_one(document)
        document["_id"] = result.inserted_id
        
        return self._serialize_document(document)
    
    def update(self, quotation_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update an existing quotation"""
        try:
            # Add updated_at timestamp
            update_data["updated_at"] = datetime.utcnow()
            
            result = self.collection.find_one_and_update(
                {"_id": ObjectId(quotation_id)},
                {"$set": update_data},
                return_document=True
            )
            
            return self._serialize_document(result) if result else None
        except Exception:
            return None
    
    def delete(self, quotation_id: str) -> bool:
        """Delete a quotation"""
        try:
            result = self.collection.delete_one({"_id": ObjectId(quotation_id)})
            return result.deleted_count > 0
        except Exception:
            return False
    
    def close(self):
        """Close the MongoDB connection"""
        if self.client:
            self.client.close()
