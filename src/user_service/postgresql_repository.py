from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from .repository import QuotationRepository
from .models import Quotation


class PostgreSQLQuotationRepository(QuotationRepository):
    """PostgreSQL/SQLite implementation of QuotationRepository using SQLAlchemy"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def _model_to_dict(self, quotation: Quotation) -> Dict[str, Any]:
        """Convert SQLAlchemy model to dictionary"""
        return {
            "id": quotation.id,
            "client_name": quotation.client_name,
            "quotation_title": quotation.quotation_title,
            "line_items": quotation.line_items,
            "status": quotation.status,
            "created_at": quotation.created_at,
            "updated_at": quotation.updated_at,
        }
    
    def get_all(self) -> List[Dict[str, Any]]:
        """Get all quotations, sorted by created_at descending"""
        quotations = self.db.query(Quotation).order_by(Quotation.created_at.desc()).all()
        return [self._model_to_dict(q) for q in quotations]
    
    def get_by_id(self, quotation_id: int) -> Optional[Dict[str, Any]]:
        """Get a quotation by ID"""
        quotation = self.db.query(Quotation).filter(Quotation.id == quotation_id).first()
        return self._model_to_dict(quotation) if quotation else None
    
    def create(self, quotation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new quotation"""
        new_quotation = Quotation(
            client_name=quotation_data["client_name"],
            quotation_title=quotation_data.get("quotation_title"),
            line_items=quotation_data.get("line_items", []),
            status=quotation_data.get("status", "draft"),
        )
        
        self.db.add(new_quotation)
        self.db.commit()
        self.db.refresh(new_quotation)
        
        return self._model_to_dict(new_quotation)
    
    def update(self, quotation_id: int, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update an existing quotation"""
        quotation = self.db.query(Quotation).filter(Quotation.id == quotation_id).first()
        if not quotation:
            return None
        
        for key, value in update_data.items():
            if hasattr(quotation, key):
                setattr(quotation, key, value)
        
        self.db.commit()
        self.db.refresh(quotation)
        
        return self._model_to_dict(quotation)
    
    def delete(self, quotation_id: int) -> bool:
        """Delete a quotation"""
        quotation = self.db.query(Quotation).filter(Quotation.id == quotation_id).first()
        if not quotation:
            return False
        
        self.db.delete(quotation)
        self.db.commit()
        
        return True
