from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any


class QuotationRepository(ABC):
    """Abstract repository interface for quotation operations"""
    
    @abstractmethod
    def get_all(self) -> List[Dict[str, Any]]:
        """Get all quotations"""
        pass
    
    @abstractmethod
    def get_by_id(self, quotation_id: Any) -> Optional[Dict[str, Any]]:
        """Get a quotation by ID"""
        pass
    
    @abstractmethod
    def create(self, quotation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new quotation"""
        pass
    
    @abstractmethod
    def update(self, quotation_id: Any, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update an existing quotation"""
        pass
    
    @abstractmethod
    def delete(self, quotation_id: Any) -> bool:
        """Delete a quotation"""
        pass
