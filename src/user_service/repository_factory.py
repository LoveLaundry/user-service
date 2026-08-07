from typing import Generator
from sqlalchemy.orm import Session

from .config import DB_TYPE, DatabaseType
from .repository import QuotationRepository
from .mongodb_repository import MongoDBQuotationRepository
from .postgresql_repository import PostgreSQLQuotationRepository
from .database import SessionLocal


# Global MongoDB repository instance (singleton pattern)
_mongodb_repo = None


def get_repository() -> Generator[QuotationRepository, None, None]:
    """
    Factory function that returns the appropriate repository based on DB_TYPE.
    This function is used as a FastAPI dependency.
    """
    global _mongodb_repo
    
    if DB_TYPE == DatabaseType.MONGODB:
        # MongoDB: Use singleton instance
        if _mongodb_repo is None:
            _mongodb_repo = MongoDBQuotationRepository()
        
        try:
            yield _mongodb_repo
        finally:
            pass  # MongoDB connection is persistent
    
    else:
        # PostgreSQL/SQLite: Create new session per request
        db: Session = SessionLocal()
        repo = PostgreSQLQuotationRepository(db)
        
        try:
            yield repo
        finally:
            db.close()


def close_connections():
    """Close all database connections. Call this on application shutdown."""
    global _mongodb_repo
    
    if _mongodb_repo is not None:
        _mongodb_repo.close()
        _mongodb_repo = None
