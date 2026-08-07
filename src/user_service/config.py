import os
from enum import Enum
from dotenv import load_dotenv

load_dotenv()


class DatabaseType(Enum):
    MONGODB = "mongodb"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"


def detect_database_type(database_url: str) -> DatabaseType:
    """
    Detect the database type from the DATABASE_URL.
    
    MongoDB URLs start with: mongodb:// or mongodb+srv://
    PostgreSQL URLs start with: postgresql:// or postgresql+psycopg://
    SQLite URLs start with: sqlite:///
    """
    if not database_url:
        raise ValueError("DATABASE_URL is not set")
    
    database_url_lower = database_url.lower()
    
    if database_url_lower.startswith("mongodb://") or database_url_lower.startswith("mongodb+srv://"):
        return DatabaseType.MONGODB
    elif database_url_lower.startswith("postgresql://") or database_url_lower.startswith("postgresql+"):
        return DatabaseType.POSTGRESQL
    elif database_url_lower.startswith("sqlite:///"):
        return DatabaseType.SQLITE
    else:
        raise ValueError(f"Unsupported database URL format: {database_url}")


# Load configuration
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")

DB_TYPE = detect_database_type(DATABASE_URL)

# MongoDB specific configuration
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "user_db")
MONGODB_COLLECTION = os.getenv("MONGODB_COLLECTION", "users")
