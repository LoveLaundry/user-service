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


# Prefer DATABASE_URL; fall back to MONGODB_MAIN_URI for Vercel.
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("MONGODB_MAIN_URI") or ""
if not DATABASE_URL:
    # Avoid hard-crashing the serverless import; health/routes will fail clearly later.
    DATABASE_URL = "mongodb://127.0.0.1:27017"
    DB_TYPE = DatabaseType.MONGODB
else:
    DB_TYPE = detect_database_type(DATABASE_URL)

MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "user_db")
MONGODB_COLLECTION = os.getenv("MONGODB_COLLECTION", "users")

# ─── Three-database architecture (new) ─────────────────────────────────
# MAIN        — production source of truth (all normal reads/writes).
# SECONDARY   — verification/replica DB, written only by the sync worker.
# LOCAL       — admin-triggered replica; never a read source for the API.
MONGODB_MAIN_URI = os.getenv("MONGODB_MAIN_URI")
MONGODB_MAIN_DB = os.getenv("MONGODB_MAIN_DB")
MONGODB_SECONDARY_URI = os.getenv("MONGODB_SECONDARY_URI")
MONGODB_SECONDARY_DB = os.getenv("MONGODB_SECONDARY_DB")
MONGODB_LOCAL_URI = os.getenv("MONGODB_LOCAL_URI")
MONGODB_LOCAL_DB = os.getenv("MONGODB_LOCAL_DB")

# ─── Sync worker tuning ────────────────────────────────────────────────
SYNC_RETRY_MAX_ATTEMPTS = int(os.getenv("SYNC_RETRY_MAX_ATTEMPTS", "5"))
SYNC_RETRY_BASE_DELAY_SECONDS = int(os.getenv("SYNC_RETRY_BASE_DELAY_SECONDS", "3"))
SYNC_WORKER_POLL_SECONDS = float(os.getenv("SYNC_WORKER_POLL_SECONDS", "1.0"))
SYNC_ENABLED = os.getenv("SYNC_ENABLED", "true").lower() in ("true", "1", "yes")


# ─── Resolved role databases ───────────────────────────────────────────
def resolve_main_uri() -> str:
    return MONGODB_MAIN_URI or DATABASE_URL


def resolve_main_db() -> str:
    return MONGODB_MAIN_DB or MONGODB_DB_NAME


def resolve_secondary_uri() -> str:
    return MONGODB_SECONDARY_URI or "mongodb://unconfigured"


def resolve_secondary_db() -> str:
    return MONGODB_SECONDARY_DB or f"{resolve_main_db()}_secondary"


def resolve_local_uri() -> str:
    return MONGODB_LOCAL_URI or "mongodb://unconfigured"


def resolve_local_db() -> str:
    return MONGODB_LOCAL_DB or f"{resolve_main_db()}_local"