"""Three-database connection layer for user_service."""
from .connection_manager import (
    ROLE_MAIN,
    ROLE_SECONDARY,
    ROLE_LOCAL,
    get_client,
    get_database,
    ping,
    close_all,
)

__all__ = [
    "ROLE_MAIN",
    "ROLE_SECONDARY",
    "ROLE_LOCAL",
    "get_client",
    "get_database",
    "ping",
    "close_all",
]
from .sql_db import Base, engine, SessionLocal, get_db

__all__.extend(["Base", "engine", "SessionLocal", "get_db"])
