from typing import Generator

from sqlalchemy.orm import Session

from .config import DB_TYPE, DatabaseType
from .database import SessionLocal
from .mongodb_repository import MongoDBUserRepository
from .postgresql_repository import PostgreSQLUserRepository
from .repository import UserRepository

_mongodb_repo = None


def get_repository() -> Generator[UserRepository, None, None]:
    global _mongodb_repo

    if DB_TYPE == DatabaseType.MONGODB:
        if _mongodb_repo is None:
            _mongodb_repo = MongoDBUserRepository()

        try:
            yield _mongodb_repo
        finally:
            pass

    else:
        db: Session = SessionLocal()
        repo = PostgreSQLUserRepository(db)

        try:
            yield repo
        finally:
            db.close()


def close_connections():
    global _mongodb_repo

    if _mongodb_repo is not None:
        _mongodb_repo.close()
        _mongodb_repo = None