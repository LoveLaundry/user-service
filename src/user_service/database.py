import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

# Only create SQLAlchemy engine for PostgreSQL/SQLite
# MongoDB will use pymongo directly
if DATABASE_URL and not (DATABASE_URL.startswith("mongodb://") or DATABASE_URL.startswith("mongodb+srv://")):
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
else:
    # Placeholder for MongoDB - won't be used
    engine = None
    SessionLocal = None


class Base(DeclarativeBase):
    pass


def get_db():
    """Get database session for PostgreSQL/SQLite"""
    if SessionLocal is None:
        raise RuntimeError("SessionLocal is not initialized. This should only be used with PostgreSQL/SQLite.")
    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
