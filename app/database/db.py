"""
Database setup — engine, session factory, and Base for SQLAlchemy models.
Uses connection settings from the central config module.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import DATABASE_URL

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. Check your .env file.")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,       # detect stale connections automatically
    pool_size=5,
    max_overflow=10,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
