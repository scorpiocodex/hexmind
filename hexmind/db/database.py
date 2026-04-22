"""Database engine factory and session management for SQLite via SQLAlchemy."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from hexmind.db.models import Base


class DatabaseManager:
    """Manages the SQLAlchemy engine, session factory, and schema initialisation."""

    def __init__(self, db_path: str) -> None:
        """Initialize with a file path or connection URL for the SQLite database."""
        self.db_path = db_path
        self._engine = None
        self._session_factory = None

    def init(self) -> None:
        """Create the engine, run migrations, and ensure all tables exist."""
        raise NotImplementedError("TODO: implement")

    def close(self) -> None:
        """Dispose the engine and release all connections."""
        raise NotImplementedError("TODO: implement")

    @contextmanager
    def get_db(self) -> Generator[Session, None, None]:
        """Yield a transactional database session, rolling back on exception."""
        raise NotImplementedError("TODO: implement")
        yield  # pragma: no cover
