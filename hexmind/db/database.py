"""Database engine factory and session management for SQLite via SQLAlchemy."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from hexmind.core.exceptions import DatabaseError
from hexmind.db.migrations import run_migrations
from hexmind.db.models import Base


class DatabaseManager:
    """Manages the SQLAlchemy engine, session factory, and schema initialisation."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        self._engine = None
        self._SessionFactory = None

    def init(self) -> None:
        """Create the engine, run migrations, and ensure all tables exist."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            engine = create_engine(f"sqlite:///{self.db_path}", echo=False)

            @event.listens_for(engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                dbapi_connection.execute("PRAGMA journal_mode=WAL")
                dbapi_connection.execute("PRAGMA foreign_keys=ON")

            Base.metadata.create_all(engine)
            run_migrations(engine)
            self._engine = engine
            self._SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)
        except SQLAlchemyError as exc:
            raise DatabaseError(f"Failed to initialise database: {exc}") from exc

    def close(self) -> None:
        """Dispose the engine connection pool."""
        if self._engine is not None:
            self._engine.dispose()

    @contextmanager
    def get_db(self) -> Generator[Session, None, None]:
        """Yield a transactional database session, rolling back on exception."""
        if self._SessionFactory is None:
            raise DatabaseError("DatabaseManager not initialized. Call init() first.")
        session: Session = self._SessionFactory()
        try:
            yield session
            session.commit()
        except SQLAlchemyError as exc:
            session.rollback()
            raise DatabaseError(f"Database operation failed: {exc}") from exc
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @property
    def engine(self):
        """Return the SQLAlchemy engine, raising if not yet initialised."""
        if self._engine is None:
            raise DatabaseError("DatabaseManager not initialized. Call init() first.")
        return self._engine

    def get_db_size_mb(self) -> float:
        """Return the database file size in MB."""
        return self.db_path.stat().st_size / (1024 * 1024)

    def vacuum(self) -> None:
        """Run VACUUM to reclaim space (requires autocommit)."""
        with self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("VACUUM"))
