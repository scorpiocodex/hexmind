"""Database schema versioning and migration runner."""

from __future__ import annotations

from sqlalchemy import Engine, text

SCHEMA_VERSION: int = 1


def get_schema_version(engine: Engine) -> int:
    """Read user_version PRAGMA from SQLite; returns 0 for a brand-new database."""
    with engine.connect() as conn:
        result = conn.execute(text("PRAGMA user_version"))
        version = result.scalar()
        return version if version is not None else 0


def set_schema_version(engine: Engine, version: int) -> None:
    """Write user_version PRAGMA to SQLite (integer literal, not a bind param)."""
    with engine.connect() as conn:
        conn.execute(text(f"PRAGMA user_version = {version}"))
        conn.commit()


def run_migrations(engine: Engine) -> None:
    """Apply any pending migrations to bring the schema to SCHEMA_VERSION.

    v0 → v1: initial table creation is handled by Base.metadata.create_all()
    before this function is called, so no additional DDL is needed here.
    """
    current = get_schema_version(engine)
    if current >= SCHEMA_VERSION:
        return

    # v0 → v1: tables already created by create_all; just stamp the version
    set_schema_version(engine, SCHEMA_VERSION)
