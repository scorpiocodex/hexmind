"""Database schema versioning and migration runner."""

from __future__ import annotations

from sqlalchemy import Engine, text

SCHEMA_VERSION: int = 1


def check_schema_version(engine: Engine) -> int:
    """Return the current schema version stored in the database, or 0 if unset."""
    raise NotImplementedError("TODO: implement")


def run_migrations(engine: Engine) -> None:
    """Apply any pending migrations to bring the schema up to SCHEMA_VERSION."""
    raise NotImplementedError("TODO: implement")
