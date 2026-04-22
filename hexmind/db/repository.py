"""CRUD repository classes for each HexMind database table."""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexmind.db.models import AIConversation, Finding, Scan, Target, ToolResultModel


class TargetRepository:
    """CRUD operations for the targets table."""

    def __init__(self, session: Session) -> None:
        """Initialize with an active SQLAlchemy session."""
        self.session = session

    def get_or_create(self, value: str, target_type: str) -> Target:
        """Return an existing target record or insert and return a new one."""
        raise NotImplementedError("TODO: implement")

    def list_all(self) -> list[Target]:
        """Return all known targets ordered by last_seen descending."""
        raise NotImplementedError("TODO: implement")

    def get_by_value(self, value: str) -> Target | None:
        """Return the target record matching value, or None."""
        raise NotImplementedError("TODO: implement")

    def update_last_seen(self, target_id: int) -> None:
        """Set last_seen to now for the given target ID."""
        raise NotImplementedError("TODO: implement")


class ScanRepository:
    """CRUD operations for the scans table."""

    def __init__(self, session: Session) -> None:
        """Initialize with an active SQLAlchemy session."""
        self.session = session

    def create(self, target_id: int, profile: str) -> Scan:
        """Insert a new scan record with status 'running' and return it."""
        raise NotImplementedError("TODO: implement")

    def get(self, scan_id: int) -> Scan | None:
        """Return the scan record for scan_id, or None."""
        raise NotImplementedError("TODO: implement")

    def list_recent(self, limit: int = 20, target: str | None = None) -> list[Scan]:
        """Return the most recent scans, optionally filtered by target value."""
        raise NotImplementedError("TODO: implement")

    def mark_done(self, scan_id: int) -> None:
        """Set scan status to 'done' and record finished_at timestamp."""
        raise NotImplementedError("TODO: implement")

    def mark_failed(self, scan_id: int, error: str) -> None:
        """Set scan status to 'failed' and store the error message."""
        raise NotImplementedError("TODO: implement")


class ToolResultRepository:
    """CRUD operations for the tool_results table."""

    def __init__(self, session: Session) -> None:
        """Initialize with an active SQLAlchemy session."""
        self.session = session

    def save(self, scan_id: int, result: object) -> ToolResultModel:
        """Persist a RunnerResult and return the saved ORM record."""
        raise NotImplementedError("TODO: implement")

    def list_for_scan(self, scan_id: int) -> list[ToolResultModel]:
        """Return all tool result records for the given scan ID."""
        raise NotImplementedError("TODO: implement")


class FindingRepository:
    """CRUD operations for the findings table."""

    def __init__(self, session: Session) -> None:
        """Initialize with an active SQLAlchemy session."""
        self.session = session

    def save(self, scan_id: int, finding_data: object) -> Finding:
        """Persist a FindingData object and return the saved ORM record."""
        raise NotImplementedError("TODO: implement")

    def list_for_scan(
        self, scan_id: int, min_severity: str | None = None
    ) -> list[Finding]:
        """Return findings for a scan, optionally filtered by minimum severity."""
        raise NotImplementedError("TODO: implement")

    def count_by_severity(self, scan_id: int) -> dict[str, int]:
        """Return a dict mapping severity label to finding count for a scan."""
        raise NotImplementedError("TODO: implement")


class AIConversationRepository:
    """CRUD operations for the ai_conversations table."""

    def __init__(self, session: Session) -> None:
        """Initialize with an active SQLAlchemy session."""
        self.session = session

    def save(
        self,
        scan_id: int,
        role: str,
        content: str,
        iteration: int = 0,
        token_count: int | None = None,
    ) -> AIConversation:
        """Persist a single AI conversation turn and return the saved record."""
        raise NotImplementedError("TODO: implement")

    def list_for_scan(self, scan_id: int) -> list[AIConversation]:
        """Return all conversation turns for a scan ordered by created_at."""
        raise NotImplementedError("TODO: implement")
