"""CRUD repository classes for each HexMind database table."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, selectinload

from hexmind.db.models import AIConversation, Finding, Scan, Target, ToolResultModel
from hexmind.db.schemas import FindingData, ScanSummary, ToolResultData

_SEVERITY_RANKS: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_SEVERITY_ORDER = case(
    _SEVERITY_RANKS,
    value=func.lower(Finding.severity),
    else_=99,
)


class TargetRepository:
    """CRUD operations for the targets table."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_or_create(self, value: str, type: str) -> Target:
        """Return existing target (updating last_seen) or insert a new one."""
        target = self.get_by_value(value)
        if target is not None:
            target.last_seen = datetime.utcnow()
            self.db.flush()
            return target
        target = Target(value=value, type=type, last_seen=datetime.utcnow())
        self.db.add(target)
        self.db.flush()
        return target

    def get_by_value(self, value: str) -> Target | None:
        """Return the target record matching value, or None."""
        return self.db.scalars(
            select(Target).where(Target.value == value)
        ).first()

    def get_by_id(self, target_id: int) -> Target | None:
        """Return the target record for target_id, or None."""
        return self.db.get(Target, target_id)

    def list_all(self) -> list[Target]:
        """Return all known targets ordered by last_seen descending."""
        return list(
            self.db.scalars(
                select(Target).order_by(Target.last_seen.desc().nullslast())
            )
        )

    def update_last_seen(self, target_id: int) -> None:
        """Set last_seen to utcnow() for the given target ID."""
        target = self.get_by_id(target_id)
        if target is not None:
            target.last_seen = datetime.utcnow()
            self.db.flush()

    def delete(self, target_id: int) -> bool:
        """Delete target and cascade. Return True if found."""
        target = self.get_by_id(target_id)
        if target is None:
            return False
        self.db.delete(target)
        self.db.flush()
        return True


class ScanRepository:
    """CRUD operations for the scans table."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self, target_id: int, profile: str = "standard", tool_flags: dict = {}
    ) -> Scan:
        """Insert a new scan record with status 'pending' and return it."""
        scan = Scan(
            target_id=target_id,
            status="pending",
            started_at=datetime.utcnow(),
            scan_profile=profile,
        )
        scan.tool_flags = tool_flags
        self.db.add(scan)
        self.db.flush()
        return scan

    def update_status(self, scan_id: int, status: str) -> None:
        """Update scan status."""
        scan = self.db.get(Scan, scan_id)
        if scan is not None:
            scan.status = status
            self.db.flush()

    def finish(
        self,
        scan_id: int,
        risk_score: int | None = None,
        executive_summary: str | None = None,
    ) -> None:
        """Set status='done', finished_at=utcnow(), optionally set risk and summary."""
        scan = self.db.get(Scan, scan_id)
        if scan is not None:
            scan.status = "done"
            scan.finished_at = datetime.utcnow()
            if risk_score is not None:
                scan.risk_score = risk_score
            if executive_summary is not None:
                scan.executive_summary = executive_summary
            self.db.flush()

    def fail(self, scan_id: int, error: str) -> None:
        """Set status='failed', finished_at=utcnow(), error_log=error."""
        scan = self.db.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.finished_at = datetime.utcnow()
            scan.error_log = error
            self.db.flush()

    def get_by_id(self, scan_id: int) -> Scan | None:
        """Return Scan with eagerly loaded target, or None."""
        return self.db.scalars(
            select(Scan)
            .where(Scan.id == scan_id)
            .options(selectinload(Scan.target))
        ).first()

    def list_all(self, limit: int = 50) -> list[Scan]:
        """Return most recent scans first."""
        return list(
            self.db.scalars(
                select(Scan)
                .options(selectinload(Scan.target))
                .order_by(Scan.started_at.desc().nullslast())
                .limit(limit)
            )
        )

    def list_for_target(self, target_id: int, limit: int = 20) -> list[Scan]:
        """Return most recent scans for a specific target."""
        return list(
            self.db.scalars(
                select(Scan)
                .where(Scan.target_id == target_id)
                .options(selectinload(Scan.target))
                .order_by(Scan.started_at.desc().nullslast())
                .limit(limit)
            )
        )

    def get_summary(self, scan_id: int) -> ScanSummary | None:
        """Build a ScanSummary dataclass for this scan."""
        scan = self.get_by_id(scan_id)
        if scan is None:
            return None
        f_repo = FindingRepository(self.db)
        finding_counts = f_repo.count_by_severity(scan_id)
        total = sum(finding_counts.values())
        return ScanSummary(
            scan_id=scan.id,
            target=scan.target.value,
            target_type=scan.target.type,
            profile=scan.scan_profile,
            status=scan.status,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            duration_str=scan.duration_str,
            finding_counts=finding_counts,
            risk_score=scan.risk_score,
            total_findings=total,
        )


class ToolResultRepository:
    """CRUD operations for the tool_results table."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, scan_id: int, data: ToolResultData) -> ToolResultModel:
        """Convert ToolResultData → ToolResultModel ORM object and persist."""
        record = ToolResultModel(
            scan_id=scan_id,
            tool_name=data.tool_name,
            command_run=data.command_run,
            raw_output=data.raw_output,
            exit_code=data.exit_code,
            duration_ms=data.duration_ms,
            started_at=data.started_at,
            tool_version=data.tool_version,
            error=data.error,
        )
        record.parsed_output = data.parsed_output
        self.db.add(record)
        self.db.flush()
        return record

    def get_for_scan(self, scan_id: int) -> list[ToolResultModel]:
        """Return all tool results for a scan, ordered by created_at."""
        return list(
            self.db.scalars(
                select(ToolResultModel)
                .where(ToolResultModel.scan_id == scan_id)
                .order_by(ToolResultModel.created_at)
            )
        )

    def get_by_tool(self, scan_id: int, tool_name: str) -> ToolResultModel | None:
        """Return the most recent result for this tool in this scan."""
        return self.db.scalars(
            select(ToolResultModel)
            .where(
                ToolResultModel.scan_id == scan_id,
                ToolResultModel.tool_name == tool_name,
            )
            .order_by(ToolResultModel.created_at.desc())
        ).first()

    def get_parsed(self, scan_id: int, tool_name: str) -> dict:
        """Return parsed_output dict for a tool in a scan, or {} if not found."""
        record = self.get_by_tool(scan_id, tool_name)
        if record is None:
            return {}
        return record.parsed_output


class FindingRepository:
    """CRUD operations for the findings table."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, scan_id: int, data: FindingData) -> Finding:
        """Convert FindingData → Finding ORM object and persist."""
        record = Finding(
            scan_id=scan_id,
            severity=data.severity,
            category=data.category,
            title=data.title,
            description=data.description,
            affected_component=data.affected_component,
            exploit_notes=data.exploit_notes,
            remediation=data.remediation,
            confidence_score=data.confidence_score,
            false_positive=data.false_positive,
        )
        record.cve_ids = data.cve_ids
        record.references = data.references
        self.db.add(record)
        self.db.flush()
        return record

    def save_batch(
        self, scan_id: int, findings: list[FindingData]
    ) -> list[Finding]:
        """Save multiple findings, deduplicating by title+component."""
        saved: list[Finding] = []
        for data in findings:
            if not self.exists(scan_id, data.title, data.affected_component):
                saved.append(self.save(scan_id, data))
        return saved

    def get_for_scan(self, scan_id: int) -> list[Finding]:
        """Return findings ordered by severity rank then confidence descending."""
        return list(
            self.db.scalars(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .order_by(_SEVERITY_ORDER, Finding.confidence_score.desc())
            )
        )

    def get_by_severity(self, scan_id: int, severity: str) -> list[Finding]:
        """Return all findings for a scan with the given severity."""
        return list(
            self.db.scalars(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    func.lower(Finding.severity) == severity.lower(),
                )
            )
        )

    def count_by_severity(self, scan_id: int) -> dict[str, int]:
        """Return counts for all five severity levels."""
        rows = self.db.execute(
            select(func.lower(Finding.severity), func.count())
            .where(Finding.scan_id == scan_id)
            .group_by(func.lower(Finding.severity))
        ).all()
        counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for severity, count in rows:
            if severity in counts:
                counts[severity] = count
        return counts

    def mark_false_positive(self, finding_id: int, is_fp: bool = True) -> None:
        """Set or clear the false_positive flag for a finding."""
        finding = self.db.get(Finding, finding_id)
        if finding is not None:
            finding.false_positive = is_fp
            self.db.flush()

    def exists(self, scan_id: int, title: str, component: str) -> bool:
        """Check for existing finding using enhanced normalized title comparison."""
        import re

        def normalize(s: str) -> str:
            s = s.strip().strip('"').strip("'").lower()
            for _ in range(4):
                prev = s
                s = re.sub(r"\s*\([^()]*\)", "", s).strip()
                if s == prev:
                    break
            s = s.replace("(", "").replace(")", "").strip()
            s = re.sub(r"apache\s+\d+[\.\d]+\s*", "apache ", s)
            s = re.sub(r"apache\s+http\s+server\s*", "apache ", s)
            s = re.sub(r"apache\s+httpd\s*", "apache ", s)
            s = re.sub(r"\s+", " ", s).strip()
            return s

        norm_title = normalize(title)
        findings   = (
            self.db.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .all()
        )
        for f in findings:
            if normalize(f.title or "") == norm_title:
                return True
        return False


class AIConversationRepository:
    """CRUD operations for the ai_conversations table."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def save_message(
        self,
        scan_id: int,
        role: str,
        content: str,
        iteration: int = 0,
        token_count: int = 0,
    ) -> AIConversation:
        """Persist a single AI conversation turn and return the saved record."""
        record = AIConversation(
            scan_id=scan_id,
            role=role,
            content=content,
            loop_iteration=iteration,
            token_count=token_count,
        )
        self.db.add(record)
        self.db.flush()
        return record

    def get_thread(self, scan_id: int) -> list[AIConversation]:
        """Return all messages for a scan ordered by created_at ascending."""
        return list(
            self.db.scalars(
                select(AIConversation)
                .where(AIConversation.scan_id == scan_id)
                .order_by(AIConversation.created_at)
            )
        )

    def get_last_assistant_message(self, scan_id: int) -> AIConversation | None:
        """Return the most recent assistant message for a scan."""
        return self.db.scalars(
            select(AIConversation)
            .where(
                AIConversation.scan_id == scan_id,
                AIConversation.role == "assistant",
            )
            .order_by(AIConversation.created_at.desc())
        ).first()

    def get_by_iteration(self, scan_id: int, iteration: int) -> list[AIConversation]:
        """Return all messages for a specific loop iteration."""
        return list(
            self.db.scalars(
                select(AIConversation).where(
                    AIConversation.scan_id == scan_id,
                    AIConversation.loop_iteration == iteration,
                )
                .order_by(AIConversation.created_at)
            )
        )
