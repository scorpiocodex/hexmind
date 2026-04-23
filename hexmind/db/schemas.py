"""Plain dataclass schemas used for inter-module data transfer (not ORM models)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

_SEVERITY_RANKS: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class ToolResultData:
    """Data transfer object for tool runner output → DB persistence."""

    tool_name: str
    command_run: str
    raw_output: str
    parsed_output: dict
    exit_code: int
    duration_ms: int
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    started_at: Optional[datetime] = None
    tool_version: str = ""


@dataclass
class FindingData:
    """Data transfer object for AI-parsed finding → DB persistence."""

    severity: str               # critical|high|medium|low|info
    category: str               # vulnerability|misconfiguration|exposure|recon
    title: str
    description: str = ""
    affected_component: str = ""
    cve_ids: list[str] = field(default_factory=list)
    exploit_notes: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    confidence_score: float = 0.0
    false_positive: bool = False

    def severity_rank(self) -> int:
        """Return numeric rank for sorting; lower value = more severe."""
        return _SEVERITY_RANKS.get(self.severity.lower(), 99)

    def to_display_dict(self) -> dict:
        """Return a flat dict suitable for Rich table rendering."""
        return {
            "severity": self.severity.upper(),
            "category": self.category,
            "title": self.title,
            "cves": ", ".join(self.cve_ids) if self.cve_ids else "—",
            "component": self.affected_component or "—",
            "confidence": f"{int(self.confidence_score * 100)}%",
        }


@dataclass
class ScanSummary:
    """Lightweight scan record for history display and comparisons."""

    scan_id: int
    target: str
    target_type: str
    profile: str
    status: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    duration_str: str
    finding_counts: dict[str, int] = field(default_factory=dict)  # {"critical": 1, …}
    risk_score: Optional[int] = None
    total_findings: int = 0

    @property
    def duration_seconds(self) -> float:
        """Return elapsed seconds between start and finish, or 0.0 if incomplete."""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return 0.0
