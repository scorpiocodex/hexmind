"""Plain dataclass schemas used for inter-module data transfer (not ORM models)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolResult:
    """Transfer object carrying tool execution data before DB persistence."""

    tool_name: str
    command_run: str
    raw_output: str
    parsed_output: dict
    exit_code: int
    duration_ms: int
    error: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class FindingData:
    """Transfer object carrying AI-extracted finding data before DB persistence."""

    severity: str
    title: str
    category: str = ""
    description: str = ""
    affected_component: str = ""
    cve_ids: list[str] = field(default_factory=list)
    exploit_notes: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class ScanSummary:
    """Lightweight summary of a scan used for history display and comparisons."""

    scan_id: int
    target: str
    profile: str
    status: str
    started_at: str
    finished_at: str | None
    finding_counts: dict[str, int] = field(default_factory=dict)
    risk_score: int | None = None
