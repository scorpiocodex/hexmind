"""SQLAlchemy 2.0 ORM models for the five HexMind database tables."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from hexmind.db.schemas import FindingData

_SEVERITY_RANKS: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------


class Target(Base):
    """Known scan target: an IP address, domain name, or CIDR block."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    type: Mapped[str] = mapped_column(String(20), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    tags_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scans: Mapped[list["Scan"]] = relationship(
        "Scan", back_populates="target", cascade="all, delete-orphan"
    )

    # ------------------------------------------------------------------
    # JSON property helpers
    # ------------------------------------------------------------------

    @property
    def tags(self) -> list[str]:
        """Return the tags list, decoded from the JSON text column."""
        return json.loads(self.tags_json) if self.tags_json else []

    @tags.setter
    def tags(self, value: list[str]) -> None:
        self.tags_json = json.dumps(value)

    def __repr__(self) -> str:
        return f"<Target id={self.id} value={self.value!r}>"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


class Scan(Base):
    """A single scan session for a target."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_target_id", "target_id"),
        Index("ix_scans_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    scan_profile: Mapped[str] = mapped_column(
        String(20), nullable=False, default="standard"
    )
    tool_flags_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    tool_results: Mapped[list["ToolResultModel"]] = relationship(
        "ToolResultModel", back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    ai_conversations: Mapped[list["AIConversation"]] = relationship(
        "AIConversation", back_populates="scan", cascade="all, delete-orphan"
    )

    # ------------------------------------------------------------------
    # JSON property helpers
    # ------------------------------------------------------------------

    @property
    def tool_flags(self) -> dict:
        """Return per-tool flag overrides decoded from the JSON text column."""
        return json.loads(self.tool_flags_json) if self.tool_flags_json else {}

    @tool_flags.setter
    def tool_flags(self, value: dict) -> None:
        self.tool_flags_json = json.dumps(value)

    # ------------------------------------------------------------------
    # Duration helpers
    # ------------------------------------------------------------------

    @property
    def duration_seconds(self) -> float | None:
        """Return elapsed seconds between start and finish, or None if still running."""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def duration_str(self) -> str:
        """Return human-readable elapsed time in 'Xm Ys' format, or '—' if not done."""
        secs = self.duration_seconds
        if secs is None:
            return "—"
        minutes = int(secs // 60)
        seconds = int(secs % 60)
        return f"{minutes}m {seconds}s"

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target_id={self.target_id} status={self.status!r}>"


# ---------------------------------------------------------------------------
# ToolResultModel
# ---------------------------------------------------------------------------


class ToolResultModel(Base):
    """Raw and parsed output from a single tool run within a scan."""

    __tablename__ = "tool_results"
    __table_args__ = (
        Index("ix_tool_results_scan_id", "scan_id"),
        Index("ix_tool_results_tool_name", "tool_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)
    command_run: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parsed_output_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    tool_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="tool_results")

    # ------------------------------------------------------------------
    # JSON property helpers
    # ------------------------------------------------------------------

    @property
    def parsed_output(self) -> dict:
        """Return structured tool output decoded from the JSON text column."""
        return json.loads(self.parsed_output_json) if self.parsed_output_json else {}

    @parsed_output.setter
    def parsed_output(self, value: dict) -> None:
        self.parsed_output_json = json.dumps(value)

    def __repr__(self) -> str:
        return f"<ToolResultModel id={self.id} tool_name={self.tool_name!r}>"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(Base):
    """A single security finding produced by AI analysis of a scan."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_component: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cve_ids_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exploit_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    false_positive: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")

    # ------------------------------------------------------------------
    # JSON property helpers
    # ------------------------------------------------------------------

    @property
    def cve_ids(self) -> list[str]:
        """Return CVE ID list decoded from the JSON text column."""
        return json.loads(self.cve_ids_json) if self.cve_ids_json else []

    @cve_ids.setter
    def cve_ids(self, value: list[str]) -> None:
        self.cve_ids_json = json.dumps(value)

    @property
    def references(self) -> list[str]:
        """Return reference URL list decoded from the JSON text column."""
        return json.loads(self.references_json) if self.references_json else []

    @references.setter
    def references(self, value: list[str]) -> None:
        self.references_json = json.dumps(value)

    # ------------------------------------------------------------------
    # Severity helpers
    # ------------------------------------------------------------------

    @property
    def severity_rank(self) -> int:
        """Return numeric rank for sorting; lower value = more severe."""
        return _SEVERITY_RANKS.get(self.severity.lower(), 99)

    # ------------------------------------------------------------------
    # DTO conversion
    # ------------------------------------------------------------------

    def to_finding_data(self) -> FindingData:
        """Convert this ORM record back to a FindingData transfer object."""
        return FindingData(
            severity=self.severity,
            category=self.category or "",
            title=self.title,
            description=self.description or "",
            affected_component=self.affected_component or "",
            cve_ids=self.cve_ids,
            exploit_notes=self.exploit_notes or "",
            remediation=self.remediation or "",
            references=self.references,
            confidence_score=self.confidence_score,
            false_positive=self.false_positive,
        )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} severity={self.severity!r} title={self.title!r}>"


# ---------------------------------------------------------------------------
# AIConversation
# ---------------------------------------------------------------------------


class AIConversation(Base):
    """A single message turn in the agentic loop conversation log."""

    __tablename__ = "ai_conversations"
    __table_args__ = (Index("ix_ai_conv_scan_id", "scan_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    token_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    loop_iteration: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="ai_conversations")

    def __repr__(self) -> str:
        return (
            f"<AIConversation id={self.id} role={self.role!r} "
            f"iteration={self.loop_iteration}>"
        )
