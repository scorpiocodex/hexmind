"""SQLAlchemy ORM models for the five HexMind database tables."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


class Target(Base):
    """Known scan target (IP, domain, or CIDR block)."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    type: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now()
    )
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="target")


class Scan(Base):
    """A single scan session for a target."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("targets.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    scan_profile: Mapped[str] = mapped_column(Text, default="standard")
    tool_flags: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_log: Mapped[str | None] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    tool_results: Mapped[list["ToolResultModel"]] = relationship(
        "ToolResultModel", back_populates="scan"
    )
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan")
    ai_conversations: Mapped[list["AIConversation"]] = relationship(
        "AIConversation", back_populates="scan"
    )


class ToolResultModel(Base):
    """Raw and parsed output from a single tool run within a scan."""

    __tablename__ = "tool_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    command_run: Mapped[str] = mapped_column(Text, nullable=False)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    parsed_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    tool_version: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="tool_results")


class Finding(Base):
    """A single security finding produced by AI analysis of a scan."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id"), nullable=False
    )
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str | None] = mapped_column(Text, nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_component: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    exploit_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")


class AIConversation(Base):
    """A single message in the AI agentic loop conversation log."""

    __tablename__ = "ai_conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id"), nullable=False
    )
    role: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    token_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now()
    )
    loop_iteration: Mapped[int] = mapped_column(Integer, default=0)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="ai_conversations")
