"""AI response parser: extracts findings, tool requests, and search requests from XML."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolRequest:
    """A single AI-requested tool invocation."""

    tool: str
    args: str
    reason: str


@dataclass
class SearchRequest:
    """A single AI-requested DuckDuckGo web search."""

    query: str


@dataclass
class CVELookupRequest:
    """A single AI-requested CVE detail lookup."""

    cve_id: str


@dataclass
class ParsedAIResponse:
    """Fully parsed AI response with structured findings and action requests."""

    findings: list = field(default_factory=list)
    tool_requests: list[ToolRequest] = field(default_factory=list)
    search_requests: list[SearchRequest] = field(default_factory=list)
    cve_lookups: list[CVELookupRequest] = field(default_factory=list)
    executive_summary: str | None = None
    risk_score: int | None = None
    raw_text: str = ""


class AIParser:
    """Parses structured XML blocks from raw AI response text."""

    def parse(self, response: str) -> dict:
        """Parse response and return a plain dict representation of all blocks."""
        raise NotImplementedError("TODO: implement")

    def parse_structured(self, response: str, target: str) -> ParsedAIResponse:
        """Parse response into a fully typed ParsedAIResponse for the given target."""
        raise NotImplementedError("TODO: implement")

    def _parse_finding(self, xml_element: object) -> object | None:
        """Convert an XML element into a FindingData object, or None if invalid."""
        raise NotImplementedError("TODO: implement")

    def _deduplicate_tool_requests(
        self, requests: list[ToolRequest], already_run: set
    ) -> list[ToolRequest]:
        """Filter out tool requests that duplicate previously executed tool+args pairs."""
        raise NotImplementedError("TODO: implement")
