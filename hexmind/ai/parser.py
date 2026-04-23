"""AI response parser: extracts findings, tool requests, and search requests from XML."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from hexmind.db.schemas import FindingData


@dataclass
class ToolRequest:
    """A single AI-requested tool invocation."""

    tool:   str
    args:   str
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

    findings:          list[FindingData]      = field(default_factory=list)
    tool_requests:     list[ToolRequest]      = field(default_factory=list)
    search_requests:   list[SearchRequest]    = field(default_factory=list)
    cve_lookups:       list[CVELookupRequest] = field(default_factory=list)
    executive_summary: Optional[str]          = None
    risk_score:        Optional[int]          = None
    raw_text:          str                    = ""


_CVE_RE     = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_VALID_SEVS = frozenset({"critical", "high", "medium", "low", "info"})


class AIParser:
    """Parses structured XML blocks from raw Ollama/Mistral AI response text.

    Each block type is extracted independently via regex so malformed XML in
    one block does not prevent parsing of others.
    """

    def _extract_blocks(self, text: str, tag: str) -> list[str]:
        """Return inner content of every <tag>...</tag> occurrence in text."""
        pattern = re.compile(
            rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>",
            re.DOTALL | re.IGNORECASE,
        )
        return [m.group(1).strip() for m in pattern.finditer(text)]

    def _get_text(self, block: str, tag: str) -> str:
        """Extract text of a child element from an XML fragment.

        Returns "" if the tag is missing or the block is malformed.
        """
        pattern = re.compile(
            rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>",
            re.DOTALL | re.IGNORECASE,
        )
        m = pattern.search(block)
        return m.group(1).strip() if m else ""

    def _parse_finding(self, block: str) -> Optional[FindingData]:
        """Parse a <finding>...</finding> inner content into FindingData.

        Returns None if essential fields (severity, title) are missing.
        """
        severity = self._get_text(block, "severity").lower()
        title    = self._get_text(block, "title")

        if not severity or not title:
            return None
        if severity not in _VALID_SEVS:
            severity = "info"

        # Parse CVE IDs — split on comma/whitespace, validate pattern
        cves_raw = self._get_text(block, "cves")
        cve_ids: list[str] = []
        if cves_raw:
            cve_ids = [
                c.strip().upper()
                for c in re.split(r"[,\s]+", cves_raw)
                if _CVE_RE.match(c.strip())
            ]

        # Parse confidence score, clamp to [0.0, 1.0]
        conf_str = self._get_text(block, "confidence")
        try:
            confidence = float(conf_str)
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.5

        return FindingData(
            severity           = severity,
            category           = self._get_text(block, "category") or "recon",
            title              = title,
            description        = self._get_text(block, "description"),
            affected_component = self._get_text(block, "component"),
            cve_ids            = cve_ids,
            exploit_notes      = self._get_text(block, "exploit"),
            remediation        = self._get_text(block, "remediation"),
            references         = [],
            confidence_score   = confidence,
        )

    def parse_structured(
        self,
        response: str,
        target:   str = "",
    ) -> ParsedAIResponse:
        """Full structured parse of an AI response.

        Extracts all block types independently; robust to partial/malformed XML.
        CVE IDs found in findings are automatically added to cve_lookups.
        """
        # ── Findings ──────────────────────────────────────────────────────
        findings: list[FindingData] = []
        for block in self._extract_blocks(response, "finding"):
            f = self._parse_finding(block)
            if f is not None:
                findings.append(f)

        # ── Tool requests ──────────────────────────────────────────────────
        tool_requests: list[ToolRequest] = []
        for block in self._extract_blocks(response, "tool_request"):
            tool   = self._get_text(block, "tool").lower().strip()
            args   = self._get_text(block, "args").strip()
            reason = self._get_text(block, "reason").strip()
            if tool and args:
                args = args.replace("{target}", target)
                tool_requests.append(ToolRequest(tool=tool, args=args, reason=reason))

        # ── Search requests ────────────────────────────────────────────────
        search_requests: list[SearchRequest] = []
        for block in self._extract_blocks(response, "search_request"):
            query = self._get_text(block, "query").strip()
            if query:
                search_requests.append(SearchRequest(query=query))

        # ── Explicit CVE lookups ───────────────────────────────────────────
        cve_lookups: list[CVELookupRequest] = []
        seen_cves: set[str] = set()
        for block in self._extract_blocks(response, "cve_lookup"):
            cve_id = self._get_text(block, "cve_id").strip().upper()
            if _CVE_RE.match(cve_id) and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                cve_lookups.append(CVELookupRequest(cve_id=cve_id))

        # Auto-extract CVE IDs from parsed findings
        for f in findings:
            for cve_id in f.cve_ids:
                if cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    cve_lookups.append(CVELookupRequest(cve_id=cve_id))

        # ── Executive summary ──────────────────────────────────────────────
        summary_blocks    = self._extract_blocks(response, "executive_summary")
        executive_summary = summary_blocks[0] if summary_blocks else None

        # ── Risk score ─────────────────────────────────────────────────────
        risk_score: Optional[int] = None
        risk_blocks = self._extract_blocks(response, "risk_score")
        if risk_blocks:
            m = re.search(r"\d+", risk_blocks[0])
            if m:
                risk_score = max(0, min(100, int(m.group())))

        return ParsedAIResponse(
            findings          = findings,
            tool_requests     = tool_requests,
            search_requests   = search_requests,
            cve_lookups       = cve_lookups,
            executive_summary = executive_summary,
            risk_score        = risk_score,
            raw_text          = response,
        )

    def parse(self, response: str) -> dict:
        """Legacy dict-based interface for older call sites."""
        result = self.parse_structured(response)
        return {
            "findings":          [vars(f) for f in result.findings],
            "tool_requests":     [vars(r) for r in result.tool_requests],
            "search_requests":   [vars(r) for r in result.search_requests],
            "cve_lookups":       [vars(r) for r in result.cve_lookups],
            "executive_summary": result.executive_summary,
            "risk_score":        result.risk_score,
        }

    def deduplicate_tool_requests(
        self,
        requests:    list[ToolRequest],
        already_run: set[tuple[str, str]],
    ) -> list[ToolRequest]:
        """Remove tool requests whose (tool, args) pair was already executed.

        Also deduplicates within the current request list.
        """
        seen:   set[tuple[str, str]] = set(already_run)
        result: list[ToolRequest]    = []
        for req in requests:
            key = (req.tool, req.args)
            if key not in seen:
                seen.add(key)
                result.append(req)
        return result

