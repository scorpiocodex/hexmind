"""Report generation orchestrator: renders Jinja2 templates to md/html/pdf/json."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from hexmind.constants import HEXMIND_VERSION
from hexmind.db.repository import (
    AIConversationRepository,
    FindingRepository,
    ScanRepository,
    TargetRepository,
    ToolResultRepository,
)
from hexmind.reports.pdf_renderer import PDFRenderer
from hexmind.ui.console import print_error, print_info, print_success

_TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportExporter:
    """
    Generates scan reports in MD, HTML, PDF, and JSON formats.
    Reads all data from DB repositories.
    Renders via Jinja2 templates.
    """

    FORMAT_EXTENSIONS = {
        "md":   ".md",
        "html": ".html",
        "pdf":  ".pdf",
        "json": ".json",
    }

    SEVERITY_ORDER = {
        "critical": 0, "high": 1,
        "medium": 2, "low": 3, "info": 4,
    }

    CVSS_WEIGHTS = {
        "critical": 40,
        "high":     20,
        "medium":    8,
        "low":       2,
        "info":      0,
    }

    def __init__(self, db_repos: dict, output_dir: Path) -> None:
        self.db_repos   = db_repos
        self.output_dir = Path(output_dir)
        self._jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._pdf_renderer = PDFRenderer()

    async def export(
        self,
        scan_id:     int,
        format:      str,
        output_path: Optional[Path] = None,
        include_raw: bool           = True,
    ) -> Path:
        """
        Export scan report in requested format.
        Returns path to generated file.

        Raises ValueError for unknown format.
        Raises KeyError if scan_id not found.
        """
        if format not in self.FORMAT_EXTENSIONS:
            raise ValueError(
                f"Unknown format '{format}'. "
                f"Use: {', '.join(self.FORMAT_EXTENSIONS)}"
            )

        ctx = self._build_context(scan_id, include_raw)

        if output_path is None:
            filename = self._get_output_filename(scan_id, format)
            self.output_dir.mkdir(parents=True, exist_ok=True)
            output_path = self.output_dir / filename

        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "md":
            content = self._render_markdown(ctx)
            output_path.write_text(content, encoding="utf-8")

        elif format == "html":
            content = self._render_html(ctx)
            output_path.write_text(content, encoding="utf-8")

        elif format == "pdf":
            html_content = self._render_pdf_html(ctx)
            success = self._pdf_renderer.render(html_content, output_path)
            if not success:
                fallback = output_path.with_suffix(".pdf.html")
                fallback.write_text(html_content, encoding="utf-8")
                print_info(
                    f"PDF rendering unavailable. "
                    f"HTML saved to: {fallback}"
                )
                return fallback

        elif format == "json":
            content = self._render_json(ctx)
            output_path.write_text(content, encoding="utf-8")

        return output_path

    # ── Context builder ────────────────────────────────────────

    def _build_context(self, scan_id: int, include_raw: bool) -> dict:
        """
        Load all scan data from DB repositories and build the
        template context dict.

        Uses self.db_repos which maps:
          "scan"    → ScanRepository
          "tool"    → ToolResultRepository
          "finding" → FindingRepository
          "ai"      → AIConversationRepository
          "target"  → TargetRepository
        """
        s_repo:  ScanRepository           = self.db_repos["scan"]
        tr_repo: ToolResultRepository     = self.db_repos["tool"]
        f_repo:  FindingRepository        = self.db_repos["finding"]
        ai_repo: AIConversationRepository = self.db_repos["ai"]

        scan = s_repo.get_by_id(scan_id)
        if not scan:
            raise KeyError(f"Scan #{scan_id} not found in database.")

        findings_orm    = f_repo.get_for_scan(scan_id)
        tool_results    = tr_repo.get_for_scan(scan_id)
        ai_convos       = ai_repo.get_thread(scan_id) if include_raw else []
        severity_counts = f_repo.count_by_severity(scan_id)

        findings_sorted = sorted(
            findings_orm,
            key=lambda f: (
                self.SEVERITY_ORDER.get(f.severity.lower(), 99),
                -(f.confidence_score or 0),
            ),
        )

        findings_dicts = []
        for f in findings_sorted:
            findings_dicts.append({
                "id":                 f.id,
                "severity":           f.severity.lower(),
                "category":           f.category or "recon",
                "title":              f.title,
                "description":        f.description or "",
                "affected_component": f.affected_component or "",
                "cve_ids":            f.cve_ids,
                "exploit_notes":      f.exploit_notes or "",
                "remediation":        f.remediation or "",
                "references":         f.references,
                "confidence_score":   f.confidence_score or 0.0,
                "confidence_pct":     int((f.confidence_score or 0) * 100),
                "false_positive":     f.false_positive,
                "created_at":         f.created_at,
            })

        tool_dicts = []
        for tr in tool_results:
            tool_dicts.append({
                "tool_name":     tr.tool_name,
                "command_run":   tr.command_run or "",
                "raw_output":    (tr.raw_output or "")[:2000]
                                 if include_raw else "[excluded]",
                "parsed_output": tr.parsed_output,
                "exit_code":     tr.exit_code,
                "duration_ms":   tr.duration_ms or 0,
                "duration_str":  f"{(tr.duration_ms or 0) / 1000:.1f}s",
                "started_at":    tr.started_at,
                "tool_version":  tr.tool_version or "",
                "error":         tr.error,
            })

        ai_dicts = [
            {
                "role":           c.role,
                "content":        c.content,
                "loop_iteration": c.loop_iteration,
                "created_at":     c.created_at,
                "token_count":    c.token_count or 0,
            }
            for c in ai_convos
        ]

        risk_score = scan.risk_score
        risk_level = self._score_to_level(risk_score)
        roadmap    = self._build_roadmap(findings_dicts)

        return {
            "scan": {
                "id":          scan.id,
                "target":      scan.target.value if scan.target else "unknown",
                "profile":     scan.scan_profile,
                "status":      scan.status,
                "started_at":  scan.started_at,
                "finished_at": scan.finished_at,
                "duration_str": scan.duration_str,
                "error_log":   scan.error_log,
            },
            "findings":          findings_dicts,
            "tool_results":      tool_dicts,
            "ai_conversations":  ai_dicts,
            "risk_score":        risk_score,
            "risk_level":        risk_level,
            "executive_summary": scan.executive_summary,
            "severity_counts":   severity_counts,
            "total_findings":    sum(severity_counts.values()),
            "include_raw":       include_raw,
            "generated_at":      datetime.utcnow().isoformat(),
            "version":           HEXMIND_VERSION,
            "roadmap":           roadmap,
        }

    # ── Renderers ──────────────────────────────────────────────

    def _render_markdown(self, ctx: dict) -> str:
        return self._jinja_env.get_template("report.md.j2").render(**ctx)

    def _render_html(self, ctx: dict) -> str:
        return self._jinja_env.get_template("report.html.j2").render(**ctx)

    def _render_pdf_html(self, ctx: dict) -> str:
        return self._jinja_env.get_template("report.pdf.j2").render(**ctx)

    def _render_json(self, ctx: dict) -> str:
        """Serialize context to formatted JSON."""
        def default_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if hasattr(obj, "__dict__"):
                return obj.__dict__
            return str(obj)

        return json.dumps(ctx, indent=2, default=default_serializer)

    # ── Helpers ────────────────────────────────────────────────

    def _calculate_risk_score(self, findings: list[dict]) -> tuple[int, str]:
        """
        Weighted risk score:
          critical=40, high=20, medium=8, low=2, info=0
        Capped at 100.
        """
        score = 0
        for f in findings:
            if not f.get("false_positive"):
                sev = f.get("severity", "info").lower()
                score += self.CVSS_WEIGHTS.get(sev, 0)
        score = min(100, score)
        return score, self._score_to_level(score)

    def _score_to_level(self, score: Optional[int]) -> str:
        if score is None:
            return "NONE"
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 10:
            return "LOW"
        return "NONE"

    def _build_roadmap(self, findings: list[dict]) -> list[dict]:
        """
        Build a deduplicated remediation roadmap.
        Groups findings by category, sorts by severity.
        Returns list of {priority, severity, title, remediation}.
        """
        seen_remediations: set[str] = set()
        roadmap: list[dict] = []

        for f in findings:
            if f.get("false_positive"):
                continue
            remediation = (f.get("remediation") or "").strip()
            if not remediation:
                continue
            key = remediation.lower()[:100]
            if key in seen_remediations:
                continue
            seen_remediations.add(key)
            roadmap.append({
                "severity":    f["severity"],
                "title":       f["title"],
                "remediation": remediation,
            })

        roadmap.sort(
            key=lambda x: self.SEVERITY_ORDER.get(x["severity"].lower(), 99)
        )
        for i, item in enumerate(roadmap, 1):
            item["priority"] = i

        return roadmap

    def _get_output_filename(self, scan_id: int, format: str) -> str:
        ts  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        ext = self.FORMAT_EXTENSIONS[format]
        return f"report_scan_{scan_id:04d}_{ts}{ext}"
