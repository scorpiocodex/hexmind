"""Report generation orchestrator: renders Jinja2 templates to md/html/pdf/json."""

from __future__ import annotations

from pathlib import Path


class ReportExporter:
    """Coordinates report rendering for a given scan across all supported formats."""

    def __init__(self, db_repos: dict, output_dir: Path) -> None:
        """Initialize with repository references and the output directory path."""
        self.db_repos = db_repos
        self.output_dir = output_dir

    async def export(
        self,
        scan_id: int,
        format: str,
        output_path: Path | None = None,
        include_raw: bool = True,
    ) -> Path:
        """Render the report for scan_id in the given format and return the output path."""
        raise NotImplementedError("TODO: implement")

    def _build_context(self, scan_id: int, include_raw: bool) -> dict:
        """Query the DB and assemble the Jinja2 template context dict for a scan."""
        raise NotImplementedError("TODO: implement")

    def _calculate_risk_score(
        self, findings: list
    ) -> tuple[int, str]:
        """Compute a 0-100 risk score and severity label from a list of findings."""
        raise NotImplementedError("TODO: implement")
