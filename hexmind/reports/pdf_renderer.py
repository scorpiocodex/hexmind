"""WeasyPrint PDF renderer wrapper for converting HTML reports to PDF."""

from __future__ import annotations

from pathlib import Path


class PDFRenderer:
    """Converts an HTML string to a PDF file using WeasyPrint."""

    def render(self, html_content: str, output_path: Path) -> bool:
        """Render html_content as a PDF at output_path; return True on success."""
        raise NotImplementedError("TODO: implement")

    def is_available(self) -> bool:
        """Return True if WeasyPrint and its system dependencies are usable."""
        raise NotImplementedError("TODO: implement")
