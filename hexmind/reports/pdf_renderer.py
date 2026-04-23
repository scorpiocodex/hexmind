"""WeasyPrint PDF renderer wrapper for converting HTML reports to PDF."""

from __future__ import annotations

from pathlib import Path

from hexmind.ui.console import print_error, print_warning


class PDFRenderer:
    """
    Wraps weasyprint for HTML → PDF conversion.
    Handles ImportError gracefully — weasyprint has heavy system deps.
    """

    def is_available(self) -> bool:
        """Return True if weasyprint can be imported."""
        try:
            import weasyprint  # noqa: F401
            return True
        except ImportError:
            return False

    def render(self, html_content: str, output_path: Path) -> bool:
        """
        Render HTML string to PDF at output_path.

        Returns True on success, False on failure.

        If weasyprint is not installed, print a helpful message and
        return False.
        If weasyprint is installed but rendering fails (e.g. missing
        system font libs), catch the exception, print the error,
        and return False.
        """
        try:
            import weasyprint
        except ImportError:
            print_warning(
                "weasyprint is not installed. "
                "Install it with: pip install weasyprint\n"
                "  Note: weasyprint requires system libraries. "
                "See https://doc.courtbouillon.org/weasyprint/stable/"
                "first_steps.html#installation"
            )
            return False

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            html = weasyprint.HTML(string=html_content)
            html.write_pdf(str(output_path))
            return True
        except Exception as e:
            print_error(f"PDF rendering failed: {e}")
            return False
