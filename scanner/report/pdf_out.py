"""PDF report: the HTML report (html_out.py) rendered with WeasyPrint.

WeasyPrint needs the Pango / GObject system libraries. They are one apt-get away on Linux
(the Docker image: libpango-1.0-0 libpangoft2-1.0-0), but usually missing on Windows and
macOS. When they are missing, render_pdf raises PdfUnavailable and callers fall back to the
HTML report (the backend answers 501).
"""

from pathlib import Path

from scanner.models import Report
from scanner.report.html_out import render_html
from scanner.rules_loader import RuleCatalogue


class PdfUnavailable(Exception):
    """WeasyPrint or its system libraries are not installed."""


def render_pdf(report: Report, catalogue: RuleCatalogue | None = None) -> bytes:
    try:
        from weasyprint import HTML  # imported here: loading it fails without Pango
    except (ImportError, OSError) as exc:
        raise PdfUnavailable(
            "PDF export needs WeasyPrint's system libraries (Pango); use the HTML report, "
            "or run the Docker image where they are installed"
        ) from exc
    return HTML(string=render_html(report, catalogue)).write_pdf()


def write_pdf(report: Report, out_dir: Path | str, catalogue: RuleCatalogue | None = None) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.pdf"
    path.write_bytes(render_pdf(report, catalogue))
    return path
