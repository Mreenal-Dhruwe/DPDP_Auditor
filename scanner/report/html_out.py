"""HTML report, rendered with Jinja2 from a Report (report.json is the master format).

One self-contained file: inline CSS, no JavaScript, no external fonts, so it opens offline
(the CLI demo backup) and prints cleanly (and can feed WeasyPrint for the PDF). Autoescaping
is on: code excerpts from scanned projects can never inject HTML into the report.
"""

from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.models import SEVERITIES, Report
from scanner.rules_loader import RuleCatalogue, load_rules

_ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(report: Report, catalogue: RuleCatalogue | None = None) -> str:
    catalogue = catalogue or load_rules()
    groups = [(severity, [f for f in report.findings if f.severity == severity]) for severity in SEVERITIES]
    return _ENV.get_template("report.html.j2").render(
        report=report,
        groups=groups,
        severities=SEVERITIES,
        rules={rule.id: rule for rule in catalogue.rules},
        per_rule=Counter(f.rule_id for f in report.findings),
        sources=catalogue.meta.sources,
    )


def write_html(report: Report, out_dir: Path | str, catalogue: RuleCatalogue | None = None) -> Path:
    """Write <out_dir>/report.html and return its path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.html"
    path.write_text(render_html(report, catalogue), encoding="utf-8")
    return path
