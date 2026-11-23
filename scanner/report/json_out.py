"""report.json - the master output. Every other format is made from the same Report."""

from pathlib import Path

from scanner.models import Report


def write_json(report: Report, out_dir: Path | str) -> Path:
    """Write <out_dir>/report.json (UTF-8, indented) and return its path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path
