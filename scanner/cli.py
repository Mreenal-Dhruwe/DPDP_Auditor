"""Command-line entry point, and the demo backup:

    python -m scanner.cli <folder> --out report/

Loads settings and the rule catalogue, scans the folder (scanner/engine.py) and writes the
reports: report.json (the master format), report.html and report.sarif by default;
--formats picks which.
"""

import argparse
import sys
from pathlib import Path

from scanner import __version__
from scanner.config import get_settings
from scanner.detectors import DETECTORS, covered_rules
from scanner.engine import scan_folder
from scanner.ingest import IngestError
from scanner.models import SEVERITIES
from scanner.report.html_out import write_html
from scanner.report.json_out import write_json
from scanner.report.sarif_out import write_sarif
from scanner.rules_loader import RulesError, load_rules


# format -> writer(report, out_dir, catalogue) -> path. report.json is the master format.
WRITERS = {
    "json": lambda report, out, catalogue: write_json(report, out),
    "html": write_html,
    "sarif": write_sarif,
}


def main(argv: list[str] | None = None) -> int:
    # Scanned code can contain any characters (Hindi text, emoji). Printing them to a
    # Windows console must never crash the scan, so unprintable characters become '?'.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog="python -m scanner.cli",
        description="Scan a project for personal-data handling issues under India's DPDP Act, 2023.",
    )
    parser.add_argument("path", type=Path, help="folder to scan")
    parser.add_argument("--out", type=Path, default=settings.report_dir,
                        help="output folder for the reports (default: REPORT_DIR)")
    parser.add_argument("--formats", default=",".join(WRITERS),
                        help=f"comma-separated report formats to write (default: {','.join(WRITERS)})")
    args = parser.parse_args(argv)
    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    unknown = [f for f in formats if f not in WRITERS]
    if unknown or not formats:
        parser.error(f"unknown format(s) {unknown}; choose from {', '.join(WRITERS)}")

    try:
        catalogue = load_rules(settings.rules_file)
        report = scan_folder(args.path, catalogue, max_files=settings.max_files)
    except (RulesError, IngestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    paths = [WRITERS[f](report, args.out, catalogue) for f in formats]

    detectors, covered = len(DETECTORS), len(covered_rules())
    print(f"DPDP Compliance Auditor {__version__} | rules v{catalogue.meta.version} "
          f"({len(catalogue.rules)} rules) | {detectors} detector{'s' * (detectors != 1)} "
          f"covering {covered} rule{'s' * (covered != 1)}")
    print(f"Scanned {report.target}: {report.files_scanned} files")
    for f in report.findings:
        print(f"  [{f.severity.upper():<8}] {f.rule_id}  {f.location}  {f.title}")
        print(f"             {f.evidence}")
    counts = " | ".join(f"{s} {report.summary.by_severity[s]}" for s in SEVERITIES)
    print(f"Findings: {report.summary.total}  ({counts})")
    for path in paths:
        print(f"Report: {path}")
    print(report.disclaimer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
