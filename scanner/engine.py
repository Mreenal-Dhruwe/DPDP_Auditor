"""The scan pipeline as one function, shared by the CLI, the backend and the evaluator:

    ingest -> detectors (Hits) -> rule engine + masking + context (Findings) -> Report
"""

from pathlib import Path

from scanner.detectors import run_all
from scanner.ingest import Project
from scanner.models import Report
from scanner.rules_loader import RuleCatalogue, load_rules


def scan_folder(folder: Path | str, catalogue: RuleCatalogue | None = None,
                max_files: int | None = None) -> Report:
    """Scan a local folder (read only) and return the validated Report."""
    catalogue = catalogue or load_rules()
    project = Project.from_folder(folder, max_files=max_files)
    known_files = set(project.files)
    sources: dict[str, list[str]] = {}

    def source_lines(rel: str | None) -> list[str] | None:
        if rel is None or rel not in known_files:
            return None
        if rel not in sources:
            sources[rel] = project.read_text(rel).splitlines()
        return sources[rel]

    findings = [catalogue.to_finding(hit, source_lines(hit.file)) for hit in run_all(project)]
    return Report(
        target=project.name,
        rules_version=catalogue.meta.version,
        disclaimer=catalogue.meta.disclaimer,
        files_scanned=len(project.files),
        findings=findings,
    )
