"""The scan pipeline as one function, shared by the CLI, the backend and the evaluator:

    ingest -> detectors (Hits) -> rule engine + masking + context (Findings) -> Report
"""

from pathlib import Path

from scanner.detectors import covered_rules, run_all
from scanner.detectors.source import is_config_file, name_of, suffix_of
from scanner.ingest import Project
from scanner.models import Coverage, Report
from scanner.rules_loader import RuleCatalogue, load_rules

FILE_KINDS = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".sql": "sql",
    ".html": "templates", ".htm": "templates", ".jinja": "templates", ".jinja2": "templates", ".j2": "templates",
    ".vue": "templates", ".svelte": "templates", ".ejs": "templates", ".hbs": "templates",
    ".json": "config", ".tf": "config",
}


def file_kind(rel: str) -> str:
    kind = FILE_KINDS.get(suffix_of(rel))
    if kind:
        return kind
    return "config" if is_config_file(rel) or name_of(rel).startswith("dockerfile") else "other"


def coverage_of(project: Project, catalogue: RuleCatalogue) -> Coverage:
    kinds: dict[str, int] = {}
    for rel in project.files:
        kinds[file_kind(rel)] = kinds.get(file_kind(rel), 0) + 1
    checked = covered_rules()
    return Coverage(
        files_by_kind=dict(sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0]))),
        rules_checked=[r.id for r in catalogue.rules if r.id in checked],
        rules_not_checked=[r.id for r in catalogue.rules if r.id not in checked],
    )


def scan_folder(folder: Path | str, catalogue: RuleCatalogue | None = None,
                max_files: int | None = None, target: str | None = None) -> Report:
    """Scan a local folder (read only) and return the validated Report. `target` is the
    name shown in the report (default: the folder name; the backend passes the upload's
    name, since uploads are unpacked into temp folders)."""
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
        target=target or project.name,
        rules_version=catalogue.meta.version,
        disclaimer=catalogue.meta.disclaimer,
        files_scanned=len(project.files),
        coverage=coverage_of(project, catalogue),
        findings=findings,
    )
