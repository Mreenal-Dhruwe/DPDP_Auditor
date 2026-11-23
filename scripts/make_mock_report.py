"""Write frontend/src/mock/report.json from the real models:

    python -m scripts.make_mock_report

The mock is what the scanner should report for target_app once every planted issue in
ground_truth.yml is detected, plus three illustrative findings (marked below) so that
every severity and every scope appears - including a project-wide finding with no file.
Everything goes through RuleCatalogue.to_finding(), so the mock always matches the
contract and its evidence is masked exactly like a real report.

tests/test_mock_report.py fails when the file is out of date: re-run this script after
changing the contract, the rules, target_app or ground_truth.yml.
"""

from datetime import datetime, timezone

from scanner.config import PROJECT_ROOT
from scanner.engine import coverage_of
from scanner.evaluate import Planted, load_ground_truth
from scanner.ingest import Project
from scanner.models import Hit, Report
from scanner.rules_loader import load_rules

OUT = PROJECT_ROOT / "frontend" / "src" / "mock" / "report.json"
TARGET_APP = PROJECT_ROOT / "target_app"
GENERATED_AT = datetime(2026, 11, 23, 9, 0, tzinfo=timezone.utc)  # fixed, so the file only changes when content does

PII = {
    "GT-01": ["password"],
    "GT-02": ["dob"],
    "GT-03": ["email", "phone", "aadhaar"],
    "GT-04": ["email", "phone"],
    "GT-07": ["full_name", "email", "phone"],
    "GT-09": ["aadhaar"],
}
CONFIDENCE = {"line": "high", "file": "high", "project": "medium"}

# Illustrative only - target_app has no docker-compose.yml or purge job, and does have a
# breach module.
EXTRAS = [
    Hit(rule_id="DPDP-TP-002", file="docker-compose.yml", line=14,
        evidence="AWS_REGION: us-east-1", confidence="high"),  # info
    Hit(rule_id="DPDP-RET-003", scope="file", file="jobs/purge_inactive.py", confidence="low",
        evidence="purge_inactive_users() erases dormant accounts with no notice to the user 48 hours before"),  # low
    Hit(rule_id="DPDP-BR-001", scope="project", confidence="low",
        evidence="No code path notifies affected users or prepares a report for the Data Protection Board"),
]


def planted_hit(planted: Planted, project: Project) -> Hit:
    if planted.scope == "line":
        evidence = project.read_text(planted.file).splitlines()[planted.line - 1]
    else:
        evidence = planted.note
    return Hit(rule_id=planted.rule_id, scope=planted.scope, file=planted.file, line=planted.line,
               evidence=evidence, pii=PII.get(planted.id, []), confidence=CONFIDENCE[planted.scope])


def build() -> Report:
    catalogue = load_rules()
    truth = load_ground_truth(PROJECT_ROOT / "ground_truth.yml")
    project = Project.from_folder(TARGET_APP)
    hits = [planted_hit(p, project) for p in truth.planted] + EXTRAS

    def source_lines(rel):  # EXTRAS point at a file target_app does not have: no context
        return project.read_text(rel).splitlines() if rel in project.files else None

    return Report(
        target=project.name,
        rules_version=catalogue.meta.version,
        disclaimer=catalogue.meta.disclaimer,
        generated_at=GENERATED_AT,
        files_scanned=len(project.files),
        coverage=coverage_of(project, catalogue),
        findings=[catalogue.to_finding(hit, source_lines(hit.file)) for hit in hits],
    )


def render() -> str:
    return build().model_dump_json(indent=2) + "\n"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(), encoding="utf-8", newline="\n")
    report = Report.model_validate_json(OUT.read_text(encoding="utf-8"))
    counts = ", ".join(f"{s} {n}" for s, n in report.summary.by_severity.items())
    scopes = sorted({f.scope for f in report.findings})
    print(f"Wrote {OUT.relative_to(PROJECT_ROOT).as_posix()}: {report.summary.total} findings ({counts}); scopes {scopes}")


if __name__ == "__main__":
    main()
