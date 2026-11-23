"""Detectors: one module per category.

A detector reads a Project and returns Hits: rule_id + scope + file + line + evidence
+ pii + confidence. Never legal text, never severity: RuleCatalogue.to_finding() adds
those from rules/dpdp_rules.yml (and masks the evidence).

To add a detector:
  1. write `def my_check(project: Project) -> list[Hit]` in the category module below
  2. register it in DETECTORS with the rule ids it may report
  3. add a vulnerable and a fixed fixture under tests/fixtures/<rule id>/ plus a test
  4. tests/test_evaluate.py then requires it to find its planted issues in target_app
     with no false positives

Module            Rules it owns
consent.py        DPDP-NOT-001, DPDP-CON-001 to DPDP-CON-006   (CON-001 done)
logs.py           DPDP-SEC-001, DPDP-SEC-007                   (SEC-001 done, Python)
storage.py        DPDP-SEC-002, DPDP-SEC-003                   (SEC-002 done)
access.py         DPDP-SEC-005, DPDP-SEC-006                   (SEC-005 done, Flask/FastAPI)
retention.py      DPDP-RET-001 to DPDP-RET-003                 (RET-001 done)
thirdparty.py     DPDP-TP-001, DPDP-TP-002
children.py       DPDP-CH-001, DPDP-CH-002
rights.py         DPDP-RT-001 to DPDP-RT-003, DPDP-BR-001
hardcoded_secrets.py  DPDP-SEC-004                         (done)
config_files.py   DPDP-SEC-008 to DPDP-SEC-010
routes.py         shared helper: finds Flask / FastAPI routes with ast
source.py         shared helper: which files to read, Python syntax trees
schemas.py        shared helper: tables and columns from SQL and ORM models

Never name a module after a standard-library module (logging.py, secrets.py ...):
tests/test_naming.py enforces it.
"""

from collections.abc import Callable
from dataclasses import dataclass

from scanner.detectors import access, consent, hardcoded_secrets, logs, retention, storage
from scanner.ingest import Project
from scanner.models import Hit


@dataclass(frozen=True)
class Detector:
    name: str
    rules: tuple[str, ...]  # the only rule ids this detector may report
    run: Callable[[Project], list[Hit]]


DETECTORS: list[Detector] = [
    Detector("consent withdrawal", ("DPDP-CON-001",), consent.consent_withdrawal),
    Detector("hardcoded secrets", ("DPDP-SEC-004",), hardcoded_secrets.hardcoded_secrets),
    Detector("personal data in logs", ("DPDP-SEC-001",), logs.pii_in_logs),
    Detector("unauthenticated personal-data routes", ("DPDP-SEC-005",), access.unauthenticated_pii_routes),
    Detector("plaintext sensitive columns", ("DPDP-SEC-002",), storage.plaintext_sensitive_columns),
    Detector("personal data with no erase path", ("DPDP-RET-001",), retention.no_erase_path),
]


def covered_rules() -> set[str]:
    return {rule for detector in DETECTORS for rule in detector.rules}


def run_all(project: Project) -> list[Hit]:
    hits: list[Hit] = []
    for detector in DETECTORS:
        for hit in detector.run(project):
            if hit.rule_id not in detector.rules:
                raise ValueError(f"detector {detector.name!r} reported {hit.rule_id}, which it does not declare")
            hits.append(hit)
    return hits
