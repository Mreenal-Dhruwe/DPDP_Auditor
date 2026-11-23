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
consent.py        DPDP-NOT-001, DPDP-CON-001 to DPDP-CON-006   (NOT-001, CON-001 to CON-004 done)
logs.py           DPDP-SEC-001, DPDP-SEC-007                   (both done; Python + JS)
storage.py        DPDP-SEC-002, DPDP-SEC-003                   (SEC-002 done)
access.py         DPDP-SEC-005, DPDP-SEC-006                   (both done; Python + Express)
retention.py      DPDP-RET-001 to DPDP-RET-003                 (RET-001 done)
thirdparty.py     DPDP-TP-001, DPDP-TP-002
children.py       DPDP-CH-001, DPDP-CH-002                     (both done)
rights.py         DPDP-RT-001 to DPDP-RT-003, DPDP-BR-001        (all done)
hardcoded_secrets.py  DPDP-SEC-004                         (done)
config_files.py   DPDP-SEC-008 to DPDP-SEC-010                 (SEC-008, SEC-010 done)
routes.py         shared helper: finds Flask / FastAPI routes with ast
source.py         shared helper: which files to read, Python syntax trees
schemas.py        shared helper: tables and columns from SQL and ORM models

Never name a module after a standard-library module (logging.py, secrets.py ...):
tests/test_naming.py enforces it.
"""

from collections.abc import Callable
from dataclasses import dataclass

from scanner.detectors import (
    access, children, config_files, consent, hardcoded_secrets, logs, retention, rights, storage, thirdparty,
)
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
    Detector("weak password hashing", ("DPDP-SEC-003",), storage.weak_password_hashing),
    Detector("personal data sent to third-party SDKs", ("DPDP-TP-001",), thirdparty.pii_to_third_parties),
    Detector("pre-ticked consent", ("DPDP-CON-002",), consent.pre_ticked_consent),
    Detector("insecure infrastructure config", ("DPDP-SEC-008",), config_files.insecure_infrastructure),
    Detector("immediate hard delete", ("DPDP-RET-002",), retention.immediate_hard_delete),
    Detector("child data without parental consent", ("DPDP-CH-001",), children.no_parental_consent),
    Detector("tracking of children", ("DPDP-CH-002",), children.tracking_children),
    Detector("excessive data in API responses", ("DPDP-SEC-006",), access.excessive_response_data),
    Detector("personal data used without consent", ("DPDP-CON-004",), consent.unconsented_use),
    Detector("no evidence of consent", ("DPDP-CON-003",), consent.consent_evidence),
    Detector("no access to own data", ("DPDP-RT-001",), rights.no_access_route),
    Detector("no correction or erasure", ("DPDP-RT-002",), rights.no_correction_or_erasure),
    Detector("no grievance channel", ("DPDP-RT-003",), rights.no_grievance_channel),
    Detector("personal-data reads with no audit log", ("DPDP-SEC-007",), logs.unaudited_reads),
    Detector("log retention under a year", ("DPDP-SEC-010",), config_files.short_log_retention),
    Detector("no notice before collection", ("DPDP-NOT-001",), consent.missing_notice),
    Detector("no breach notification", ("DPDP-BR-001",), rights.no_breach_process),
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
