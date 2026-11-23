"""Compare a scan with an answer key (precision / recall):

    python -m scanner.evaluate [folder] [--ground-truth ground_truth.yml]

Defaults to target_app/ and ground_truth.yml. A finding detects a planted issue when the
rule is the same and, depending on the planted issue's scope:
    line     same file, reported line within LINE_TOLERANCE lines
    file     same file
    project  anywhere (absence checks)
Every finding that detects no planted issue is a false positive.
"""

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, model_validator

from scanner.config import PROJECT_ROOT
from scanner.detectors import covered_rules
from scanner.engine import scan_folder
from scanner.models import (
    ContractModel, Finding, Line, RelPath, Report, RuleId, Scope, Text, check_location, describe_location,
)
from scanner.rules_loader import load_rules

LINE_TOLERANCE = 3


class Planted(ContractModel):
    id: str = Field(pattern=r"^[A-Z]+-\d{2,}$")  # GT-01, JS-01 ...
    rule_id: RuleId
    scope: Scope = "line"
    file: RelPath | None = None
    line: Line | None = None
    anchor: str | None = Field(None, min_length=3)  # text that must be on `line` (or in `file`)
    clue: Literal["pattern", "structure", "absence", "config"]
    note: Text

    @model_validator(mode="after")
    def _location(self) -> "Planted":
        check_location(self.scope, self.file, self.line)
        if self.file is not None and self.anchor is None:
            raise ValueError("an entry with a file needs an anchor")
        return self

    @property
    def location(self) -> str:
        return describe_location(self.scope, self.file, self.line)


class RuleNote(ContractModel):
    rule_id: RuleId
    note: Text


class GroundTruth(ContractModel):
    target: Text
    planted: list[Planted] = Field(min_length=1)
    compliant: list[RuleNote] = []
    not_applicable: list[RuleNote] = []
    # Rules this answer key does not judge (e.g. a small fixture app built to test one
    # language). Findings for them are set aside, not counted as false positives.
    out_of_scope: list[RuleNote] = []
    must_not_appear_in_report: list[str] = []


def load_ground_truth(path: Path | str) -> GroundTruth:
    return GroundTruth.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def detects(finding: Finding, planted: Planted) -> bool:
    if finding.rule_id != planted.rule_id:
        return False
    if planted.scope == "project":
        return True
    if finding.file != planted.file:
        return False
    if planted.scope == "file":
        return True
    return finding.line is not None and abs(finding.line - planted.line) <= LINE_TOLERANCE


@dataclass
class Evaluation:
    detected: list[tuple[Planted, Finding]]
    missed: list[Planted]
    false_positives: list[Finding]
    findings: int
    covered: set[str]
    ignored: int = 0  # findings for out-of-scope rules

    @property
    def missed_with_detector(self) -> list[Planted]:
        return [p for p in self.missed if p.rule_id in self.covered]

    def ratios(self) -> dict[str, tuple[int, int]]:
        planted_covered = len(self.detected) + len(self.missed_with_detector)
        return {
            "Precision": (self.findings - len(self.false_positives), self.findings),
            "Recall": (len(self.detected), len(self.detected) + len(self.missed)),
            "Recall on rules with a detector": (len(self.detected), planted_covered),
        }


def evaluate(report: Report, truth: GroundTruth, covered: set[str]) -> Evaluation:
    out_of_scope = {n.rule_id for n in truth.out_of_scope}
    findings = [f for f in report.findings if f.rule_id not in out_of_scope]
    covered = covered - out_of_scope
    detected, missed, true_positive_ids = [], [], set()
    for planted in truth.planted:
        matching = [f for f in findings if detects(f, planted)]
        if matching:
            detected.append((planted, matching[0]))
            true_positive_ids.update(f.id for f in matching)
        else:
            missed.append(planted)
    false_positives = [f for f in findings if f.id not in true_positive_ids]
    return Evaluation(detected, missed, false_positives, len(findings), covered,
                      ignored=len(report.findings) - len(findings))


def _ratio(name: str, hit: int, total: int) -> str:
    return f"{name} {hit}/{total} ({hit / total:.0%})" if total else f"{name} n/a"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scanner.evaluate", description=__doc__.splitlines()[0])
    parser.add_argument("folder", nargs="?", type=Path, default=PROJECT_ROOT / "target_app")
    parser.add_argument("--ground-truth", type=Path, default=PROJECT_ROOT / "ground_truth.yml")
    args = parser.parse_args(argv)

    truth = load_ground_truth(args.ground_truth)
    catalogue = load_rules()
    report = scan_folder(args.folder, catalogue)
    covered = covered_rules()
    result = evaluate(report, truth, covered)
    compliant = {n.rule_id for n in truth.compliant}
    not_applicable = {n.rule_id for n in truth.not_applicable}

    print(f"Evaluating {report.target} against {args.ground_truth.name}: {len(truth.planted)} planted issues")
    print(f"Detectors cover {len(covered)} of {len(catalogue.rules)} rules: {', '.join(sorted(covered)) or 'none'}")
    if truth.out_of_scope:
        print(f"Judged here: {len(catalogue.rules) - len(truth.out_of_scope)} rules; "
              f"{len(truth.out_of_scope)} out of scope ({result.ignored} findings for them set aside)")
    print()
    found = {p.id: f for p, f in result.detected}
    for p in truth.planted:
        if p.id in found:
            status, extra = "found ", f"-> reported at {found[p.id].location}"
        else:
            status, extra = "MISSED" if p.rule_id in covered else "missed", "" if p.rule_id in covered else "(no detector yet)"
        print(f"  {status}  {p.id}  {p.rule_id}  {p.location}  {extra}")
    print(f"\nFalse positives: {len(result.false_positives) or 'none'}")
    for f in result.false_positives:
        why = " (decoy: compliant here)" if f.rule_id in compliant else (
            " (rule not applicable here)" if f.rule_id in not_applicable else "")
        print(f"  {f.rule_id}  {f.location}{why}  {f.evidence}")
    print(" | ".join(_ratio(name, *pair) for name, pair in result.ratios().items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
