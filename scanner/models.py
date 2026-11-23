"""The Finding contract, shared by the engine, the reports, the backend and the frontend.

Frozen in hours 0-4. Change it only as a team decision, and then update CLAUDE.md and
regenerate the TypeScript types (python -m scripts.make_ts_types) and the mock report
(python -m scripts.make_mock_report); tests fail while either is out of date.

How a finding is made:
    detector     -> Hit       rule_id, file, line, evidence, pii, confidence (no legal text)
    rule engine  -> Finding   + title, category, law, penalty, severity, severity_reason, fix,
                              looked up by rule_id in rules/dpdp_rules.yml
                              (RuleCatalogue.to_finding in scanner/rules_loader.py)
    cli/backend  -> Report    all findings + summary counts; report.json is the master format
"""

import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Literal, get_args

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from scanner import __version__

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
# What a finding is about:
#   line    one place in the code              -> file and line required
#   file    a whole file ("no USER in Dockerfile") -> file required, no line
#   project something missing everywhere       -> file/line optional: related code, if any
#           (e.g. the consent-grant route when no withdraw route exists)
Scope = Literal["line", "file", "project"]
SEVERITIES: tuple[str, ...] = get_args(Severity)  # most severe first

DISCLAIMER = "Legal mapping is indicative, not legal advice."
EVIDENCE_MAX_CHARS = 300
CONTEXT_RADIUS = 3  # source lines shown either side of the finding
CONTEXT_LINE_MAX_CHARS = 200

# Reusable field types. The patterns match the references used in rules/dpdp_rules.yml.
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
RuleId = Annotated[str, StringConstraints(pattern=r"^DPDP-[A-Z]+-\d{3}$")]  # DPDP-SEC-001
ActRef = Annotated[str, StringConstraints(pattern=r"^s\.\d+(\([0-9a-z]+\))*$")]  # s.8(5)
RulesRef = Annotated[str, StringConstraints(pattern=r"^Rule \d+(\([0-9a-z]+\))*$")]  # Rule 6(1)(a)
Line = Annotated[int, Field(ge=1)]


def _relative_posix_path(value: str) -> str:
    """'src\\app.py' -> 'src/app.py': forward slashes, relative to the scanned folder.

    Absolute paths and '..' are refused, so a report can never reveal server folders such
    as the temp folder an upload was unpacked into.
    """
    text = value.strip().replace("\\", "/")
    path = PurePosixPath(text)
    if (
        not text
        or str(path) == "."
        or path.is_absolute()
        or PureWindowsPath(text).drive
        or ".." in path.parts
    ):
        raise ValueError("must be a path relative to the scanned folder (no absolute paths, no '..')")
    return str(path)


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _one_line(value: str) -> str:
    """Evidence is one trimmed line."""
    text = " ".join(value.split())
    if not text:
        raise ValueError("evidence must not be empty")
    return text


def _capped_evidence(value: str) -> str:
    """Cut very long lines (minified code). Runs on Finding only, i.e. after masking, so a
    cut can never leave half a secret that the masking patterns no longer recognise."""
    return _cut(value, EVIDENCE_MAX_CHARS)


def _context_line(value: str) -> str:
    """One source line for the code viewer: indentation kept, cut at 200 characters."""
    return _cut(value.replace("\r", "").replace("\n", " ").rstrip(), CONTEXT_LINE_MAX_CHARS)


def _labels(values: list[str]) -> list[str]:
    """PII labels in lower case, without repeats, in first-seen order."""
    labels: list[str] = []
    for value in values:
        label = value.strip().lower()
        if label and label not in labels:
            labels.append(label)
    return labels


RelPath = Annotated[str, AfterValidator(_relative_posix_path)]
Evidence = Annotated[str, AfterValidator(_one_line)]  # Hit: not cut yet (masking comes first)
CappedEvidence = Annotated[str, AfterValidator(_one_line), AfterValidator(_capped_evidence)]
ContextLine = Annotated[str, AfterValidator(_context_line)]
PiiLabels = Annotated[list[str], AfterValidator(_labels)]


def check_location(scope: str, file: str | None, line: int | None) -> None:
    """The scope decides which of file / line must be present (see Scope above)."""
    if scope == "line" and (file is None or line is None):
        raise ValueError("scope 'line' needs both file and line")
    if scope == "file" and (file is None or line is not None):
        raise ValueError("scope 'file' needs a file and no line")
    if line is not None and file is None:
        raise ValueError("a line needs a file")


def describe_location(scope: str, file: str | None, line: int | None) -> str:
    """Human-readable location: 'app.py:12', 'Dockerfile', 'project-wide (see app.py:125)'."""
    where = f"{file}:{line}" if line is not None else file
    if scope == "project":
        return f"project-wide (see {where})" if where else "project-wide"
    return where or ""


class ContractModel(BaseModel):
    """Base for every contract model: unknown keys are errors, so typos fail loudly.
    Fields with defaults are always present in the JSON output, so the generated
    TypeScript types mark them as required."""

    model_config = ConfigDict(extra="forbid", json_schema_serialization_defaults_required=True)


class Law(ContractModel):
    """Where an obligation comes from. Same shape in the rules YAML and in a Finding."""

    act: list[ActRef] = []
    rules: list[RulesRef] = []
    requirement: Text

    @model_validator(mode="after")
    def _has_a_reference(self) -> "Law":
        if not self.act and not self.rules:
            raise ValueError("needs at least one Act section or Rule reference")
        return self


class PenaltyCap(ContractModel):
    """One entry of the penalty Schedule to the Act (s.33)."""

    schedule_item: int = Field(ge=1)
    provision: Text
    cap: Annotated[str, StringConstraints(pattern=r"^Rs [\d,]+ crore$")]  # "Rs 250 crore"

    @property
    def crore(self) -> int:
        return int(self.cap.split()[1].replace(",", ""))


class Hit(ContractModel):
    """What a detector returns: where the problem is and what it saw. No legal meaning."""

    rule_id: RuleId
    scope: Scope = "line"
    file: RelPath | None = None
    line: Line | None = None
    evidence: Evidence  # secrets the detector knows about must already be masked
    pii: PiiLabels = []
    confidence: Confidence

    @model_validator(mode="after")
    def _location_fits_scope(self) -> "Hit":
        check_location(self.scope, self.file, self.line)
        return self


class Context(ContractModel):
    """Masked source lines around a finding, for the code viewer. Needed because uploads
    are deleted after the scan, so the frontend cannot fetch the file later."""

    start_line: Line  # line number of lines[0]
    lines: list[ContextLine] = Field(min_length=1, max_length=2 * CONTEXT_RADIUS + 1)


class Finding(ContractModel):
    """A Hit plus the legal meaning of its rule: one entry in report.json."""

    id: str = ""  # filled in below: stable for the same rule and location
    rule_id: RuleId
    title: Text
    category: Text
    scope: Scope = "line"
    file: RelPath | None = None
    line: Line | None = None
    evidence: CappedEvidence
    context: Context | None = None  # only when there is a line to show it around
    pii: PiiLabels = []
    confidence: Confidence
    law: Law
    penalty: PenaltyCap
    severity: Severity
    severity_reason: Text
    fix: Text

    @model_validator(mode="after")
    def _location_and_id(self) -> "Finding":
        check_location(self.scope, self.file, self.line)
        if self.context is not None:
            first = self.context.start_line
            if self.line is None or not first <= self.line < first + len(self.context.lines):
                raise ValueError("context must surround the finding's line")
        if not self.id:
            key = f"{self.rule_id}|{self.file or ''}|{self.line or ''}"
            self.id = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        return self

    @property
    def location(self) -> str:
        return describe_location(self.scope, self.file, self.line)


class Summary(ContractModel):
    """Counts for the dashboard tiles and charts. Always recomputed from the findings."""

    total: int = 0
    by_severity: dict[Severity, int] = Field(default_factory=lambda: dict.fromkeys(SEVERITIES, 0))
    by_category: dict[str, int] = {}
    by_provision: dict[str, int] = {}  # Act sections and Rules, e.g. "s.8(5)", "Rule 6(1)(a)"

    @classmethod
    def of(cls, findings: list[Finding]) -> "Summary":
        severities = Counter(f.severity for f in findings)
        provisions = Counter(ref for f in findings for ref in f.law.act + f.law.rules)
        return cls(
            total=len(findings),
            by_severity={s: severities[s] for s in SEVERITIES},
            by_category=dict(Counter(f.category for f in findings).most_common()),
            by_provision=dict(provisions.most_common()),
        )


class Coverage(ContractModel):
    """What the scan looked at, so a reader knows what "no findings" means."""

    files_by_kind: dict[str, int] = {}  # python, javascript, typescript, templates, sql, config, other
    rules_checked: list[RuleId] = []  # rules with an automated detector
    rules_not_checked: list[RuleId] = []  # rules that need a manual review


class Report(ContractModel):
    """The master output format (report.json). HTML, PDF and SARIF are made from it."""

    tool: str = "DPDP Compliance Auditor"
    tool_version: str = __version__
    rules_version: Text
    target: Text  # project name shown to the user - never a server path
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    files_scanned: int = Field(0, ge=0)
    coverage: Coverage | None = None
    disclaimer: Text = DISCLAIMER
    summary: Summary = Field(default_factory=Summary)  # recomputed; any input is ignored
    findings: list[Finding] = []

    @field_validator("target")
    @classmethod
    def _not_a_server_path(cls, value: str) -> str:
        if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
            raise ValueError("must be a project name, not an absolute path")
        return value

    @field_validator("disclaimer")
    @classmethod
    def _keeps_the_disclaimer(cls, value: str) -> str:
        if DISCLAIMER not in value:
            raise ValueError(f"must contain {DISCLAIMER!r}")
        return value

    @model_validator(mode="after")
    def _sort_dedupe_count(self) -> "Report":
        """Same input, same report: drop repeats (same id), most severe first, then count."""
        unique: dict[str, Finding] = {}
        for finding in self.findings:
            unique.setdefault(finding.id, finding)
        self.findings = sorted(
            unique.values(),
            key=lambda f: (SEVERITIES.index(f.severity), f.file or "", f.line or 0, f.rule_id),
        )
        self.summary = Summary.of(self.findings)
        return self
