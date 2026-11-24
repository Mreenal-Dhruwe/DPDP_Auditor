"""Load and validate rules/dpdp_rules.yml - the single source of truth for legal meaning.

    from scanner.rules_loader import load_rules
    catalogue = load_rules()                  # file from RULES_FILE (scanner/config.py)
    rule = catalogue.get("DPDP-SEC-001")
    finding = catalogue.to_finding(hit)       # rule engine step: Hit -> Finding

Check the file from the command line (exit code 1 if anything is wrong):
    python -m scanner.rules_loader [path/to/rules.yml]

All problems are reported together, each naming the rule and the field, for example
    rules[7] DPDP-SEC-001 -> severity: Input should be 'critical', 'high', ...
"""

import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, ValidationError, model_validator

from scanner.config import PROJECT_ROOT, get_settings
from scanner.masking import mask_evidence, secret_values
from scanner.pii import default_matcher
from scanner.models import (
    CONTEXT_RADIUS,
    DISCLAIMER,
    SEVERITIES,
    Context,
    ContractModel,
    Finding,
    Hit,
    Law,
    PenaltyCap,
    RuleId,
    Severity,
    Text,
)

Target = Literal["frontend", "api", "backend", "schema", "config", "iac", "mobile"]
Sensitivity = Literal["high", "medium", "low"]

# From severity_model in the YAML: "critical" needs a penalty cap of at least Rs 200 crore.
CRITICAL_MIN_CRORE = 200


class RulesError(Exception):
    """The rules file is missing, unreadable or invalid. The message lists every problem."""


class Meta(ContractModel):
    version: Text
    sources: dict[str, Text]
    commencement: dict[str, Text]
    disclaimer: Text


class Identifier(ContractModel):
    """A personal-data value pattern, e.g. Aadhaar or PAN."""

    name: Text
    pattern: Text
    validated_by: Literal["verhoeff"] | None = Field(None, alias="validate")
    sensitivity: Sensitivity


class FieldNames(ContractModel):
    high: list[Text]
    medium: list[Text]
    child_markers: list[Text]


class PersonalData(ContractModel):
    identifiers: list[Identifier] = Field(min_length=1)
    field_names: FieldNames


class Rule(ContractModel):
    id: RuleId
    category: Text
    title: Text
    detects: list[Text] = Field(min_length=1)
    targets: list[Target] = Field(min_length=1)
    law: Law
    penalty: Text  # key into penalty_caps, e.g. "P1"
    severity: Severity
    severity_reason: Text
    fix: Text


_last_file: tuple[list[str], set[str]] | None = None


def _file_secrets(source_lines: list[str]) -> set[str]:
    """Secret values found anywhere in this file; the last file is cached (findings of one file arrive together)."""
    global _last_file
    if _last_file is None or _last_file[0] is not source_lines:
        _last_file = (source_lines, secret_values(source_lines))
    return _last_file[1]


class RuleCatalogue(ContractModel):
    """The whole rules file, validated. Get one with load_rules()."""

    meta: Meta
    penalty_caps: dict[str, PenaltyCap]
    severity_model: dict[Severity, Text]
    personal_data: PersonalData
    rules: list[Rule] = Field(min_length=1)

    @model_validator(mode="after")
    def _cross_checks(self) -> "RuleCatalogue":
        """Checks that look at more than one part of the file. Collects every problem."""
        problems = []
        for rule_id, count in Counter(r.id for r in self.rules).items():
            if count > 1:
                problems.append(f"duplicate rule id {rule_id}")
        for rule in self.rules:
            cap = self.penalty_caps.get(rule.penalty)
            if cap is None:
                known = ", ".join(self.penalty_caps)
                problems.append(f"{rule.id}: penalty {rule.penalty!r} is not one of penalty_caps ({known})")
            elif rule.severity == "critical" and cap.crore < CRITICAL_MIN_CRORE:
                problems.append(
                    f"{rule.id}: 'critical' needs a penalty cap of at least Rs {CRITICAL_MIN_CRORE} crore,"
                    f" but {rule.penalty} is {cap.cap}"
                )
        missing = [s for s in SEVERITIES if s not in self.severity_model]
        if missing:
            problems.append(f"severity_model does not define: {', '.join(missing)}")
        for name, count in Counter(i.name for i in self.personal_data.identifiers).items():
            if count > 1:
                problems.append(f"duplicate identifier name {name}")
        for ident in self.personal_data.identifiers:
            try:
                re.compile(ident.pattern)
            except re.error as exc:
                problems.append(f"identifier {ident.name}: pattern is not a valid regex ({exc})")
        if DISCLAIMER not in self.meta.disclaimer:
            problems.append(f"meta.disclaimer must contain {DISCLAIMER!r}")
        if problems:
            raise ValueError("\n".join(problems))
        return self

    def get(self, rule_id: str) -> Rule:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        raise RulesError(f"unknown rule id {rule_id!r}: add it to the rules file first")

    def to_finding(self, hit: Hit, source_lines: list[str] | None = None) -> Finding:
        """Rule engine step: attach the legal meaning of hit.rule_id to a detector hit.

        source_lines (the lines of hit.file) are used to build the context shown in the
        code viewer. Evidence and every context line pass through the masking safety net
        here, so no code path can put unmasked secrets or personal data into a report.
        """
        rule = self.get(hit.rule_id)
        context = None
        if source_lines and hit.line is not None and hit.line <= len(source_lines):
            start = max(1, hit.line - CONTEXT_RADIUS)
            end = min(len(source_lines), hit.line + CONTEXT_RADIUS)
            known = _file_secrets(source_lines)
            masked = [mask_evidence(source_lines[n - 1], self.personal_data.identifiers, known, default_matcher()) for n in range(start, end + 1)]
            context = Context(start_line=start, lines=masked)
        severity, severity_reason = rule.severity, rule.severity_reason
        if hit.severity and SEVERITIES.index(hit.severity) > SEVERITIES.index(rule.severity) and hit.severity_note:
            severity = hit.severity
            severity_reason = f"{hit.severity_note} (rule default: {rule.severity}) {rule.severity_reason}"
        return Finding(
            context=context,
            rule_id=rule.id,
            title=rule.title,
            category=rule.category,
            scope=hit.scope,
            file=hit.file,
            line=hit.line,
            evidence=mask_evidence(hit.evidence, self.personal_data.identifiers, _file_secrets(source_lines or []), default_matcher()),
            pii=hit.pii,
            confidence=hit.confidence,
            law=rule.law.model_copy(deep=True),  # copies, so a finding can't change the rule
            penalty=self.penalty_caps[rule.penalty].model_copy(),
            severity=severity,
            severity_reason=severity_reason,
            fix=rule.fix,
        )


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses duplicate keys (plain PyYAML silently keeps the last)."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    "while reading a mapping", node.start_mark,
                    f"found duplicate key {key!r}", key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_rules(path: Path | str | None = None) -> RuleCatalogue:
    """Read and validate the rules file (default: RULES_FILE from settings)."""
    path = Path(path) if path is not None else get_settings().rules_file
    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.load(fh, Loader=_UniqueKeyLoader)
    except OSError as exc:
        raise RulesError(f"cannot read rules file {path}: {exc.strerror or exc}") from None
    except yaml.YAMLError as exc:
        raise RulesError(f"{_display(path)} is not valid YAML:\n{exc}") from None
    return parse_rules(data, source=_display(path))


def parse_rules(data: Any, source: str = "rules file") -> RuleCatalogue:
    """Validate already-parsed YAML data. Raises RulesError listing every problem."""
    if not isinstance(data, dict):
        raise RulesError(f"{source}: expected a mapping (meta, penalty_caps, rules, ...) at the top level")
    try:
        return RuleCatalogue.model_validate(data)
    except ValidationError as exc:
        problems = "\n".join(f"  - {line}" for line in _describe(exc, data))
        raise RulesError(f"{source} is invalid:\n{problems}") from None


def _describe(exc: ValidationError, data: dict) -> list[str]:
    """Pydantic errors as lines that name the rule: 'rules[7] DPDP-SEC-001 -> severity: ...'."""
    lines = []
    for err in exc.errors():
        loc = list(err["loc"])
        if len(loc) >= 2 and loc[0] == "rules" and isinstance(loc[1], int):
            where = f"rules[{loc[1]}] {_rule_id_at(data, loc[1])}"
            rest = ".".join(str(part) for part in loc[2:])
            if rest:
                where += f" -> {rest}"
        else:
            where = ".".join(str(part) for part in loc)
        cause = err.get("ctx", {}).get("error")
        messages = str(cause).splitlines() if err["type"] == "value_error" and cause else [err["msg"]]
        lines += [f"{where}: {message}" if where else message for message in messages]
    return lines


def _rule_id_at(data: dict, index: int) -> str:
    try:
        return str(data["rules"][index].get("id", "?"))
    except (KeyError, IndexError, TypeError, AttributeError):
        return "?"


def _display(path: Path) -> str:
    """Path relative to the project root when possible (shorter, and no user folders)."""
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    """python -m scanner.rules_loader [path]: validate the rules file and print a summary."""
    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else get_settings().rules_file
    try:
        catalogue = load_rules(path)
    except RulesError as exc:
        print(f"FAILED  {exc}", file=sys.stderr)
        return 1
    rules = catalogue.rules
    severities = Counter(r.severity for r in rules)
    penalties = sorted(Counter(r.penalty for r in rules).items())
    print(f"OK  {_display(path)}  v{catalogue.meta.version}  {len(rules)} rules, all fields valid")
    print("  severity     " + ", ".join(f"{s} {severities[s]}" for s in SEVERITIES))
    print("  categories   " + ", ".join(f"{c} {n}" for c, n in Counter(r.category for r in rules).items()))
    print("  penalty caps " + ", ".join(f"{p} x{n} ({catalogue.penalty_caps[p].cap})" for p, n in penalties))
    names = ", ".join(i.name for i in catalogue.personal_data.identifiers)
    print(f"  identifiers  {names} (all regexes compile)")
    print(f"  {catalogue.meta.disclaimer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
