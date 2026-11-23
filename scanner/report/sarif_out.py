"""SARIF 2.1.0 output, for GitHub code scanning, IDE plugins and other security tools.

Mapping from the Report:
- every rule in rules/dpdp_rules.yml -> a SARIF rule (title, requirement, fix, law refs as tags)
- severity -> level: critical/high = error, medium = warning, low/info = note; GitHub's
  numeric `security-severity` is set as well, so code scanning sorts findings correctly
- Finding.id -> partialFingerprints (stable for the same rule, file and line across scans)
- file / line -> physicalLocation relative to the scanned folder (%SRCROOT%). No absolute
  paths are written, so a report can never reveal server folders. A project-wide finding
  with no related file has no location (GitHub code scanning skips such results).
Evidence is the already-masked evidence from the Report; source context is not repeated.
"""

import json
import re
from pathlib import Path
from typing import Any

from scanner.models import Report
from scanner.rules_loader import RuleCatalogue, load_rules

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "1.0"}


def _pascal(title: str) -> str:
    return "".join(word.capitalize() for word in re.findall(r"[A-Za-z0-9]+", title))


def _rule(rule: Any) -> dict:
    law = rule.law
    refs = [f"DPDP Act {ref}" for ref in law.act] + [f"DPDP Rules {ref}" for ref in law.rules]
    return {
        "id": rule.id,
        "name": _pascal(rule.title),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": law.requirement},
        "help": {
            "text": f"{rule.fix}\n\nLaw: {', '.join(refs)}. {law.requirement}",
            "markdown": f"**Fix:** {rule.fix}\n\n**Law:** {', '.join(refs)}. {law.requirement}",
        },
        "defaultConfiguration": {"level": LEVEL[rule.severity]},
        "properties": {
            # SARIF requires unique tags ("security" is also a category name)
            "tags": list(dict.fromkeys(["dpdp", "privacy", "security", rule.category.lower(), *law.act, *law.rules])),
            "security-severity": SECURITY_SEVERITY[rule.severity],
            "severity": rule.severity,
        },
    }


def to_sarif(report: Report, catalogue: RuleCatalogue | None = None) -> dict:
    catalogue = catalogue or load_rules()
    rule_index = {rule.id: i for i, rule in enumerate(catalogue.rules)}
    results = []
    for f in report.findings:
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": LEVEL[f.severity],
            "message": {"text": f"{f.title} ({f.location}): {f.evidence}"},
            "partialFingerprints": {"dpdpFindingId/v1": f.id},
            "properties": {
                "severity": f.severity,
                "security-severity": SECURITY_SEVERITY[f.severity],
                "confidence": f.confidence,
                "scope": f.scope,
                "pii": f.pii,
                "law": f.law.model_dump(),
                "penaltyCap": f.penalty.cap,
                "severityReason": f.severity_reason,
                "fix": f.fix,
            },
        }
        if f.file is not None:
            location: dict[str, Any] = {"artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"}}
            if f.line is not None:
                location["region"] = {"startLine": f.line, "snippet": {"text": f.evidence}}
            result["locations"] = [{"physicalLocation": location}]
        results.append(result)
    run = {
        "tool": {"driver": {
            "name": report.tool,
            "version": report.tool_version,
            "semanticVersion": report.tool_version,
            "rules": [_rule(rule) for rule in catalogue.rules],
        }},
        "automationDetails": {"id": f"dpdp-compliance/{report.target}/"},
        "invocations": [{"executionSuccessful": True, "endTimeUtc": report.generated_at.isoformat()}],
        "results": results,
        "properties": {
            "target": report.target,
            "rulesVersion": report.rules_version,
            "filesScanned": report.files_scanned,
            "coverage": report.coverage.model_dump() if report.coverage else None,
            "disclaimer": report.disclaimer,
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def write_sarif(report: Report, out_dir: Path | str, catalogue: RuleCatalogue | None = None) -> Path:
    """Write <out_dir>/report.sarif and return its path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.sarif"
    path.write_text(json.dumps(to_sarif(report, catalogue), indent=2, ensure_ascii=False), encoding="utf-8")
    return path
