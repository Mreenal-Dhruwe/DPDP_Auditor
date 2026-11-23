"""Config and IaC detectors (.env, Dockerfile, docker-compose, cloud YAML, Terraform):
DPDP-SEC-008 to DPDP-SEC-010. (Hardcoded secrets, DPDP-SEC-004, live in hardcoded_secrets.py.)

Implemented: DPDP-SEC-008, insecure infrastructure configuration:
- Dockerfile: the final stage never sets USER (a whole-file finding), or its last USER is root
- Python: app.run(debug=True), DEBUG = True in settings / config modules, CORS(app) with
  no origins (flask-cors then allows every origin), CORS / CORSMiddleware with "*",
  TLS verification turned off (verify=False)
- config files: DEBUG=true / FLASK_DEBUG=1, NODE_TLS_REJECT_UNAUTHORIZED=0,
  sslmode=disable, privileged: true (compose), public S3 ACLs and public databases (Terraform)

Also implemented: DPDP-SEC-010 (log retention shorter than one year); see its section.
"""

import ast
import re

from scanner.detectors.source import (
    dotted_name, is_config_file, is_example_file, is_test_file, name_of, python_trees, string_key, suffix_of,
    text_files,
)
from scanner.ingest import Project
from scanner.models import Hit

SEC_008 = "DPDP-SEC-008"

# (pattern, what is wrong) for lines of config files
CONFIG_LINE_CHECKS = [
    (re.compile(r"^\s*(?:export\s+|ENV\s+|-\s*)?(?:DEBUG|FLASK_DEBUG|DJANGO_DEBUG|APP_DEBUG)\s*[:=]\s*['\"]?(?:true|1|yes|on)['\"]?\s*$",
                re.IGNORECASE), "debug mode switched on"),
    (re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['\"]?0"), "TLS certificate checks turned off"),
    (re.compile(r"sslmode\s*=\s*disable", re.IGNORECASE), "database connection without TLS"),
    (re.compile(r"^\s*privileged\s*:\s*true\s*$", re.IGNORECASE), "privileged container"),
    (re.compile(r"""\bacl\s*=\s*["']public-read(?:-write)?["']""", re.IGNORECASE), "storage bucket readable by anyone"),
    (re.compile(r"\b(?:block_public_acls|block_public_policy|restrict_public_buckets)\s*=\s*false", re.IGNORECASE),
     "public-access block turned off"),
    (re.compile(r"\bpublicly_accessible\s*=\s*true", re.IGNORECASE), "database reachable from the internet"),
]


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Dockerfile lines with backslash continuations joined: (first line number, text)."""
    result, buffer, start = [], "", 0
    for n, line in enumerate(text.splitlines(), 1):
        if not buffer:
            start = n
        buffer += line.rstrip("\\").strip() + " "
        if not line.rstrip().endswith("\\"):
            result.append((start, buffer.strip()))
            buffer = ""
    if buffer:
        result.append((start, buffer.strip()))
    return result


def _dockerfile(rel: str, text: str) -> list[Hit]:
    final_from, users = None, []
    for n, line in _logical_lines(text):
        word = line.split(" ", 1)[0].upper()
        if word == "FROM":
            final_from, users = (n, line), []
        elif word == "USER":
            users.append((n, line))
    if final_from is None:
        return []
    if not users:
        return [Hit(rule_id=SEC_008, scope="file", file=rel, confidence="high",
                    evidence=f"No USER instruction after '{final_from[1]}': the container runs as root")]
    n, line = users[-1]
    user = line.split(" ", 1)[1].split(":")[0].strip() if " " in line else ""
    if user in {"root", "0"}:
        return [Hit(rule_id=SEC_008, file=rel, line=n, confidence="high",
                    evidence=f"{line}  [the container runs as root]")]
    return []


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _has_star(node: ast.AST | None) -> bool:
    return node is not None and any(isinstance(n, ast.Constant) and n.value == "*" for n in ast.walk(node))


def _python(rel: str, tree: ast.Module, lines: list[str]) -> list[Hit]:
    hits = []
    settings_module = re.search(r"(settings|config)\w*\.py$", name_of(rel)) is not None

    def report(line: int, why: str) -> None:
        hits.append(Hit(rule_id=SEC_008, file=rel, line=line, confidence="high",
                        evidence=f"{lines[line - 1].strip()}  [{why}]"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = dotted_name(node.func)
            last = called.rsplit(".", 1)[-1]
            debug = _keyword(node, "debug")
            if last == "run" and isinstance(debug, ast.Constant) and debug.value is True:
                report(node.lineno, "debug mode switched on")
            elif last == "CORS":
                if _keyword(node, "origins") is None and _keyword(node, "resources") is None:
                    report(node.lineno, "CORS without origins allows every website")
                elif _has_star(_keyword(node, "origins")) or _has_star(_keyword(node, "resources")):
                    report(node.lineno, "CORS allows every website")
            elif last == "add_middleware" and node.args and dotted_name(node.args[0]).endswith("CORSMiddleware") \
                    and _has_star(_keyword(node, "allow_origins")):
                report(node.lineno, "CORS allows every website")
            verify = _keyword(node, "verify")
            if isinstance(verify, ast.Constant) and verify.value is False:
                report(node.lineno, "TLS certificate verification turned off")
        elif settings_module and isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and node.value.value is True and any(isinstance(t, ast.Name) and t.id == "DEBUG" for t in node.targets):
            report(node.lineno, "debug mode switched on")
    return hits


def insecure_infrastructure(project: Project) -> list[Hit]:
    hits = []
    trees = dict(python_trees(project))
    for rel in text_files(project):
        if is_test_file(rel) or is_example_file(rel):
            continue
        text = project.read_text(rel)
        if name_of(rel).startswith("dockerfile"):
            hits += _dockerfile(rel, text)
        if rel in trees:
            hits += _python(rel, trees[rel], text.splitlines())
        elif is_config_file(rel) or suffix_of(rel) in {".tf", ".json"}:
            for n, line in enumerate(text.splitlines(), 1):
                for pattern, why in CONFIG_LINE_CHECKS:
                    if pattern.search(line):
                        hits.append(Hit(rule_id=SEC_008, file=rel, line=n, confidence="high",
                                        evidence=f"{line.strip()}  [{why}]"))
                        break
    return sorted(hits, key=lambda h: (h.file, h.line or 0))


# --- DPDP-SEC-010: log retention shorter than one year --------------------------------------
#
# Rule 8(3): personal data, traffic data and processing logs must be kept for at least a year.
# Retention settings are turned into days and reported below 365:
#   Python   TimedRotatingFileHandler(when=..., interval=..., backupCount=N), in code or in a
#            dictConfig dict ("class": "...TimedRotatingFileHandler", "when", "backupCount")
#   Node     winston-daily-rotate-file maxFiles ('14d', or a count of daily files),
#            file-stream-rotator max_logs ('2d', or a count with frequency 'daily')
#   IaC      CloudWatch retention_in_days / RetentionInDays, GCP retention_days,
#            logrotate `rotate N` with daily / weekly / monthly
# backupCount=0 keeps every file (no deletion) and size-based rotation cannot be turned into
# days, so neither is reported.

SEC_010 = "DPDP-SEC-010"
MIN_DAYS = 365
WHEN_DAYS = {"S": 1 / 86400, "M": 1 / 1440, "H": 1 / 24, "D": 1, "MIDNIGHT": 1, "W": 7}
_RETENTION_IAC = re.compile(r"\b(retention_in_days|RetentionInDays|retention_days)\b[\"']?\s*[:=]\s*[\"']?(\d+)")
_JS_MAXFILES = re.compile(r"\bmaxFiles\s*:\s*['\"]?(\d+)\s*(d?)['\"]?")
_JS_MAXLOGS = re.compile(r"\bmax_logs\s*:\s*['\"]?(\d+)\s*(d?)['\"]?")
_LOGROTATE_ROTATE = re.compile(r"^\s*rotate\s+(\d+)", re.MULTILINE)
_LOGROTATE_PERIOD = re.compile(r"^\s*(daily|weekly|monthly|yearly)\b", re.MULTILINE)
PERIOD_DAYS = {"daily": 1, "weekly": 7, "monthly": 30, "yearly": 365}


def _days(when: str, interval: int, count: int) -> float | None:
    unit = WHEN_DAYS.get(when.upper().rstrip("0123456"))  # W0..W6 -> W
    return None if unit is None or count <= 0 else unit * max(interval, 1) * count


def _py_rotation(tree: ast.Module) -> list[tuple[int, float, str]]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and dotted_name(node.func).endswith("TimedRotatingFileHandler"):
            values = {kw.arg: kw.value for kw in node.keywords}
            for name, index in (("when", 1), ("interval", 2), ("backupCount", 3)):
                if name not in values and len(node.args) > index:
                    values[name] = node.args[index]
        elif isinstance(node, ast.Dict) and any(isinstance(v, ast.Constant) and str(v.value).endswith("TimedRotatingFileHandler")
                                                for v in node.values):
            values = {string_key(k): v for k, v in zip(node.keys, node.values) if k is not None}
        else:
            continue
        def constant(name, default):
            value = values.get(name)
            return value.value if isinstance(value, ast.Constant) else default
        when, interval, count = str(constant("when", "h")), int(constant("interval", 1) or 1), int(constant("backupCount", 0) or 0)
        if (days := _days(when, interval, count)) is not None:
            found.append((node.lineno, days, f"TimedRotatingFileHandler keeps {count} file(s) of {interval} {when}"))
    return found


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _text_rotation(rel: str, text: str) -> list[tuple[int, float, str]]:
    found = []
    for m in _RETENTION_IAC.finditer(text):
        found.append((_line_of(text, m.start()), int(m.group(2)), f"{m.group(1)} = {m.group(2)}"))
    if suffix_of(rel) in {".js", ".ts", ".mjs", ".cjs"}:
        if "DailyRotateFile" in text or "winston-daily-rotate-file" in text:
            for m in _JS_MAXFILES.finditer(text):  # a count of files is a count of days with the daily pattern
                found.append((_line_of(text, m.start()), int(m.group(1)), f"daily log files, maxFiles {m.group(0).split(':', 1)[1].strip()}"))
        if "file-stream-rotator" in text or "getStream(" in text:
            daily = re.search(r"frequency\s*:\s*['\"]daily['\"]", text) is not None
            for m in _JS_MAXLOGS.finditer(text):
                if m.group(2) or daily:
                    found.append((_line_of(text, m.start()), int(m.group(1)), f"rotated logs, max_logs {m.group(0).split(':', 1)[1].strip()}"))
    if "logrotate" in rel.lower():
        period = _LOGROTATE_PERIOD.search(text)
        for m in _LOGROTATE_ROTATE.finditer(text):
            if period:
                found.append((_line_of(text, m.start()), int(m.group(1)) * PERIOD_DAYS[period.group(1)],
                              f"logrotate {period.group(1)}, rotate {m.group(1)}"))
    return found


def short_log_retention(project: Project) -> list[Hit]:
    hits = []
    trees = dict(python_trees(project))
    for rel in text_files(project):
        if is_test_file(rel) or is_example_file(rel):
            continue
        text = project.read_text(rel)
        found = _py_rotation(trees[rel]) if rel in trees else []
        found += _text_rotation(rel, text)
        lines = text.splitlines()
        for line, days, how in found:
            if days < MIN_DAYS:
                shown = f"{days:g}" if days >= 1 else f"{days * 24:g} hours, i.e. under 1"
                hits.append(Hit(rule_id=SEC_010, file=rel, line=line, confidence="high",
                                evidence=f"{lines[line - 1].strip()}  [{how}: logs are deleted after {shown} days; "
                                         f"Rule 8(3) asks for at least one year]"))
    return sorted({(h.file, h.line): h for h in hits}.values(), key=lambda h: (h.file, h.line))
