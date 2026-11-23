"""Logging detectors: DPDP-SEC-001 (personal data written to logs) and DPDP-SEC-007
(personal-data reads with no audit log).

Implemented: DPDP-SEC-001, for Python. A log call is print(...) or <logger>.<level>(...)
where <logger> is log / logger / logging / app.logger / self.log ... Its arguments are
searched for names that refer to personal data (scanner/pii.py): variables, attributes
(user.email), string keys (row["phone"], {"email": ...}) and f-string parts. Literal text
("aadhaar %s") does not count: only the values that get logged. Values wrapped in a
masking call (mask_email(email), hash(phone), redact(...)) are safe. Logging a whole
request body (request.json, request.form, request.get_json()) is reported too.
"""

import ast

from scanner.detectors.source import dotted_name, is_test_file, python_trees, string_key
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import PiiMatcher, default_matcher

SEC_001 = "DPDP-SEC-001"
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
SAFE_WRAPPERS = ("mask", "redact", "hash", "anonymi", "pseudonym", "encrypt", "sha", "md5", "token", "scrub")
REQUEST_BODY = {"json", "form", "data", "values", "body", "files", "get_json"}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def is_log_call(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id == "print"
    if isinstance(call.func, ast.Attribute) and call.func.attr in LOG_METHODS:
        receiver = dotted_name(call.func.value).rsplit(".", 1)[-1].lower()
        return "log" in receiver  # log, logger, _logger, logging, LOG
    return False


class _PiiFinder:
    """Collects (label, confidence) for personal data in a log call's arguments."""

    def __init__(self, matcher: PiiMatcher):
        self.matcher = matcher
        self.found: dict[str, str] = {}

    def name(self, name: str | None) -> None:
        match = self.matcher.match(name) if name else None
        if match and not match.protected:
            best = self.found.get(match.label)
            if best is None or CONFIDENCE_ORDER[match.confidence] < CONFIDENCE_ORDER[best]:
                self.found[match.label] = match.confidence

    def visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            called = dotted_name(node.func).lower()
            if any(word in called for word in SAFE_WRAPPERS):
                return  # mask_email(email): safe
            if called.startswith("request.") and called.rsplit(".", 1)[-1] in REQUEST_BODY:
                self.found.setdefault("request body", "medium")
            for child in node.args + [kw.value for kw in node.keywords]:
                self.visit(child)  # not node.func: format_phone(...) is a function, not data
            return
        if isinstance(node, ast.Name):
            self.name(node.id)
        elif isinstance(node, ast.Attribute):
            if dotted_name(node) in {f"request.{b}" for b in REQUEST_BODY}:
                self.found.setdefault("request body", "medium")
                return
            self.name(node.attr)
        elif isinstance(node, ast.Subscript):
            key = string_key(node.slice)
            if key is not None:
                self.name(key)  # row["email"] -> email; don't also report request.form as a whole body
                if dotted_name(node.value) in {f"request.{b}" for b in REQUEST_BODY}:
                    return
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is not None:
                    self.name(string_key(key))
                self.visit(value)
            return
        elif isinstance(node, ast.Constant):
            return  # literal text is not logged data
        for child in ast.iter_child_nodes(node):
            self.visit(child)


def pii_in_logs(project: Project) -> list[Hit]:
    matcher = default_matcher()
    hits = []
    for rel, tree in python_trees(project):
        lines = None
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and is_log_call(node)):
                continue
            finder = _PiiFinder(matcher)
            for arg in node.args + [kw.value for kw in node.keywords]:
                finder.visit(arg)
            if not finder.found:
                continue
            lines = lines or project.read_text(rel).splitlines()
            best = min(finder.found.values(), key=CONFIDENCE_ORDER.get)
            hits.append(Hit(
                rule_id=SEC_001, file=rel, line=node.lineno, evidence=lines[node.lineno - 1],
                pii=sorted(finder.found), confidence="low" if is_test_file(rel) else best,
            ))
    return sorted(hits, key=lambda h: (h.file, h.line))
