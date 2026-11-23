"""Logging detectors: DPDP-SEC-001 (personal data written to logs) and DPDP-SEC-007
(personal-data reads with no audit log).

Implemented: DPDP-SEC-001, for Python and JavaScript / TypeScript. A log call is print(...)
or <logger>.<level>(...) where <logger> is log / logger / logging / app.logger / self.log ...
(JS: console.log / console.error ..., logger.info, this.logger.warn ...). Its arguments are
searched for personal data with PiiRefs (pii_refs.py): only the values that get logged
count, not literal text, and masked values are safe. Logging a whole request body
(request.json, request.form, request.get_json()) is reported too.
"""

import ast

from scanner.detectors.javascript import JsPiiRefs, arguments, callee, js_files, line_of, walk
from scanner.detectors.pii_refs import PiiRefs, best_confidence
from scanner.detectors.source import dotted_name, is_test_file, python_trees
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import default_matcher

SEC_001 = "DPDP-SEC-001"
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}


def is_log_call(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id == "print"
    if isinstance(call.func, ast.Attribute) and call.func.attr in LOG_METHODS:
        receiver = dotted_name(call.func.value).rsplit(".", 1)[-1].lower()
        return "log" in receiver  # log, logger, _logger, logging, LOG
    return False


def _js_log_call(called: str) -> bool:
    """console.log / console.error ..., logger.info, this.logger.warn, log.debug ..."""
    parts = called.split(".")
    if len(parts) < 2 or parts[-1] not in LOG_METHODS | {"trace"}:
        return False
    return parts[-2] == "console" or "log" in parts[-2].lower()


def _js_pii_in_logs(project: Project, matcher) -> list[Hit]:
    hits = []
    for f in js_files(project):
        for node in walk(f.root):
            if node.type != "call_expression" or not _js_log_call(callee(node)):
                continue
            refs = JsPiiRefs(matcher)
            for arg in arguments(node):
                refs.visit(arg)
            if refs.found:
                line = line_of(node)
                hits.append(Hit(rule_id=SEC_001, file=f.rel, line=line, evidence=f.lines[line - 1],
                                pii=sorted(refs.found),
                                confidence="low" if is_test_file(f.rel) else best_confidence(refs.found)))
    return hits


def pii_in_logs(project: Project) -> list[Hit]:
    matcher = default_matcher()
    hits = _js_pii_in_logs(project, matcher)
    for rel, tree in python_trees(project):
        lines = None
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and is_log_call(node)):
                continue
            refs = PiiRefs(matcher)
            for arg in node.args + [kw.value for kw in node.keywords]:
                refs.visit(arg)
            if not refs.found:
                continue
            lines = lines or project.read_text(rel).splitlines()
            hits.append(Hit(
                rule_id=SEC_001, file=rel, line=node.lineno, evidence=lines[node.lineno - 1],
                pii=sorted(refs.found), confidence="low" if is_test_file(rel) else best_confidence(refs.found),
            ))
    return sorted(hits, key=lambda h: (h.file, h.line))
