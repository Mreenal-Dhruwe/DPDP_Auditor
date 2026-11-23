"""Logging detectors: DPDP-SEC-001 (personal data written to logs) and DPDP-SEC-007
(personal-data reads with no audit log).

Implemented: DPDP-SEC-001, for Python and JavaScript / TypeScript. A log call is print(...)
or <logger>.<level>(...) where <logger> is log / logger / logging / app.logger / self.log ...
(JS: console.log / console.error ..., logger.info, this.logger.warn ...). Its arguments are
searched for personal data with PiiRefs (pii_refs.py): only the values that get logged
count, not literal text, and masked values are safe. Logging a whole request body
(request.json, request.form, request.get_json()) is reported too.

Also implemented: DPDP-SEC-007 (personal-data reads with no audit log); see its section.
"""

import ast
import re

from scanner.detectors.access import labels_in_select
from scanner.detectors.javascript import JsPiiRefs, arguments, callee, js_files, line_of, walk
from scanner.detectors.routes import find_routes, resolve_js_handler
from scanner.detectors.schemas import find_tables
from scanner.detectors.pii_refs import PiiRefs, best_confidence
from scanner.detectors.source import dotted_name, is_test_file, python_trees, suffix_of, text_files
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import default_matcher

SEC_001 = "DPDP-SEC-001"
JS_SUFFIXES = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
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


# --- DPDP-SEC-007: personal-data reads with no audit log ----------------------------------
#
# Rule 6(1)(c): keep logs of access to personal data. Only checked when the app has a logger
# set up (logging / structlog / loguru; winston / pino / bunyan / log4js) - the rule is about
# using it on the paths that matter - and skipped when request-logging middleware already
# records every request (morgan, pino-http, express-winston; a Flask after_request /
# before_request hook that logs covers its file). A route whose handler reads personal data
# (a SELECT of personal-data columns, SELECT * of a people table, an ORM read of a model with
# personal data: User.query..., User.objects..., User.findByPk ...) needs an audit or log call
# in the handler, or in a same-file helper it calls. One finding per route, medium
# confidence: the read may be logged by a proxy or the database.

SEC_007 = "DPDP-SEC-007"
PY_LOGGERS = re.compile(r"^\s*(?:import\s+(?:logging|structlog|loguru)|from\s+(?:logging|structlog|loguru)\b)|getLogger\(",
                        re.MULTILINE)
JS_LOGGERS = re.compile(r"""(?:require\(|from\s+)['"](?:winston|pino|bunyan|log4js|loglevel|signale)['"]""")
REQUEST_LOGGING = re.compile(r"""\bmorgan\(|['"]morgan['"]|pino-?[Hh]ttp|expressWinston\.logger|express-winston|['"]express-pino-logger['"]""")
READ_METHODS = {"findByPk", "findOne", "findAll", "findAndCountAll", "findById", "find", "get", "get_or_404",
                "first", "all", "filter", "filter_by", "one", "scalar"}


def _logger_setup(project: Project) -> str | None:
    for rel in text_files(project):
        if is_test_file(rel):
            continue
        text = project.read_text(rel)
        pattern = PY_LOGGERS if rel.endswith(".py") else JS_LOGGERS if suffix_of(rel) in JS_SUFFIXES else None
        if pattern is not None and (m := pattern.search(text)):
            return f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
    return None


def _person_models(project: Project) -> dict[str, list[str]]:
    """Model and table names (lower case) -> personal-data labels they hold."""
    matcher = default_matcher()
    models = {}
    for table in find_tables(project):
        labels = sorted({m.label for c in table.columns if (m := matcher.match(c.name))})
        if labels:
            for key in {table.name.lower(), table.name.lower().rstrip("s"), (table.model or "").lower()} - {""}:
                models[key] = labels
    return models


def _model_labels(name: str, models: dict[str, list[str]]) -> list[str] | None:
    key = name.lower()
    return models.get(key) or models.get(key.removesuffix("model"))


def _py_reads(func: ast.AST, models, matcher) -> list[str]:
    labels = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for label in labels_in_select(node.value, matcher):
                labels.add(label.replace("all columns of ", ""))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.attr in {"query", "objects"} \
                and (found := _model_labels(node.value.id, models)):
            labels |= set(found)
    return sorted(labels)


def _py_logs(func: ast.AST, helpers: dict[str, ast.AST], depth: int = 0) -> bool:
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func)
        if "audit" in name.lower() or is_log_call(node):
            return True
        if depth == 0 and name in helpers and _py_logs(helpers[name], helpers, 1):
            return True
    return False


def _py_hook_files(project: Project) -> set[str]:
    """Files with a before_request / after_request hook that logs every request."""
    covered = set()
    for rel, tree in python_trees(project):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    dotted_name(d).endswith(("before_request", "after_request")) for d in node.decorator_list) \
                    and _py_logs(node, {}):
                covered.add(rel)
    return covered


def _js_reads(handler, models) -> list[str]:
    labels = set()
    for node in walk(handler):
        if node.type == "call_expression":
            parts = callee(node).split(".")
            if len(parts) >= 2 and parts[-1] in READ_METHODS and (found := _model_labels(parts[-2], models)):
                labels |= set(found)
    return sorted(labels)


def _js_logs(handler) -> bool:
    return any(n.type == "call_expression" and ("audit" in callee(n).lower() or _js_log_call(callee(n)))
               for n in walk(handler))


def unaudited_reads(project: Project) -> list[Hit]:
    where = _logger_setup(project)
    if where is None:
        return []
    if any(REQUEST_LOGGING.search(project.read_text(rel)) for rel in text_files(project) if not is_test_file(rel)):
        return []  # every request is already logged
    matcher = default_matcher()
    models = _person_models(project)
    hooked = _py_hook_files(project)
    helpers_by_file = {rel: {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
                       for rel, tree in python_trees(project)}
    hits = []
    for route in find_routes(project):
        if is_test_file(route.file):
            continue
        if route.language == "js":
            _, handler = resolve_js_handler(project, route)
            if handler is None:
                continue
            labels, logged = _js_reads(handler, models), _js_logs(handler)
        else:
            if route.file in hooked:
                continue
            labels = _py_reads(route.node, models, matcher)
            logged = _py_logs(route.node, helpers_by_file.get(route.file, {}))
        if labels and not logged:
            hits.append(Hit(rule_id=SEC_007, file=route.file, line=route.line, pii=labels, confidence="medium",
                            evidence=f"{route.describe()} reads {', '.join(labels)} but writes no audit or log "
                                     f"entry; the app has a logger ({where})"))
    return sorted(hits, key=lambda h: (h.file, h.line))
