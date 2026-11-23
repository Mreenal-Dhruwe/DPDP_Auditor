"""Access detectors: DPDP-SEC-005 (personal data on an unauthenticated route / IDOR) and
DPDP-SEC-006 (too much data in API responses).

Implemented: DPDP-SEC-005 for Flask / FastAPI routes (via routes.py). A route is reported
when it RETURNS personal data and nothing on it checks who is asking:
- returned data: variables filled from a SELECT whose columns are personal data
  (SELECT * from a people table counts), or from a person-like ORM model (User.query...),
  plus attributes / keys / keywords in the return value itself (user.email, email=...)
- authentication: an auth decorator (login_required, jwt_required, requires_auth ...),
  a FastAPI Depends(get_current_user ...) parameter, a session / current_user / g.user
  check in the body, or an auth before_request hook in the same file
Reading personal data without returning it (a login route reading password_hash) is fine.
"""

import ast
import re

from tree_sitter import Node

from scanner.detectors.javascript import FUNCTION_TYPES, JsPiiRefs, arguments, callee, string_value, text, walk
from scanner.detectors.routes import Route, find_routes, resolve_js_handler
from scanner.detectors.source import PEOPLE_TABLES, dotted_name, python_trees, string_key
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import PiiMatcher, default_matcher

SEC_005 = "DPDP-SEC-005"
AUTH_WORDS = ("login_required", "auth", "jwt", "token_required", "permission", "role", "admin_required",
              "protected", "authenticated", "current_user", "verify", "requires_user")
AUTH_NAMES = {"session", "current_user", "get_jwt_identity", "verify_jwt_in_request"}
_SELECT = re.compile(r"\bselect\s+(.+?)\s+from\s+[`\"\[]?(\w+)", re.IGNORECASE | re.DOTALL)
_PATH_ID = re.compile(r"[<{](?:\w+:)?(\w*id)[>}]|:(\w*id)\b", re.IGNORECASE)  # <int:user_id>, {id}, :id
# Express: middleware names that check the user, and in-handler checks
JS_AUTH_WORDS = AUTH_WORDS + ("deny", "passport", "ensure", "logged")
JS_AUTH_HINTS = re.compile(r"req\.user\b|req\.session\b|isAuthenticated\(|jwt\.verify|verifyToken|"
                           r"authenticatedUsers|req\.auth\b|getCurrentUser", re.IGNORECASE)
_JS_SEND = re.compile(r"^(?:res|response|reply)(?:\.\w+)*\.(?:json|send|jsonp|end|render)$")


def _is_auth(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in AUTH_WORDS)


def _has_auth(route: Route, guarded_files: set[str]) -> bool:
    if route.file in guarded_files or any(_is_auth(d) for d in route.decorators):
        return True
    func = route.node
    defaults = func.args.defaults + func.args.kw_defaults
    for default in defaults:  # FastAPI: user = Depends(get_current_user)
        if isinstance(default, ast.Call) and dotted_name(default.func).endswith("Depends") and default.args:
            if _is_auth(dotted_name(default.args[0])) or "user" in dotted_name(default.args[0]).lower():
                return True
    for node in ast.walk(func):
        name = dotted_name(node) if isinstance(node, (ast.Name, ast.Attribute)) else ""
        if name.split(".")[0] in AUTH_NAMES or name in {"g.user", "request.user"}:
            return True
        if isinstance(node, ast.Call) and _is_auth(dotted_name(node.func)):
            return True
    return False


def _auth_hook_files(project: Project) -> set[str]:
    """Files with a before_request hook that checks the user: all their routes are guarded."""
    guarded = set()
    for rel, tree in python_trees(project):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                dotted_name(d).endswith("before_request") for d in node.decorator_list
            ):
                body_names = {dotted_name(n) for n in ast.walk(node) if isinstance(n, (ast.Name, ast.Attribute))}
                if any(n.split(".")[0] in AUTH_NAMES or _is_auth(n) for n in body_names):
                    guarded.add(rel)
    return guarded


def _labels_in_sql(node: ast.AST, matcher: PiiMatcher) -> set[str]:
    labels = set()
    for const in ast.walk(node):
        if isinstance(const, ast.Constant) and isinstance(const.value, str):
            labels |= labels_in_select(const.value, matcher)
    return labels


def labels_in_select(sql: str, matcher: PiiMatcher) -> set[str]:
    """Personal data selected by SQL text: 'SELECT email, phone FROM users' -> {email, phone}."""
    labels = set()
    for columns, table in _SELECT.findall(sql):
        for column in columns.split(","):
            name = column.strip().split()[-1].split(".")[-1].strip('`"[]') if column.strip() else ""
            if name == "*":
                if table.lower() in PEOPLE_TABLES:
                    labels.add(f"all columns of {table}")
            elif name and (match := matcher.match(name)) and not match.protected:
                labels.add(match.label)
    return labels


def _labels_in_value(node: ast.AST, matcher: PiiMatcher, tainted: dict[str, set[str]]) -> set[str]:
    """Personal data referenced by an expression (a returned value or an assigned one)."""
    labels = _labels_in_sql(node, matcher)
    for sub in ast.walk(node):
        name = None
        if isinstance(sub, ast.Name):
            labels |= tainted.get(sub.id, set())
            if sub.id in {t.title() for t in PEOPLE_TABLES}:  # ORM model class: User, Customer ...
                labels.add(f"{sub.id.lower()} record")
            continue
        if isinstance(sub, ast.Attribute):
            name = sub.attr
        elif isinstance(sub, ast.Subscript):
            name = string_key(sub.slice)
        elif isinstance(sub, ast.keyword):
            name = sub.arg
        if name and (match := matcher.match(name)) and not match.protected:
            labels.add(match.label)
    if isinstance(node, ast.Dict):
        for key in node.keys:
            if key is not None and (k := string_key(key)) and (m := matcher.match(k)) and not m.protected:
                labels.add(m.label)
    return labels


def _returned_pii(route: Route, matcher: PiiMatcher) -> set[str]:
    tainted: dict[str, set[str]] = {}
    returned: set[str] = set()
    for node in ast.walk(route.node):  # assignments before use is not checked: good enough here
        if isinstance(node, ast.Assign):
            labels = _labels_in_value(node.value, matcher, tainted)
            if labels:
                for target in node.targets:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name):
                            tainted[name.id] = tainted.get(name.id, set()) | labels
    for node in ast.walk(route.node):
        if isinstance(node, ast.Return) and node.value is not None:
            returned |= _labels_in_value(node.value, matcher, tainted)
    return returned


# --- Express (JavaScript / TypeScript) ------------------------------------------------------

def _js_has_auth(route: Route, handler: Node | None) -> bool:
    if any(any(word in name.lower() for word in JS_AUTH_WORDS) for name in route.decorators):
        return True
    return handler is not None and JS_AUTH_HINTS.search(text(handler)) is not None


def _js_names(pattern: Node | None) -> list[str]:
    """Variable names bound by `user` or `{ email, phone }` or `[row]`."""
    if pattern is None:
        return []
    return [text(n) for n in walk(pattern) if n.type in {"identifier", "shorthand_property_identifier_pattern"}]


def _js_value_labels(value: Node, matcher: PiiMatcher, tainted: dict[str, set[str]]) -> set[str]:
    refs = JsPiiRefs(matcher, tainted)
    refs.visit(value)
    labels = set(refs.found)
    for n in walk(value):
        sql = string_value(n) if n.type == "string" else text(n) if n.type == "template_string" else None
        if sql:
            labels |= labels_in_select(sql, matcher)
    return labels


def _js_returned_pii(handler: Node, matcher: PiiMatcher) -> set[str]:
    tainted: dict[str, set[str]] = {}
    returned: set[str] = set()
    for node in walk(handler):  # pre-order: an assignment is seen before the code that uses it
        if node.type == "variable_declarator" and (value := node.child_by_field_name("value")) is not None:
            labels = _js_value_labels(value, matcher, tainted)
            for name in _js_names(node.child_by_field_name("name")) if labels else []:
                tainted[name] = tainted.get(name, set()) | labels
        elif node.type == "call_expression" and callee(node).endswith(".then"):
            function = node.child_by_field_name("function")
            labels = _js_value_labels(function.child_by_field_name("object"), matcher, tainted)
            args = arguments(node)
            if labels and args and args[0].type in FUNCTION_TYPES:  # User.findByPk(id).then(user => ...)
                params = args[0].child_by_field_name("parameters") or args[0].child_by_field_name("parameter")
                for name in _js_names(params):
                    tainted[name] = tainted.get(name, set()) | labels
        elif node.type == "call_expression" and _JS_SEND.match(callee(node)):
            refs = JsPiiRefs(matcher, tainted)
            for arg in arguments(node):
                refs.visit(arg)
            returned |= set(refs.found)
    returned.discard("request body")  # echoing what the client itself sent is not exposure
    return returned


def unauthenticated_pii_routes(project: Project) -> list[Hit]:
    matcher = default_matcher()
    guarded = _auth_hook_files(project)
    hits = []
    for route in find_routes(project):
        handler_file = route.file
        if route.language == "js":
            handler_file, handler = resolve_js_handler(project, route)
            if handler is None or _js_has_auth(route, handler):
                continue
            labels = _js_returned_pii(handler, matcher)
        else:
            if _has_auth(route, guarded):
                continue
            labels = _returned_pii(route, matcher)
        if not labels:
            continue
        idor = _PATH_ID.search(route.path)
        described = route.describe() if handler_file == route.file else             f"{'/'.join(sorted(route.methods))} {route.path or '?'} (handler in {handler_file})"
        evidence = f"{described} returns {', '.join(sorted(labels))} with no authentication check"
        if idor:
            evidence += f"; anyone can change {idor.group(0)} to read other people's data (IDOR)"
        broad = any(label.startswith("all columns") or label.endswith("record") for label in labels)
        hits.append(Hit(rule_id=SEC_005, file=route.file, line=route.line, evidence=evidence,
                        pii=sorted(labels), confidence="medium" if broad else "high"))
    return sorted(hits, key=lambda h: (h.file, h.line))
