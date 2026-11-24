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

Implemented: DPDP-SEC-006 (whole records with high-sensitivity fields sent in responses),
for Flask / FastAPI / DRF and Express + Sequelize: see the section at the end.
"""

import ast
import re

from tree_sitter import Node

from scanner.detectors.javascript import (
    FUNCTION_TYPES, JsPiiRefs, arguments, callee, js_files, line_of, string_value, text, walk,
)
from scanner.detectors.routes import Route, find_routes, resolve_js_handler
from scanner.detectors.schemas import MONGO_FINDERS, find_tables, mongo_aliases, mongo_collection_of
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


# --- DPDP-SEC-006: excessive data in API responses -------------------------------------------
#
# A response that sends a whole record holding high-sensitivity data (password hashes,
# Aadhaar, PAN, passport, card and bank numbers - the "high" field names in the rules YAML),
# or such a field by name. Authenticated or not: it is about what is sent, not who asks.
# Whole records:
#   Python  rows of SELECT * (columns from the schema) or of a SELECT naming such a column;
#           ORM records (User.query..., User.objects...) sent as __dict__, vars(), dict(),
#           model_to_dict() or a to_dict()/as_dict() that copies every column; FastAPI
#           routes with a response_model or a return annotation filter the output and are
#           skipped; DRF ModelSerializer with fields = "__all__"
#   Express Sequelize finders (findByPk, findOne, findAll ...) without `attributes`, sent with
#           res.json / res.send, unless the model hides fields (defaultScope, toJSON)

SEC_006 = "DPDP-SEC-006"
WHOLE_CALLS = {"dict", "vars", "model_to_dict", "asdict", "jsonable_encoder", "list"}
RECORD_METHODS = {"to_dict", "as_dict", "serialize", "to_json"}
GENERIC_COPY = re.compile(r"__table__|__dict__|__mapper__|\binspect\(|\.columns\b|_meta\.fields")
SEQUELIZE_FINDERS = {"findByPk", "findOne", "findAll", "findAndCountAll", "findOrCreate", "create", "findById"}
HIDES_FIELDS = re.compile(r"defaultScope[\s\S]{0,300}?exclude|toJSON\s*\(")


def _sensitive(name: str, matcher: PiiMatcher) -> str | None:
    """Label of a high-sensitivity field; a password hash still counts (it can be cracked)."""
    match = matcher.match(name)
    if match and match.sensitivity == "high" and (not match.protected or match.label == "password"):
        return match.label
    return None


class _Records:
    """Tables with high-sensitivity columns, found by table or model name (User, UserModel, users)."""

    def __init__(self, project: Project, matcher: PiiMatcher) -> None:
        self.by_name: dict[str, tuple[str, list[str], str]] = {}  # key -> (shown name, labels, model file)
        for table in find_tables(project):
            labels = sorted({label for c in table.columns if (label := _sensitive(c.name, matcher))})
            if not labels:
                continue
            shown = table.model or table.name
            for key in {table.name.lower(), table.name.lower().rstrip("s"), (table.model or "").lower()} - {""}:
                if key in self.by_name:  # same collection written in several files: union of the fields
                    labels = sorted(set(labels) | set(self.by_name[key][1]))
                self.by_name[key] = (shown, labels, table.file)

    def get(self, name: str) -> tuple[str, list[str], str] | None:
        key = name.lower()
        return self.by_name.get(key) or self.by_name.get(key.removesuffix("model")) \
            or self.by_name.get(key.removesuffix("models"))


def _select_record(sql: str, records: _Records, matcher: PiiMatcher) -> tuple[str, list[str]] | None:
    for columns, table in _SELECT.findall(sql):
        names = [c.strip().split()[-1].split(".")[-1].strip('`"[]') for c in columns.split(",") if c.strip()]
        if "*" in names and (record := records.get(table)):
            return f"SELECT * FROM {table}", record[1]
        labels = sorted({label for n in names if (label := _sensitive(n, matcher))})
        if labels:
            return f"SELECT {', '.join(n for n in names if _sensitive(n, matcher))} FROM {table}", labels
    return None


def _python_source(node: ast.AST, records: _Records, matcher: PiiMatcher) -> tuple[str, list[str], str] | None:
    """(how, labels, confidence) when a value loads a sensitive record."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and (hit := _select_record(sub.value, records, matcher)):
            return hit[0], hit[1], "high"
        if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.attr in {"query", "objects"} \
                and (record := records.get(sub.value.id)):
            return f"{sub.value.id} record", record[1], "medium"
    return None


def _generic_methods(project: Project) -> set[str]:
    """Record methods (to_dict ...) whose body copies every column instead of picking fields."""
    found = set()
    for _, tree in python_trees(project):
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            for fn in cls.body:
                if isinstance(fn, ast.FunctionDef) and fn.name in RECORD_METHODS and GENERIC_COPY.search(ast.unparse(fn)):
                    found.add(fn.name)
    return found


TEST_ONLY_CALLS = {"len", "bool", "isinstance", "hasattr", "type", "id"}


def _masked(field: ast.AST, parents: dict) -> bool:
    """row["pan"][-4:] or mask(row["pan"]): the value is cut or masked before it is sent."""
    outer = parents.get(field)
    return (isinstance(outer, ast.Subscript) and outer.value is field and isinstance(outer.slice, ast.Slice)) or \
        (isinstance(outer, ast.Call) and "mask" in dotted_name(outer.func).lower())


def _only_tested(node: ast.AST, parents: dict) -> bool:
    """`row is not None`, `not user`, len(rows): the record decides something but is not sent."""
    parent = parents.get(node)
    return isinstance(parent, (ast.Compare, ast.BoolOp, ast.UnaryOp)) or (
        isinstance(parent, ast.Call) and dotted_name(parent.func) in TEST_ONLY_CALLS)


def _python_exposed(value: ast.AST, tainted: dict, generic: set[str], matcher: PiiMatcher):
    """(how, labels, confidence) sent by a returned value: whole tainted records or sensitive fields."""
    parents = {child: parent for parent in ast.walk(value) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(value):
        if isinstance(node, ast.Name) and node.id in tainted:
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute) and parent.value is node:
                if parent.attr == "__dict__" or (parent.attr in generic and isinstance(parents.get(parent), ast.Call)):
                    return tainted[node.id]
                if (label := _sensitive(parent.attr, matcher)) and not _masked(parent, parents):
                    return f"{node.id}.{parent.attr}", [label], "high"
                continue
            if isinstance(parent, ast.Subscript) and parent.value is node:
                key = string_key(parent.slice)
                if key and (label := _sensitive(key, matcher)) and not _masked(parent, parents):
                    return f'{node.id}["{key}"]', [label], "high"
                continue
            if _only_tested(node, parents):
                continue
            return tainted[node.id]  # the record itself: jsonify(dict(row)), return user, [dict(r) for r in rows]
    return None


def _filtered_by_fastapi(route: Route) -> bool:
    func = route.node
    if func.returns is not None and dotted_name(func.returns) not in {"dict", "Any", "list", ""}:
        return True
    return any(isinstance(d, ast.Call) and any(k.arg == "response_model" for k in d.keywords)
               for d in func.decorator_list)


def _python_excessive(project: Project, records: _Records, matcher: PiiMatcher) -> list[Hit]:
    generic = _generic_methods(project)
    hits = []
    for route in find_routes(project):
        if route.language != "python" or _filtered_by_fastapi(route):
            continue
        tainted: dict[str, tuple[str, list[str], str]] = {}
        for node in ast.walk(route.node):
            if isinstance(node, ast.Assign):
                source = _python_source(node.value, records, matcher)
                if source is None:  # row = cur.fetchone() with cur already tainted
                    names = [n.id for n in ast.walk(node.value) if isinstance(n, ast.Name) and n.id in tainted]
                    source = tainted[names[0]] if names else None
                if source:
                    for target in node.targets:
                        for name in ast.walk(target):
                            if isinstance(name, ast.Name):
                                tainted[name.id] = source
            elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
                names = [n.id for n in ast.walk(node.iter) if isinstance(n, ast.Name) and n.id in tainted]
                if names:
                    tainted[node.target.id] = tainted[names[0]]
        lines = project.read_text(route.file).splitlines()
        for node in ast.walk(route.node):
            if not (isinstance(node, ast.Return) and node.value is not None):
                continue
            exposed = _python_exposed(node.value, tainted, generic, matcher)
            if exposed is None and (direct := _python_source(node.value, records, matcher)) \
                    and any(isinstance(c, ast.Call) and dotted_name(c.func).split(".")[-1] in WHOLE_CALLS | {"jsonify"}
                            for c in ast.walk(node.value)):
                exposed = direct  # return jsonify(dict(db.execute("SELECT * ...").fetchone()))
            if exposed:
                how, labels, confidence = exposed
                hits.append(Hit(rule_id=SEC_006, file=route.file, line=node.lineno, pii=labels, confidence=confidence,
                                evidence=f"{lines[node.lineno - 1].strip()}  [{route.describe()} sends {how} with "
                                         f"{', '.join(labels)}; return only the fields the client needs]"))
    return hits


def _drf_all_fields(project: Project, records: _Records) -> list[Hit]:
    hits = []
    for rel, tree in python_trees(project):
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            if not any("ModelSerializer" in dotted_name(b) for b in cls.bases):
                continue
            meta = next((b for b in cls.body if isinstance(b, ast.ClassDef) and b.name == "Meta"), None)
            fields = model = None
            for stmt in meta.body if meta else []:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                    if stmt.targets[0].id == "model":
                        model = dotted_name(stmt.value)
                    elif stmt.targets[0].id == "fields" and string_key(stmt.value) == "__all__":
                        fields = stmt
            if fields and model and (record := records.get(model.split(".")[-1])):
                line = project.read_text(rel).splitlines()[fields.lineno - 1].strip()
                hits.append(Hit(rule_id=SEC_006, file=rel, line=fields.lineno, pii=record[1], confidence="high",
                                evidence=f"{line}  [{cls.name} serialises every field of {record[0]}, including "
                                         f"{', '.join(record[1])}; list the fields the client needs]"))
    return hits


def _mongo_finder(call: Node, records: _Records, aliases: dict[str, str]) -> tuple[str, list[str]] | None:
    """usersCol.findOne(query) / db.collection("users").find(query) without a projection."""
    function = call.child_by_field_name("function")
    if function is None or function.type != "member_expression" or text(function.child_by_field_name("property")) not in MONGO_FINDERS:
        return None
    collection = mongo_collection_of(function.child_by_field_name("object"), aliases)
    record = records.get(collection) if collection else None
    if record is None or any(a.type == "object" for a in arguments(call)[1:]) or ".project(" in text(call.parent):
        return None  # unknown collection, or an options / projection object limits the fields
    return f"{collection}.{text(function.child_by_field_name('property'))}()", record[1]


def _js_finder(node: Node, records: _Records, hidden: set[str], aliases: dict[str, str] | None = None) -> tuple[str, list[str]] | None:
    """User.findByPk(id) without `attributes` -> ("User.findByPk()", labels)."""
    for call in walk(node):
        if call.type != "call_expression":
            continue
        if aliases is not None and (mongo := _mongo_finder(call, records, aliases)):
            return mongo
        called = callee(call)
        parts = called.split(".")
        if len(parts) < 2 or parts[-1] not in SEQUELIZE_FINDERS or (record := records.get(parts[-2])) is None:
            continue
        if record[2] in hidden or any("attributes" in text(a) for a in arguments(call)):
            continue
        return f"{called}()", record[1]
    return None


def _js_excessive(project: Project, records: _Records) -> list[Hit]:
    hidden = {f for _, _, f in records.by_name.values() if HIDES_FIELDS.search(project.read_text(f))}
    hits = []
    mongo_alias_map = {f.rel: mongo_aliases(f) for f in js_files(project)}
    for route in find_routes(project):
        if route.language != "js":
            continue
        handler_file, handler = resolve_js_handler(project, route)
        if handler is None:
            continue
        tainted: dict[str, tuple[str, list[str]]] = {}
        lines = project.read_text(handler_file).splitlines()
        aliases = mongo_alias_map.get(handler_file, {})
        for node in walk(handler):
            if node.type == "call_expression" and (mongo := _mongo_finder(node, records, aliases)):
                callback = next((a for a in arguments(node) if a.type in FUNCTION_TYPES), None)
                params = callback.child_by_field_name("parameters") if callback is not None else None
                names = [text(p) for p in params.named_children] if params is not None else []
                if len(names) >= 2:  # findOne(query, (err, user) => res.json(user))
                    tainted[names[1]] = mongo
            if node.type == "variable_declarator" and (value := node.child_by_field_name("value")) is not None:
                if source := _js_finder(value, records, hidden, aliases):
                    for name in _js_names(node.child_by_field_name("name")):
                        tainted[name] = source
            elif node.type == "call_expression" and callee(node).endswith(".then"):
                function = node.child_by_field_name("function")
                args = arguments(node)
                source = _js_finder(function.child_by_field_name("object"), records, hidden, aliases)
                if source and args and args[0].type in FUNCTION_TYPES:
                    params = args[0].child_by_field_name("parameters") or args[0].child_by_field_name("parameter")
                    for name in _js_names(params):
                        tainted[name] = source
            elif node.type == "call_expression" and _JS_SEND.match(callee(node)):
                exposed = None
                for arg in arguments(node):
                    exposed = exposed or _js_finder(arg, records, hidden, aliases)  # res.json(await User.findAll())
                    for sub in walk(arg):
                        if exposed:
                            break
                        if sub.type in {"identifier", "shorthand_property_identifier"} and text(sub) in tainted:
                            parent = sub.parent
                            if parent is not None and parent.type == "member_expression" \
                                    and parent.child_by_field_name("object") == sub:
                                continue  # user.email: one field, judged below
                            exposed = tainted[text(sub)]
                        elif sub.type == "property_identifier" and sub.parent is not None \
                                and sub.parent.type == "member_expression" \
                                and text(sub.parent.child_by_field_name("object")) in tainted \
                                and (label := _sensitive(text(sub), default_matcher())):
                            exposed = (text(sub.parent), [label])
                if exposed:
                    line = line_of(node)
                    hits.append(Hit(rule_id=SEC_006, file=handler_file, line=line, pii=exposed[1], confidence="high",
                                    evidence=f"{lines[line - 1].strip()}  [{route.describe()} sends {exposed[0]} "
                                             f"with {', '.join(exposed[1])}; pass `attributes` or pick the fields]"))
    return hits


def excessive_response_data(project: Project) -> list[Hit]:
    matcher = default_matcher()
    records = _Records(project, matcher)
    if not records.by_name:
        return []
    found = _python_excessive(project, records, matcher) + _drf_all_fields(project, records) + _js_excessive(project, records)
    unique = {(h.file, h.line): h for h in found}  # one handler can serve several routes
    return sorted(unique.values(), key=lambda h: (h.file, h.line))
