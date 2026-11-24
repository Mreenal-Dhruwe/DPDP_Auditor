"""Retention detectors: DPDP-RET-001 to DPDP-RET-003 (no erasure path, immediate hard
delete, no pre-erasure notice).

Implemented: DPDP-RET-001. Every table holding personal data (any sensitivity, protected or
not - an encrypted Aadhaar number still has to be erasable) needs some way to erase or
anonymise it in the application code. Accepted as an erase path, in code files (not .sql
files: a DELETE in a seed or migration file is not a user-erasure path):
- DELETE FROM <table>, TRUNCATE <table>
- UPDATE <table> SET ... NULL (anonymising)
- ORM deletes: <Model>.query...delete(), <Model>.objects...delete(), delete(<Model>),
  session.delete(...) in a file that uses <Model>
- a function whose name mentions anonymise / anonymize / purge / erase / forget in a file
  that mentions the table or model
One finding per table, at its definition. Confidence is medium: erasure may also happen
outside this repository (a database job, another service). It drops to low when the project
uses a library that generates REST endpoints from models (finale-rest, epilogue,
json-server, DRF ModelViewSet ...): those can include DELETE routes that are not in the code.
"""

import ast
import re

from scanner.detectors.javascript import FUNCTION_TYPES, js_files, line_of, text, walk
from scanner.detectors.routes import find_routes
from scanner.detectors.schemas import Table, find_tables
from scanner.detectors.source import PEOPLE_TABLES, dotted_name, is_test_file, python_trees, suffix_of, text_files
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import default_matcher, split_words

RET_001 = "DPDP-RET-001"
RET_002 = "DPDP-RET-002"
DELETE_WORDS = {"delete", "remove", "erase", "close", "destroy", "deactivate", "terminate"}
ACCOUNT_WORDS = {"account", "accounts", "user", "users", "profile", "me", "customer", "member", "self"}
LOG_TABLE_WORDS = {"log", "logs", "audit", "history", "event", "events", "activity", "consent", "consents",
                   "session", "sessions", "trail"}
SOFT_DELETE_MARKERS = re.compile(r"deleted_at|is_deleted|soft_delete|deactivated|scheduled_for_deletion|"
                                 r"erase_after|retention|anonymi[sz]e_after", re.IGNORECASE)
_DELETE_SQL = re.compile(r"\bdelete\s+from\s+[`\"\[]?(?:\w+\.)?(\w+)", re.IGNORECASE)
# Libraries that generate REST endpoints (often including DELETE) from models.
# package / requirement name -> name shown in the evidence
REST_GENERATOR_PACKAGES = {
    "finale-rest": "finale-rest", "epilogue": "epilogue", "json-server": "json-server",
    "@nestjsx/crud": "NestJS CRUD", "@dataui/crud": "NestJS CRUD", "@loopback/rest-crud": "LoopBack",
    "loopback": "LoopBack", "feathers-sequelize": "Feathers", "sails": "Sails blueprints",
    "flask-restless": "Flask-Restless", "flask-restless-ng": "Flask-Restless",
    "fastapi-crudrouter": "fastapi-crudrouter", "fastapi-crud": "fastapi-crud",
}
REST_GENERATOR_CODE = re.compile(r"\b(finale|epilogue)\.resource\(|\bModelViewSet\b|\bCRUDRouter\(|\bAPIManager\(")
_ERASE_FUNCTION = re.compile(r"\b(?:def|function|const|let|var)\s+\w*(?:anonymi[sz]|purge|erase|forget)\w*", re.IGNORECASE)


def _erase_patterns(table: Table) -> list[tuple[str, re.Pattern]]:
    """(keyword, pattern) pairs. The keyword (lower case) must appear in a file before the
    slower regex runs on it: most files contain no 'delete' / 'destroy' / 'truncate' at all."""
    name = re.escape(table.name)
    patterns = [
        ("delete", rf"\bdelete\s+from\s+[`\"\[]?(?:\w+\.)?{name}\b"),
        ("truncate", rf"\btruncate\s+(?:table\s+)?[`\"\[]?{name}\b"),
        ("null", rf"\bupdate\s+[`\"\[]?{name}[`\"\]]?\s+set\b[^;]{{0,300}}?\bnull\b"),
    ]
    # raw MongoDB driver: members.deleteOne(...) / db.collection("members").deleteMany(...)
    patterns.append(("delete", r"\.(?:deleteOne|deleteMany|findOneAndDelete)\("))
    patterns.append(("remove", r"\.remove\(\s*\{"))
    if table.model:
        model = re.escape(table.model)
        patterns += [  # SQLAlchemy and Django, then Sequelize
            ("delete(", rf"\b{model}\.(?:query|objects)\b[^\n]*\.delete\("),
            ("delete(", rf"\bdelete\(\s*{model}\b"),
            ("destroy(", rf"\b{model}\.destroy\("),
            ("null", rf"\b{model}\.update\([^;]{{0,300}}?\bnull\b"),
        ]
    return [(keyword, re.compile(p, re.IGNORECASE | re.DOTALL)) for keyword, p in patterns]


def _has_erase_path(table: Table, code: dict[str, tuple[str, str, bool]]) -> bool:
    """code: {file: (text, lower-cased text, has an anonymise/purge function)}. Only files that
    mention the table or model, and the pattern's keyword, are searched with the regexes."""
    patterns = _erase_patterns(table)
    names = {table.name.lower()} | ({table.model.lower()} if table.model else set())
    mentions = re.compile(rf"\b(?:{re.escape(table.name)}{'|' + re.escape(table.model) if table.model else ''})\b",
                          re.IGNORECASE)
    for text, lowered, erase_function in code.values():
        if not any(name in lowered for name in names):
            continue
        if any(keyword in lowered and p.search(text) for keyword, p in patterns):
            return True
        if mentions.search(text) and (erase_function or (table.model and "session.delete(" in text)):
            return True
    return False


def generated_rest_endpoints(project: Project) -> str | None:
    """Name of a library that generates REST endpoints from models, if the project uses one."""
    for rel in project.files:
        name = rel.rsplit("/", 1)[-1].lower()
        if name == "package.json" or name.startswith("requirements") or name == "pyproject.toml":
            text = project.read_text(rel).lower()
            for package, shown in REST_GENERATOR_PACKAGES.items():
                if re.search(rf"[\"'\s]{re.escape(package)}[\"'\s=<>~^!\[]", text) or text.startswith(package):
                    return shown
    for rel in text_files(project):
        if (m := REST_GENERATOR_CODE.search(project.read_text(rel))) is not None:
            return {"finale": "finale-rest", "epilogue": "epilogue"}.get(m.group(1) or "", m.group(0).rstrip("("))
    return None


def no_erase_path(project: Project) -> list[Hit]:
    matcher = default_matcher()
    generator = generated_rest_endpoints(project)
    code = {}
    for rel in text_files(project):
        if suffix_of(rel) not in {".sql", ".md"}:
            text = project.read_text(rel)
            lowered = text.lower()
            # cheap substring test first: the regex only runs on files that can match
            erase_function = any(w in lowered for w in ("anonymi", "purge", "erase", "forget")) \
                and _ERASE_FUNCTION.search(text) is not None
            code[rel] = (text, lowered, erase_function)
    hits = []
    seen_collections: set[str] = set()  # a MongoDB collection written in several files is one table
    for table in find_tables(project):
        labels = sorted({m.label for c in table.columns if (m := matcher.match(c.name))})
        if not labels or _has_erase_path(table, code):
            continue
        if table.model is None and suffix_of(table.file) in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}:
            if table.name in seen_collections:
                continue
            seen_collections.add(table.name)
        lines = project.read_text(table.file).splitlines()
        defined = lines[table.line - 1].strip() if table.line <= len(lines) else table.name
        note = (f"; {generator} generates REST endpoints, so a delete path may exist outside the scanned code"
                if generator else "")
        hits.append(Hit(
            rule_id=RET_001, file=table.file, line=table.line, pii=labels, confidence="low" if generator else "medium",
            evidence=f"{defined}  [table {table.name} holds {', '.join(labels)}; no code deletes or anonymises it{note}]",
        ))
    return sorted(hits, key=lambda h: (h.file, h.line))


# --- DPDP-RET-002: immediate hard delete --------------------------------------------------

def _deleted_tables(func: ast.AST, models: dict[str, str]) -> list[tuple[int, str]]:
    """(line, table) for every hard delete inside a function: SQL and ORM."""
    found = []
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found += [(node.lineno, t.lower()) for t in _DELETE_SQL.findall(node.value)]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "delete":
            chain = dotted_name(node.func.value)  # User.query.filter_by(...) -> "User.query.filter_by"
            root = chain.split(".")[0]
            if root in models:
                found.append((node.lineno, models[root]))
            elif chain.endswith("session") and node.args:  # db.session.delete(user)
                found.append((node.lineno, dotted_name(node.args[0]).split(".")[0].lower()))
    return found


def _is_people_table(table: str, pii_tables: set[str]) -> bool:
    return table in pii_tables or table in PEOPLE_TABLES or table.rstrip("s") in PEOPLE_TABLES


def immediate_hard_delete(project: Project) -> list[Hit]:
    """DPDP-RET-002: account deletion that hard-deletes personal data at once.

    Rule 8(3) requires keeping personal data, traffic data and processing logs for at
    least one year, then erasing them. An account-deletion function (a DELETE route on an
    account-like path, or a function named like delete_account / remove_user) that
    immediately hard-deletes rows of a personal-data table is reported, with high
    confidence when it also wipes logs, audit, consent or history tables. Soft deletes
    (deleted_at, is_deleted, scheduled erasure) and purge jobs that are not account
    deletion are not reported.
    """
    matcher = default_matcher()
    tables = find_tables(project)
    pii_tables = {t.name.lower() for t in tables if any(matcher.match(c.name) for c in t.columns)}
    models = {t.model: t.name.lower() for t in tables if t.model}
    delete_routes = {(r.file, r.line) for r in find_routes(project) if "DELETE" in r.methods}
    hits = []
    for rel, tree in python_trees(project):
        if is_test_file(rel):
            continue
        lines = project.read_text(rel).splitlines()
        for func in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            words = set(split_words(func.name))
            named_like_it = bool(words & DELETE_WORDS) and bool(words & ACCOUNT_WORDS)
            if not ((rel, func.lineno) in delete_routes or named_like_it):
                continue
            body = "\n".join(lines[func.lineno - 1:(func.end_lineno or func.lineno)])
            if SOFT_DELETE_MARKERS.search(body):
                continue
            deleted = _deleted_tables(func, models)
            people = [(n, t) for n, t in deleted if _is_people_table(t, pii_tables)]
            if not people:
                continue
            logs = sorted({t for _, t in deleted if set(split_words(t)) & LOG_TABLE_WORDS})
            line, table = min(people)
            also = f"; also wipes {', '.join(logs)} at once" if logs else ""
            hits.append(Hit(
                rule_id=RET_002, file=rel, line=line, confidence="high" if logs else "medium",
                evidence=f"{lines[line - 1].strip()}  [{func.name}() hard-deletes {table} immediately{also}]",
            ))
    return sorted(hits, key=lambda h: (h.file, h.line))


# --- DPDP-RET-003: no notice before erasing inactive accounts ---------------------------------
#
# Rule 8(2) (Third Schedule fiduciaries: large e-commerce, gaming, social media): erase after
# the inactivity period, but tell the user at least 48 hours before. A function or job that
# deletes or anonymises accounts selected by inactivity (last_login, last_seen, inactive,
# dormant ...) is reported when nothing in it - or in a same-file function it calls - notifies
# the user (notify, notice, email, SMS, warn, remind). Python and JavaScript / TypeScript.
# Low confidence: the notice may be sent by another job, and the rule only binds Third
# Schedule classes.

RET_003 = "DPDP-RET-003"
INACTIVITY = re.compile(r"inactiv|dormant|last_?login|lastLogin|last_?seen|lastSeen|last_?active|lastActive"
                        r"|last_?activity|lastActivity|idle_?since", re.IGNORECASE)
ERASES = re.compile(r"\bdelete\s+from\b|\.delete\(|\.destroy\(|\bdelete_many\(|\bdeleteMany\(|anonymi[sz]|\berase"
                    r"|\bpurge|\btruncate\b", re.IGNORECASE)
# a message to the user - not the word "email" alone (`email: null` wipes the field)
NOTIFIES = re.compile(r"notif|notice|send_?e?-?mail|sendMail|mail(?:er)?\.send|\bsms\b|sendSms|send_sms"
                      r"|\bwarn(?!ing\()|remind|alert_user|push_message", re.IGNORECASE)


def _py_inactive_purges(project: Project) -> list[tuple[str, int, str]]:
    found = []
    for rel, tree in python_trees(project):
        if is_test_file(rel):
            continue
        lines = project.read_text(rel).splitlines()
        functions = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        source = {name: "\n".join(lines[f.lineno - 1:f.end_lineno]) for name, f in functions.items()}
        for name, func in functions.items():
            body = source[name]
            if not (INACTIVITY.search(body) and ERASES.search(body)):
                continue
            called = {dotted_name(c.func).rsplit(".", 1)[-1] for c in ast.walk(func) if isinstance(c, ast.Call)}
            if NOTIFIES.search(body) or any(NOTIFIES.search(source[c]) for c in called if c in source and c != name):
                continue
            found.append((rel, func.lineno, name))
    return found


def _js_inactive_purges(project: Project) -> list[tuple[str, int, str]]:
    found = []
    for f in js_files(project):
        if is_test_file(f.rel):
            continue
        matches = []
        for node in walk(f.root):
            if node.type in FUNCTION_TYPES:
                body = text(node)
                if INACTIVITY.search(body) and ERASES.search(body) and not NOTIFIES.search(body):
                    matches.append(node)
        for node in matches:  # keep the outermost function only
            parent = node.parent
            while parent is not None and parent not in matches:
                parent = parent.parent
            if parent is None:
                name = text(node.child_by_field_name("name"))
                if not name and node.parent is not None and node.parent.type == "variable_declarator":
                    name = text(node.parent.child_by_field_name("name"))
                found.append((f.rel, line_of(node), name or "job"))
    return found


def no_inactivity_notice(project: Project) -> list[Hit]:
    hits = []
    for rel, line, name in _py_inactive_purges(project) + _js_inactive_purges(project):
        source = project.read_text(rel).splitlines()[line - 1].strip()
        hits.append(Hit(rule_id=RET_003, file=rel, line=line, confidence="low",
                        evidence=f"{source}  [{name}() erases inactive accounts but nothing warns the user first; "
                                 f"Rule 8(2) asks for 48 hours' notice; verify manually: the notice may be another "
                                 f"job, and the rule binds Third Schedule fiduciaries]"))
    return sorted(hits, key=lambda h: (h.file, h.line))
