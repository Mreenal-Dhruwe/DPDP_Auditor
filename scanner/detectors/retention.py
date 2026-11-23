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
    for table in find_tables(project):
        labels = sorted({m.label for c in table.columns if (m := matcher.match(c.name))})
        if not labels or _has_erase_path(table, code):
            continue
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
