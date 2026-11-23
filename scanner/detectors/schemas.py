"""Tables and columns, from SQL and ORM models. Shared by storage (SEC-002) and retention
(RET-001). Reads files only.

Sources:
- CREATE TABLE statements in .sql files and in SQL strings inside Python code
- SQLAlchemy models (x = Column(...), db.Column(...), mapped_column(...))
- Django models (class X(models.Model): x = models.CharField(...))
- Sequelize models (JS/TS): const User = sequelize.define('User', {...}, {tableName}) and
  UserModel.init({...}, {tableName, sequelize}). A column whose setter hashes or encrypts
  the value (set(v) { this.setDataValue('password', bcrypt.hashSync(v)) }) gets type
  "<TYPE>_HASHED" so storage checks treat it as protected.
"""

import ast
import re
from dataclasses import dataclass, field

from scanner.detectors.javascript import arguments, callee, dotted, js_files, line_of, string_value, text, walk
from scanner.detectors.source import PEOPLE_TABLES, dotted_name, python_trees, string_key, suffix_of  # noqa: F401
from scanner.ingest import Project

_HASHING_SETTER = re.compile(r"hash|encrypt|bcrypt|argon|scrypt|cipher", re.IGNORECASE)

_CREATE = re.compile(
    r"\bcreate\s+(?:temporary\s+|temp\s+)?table\s+(?:if\s+not\s+exists\s+)?([`\"\[\]\w.]+)\s*\(", re.IGNORECASE
)
_COLUMN = re.compile(r"[`\"\[]?(\w+)[`\"\]]?\s+([A-Za-z]\w*)")
CONSTRAINT_WORDS = {"primary", "foreign", "unique", "constraint", "check", "key", "index", "exclude"}


@dataclass
class Column:
    name: str
    type: str  # upper case: TEXT, VARCHAR, BLOB, STRING (SQLAlchemy), CHARFIELD (Django) ...
    line: int


@dataclass
class Table:
    name: str
    file: str
    line: int  # where the table (or model class) is defined
    model: str | None = None  # ORM class name, if it comes from a model
    columns: list[Column] = field(default_factory=list)


def _blank_comments(sql: str) -> str:
    """Replace -- and /* */ comments with spaces, keeping every offset and line break."""
    sql = re.sub(r"--[^\n]*", lambda m: " " * len(m.group()), sql)
    return re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group()), sql, flags=re.DOTALL)


def sql_tables(sql: str, file: str, first_line: int = 1) -> list[Table]:
    """Tables in SQL text. first_line: the file line on which `sql` starts."""
    text = _blank_comments(sql)
    tables = []
    for m in _CREATE.finditer(text):
        name = m.group(1).split(".")[-1].strip('`"[]')
        table = Table(name, file, first_line + text.count("\n", 0, m.start()))
        depth, part_start, i = 1, m.end(), m.end()
        while i < len(text) and depth:
            char = text[i]
            depth += (char == "(") - (char == ")")
            if (char == "," and depth == 1) or depth == 0:
                chunk = text[part_start:i]
                offset = part_start + len(chunk) - len(chunk.lstrip())
                col = _COLUMN.match(chunk.lstrip())
                if col and col.group(1).lower() not in CONSTRAINT_WORDS:
                    line = first_line + text.count("\n", 0, offset)
                    table.columns.append(Column(col.group(1), col.group(2).upper(), line))
                part_start = i + 1
            i += 1
        tables.append(table)
    return tables


def _orm_column_type(value: ast.AST) -> str | None:
    """'STRING' for Column(String(12)), 'CHARFIELD' for models.CharField(...), else None."""
    if not isinstance(value, ast.Call):
        return None
    called = dotted_name(value.func)
    last = called.rsplit(".", 1)[-1]
    if last in {"Column", "mapped_column"}:
        types = [a for a in value.args if not (isinstance(a, ast.Constant) and isinstance(a.value, str))]
        return dotted_name(types[0]).rsplit(".", 1)[-1].upper() if types else "UNKNOWN"
    if called.startswith("models.") and last.endswith("Field"):
        return last.upper()
    return None


def _orm_tables(tree: ast.Module, file: str) -> list[Table]:
    tables = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        table = Table(node.name.lower(), file, node.lineno, model=node.name)
        for stmt in node.body:
            target, value = None, None
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target, value = stmt.targets[0], stmt.value
            elif isinstance(stmt, ast.AnnAssign):
                target, value = stmt.target, stmt.value
            if not isinstance(target, ast.Name):
                continue
            if target.id == "__tablename__" and (name := string_key(value)):
                table.name = name
            elif value is not None and (col_type := _orm_column_type(value)):
                table.columns.append(Column(target.id, col_type, stmt.lineno))
        if table.columns:
            tables.append(table)
    return tables


def _sequelize_column(pair) -> Column | None:
    key = pair.child_by_field_name("key")
    value = pair.child_by_field_name("value")
    name = string_value(key) if key is not None and key.type == "string" else text(key)
    if not name or value is None:
        return None
    if value.type == "object":  # { type: DataTypes.STRING, allowNull: false, set (v) {...} }
        col_type = "UNKNOWN"
        for item in value.named_children:
            item_key = text(item.child_by_field_name("key") or item.child_by_field_name("name"))
            if item.type == "pair" and item_key == "type":
                col_type = dotted(item.child_by_field_name("value")).rsplit(".", 1)[-1].upper() or "UNKNOWN"
            elif item_key == "set" and _HASHING_SETTER.search(text(item)):
                col_type += "_HASHED"
    else:  # phone: DataTypes.STRING
        col_type = (dotted(value).rsplit(".", 1)[-1] or value.type).upper()
    return Column(name, col_type, line_of(pair))


def _sequelize_tables(project: Project) -> list[Table]:
    tables = []
    for f in js_files(project):
        for node in walk(f.root):
            if node.type != "call_expression":
                continue
            called, args = callee(node), arguments(node)
            if called.endswith(".define") and len(args) >= 2 and string_value(args[0]) and args[1].type == "object":
                model, attributes, options = string_value(args[0]), args[1], args[2] if len(args) > 2 else None
                parent = node.parent.parent if node.parent is not None and node.parent.type == "await_expression" \
                    else node.parent
                if parent is not None and parent.type == "variable_declarator":
                    model = text(parent.child_by_field_name("name"))  # code refers to the variable: User.destroy()
            elif called.endswith(".init") and called.count(".") == 1 and args and args[0].type == "object":
                model, attributes, options = called.split(".")[0], args[0], args[1] if len(args) > 1 else None
            else:
                continue
            table_name = model
            for item in options.named_children if options is not None and options.type == "object" else []:
                if item.type == "pair" and text(item.child_by_field_name("key")) == "tableName":
                    table_name = string_value(item.child_by_field_name("value")) or table_name
            columns = [c for p in attributes.named_children if p.type == "pair" and (c := _sequelize_column(p))]
            if columns:
                tables.append(Table(table_name, f.rel, line_of(node), model=model, columns=columns))
    return tables


def find_tables(project: Project) -> list[Table]:
    """All tables, computed once per scan (storage, retention and children all need them)."""
    return project.cached("tables", lambda: _find_tables(project))


def _find_tables(project: Project) -> list[Table]:
    tables = _sequelize_tables(project)
    for rel in project.files:
        if suffix_of(rel) == ".sql":
            tables += sql_tables(project.read_text(rel), rel)
    for rel, tree in python_trees(project):
        tables += _orm_tables(tree, rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and _CREATE.search(node.value):
                tables += sql_tables(node.value, rel, first_line=node.lineno)
    return tables
