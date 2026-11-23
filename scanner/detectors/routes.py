"""Find web routes in Python code with ast: Flask (@app.route, @bp.post ...) and FastAPI
(@app.get, @router.delete ...). Files are parsed, never imported or run.

Shared by the detectors that reason about routes (consent, access, rights).
"""

import ast
from dataclasses import dataclass, field

from scanner.detectors.source import dotted_name, is_test_file, python_trees
from scanner.ingest import Project

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
SHORTCUTS = {m.lower(): m for m in HTTP_METHODS}  # @app.post("/x") == route("/x", methods=["POST"])


@dataclass(frozen=True)
class Route:
    file: str  # relative to the project root
    line: int  # the `def` line, as ast reports it
    function: str
    path: str  # "" when the path is not a string literal
    methods: frozenset[str]
    decorators: tuple[str, ...] = ()  # dotted names of all decorators, e.g. ("app.route", "login_required")
    node: ast.FunctionDef | ast.AsyncFunctionDef | None = field(default=None, compare=False, repr=False)

    def describe(self) -> str:
        return f"{'/'.join(sorted(self.methods))} {self.path or '?'} ({self.function})"


def find_routes(project: Project, include_tests: bool = False) -> list[Route]:
    routes = []
    for rel, tree in python_trees(project):
        if not include_tests and is_test_file(rel):
            continue
        for node in ast.walk(tree):  # walk, not just top level: app factories define routes inside functions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = tuple(dotted_name(d) for d in node.decorator_list)
                for decorator in node.decorator_list:
                    found = _route_decorator(decorator)
                    if found:
                        routes.append(Route(rel, node.lineno, node.name, *found, decorators=names, node=node))
    return routes


def _route_decorator(decorator: ast.expr) -> tuple[str, frozenset[str]] | None:
    """(path, methods) if the decorator registers a route, else None."""
    if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)):
        return None
    kind = decorator.func.attr
    if kind == "route":
        methods = {"GET"}  # Flask's default
    elif kind in SHORTCUTS:
        methods = {SHORTCUTS[kind]}
    else:
        return None
    first = decorator.args[0] if decorator.args else None
    path = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else ""
    if path and not path.startswith("/"):
        return None  # e.g. @mock.patch("module.func"): not a web route
    if kind in SHORTCUTS and not path:
        return None
    for keyword in decorator.keywords:
        if keyword.arg == "methods":
            literal = _strings(keyword.value)
            methods = set(literal) if literal is not None else set(HTTP_METHODS)  # unknown: assume any
    return path, frozenset(m.upper() for m in methods)


def _strings(node: ast.expr) -> list[str] | None:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and all(
        isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts
    ):
        return [e.value for e in node.elts]
    return None
