"""Find web routes: Python with ast - Flask (@app.route, @bp.post ...) and FastAPI
(@app.get, @router.delete ...) - and JavaScript / TypeScript with tree-sitter - Express
(app.get('/x', auth, handler), router.post(...), guarded by app.use('/prefix', auth)).
Files are parsed, never imported or run.

Shared by the detectors that reason about routes (consent, access, retention; rights next).
"""

import ast
from dataclasses import dataclass, field
from typing import Any

from scanner.detectors.javascript import FUNCTION_TYPES, arguments, dotted, js_files, line_of, string_value, walk
from scanner.detectors.source import dotted_name, is_test_file, python_trees
from scanner.ingest import Project

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
SHORTCUTS = {m.lower(): m for m in HTTP_METHODS}  # @app.post("/x") == route("/x", methods=["POST"])
EXPRESS_FACTORIES = {"express", "express.Router", "Router", "express.default"}


@dataclass(frozen=True)
class Route:
    file: str  # relative to the project root
    line: int  # Python: the `def` line (what ast reports); Express: the app.get(...) line
    function: str  # handler name ("" for an anonymous Express handler)
    path: str  # "" when the path is not a string literal
    methods: frozenset[str]
    decorators: tuple[str, ...] = ()  # Python decorators, or Express middleware (route + app.use guards)
    node: Any = field(default=None, compare=False, repr=False)  # ast function / tree-sitter handler node
    language: str = "python"  # "python" | "js"
    module: Any = field(default=None, compare=False, repr=False)  # tree-sitter root of the file (js)

    def describe(self) -> str:
        return f"{'/'.join(sorted(self.methods))} {self.path or '?'} ({self.function or 'handler'})"


def find_routes(project: Project, include_tests: bool = False) -> list[Route]:
    """All routes, computed once per scan (consent, access and retention all need them)."""
    return project.cached(f"routes:{include_tests}",
                          lambda: _python_routes(project, include_tests) + _express_routes(project, include_tests))


def _python_routes(project: Project, include_tests: bool) -> list[Route]:
    routes = []
    for rel, tree in python_trees(project):
        if not include_tests and is_test_file(rel):
            continue
        for node in ast.walk(tree):  # walk, not just top level: app factories define routes inside functions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = tuple(dotted_name(d) for d in node.decorator_list)
                for decorator in node.decorator_list:
                    found = _python_route_decorator(decorator)
                    if found:
                        routes.append(Route(rel, node.lineno, node.name, *found, decorators=names, node=node))
    return routes


def _python_route_decorator(decorator: ast.expr) -> tuple[str, frozenset[str]] | None:
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


def _middleware_name(node: Any) -> str:
    return dotted(node) or node.type


def _guards_path(prefix: str, path: str) -> bool:
    """Express prefix matching: app.use('/admin', auth) guards /admin and /admin/..., not /administrator."""
    if not prefix or prefix == "/":
        return True
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def _express_routes(project: Project, include_tests: bool) -> list[Route]:
    routes = []
    for f in js_files(project):
        if not include_tests and is_test_file(f.rel):
            continue
        calls = [n for n in walk(f.root) if n.type == "call_expression"]
        apps = {"app", "router"}  # plus every variable created by express() / Router()
        for node in walk(f.root):
            if node.type == "variable_declarator" and (value := node.child_by_field_name("value")) is not None \
                    and value.type == "call_expression" and dotted(value) in EXPRESS_FACTORIES:
                apps.add(dotted(node.child_by_field_name("name")))
        guards: list[tuple[str, list[str]]] = []
        for call in calls:  # app.use('/prefix', mw1, mw2) or app.use(mw)
            function = call.child_by_field_name("function")
            if function is None or function.type != "member_expression" or dotted(function).rsplit(".", 1)[-1] != "use":
                continue
            if dotted(function.child_by_field_name("object")) not in apps:
                continue
            args = arguments(call)
            prefix = string_value(args[0]) if args else None
            guards.append((prefix or "", [_middleware_name(a) for a in args if string_value(a) is None]))
        for call in calls:
            function = call.child_by_field_name("function")
            if function is None or function.type != "member_expression":
                continue
            method = dotted(function).rsplit(".", 1)[-1]
            if method not in SHORTCUTS and method != "all":
                continue
            if dotted(function.child_by_field_name("object")) not in apps:
                continue  # axios.get('/x') is a client call, not a route
            args = arguments(call)
            path = string_value(args[0]) if args else None
            if len(args) < 2 or path is None or not path.startswith("/"):
                continue
            handler = args[-1]
            if handler.type in FUNCTION_TYPES:
                name = dotted(handler.child_by_field_name("name"))
            else:
                name = dotted(handler).rsplit(".", 1)[-1]  # whoami or whoami() -> "whoami"
            middleware = [_middleware_name(a) for a in args[1:-1]]
            guarded = [n for prefix, names in guards if _guards_path(prefix, path) for n in names]
            methods = HTTP_METHODS if method == "all" else frozenset({SHORTCUTS[method]})
            routes.append(Route(f.rel, line_of(call), name, path, methods, tuple(middleware + guarded),
                                node=handler, language="js", module=f.root))
    return routes


def _strings(node: ast.expr) -> list[str] | None:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and all(
        isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts
    ):
        return [e.value for e in node.elts]
    return None
