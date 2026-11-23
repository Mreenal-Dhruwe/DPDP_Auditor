"""JavaScript / TypeScript support: parse with tree-sitter (read only, never run).

    for f in js_files(project):          # .js .jsx .mjs .cjs .ts .tsx (not .d.ts, not .min.js)
        for node in walk(f.root):
            if node.type == "call_expression":
                callee(node)              # "res.status.json", "console.log", "User.findByPk"

JsPiiRefs is the JavaScript twin of pii_refs.PiiRefs: which personal data does an
expression pass along (identifiers, user.email, row['phone'], {email}, `${aadhaar}`)?
"""

from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from scanner.detectors.pii_refs import CONFIDENCE_ORDER, SAFE_WRAPPERS
from scanner.detectors.source import MAX_TEXT_BYTES, PEOPLE_TABLES, suffix_of
from scanner.ingest import Project
from scanner.pii import PiiMatcher

GRAMMARS = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
}
FUNCTION_TYPES = {"arrow_function", "function_expression", "function", "function_declaration",
                  "generator_function", "generator_function_declaration", "method_definition"}
REQUEST_BODY_JS = {"req.body", "request.body", "req.query", "request.query", "ctx.request.body"}


@lru_cache
def _parser(grammar: str) -> Parser:
    if grammar == "javascript":
        return Parser(Language(tree_sitter_javascript.language()))
    if grammar == "tsx":
        return Parser(Language(tree_sitter_typescript.language_tsx()))
    return Parser(Language(tree_sitter_typescript.language_typescript()))


@dataclass
class JsFile:
    rel: str
    root: Node
    lines: list[str]


def is_js_file(rel: str) -> bool:
    return suffix_of(rel) in GRAMMARS and not rel.lower().endswith((".d.ts", ".min.js"))


def js_files(project: Project) -> list[JsFile]:
    """Every JS / TS file, parsed once per scan."""

    def parse_all() -> list[JsFile]:
        parsed = []
        for rel in project.files:
            if is_js_file(rel) and (project.root / rel).stat().st_size <= MAX_TEXT_BYTES:
                source = project.read_text(rel)
                tree = _parser(GRAMMARS[suffix_of(rel)]).parse(source.encode("utf-8"))
                parsed.append(JsFile(rel, tree.root_node, source.splitlines()))
        return parsed

    return project.cached("js_files", parse_all)


def text(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text is not None else ""


def line_of(node: Node) -> int:
    return node.start_point[0] + 1


def walk(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def dotted(node: Node | None) -> str:
    """'res.status.json' for res.status(201).json, 'User.findByPk' ... '' if not a name."""
    if node is None:
        return ""
    if node.type in {"identifier", "property_identifier", "this", "shorthand_property_identifier"}:
        return text(node)
    if node.type == "member_expression":
        base = dotted(node.child_by_field_name("object"))
        prop = text(node.child_by_field_name("property"))
        return f"{base}.{prop}" if base else prop
    if node.type == "call_expression":
        return dotted(node.child_by_field_name("function"))
    if node.type in {"await_expression", "parenthesized_expression", "non_null_expression", "as_expression"}:
        return dotted(node.named_children[0]) if node.named_children else ""
    return ""


def callee(call: Node) -> str:
    return dotted(call.child_by_field_name("function"))


def arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [a for a in args.named_children if a.type != "comment"] if args is not None else []


def string_value(node: Node | None) -> str | None:
    """The value of a plain string literal ('x', "x", `x` without ${}), else None."""
    if node is None:
        return None
    if node.type == "string":
        return text(node)[1:-1]
    if node.type == "template_string" and not any(c.type == "template_substitution" for c in node.children):
        return text(node)[1:-1]
    return None


def model_label(name: str) -> str | None:
    """'user record' for User / UserModel / Users; None for names that are not people."""
    base = name.split(".")[-1]
    base = base[:-5] if base.endswith("Model") and len(base) > 5 else base
    return f"{base.lower()} record" if base.lower() in PEOPLE_TABLES else None


class JsPiiRefs:
    """Personal data passed along by a JavaScript expression (see pii_refs.PiiRefs)."""

    def __init__(self, matcher: PiiMatcher, tainted: dict[str, set[str]] | None = None):
        self.matcher = matcher
        self.tainted = tainted or {}
        self.found: dict[str, str] = {}

    def add(self, label: str, confidence: str) -> None:
        best = self.found.get(label)
        if best is None or CONFIDENCE_ORDER[confidence] < CONFIDENCE_ORDER[best]:
            self.found[label] = confidence

    def name(self, name: str | None) -> None:
        match = self.matcher.match(name) if name else None
        if match and not match.protected:
            self.add(match.label, match.confidence)

    def visit(self, node: Node) -> None:
        kind = node.type
        if kind == "call_expression":
            called = callee(node)
            if any(word in called.lower() for word in SAFE_WRAPPERS):
                return
            parts = called.split(".")
            if len(parts) >= 2 and parts[-1].startswith("find") and (label := model_label(parts[-2])):
                self.add(label, "medium")  # User.findByPk(...) returns a person's record
            for arg in arguments(node):
                self.visit(arg)
            return
        if kind in {"identifier", "shorthand_property_identifier"}:
            for label in self.tainted.get(text(node), ()):
                self.add(label, "medium")
            self.name(text(node))
            return
        if kind == "member_expression":
            if dotted(node) in REQUEST_BODY_JS:
                self.add("request body", "medium")
                return
            self.name(text(node.child_by_field_name("property")))
            obj = node.child_by_field_name("object")
            if obj is not None and obj.type not in {"identifier", "this", "member_expression"}:
                self.visit(obj)  # (await find()).email: look inside the call too
            return
        if kind == "subscript_expression":
            self.name(string_value(node.child_by_field_name("index")))
            return
        if kind == "pair":
            key = node.child_by_field_name("key")
            self.name(string_value(key) if key is not None and key.type == "string" else text(key))
            value = node.child_by_field_name("value")
            if value is not None:
                self.visit(value)
            return
        if kind in {"string", "comment", "number", "regex"} | FUNCTION_TYPES:
            return  # literal text and callbacks are not data
        for child in node.named_children:
            self.visit(child)
