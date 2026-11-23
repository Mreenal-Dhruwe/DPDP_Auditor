"""Which personal data does a Python expression pass along? Shared by the detectors that
look at what goes INTO a call: logs (SEC-001) and third-party SDKs (TP-001).

    refs = PiiRefs(default_matcher())
    refs.visit(call_argument)
    refs.found   # {"email": "high", "request body": "medium"}

Counted: variables (email), attributes (user.email), string keys (row["phone"],
{"aadhaar": ...}) and f-string parts. Not counted: literal text ("aadhaar %s"), function
names (format_phone(...)), protected values (password_hash) and anything wrapped in a
masking call (mask_email(email), hash(phone), redact(...)).
"""

import ast

from scanner.detectors.source import dotted_name, string_key
from scanner.pii import PiiMatcher

SAFE_WRAPPERS = ("mask", "redact", "hash", "anonymi", "pseudonym", "encrypt", "sha", "md5", "token", "scrub")
REQUEST_BODY = {"json", "form", "data", "values", "body", "files", "get_json"}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def best_confidence(found: dict[str, str]) -> str:
    return min(found.values(), key=CONFIDENCE_ORDER.get)


class PiiRefs:
    def __init__(self, matcher: PiiMatcher):
        self.matcher = matcher
        self.found: dict[str, str] = {}

    def add(self, label: str, confidence: str) -> None:
        best = self.found.get(label)
        if best is None or CONFIDENCE_ORDER[confidence] < CONFIDENCE_ORDER[best]:
            self.found[label] = confidence

    def name(self, name: str | None) -> None:
        match = self.matcher.match(name) if name else None
        if match and not match.protected:
            self.add(match.label, match.confidence)

    def visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            called = dotted_name(node.func).lower()
            if any(word in called for word in SAFE_WRAPPERS):
                return  # mask_email(email): safe
            if called.startswith("request.") and called.rsplit(".", 1)[-1] in REQUEST_BODY:
                self.add("request body", "medium")
            for child in node.args + [kw.value for kw in node.keywords]:
                self.visit(child)  # not node.func: format_phone(...) is a function, not data
            return
        if isinstance(node, ast.Name):
            self.name(node.id)
        elif isinstance(node, ast.Attribute):
            if dotted_name(node) in {f"request.{b}" for b in REQUEST_BODY}:
                self.add("request body", "medium")
                return
            self.name(node.attr)
        elif isinstance(node, ast.Subscript):
            key = string_key(node.slice)
            if key is not None:
                self.name(key)  # row["email"] -> email; request.form["email"] is not the whole body
                if dotted_name(node.value) in {f"request.{b}" for b in REQUEST_BODY}:
                    return
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is not None:
                    self.name(string_key(key))
                self.visit(value)
            return
        elif isinstance(node, ast.Constant):
            return  # literal text is not data
        for child in ast.iter_child_nodes(node):
            self.visit(child)
