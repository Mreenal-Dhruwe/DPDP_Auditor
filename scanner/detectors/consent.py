"""Notice and consent detectors: DPDP-NOT-001, DPDP-CON-001 to DPDP-CON-006.

Implemented: DPDP-CON-001 (consent can be given but not withdrawn) and DPDP-CON-002
(pre-ticked or default-true consent).
"""

import ast
import re

from scanner.detectors.routes import Route, find_routes
from scanner.detectors.source import dotted_name, is_test_file, python_trees, suffix_of
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import split_words

CON_001 = "DPDP-CON-001"
CON_002 = "DPDP-CON-002"
TEMPLATE_SUFFIXES = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".jsx", ".tsx", ".vue", ".svelte",
                     ".ejs", ".hbs", ".erb", ".php", ".twig"}
CONSENT_TEXT = ("consent", "marketing", "newsletter", "opt-in", "opt in", "optin", "offers", "promotion",
                "promotional", "subscribe", "agree", "terms", "product updates", "share my data", "partners")
CONSENT_FIELD_WORDS = {"consent", "consents", "marketing", "newsletter", "optin", "subscribed", "subscribe",
                       "agree", "agreed", "accepted", "promotions", "offers"}

GRANT_STRONG = ("consent", "optin")  # clearly about consent
GRANT_WEAK = ("agree", "accept")  # could also be "accept invite": lower confidence
WITHDRAW = ("withdraw", "revoke", "revocation", "optout", "unsubscribe", "decline")
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _words(route: Route) -> list[str]:
    """Words in the function name and path, plus joined neighbours: opt_in -> 'optin'."""
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", f"{route.function} {route.path}")  # camelCase
    words = re.findall(r"[a-z]+", text.lower())
    return words + [a + b for a, b in zip(words, words[1:])]


def _mentions(words: list[str], stems: tuple[str, ...]) -> bool:
    return any(word.startswith(stem) for word in words for stem in stems)


def consent_withdrawal(project: Project) -> list[Hit]:
    """DPDP-CON-001: a route grants consent, but no route anywhere withdraws it.

    An absence check over the whole project, so the finding has scope 'project'; it points
    at the first grant route as related code.
    """
    grants, withdrawals = [], []
    for route in find_routes(project):
        words = _words(route)
        if _mentions(words, WITHDRAW) or ("DELETE" in route.methods and _mentions(words, ("consent",))):
            withdrawals.append(route)
        elif route.methods & WRITE_METHODS and _mentions(words, GRANT_STRONG + GRANT_WEAK):
            grants.append(route)
    if not grants or withdrawals:
        return []

    first = min(grants, key=lambda r: (r.file, r.line))
    strong = any(_mentions(_words(r), GRANT_STRONG) for r in grants)
    method = sorted(first.methods & WRITE_METHODS)[0]
    more = f" (+{len(grants) - 1} more grant routes)" if len(grants) > 1 else ""
    handler = f" ({first.function})" if first.function else ""
    evidence = (f"{method} {first.path or '?'}{handler} grants consent{more};"
                f" no route anywhere withdraws or revokes it")
    return [Hit(rule_id=CON_001, scope="project", file=first.file, line=first.line,
                evidence=evidence, confidence="high" if strong else "medium")]


# --- DPDP-CON-002: pre-ticked or default-true consent ----------------------------------

def input_tags(text: str) -> list[tuple[int, str]]:
    """(offset, tag text) for every <input ...> tag. Reads up to the closing '>' while
    skipping quoted strings and {...} expressions, so JSX like onChange={e => f(e)} works."""
    tags = []
    for m in re.finditer(r"<input\b", text, re.IGNORECASE):
        i, depth, quote = m.end(), 0, ""
        while i < len(text):
            char = text[i]
            if quote:
                quote = "" if char == quote else quote
            elif char in "\"'`":
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif char == ">" and depth <= 0:
                break
            i += 1
        tags.append((m.start(), text[m.start():i + 1]))
    return tags


def attribute(tag: str, name: str) -> str | None:
    m = re.search(rf"""(?<![\w.:-]){name}\s*=\s*(?:"([^"]*)"|'([^']*)'|\{{([^}}]*)\}})""", tag, re.IGNORECASE)
    return next((g for g in m.groups() if g is not None), "") if m else None


def is_pre_ticked(tag: str) -> bool:
    """checked, checked="checked", checked={true}, defaultChecked ... but not checked={state}."""
    for m in re.finditer(r"(?<![\w.$:-])(checked|defaultChecked|v-bind:checked|:checked)(?![\w-])", tag):
        rest = tag[m.end():].lstrip()
        if not rest.startswith("="):
            return True  # boolean attribute: present means ticked
        value = re.match(r"""=\s*(?:"([^"]*)"|'([^']*)'|\{([^}]*)\}|(\w+))""", rest)
        raw = next((g for g in value.groups() if g is not None), "") if value else ""
        if raw.strip().lower() in {"", "checked", "true"}:
            return True
    return False


def _label_text(text: str, offset: int, tag: str) -> str:
    """The text of the <label> around the checkbox (or the text right after it)."""
    start = text.rfind("<label", 0, offset)
    if start != -1 and "</label" not in text[start:offset].lower():
        end = text.lower().find("</label", offset)
        return text[start:end if end != -1 else offset + 300]
    return text[offset:offset + len(tag) + 200]


def _pre_ticked_checkboxes(project: Project) -> list[Hit]:
    hits = []
    for rel in project.files:
        if suffix_of(rel) not in TEMPLATE_SUFFIXES or is_test_file(rel):
            continue
        text = project.read_text(rel)
        for offset, tag in input_tags(text):
            if (attribute(tag, "type") or "").lower() != "checkbox" or not is_pre_ticked(tag):
                continue
            about = " ".join(filter(None, [attribute(tag, "name"), attribute(tag, "id"), attribute(tag, "value"),
                                           re.sub(r"<[^>]+>", " ", _label_text(text, offset, tag))])).lower()
            about = about.replace("_", " ").replace("-", " ")
            if not any(word.replace("-", " ") in about for word in CONSENT_TEXT):
                continue  # a ticked "remember me" box is not consent
            line = text.count("\n", 0, offset) + 1
            hits.append(Hit(rule_id=CON_002, file=rel, line=line, confidence="high",
                            evidence=f"{text.splitlines()[line - 1].strip()}  [consent checkbox is ticked by default]"))
    return hits


def _true_by_default(value: ast.AST | None) -> bool:
    if isinstance(value, ast.Constant):
        return value.value is True
    if isinstance(value, ast.Call):  # Column(Boolean, default=True), BooleanField(default=True), Field(True)
        for kw in value.keywords:
            if kw.arg in {"default", "server_default"} and (
                (isinstance(kw.value, ast.Constant) and kw.value.value in (True, "true", "1", "t"))
                or dotted_name(kw.value).lower().endswith("true()")
            ):
                return True
        return bool(value.args) and isinstance(value.args[0], ast.Constant) and value.args[0].value is True \
            and dotted_name(value.func).rsplit(".", 1)[-1] == "Field"
    return False


def _default_true_fields(project: Project) -> list[Hit]:
    hits = []
    for rel, tree in python_trees(project):
        if is_test_file(rel):
            continue
        lines = project.read_text(rel).splitlines()
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            for stmt in cls.body:
                target, value = (stmt.targets[0], stmt.value) if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                    else (stmt.target, stmt.value) if isinstance(stmt, ast.AnnAssign) else (None, None)
                if not isinstance(target, ast.Name) or not (set(split_words(target.id)) & CONSENT_FIELD_WORDS):
                    continue
                if _true_by_default(value):
                    hits.append(Hit(rule_id=CON_002, file=rel, line=stmt.lineno, confidence="high",
                                    evidence=f"{lines[stmt.lineno - 1].strip()}  [{cls.name}.{target.id} defaults to consent given]"))
    return hits


def pre_ticked_consent(project: Project) -> list[Hit]:
    """DPDP-CON-002: a consent checkbox ticked by default, or a consent field that defaults
    to True. Consent must be a clear affirmative action by the user (s.6(1))."""
    return sorted(_pre_ticked_checkboxes(project) + _default_true_fields(project), key=lambda h: (h.file, h.line))
