"""Children detectors: DPDP-CH-001 (no verifiable parental consent) and DPDP-CH-002
(tracking or targeted ads possible for children).

Implemented: DPDP-CH-001, an absence check over the whole project:
1. Is a date of birth or age collected? Looked for in Python request handling (form["dob"],
   data.get("age")), in form inputs (<input name="dob">) and in table columns.
2. Is there a parent / guardian consent flow anywhere? Words like guardian, parental,
   parent_email, parent_consent, verify_parent in code and templates.
Collected and no flow -> one project-wide finding, pointing at the first place the data is
collected (backend code first, then forms, then schema). An age check alone (is_adult) is
not a parental-consent flow: under-18s still get processed without a parent's consent.

Implemented: DPDP-CH-002 (s.9(3): no tracking, behavioural monitoring or targeted ads aimed
at children). Only when the app collects a date of birth or age (same search as CH-001):
- trackers in pages and frontend code: Google Analytics / Tag Manager, Meta Pixel, AdSense,
  Google Ads, LinkedIn Insight, Hotjar, Clarity, Segment, Mixpanel, PostHog, Amplitude,
  Firebase Analytics, CleverTap, MoEngage (script URLs and init calls; *.min.js skipped)
- backend tracking calls to analytics SDKs (thirdparty.py: mp.track, analytics.identify ...)
A tracker is fine when an age check gates it: an if / {% if %} / && / ?: mentioning adult,
minor, child, age, dob or 18 in the lines just before it (pages, JS), or an enclosing `if`
or an earlier `if not adult: return` (Python). One finding per file and tracker. High
confidence for ad trackers or a page that itself asks for the age, medium otherwise.
"""

import ast
import re
from collections.abc import Iterator

from scanner.detectors.consent import TEMPLATE_SUFFIXES, attribute, input_tags
from scanner.detectors.schemas import find_tables
from scanner.detectors.source import dotted_name, is_test_file, python_trees, string_key, suffix_of, text_files
from scanner.detectors.thirdparty import SEND_METHODS, TRACKING_VENDORS, _clients, _sdk_names
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import split_words

CH_001 = "DPDP-CH-001"
CH_002 = "DPDP-CH-002"
NOT_AN_AGE = {"max", "min", "cache", "cookie", "ttl", "token", "session", "password", "header", "file"}
PARENTAL_FLOW = re.compile(
    r"guardian|parental|parent[\s_-]?(?:email|phone|mobile|consent|verification|verify|approval|otp)|"
    r"verify[\s_-]?parent|verifiable[\s_-]?consent", re.IGNORECASE)


def is_age_field(name: str | None) -> bool:
    words = split_words(name or "")
    if not words or set(words) & NOT_AN_AGE:
        return False
    return "dob" in words or "birth" in words or "birthday" in words or "birthdate" in words or "age" in words


def _collections(project: Project) -> Iterator[tuple[str, int, str]]:
    """(file, line, how) for each file where a DOB / age is collected: backend code first,
    then forms, then table columns. One entry per file (its first place)."""
    for rel, tree in python_trees(project):
        if is_test_file(rel):
            continue
        keys = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and is_age_field(string_key(node.slice)):
                keys.append((node.lineno, string_key(node.slice)))
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" \
                    and node.args and is_age_field(string_key(node.args[0])):
                keys.append((node.lineno, string_key(node.args[0])))
        if keys:
            line, key = min(keys)
            yield rel, line, f"the backend reads '{key}'"
    for rel in project.files:
        if suffix_of(rel) in TEMPLATE_SUFFIXES and not is_test_file(rel):
            text = project.read_text(rel)
            for offset, tag in input_tags(text):
                if is_age_field(attribute(tag, "name")) or (attribute(tag, "type") or "").lower() == "date" \
                        and is_age_field(attribute(tag, "id")):
                    yield rel, text.count("\n", 0, offset) + 1, f"a form asks for '{attribute(tag, 'name')}'"
                    break
    for table in find_tables(project):
        for column in table.columns:
            if is_age_field(column.name):
                yield table.file, column.line, f"table {table.name} stores '{column.name}'"
                break


def _first_collection(project: Project) -> tuple[str, int, str] | None:
    return next(_collections(project), None)


# A date of birth alone is a weak clue: most apps ask adults for it. A stronger one is code that
# shows minors can be users: an age check against 18, or minor / under-18 / kids / school words
# ("child" is not used: it is DOM and React vocabulary).
_MINOR_WORDS = (r"is[_ ]?minor|minors?|under[_ -]?18|under[_ -]?age(?:d)?|is[_ ]?adult|over[_ -]?18|"
                r"juveniles?|kids?|students?|schools?")
_AGE_CHECK = r"\bage\w*\s*(?:<|>)=?\s*1[78]\b|(?:<|>)=?\s*1[78]\b[^\n]{0,20}\bage\b|\b1[78]\s*(?:<|>)=?\s*\w*age\b"
MINOR_SIGNAL = re.compile(rf"\b(?:{_MINOR_WORDS})\b|{_AGE_CHECK}", re.IGNORECASE)
MINOR_SIGNAL_NO_JS = re.compile(rf"\b(?:{_MINOR_WORDS})\b|{_AGE_CHECK}", re.IGNORECASE)
CODE_SUFFIXES = TEMPLATE_SUFFIXES | {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".kt"}


def _minor_signal(project: Project) -> str | None:
    """First sign (file:line, matched text) that minors can use the app, else None."""
    for rel in text_files(project):
        suffix = suffix_of(rel)
        if suffix not in CODE_SUFFIXES or is_test_file(rel):
            continue
        if m := MINOR_SIGNAL.search(project.read_text(rel)):
            text = project.read_text(rel)
            return f"{rel}:{text.count(chr(10), 0, m.start()) + 1} '{m.group(0).strip()}'"
    return None


def no_parental_consent(project: Project) -> list[Hit]:
    collected = _first_collection(project)
    if collected is None:
        return []
    for rel in text_files(project):
        if not is_test_file(rel) and PARENTAL_FLOW.search(project.read_text(rel)):
            return []
    rel, line, how = collected
    signal = _minor_signal(project)
    evidence = (f"Date of birth / age is collected ({how}), but no parent or guardian consent "
                f"flow exists anywhere, so under-18s are processed without a parent's consent")
    if signal:
        return [Hit(rule_id=CH_001, scope="project", file=rel, line=line, pii=["dob"], confidence="medium",
                    evidence=f"{evidence} [the code deals with minors: {signal}]")]
    return [Hit(rule_id=CH_001, scope="project", file=rel, line=line, pii=["dob"], confidence="low",
                evidence=f"{evidence} [only a date of birth was found, nothing shows minors use the app; "
                         f"verify manually: it may be collected from adults only]")]


# --- DPDP-CH-002: tracking or targeted ads possible for children ----------------------------

# (pattern, tracker name, is it an advertising tracker?)
TRACKERS = [
    (r"googletagmanager\.com/gtag/js|gtag\(\s*['\"]config['\"]", "Google Analytics (gtag.js)", False),
    (r"googletagmanager\.com/gtm\.js", "Google Tag Manager", False),
    (r"google-analytics\.com/(?:analytics|ga)\.js|\bReactGA4?\.initialize\(|\bga\(\s*['\"]create['\"]",
     "Google Analytics", False),
    (r"connect\.facebook\.net/[\w_]+/fbevents\.js|\bfbq\(\s*['\"]init['\"]|ReactPixel\.init\(", "Meta Pixel", True),
    (r"pagead2\.googlesyndication\.com|\badsbygoogle\b", "Google AdSense", True),
    (r"googleadservices\.com|doubleclick\.net", "Google Ads", True),
    (r"snap\.licdn\.com|_linkedin_partner_id", "LinkedIn Insight Tag", True),
    (r"static\.hotjar\.com|\bhj\(\s*['\"]identify|Hotjar\.init\(", "Hotjar session recording", False),
    (r"clarity\.ms/tag", "Microsoft Clarity session recording", False),
    # browser snippets and Node server SDKs (Mixpanel.init, new PostHog(...), new Analytics({ writeKey }))
    (r"cdn\.segment\.com|\banalytics\.load\(|\bnew\s+Analytics\(\s*\{\s*writeKey", "Segment", False),
    (r"\b[Mm]ixpanel\.init\(", "Mixpanel", False),
    (r"\b[Pp]ost[Hh]og\.init\(|\bnew\s+PostHog\(", "PostHog", False),
    (r"\b[Aa]mplitude\.(?:init|getInstance)\(", "Amplitude", False),
    (r"\bgetAnalytics\(", "Firebase Analytics", False),
    (r"\bclevertap\.(?:init|account\.push)\b", "CleverTap", False),
    (r"\bmoengage\.(?:initialize|init)\(|Moengage\s*=", "MoEngage", False),
]
_TRACKERS = [(re.compile(p), name, ads) for p, name, ads in TRACKERS]
TRACKER_SUFFIXES = TEMPLATE_SUFFIXES | {".js", ".ts", ".mjs", ".cjs"}
AGE_WORDS = {"adult", "adults", "minor", "minors", "child", "children", "kid", "kids", "age", "dob", "birth",
             "birthdate", "birthday", "18", "over18", "under18"}
_CONDITION = re.compile(r"\bif\b|\{%-?\s*if\b|&&|\?|\bunless\b|v-if|\*ngIf", re.IGNORECASE)
GATE_WINDOW = 12  # lines before a tracker searched for an age check


def _mentions_age(text: str) -> bool:
    return bool(set(split_words(text)) & AGE_WORDS)


def _age_gated_text(lines: list[str], line: int) -> bool:
    """An age condition in the lines just before (or on) a tracker in a page or JS file."""
    window = lines[max(0, line - 1 - GATE_WINDOW):line]
    return any(_CONDITION.search(text) and _mentions_age(text) for text in window)


def _frontend_trackers(project: Project, age_files: set[str]) -> list[tuple[str, int, str, bool]]:
    found = []
    for rel in text_files(project):
        if suffix_of(rel) not in TRACKER_SUFFIXES or is_test_file(rel) or rel.endswith(".min.js"):
            continue
        text = project.read_text(rel)
        lines = text.splitlines()
        for pattern, name, ads in _TRACKERS:
            for m in pattern.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                if not _age_gated_text(lines, line):
                    found.append((rel, line, name, ads or rel in age_files))
                    break  # one finding per file and tracker
    return found


def _names_in(node: ast.AST) -> str:
    return " ".join(dotted_name(n) for n in ast.walk(node) if isinstance(n, (ast.Name, ast.Attribute)))


def _python_gated(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    """An enclosing `if` on age, or an earlier `if not adult: return` in the same function."""
    node = call
    while node in parents:
        parent = parents[node]
        if isinstance(parent, (ast.If, ast.IfExp, ast.While)) and _mentions_age(_names_in(parent.test)):
            return True
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for stmt in ast.walk(parent):
                if isinstance(stmt, ast.If) and stmt.lineno < call.lineno and _mentions_age(_names_in(stmt.test)) \
                        and any(isinstance(s, (ast.Return, ast.Raise)) for s in stmt.body):
                    return True
            return False
        node = parent
    return False


def _backend_tracking(project: Project) -> list[tuple[str, int, str, bool]]:
    found = []
    for rel, tree in python_trees(project):
        sdk = {name: vendor for name, vendor in _sdk_names(tree).items() if vendor in TRACKING_VENDORS}
        if not sdk or is_test_file(rel):
            continue
        clients = _clients(tree, sdk)
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        seen = set()
        for node in sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)), key=lambda n: n.lineno):
            if not isinstance(node.func, ast.Attribute) or node.func.attr not in SEND_METHODS:
                continue
            receiver = dotted_name(node.func.value)
            vendor = clients.get(receiver) or clients.get(receiver.split(".")[0])
            if vendor and vendor not in seen and not _python_gated(node, parents):
                seen.add(vendor)
                found.append((rel, node.lineno, vendor, False))
    return found


def tracking_children(project: Project) -> list[Hit]:
    collected = _first_collection(project)
    if collected is None:
        return []
    age_file, age_line, how = collected
    age_files = {rel for rel, _, _ in _collections(project)}  # a tracker on such a page: high confidence
    hits = []
    for rel, line, name, high in _frontend_trackers(project, age_files) + _backend_tracking(project):
        source = project.read_text(rel).splitlines()[line - 1].strip()
        hits.append(Hit(
            rule_id=CH_002, file=rel, line=line, pii=["dob"], confidence="high" if high else "medium",
            evidence=f"{source}  [{name} runs for every user, children included: the app collects date of "
                     f"birth / age ({how}, {age_file}:{age_line}) but no age check stops the tracking]",
        ))
    return sorted(hits, key=lambda h: (h.file, h.line))
