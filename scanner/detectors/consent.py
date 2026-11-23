"""Notice and consent detectors: DPDP-NOT-001, DPDP-CON-001 to DPDP-CON-006.

Implemented: DPDP-CON-001 (consent can be given but not withdrawn), DPDP-CON-002
(pre-ticked or default-true consent), DPDP-CON-003 (no evidence of consent) and DPDP-CON-004
(personal data used without a consent check), DPDP-CON-005 (over-collection), DPDP-CON-006 (one language)
and DPDP-NOT-001 (no notice); see their sections.
"""

import ast
import re

from scanner.detectors.javascript import FUNCTION_TYPES, JsPiiRefs, arguments, callee, js_files, line_of, text, walk
from scanner.detectors.pii_refs import PiiRefs
from scanner.detectors.routes import Route, find_routes
from scanner.detectors.schemas import Table, find_tables
from scanner.detectors.source import dotted_name, is_test_file, python_trees, suffix_of, text_files
from scanner.detectors.thirdparty import SEND_METHODS, TRACKING_VENDORS, _clients, _sdk_names
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import default_matcher, split_words

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


# --- DPDP-CON-004: personal data used without checking consent ------------------------------
#
# Only when the app records consent somewhere (a consent table or column, a consent form
# field, a consent key in code). Then a call that sends personal data to
#   - a marketing function (sendPromo, add_to_campaign, newsletter ...),
#   - an analytics SDK (mp.track, analytics.identify, posthog.capture ...), or
#   - an email send inside a marketing-named function
# must sit behind a consent check on the same path: an enclosing if / && / ?: whose
# condition mentions consent, opt-in or subscription, or an earlier `if not consent: return`
# in the same function. A check in a caller (another function) is not seen: medium confidence
# for analytics and email, high for functions that say they are marketing.

CON_004 = "DPDP-CON-004"
MARKETING_WORDS = {"marketing", "promo", "promos", "promotion", "promotions", "promotional", "newsletter",
                   "newsletters", "campaign", "campaigns", "offer", "offers", "advert", "adverts", "advertising",
                   "remarketing", "retarget", "retargeting", "drip"}
EMAIL_SENDS = {"send_mail", "sendmail", "send_email", "sendemail", "send_message", "send", "deliver"}
JS_TRACKERS = {"mixpanel", "analytics", "posthog", "amplitude", "segment", "gtag", "fbq", "clevertap", "moengage",
               "braze", "intercom", "hubspot", "rudderanalytics", "customerio"}
CONSENT_GUARD = re.compile(r"consent|opt[_-]?in|opted|subscri|permission", re.IGNORECASE)
_CONSENT_MARK = re.compile(r"\w*(?:consent|opt_?in|optIn|subscribed)\w*", re.IGNORECASE)
CODE_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".sql"} | TEMPLATE_SUFFIXES


def _consent_recorded(project: Project) -> str | None:
    """Where the app records consent ("models.js:30"), or None if it never does."""
    for table in find_tables(project):
        if "consent" in table.name.lower() or any(_CONSENT_MARK.fullmatch(c.name) for c in table.columns):
            return f"{table.file}:{table.line}"
    for rel in text_files(project):
        if suffix_of(rel) in CODE_SUFFIXES and not is_test_file(rel):
            text = project.read_text(rel)
            if m := _CONSENT_MARK.search(text):
                return f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
    return None


def _py_guarded(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    node = call
    while node in parents:
        parent = parents[node]
        if isinstance(parent, (ast.If, ast.IfExp, ast.While)) and CONSENT_GUARD.search(ast.unparse(parent.test)):
            return True
        if isinstance(parent, ast.BoolOp) and CONSENT_GUARD.search(ast.unparse(parent)):
            return True  # consent_given and send_offer(...)
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return any(isinstance(stmt, ast.If) and stmt.lineno < call.lineno and CONSENT_GUARD.search(ast.unparse(stmt.test))
                       and any(isinstance(s, (ast.Return, ast.Raise)) for s in stmt.body) for stmt in ast.walk(parent))
        node = parent
    return False


def _py_unconsented(project: Project, matcher) -> list[tuple[str, int, str, dict, str]]:
    found = []
    for rel, tree in python_trees(project):
        if is_test_file(rel):
            continue
        sdk = {name: vendor for name, vendor in _sdk_names(tree).items() if vendor in TRACKING_VENDORS}
        clients = _clients(tree, sdk) if sdk else {}
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for func in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            in_marketing = bool(set(split_words(func.name)) & MARKETING_WORDS)
            for call in (n for n in ast.walk(func) if isinstance(n, ast.Call)):
                name = dotted_name(call.func)
                last = name.rsplit(".", 1)[-1]
                receiver = dotted_name(call.func.value) if isinstance(call.func, ast.Attribute) else ""
                vendor = clients.get(receiver) or clients.get(receiver.split(".")[0])
                if vendor and last in SEND_METHODS:
                    what, strong = f"{vendor} ({name})", False
                elif set(split_words(last)) & MARKETING_WORDS:
                    what, strong = f"marketing call {name}()", True
                elif last.lower() in EMAIL_SENDS and in_marketing:
                    what, strong = f"email from {func.name}()", False
                else:
                    continue
                refs = PiiRefs(matcher)
                for arg in call.args + [kw.value for kw in call.keywords]:
                    refs.visit(arg)
                if refs.found and not _py_guarded(call, parents):
                    found.append((rel, call.lineno, what, refs.found, "high" if strong else "medium"))
    return found


def _js_function_names(node) -> list[str]:
    """Names of the functions around a node: `export const sendOffers = () => async (req, res) => ...`."""
    names = []
    current = node.parent
    while current is not None:
        if current.type in FUNCTION_TYPES:
            name = text(current.child_by_field_name("name"))
            if not name and current.parent is not None and current.parent.type == "variable_declarator":
                name = text(current.parent.child_by_field_name("name"))
            names.append(name)
        current = current.parent
    return [n for n in names if n]


def _js_guarded(call) -> bool:
    current, child = call.parent, call
    while current is not None:
        if current.type in {"if_statement", "ternary_expression"}:
            condition = current.child_by_field_name("condition")
            if condition is not None and condition != child and CONSENT_GUARD.search(text(condition)):
                return True
        if current.type == "binary_expression" and "&&" in text(current) and CONSENT_GUARD.search(
                text(current.child_by_field_name("left"))):
            return True
        if current.type in FUNCTION_TYPES:
            body = current.child_by_field_name("body")
            for stmt in walk(body) if body is not None else []:
                if stmt.type == "if_statement" and stmt.start_byte < call.start_byte \
                        and CONSENT_GUARD.search(text(stmt.child_by_field_name("condition"))) \
                        and any(n.type in {"return_statement", "throw_statement"}
                                for n in walk(stmt.child_by_field_name("consequence"))):
                    return True
            return False
        child, current = current, current.parent
    return False


def _js_unconsented(project: Project, matcher) -> list[tuple[str, int, str, dict, str]]:
    found = []
    for f in js_files(project):
        if is_test_file(f.rel):
            continue
        for call in walk(f.root):
            if call.type != "call_expression":
                continue
            called = callee(call)
            parts = called.split(".")
            last = parts[-1]
            if parts[0].lower() in JS_TRACKERS and last in SEND_METHODS and len(parts) > 1:
                what, strong = f"analytics ({called})", False
            elif set(split_words(last)) & MARKETING_WORDS:
                what, strong = f"marketing call {called}()", True
            elif last.lower() in EMAIL_SENDS and any(set(split_words(n)) & MARKETING_WORDS for n in _js_function_names(call)):
                what, strong = f"email ({called})", False
            else:
                continue
            refs = JsPiiRefs(matcher)
            for arg in arguments(call):
                refs.visit(arg)
            if refs.found and not _js_guarded(call):
                found.append((f.rel, line_of(call), what, refs.found, "high" if strong else "medium"))
    return found


def unconsented_use(project: Project) -> list[Hit]:
    where = _consent_recorded(project)
    if where is None:
        return []  # the app never records consent: nothing to check against
    matcher = default_matcher()
    hits = []
    for rel, line, what, found, confidence in _py_unconsented(project, matcher) + _js_unconsented(project, matcher):
        source = project.read_text(rel).splitlines()[line - 1].strip()
        hits.append(Hit(rule_id=CON_004, file=rel, line=line, pii=sorted(found), confidence=confidence,
                        evidence=f"{source}  [{what} receives {', '.join(sorted(found))} with no consent check on "
                                 f"this path; the app records consent ({where})]"))
    return sorted({(h.file, h.line): h for h in hits}.values(), key=lambda h: (h.file, h.line))


# --- DPDP-CON-003: no evidence of consent stored ---------------------------------------------
#
# s.6(10): the fiduciary must be able to prove consent was given. Consent kept as a bare
# yes/no cannot show when it was given or what the person agreed to. Checked:
# - a consent table (name contains "consent"): needs a time column (granted_at, created_at,
#   timestamp ...; Sequelize adds createdAt unless `timestamps: false`) and a purpose or
#   notice-version column
# - a consent flag on another table (users.marketing_consent BOOLEAN): needs a matching time
#   column in the same table (marketing_consent_at, consented_at ...)
# Medium confidence: the evidence may live in a consent manager or an audit log.

CON_003 = "DPDP-CON-003"
TIME_COLUMN = re.compile(r"(_at|_on|At|On|time|date|timestamp|Date|Time)$|^(created|updated|timestamp|date|time)",
                         re.IGNORECASE)
PURPOSE_COLUMN = re.compile(r"purpose|version|notice|policy|consent_text|scope", re.IGNORECASE)
CONSENT_FLAG = re.compile(r"consent|opt_?in|optIn|subscribed|agreed|accepted", re.IGNORECASE)
_SEQUELIZE_NO_TIMESTAMPS = re.compile(r"timestamps\s*:\s*false")


def _auto_timestamps(project: Project, table: Table, tables: list[Table]) -> bool:
    """Sequelize models get createdAt / updatedAt unless the options say timestamps: false."""
    if suffix_of(table.file) not in {".js", ".ts", ".mjs", ".cjs"}:
        return False
    lines = project.read_text(table.file).splitlines()
    later = [t.line for t in tables if t.file == table.file and t.line > table.line]
    chunk = "\n".join(lines[table.line - 1:(min(later) - 1) if later else len(lines)])
    return not _SEQUELIZE_NO_TIMESTAMPS.search(chunk)


def consent_evidence(project: Project) -> list[Hit]:
    tables = find_tables(project)
    hits = []
    for table in tables:
        names = [c.name for c in table.columns]
        has_time = any(TIME_COLUMN.search(n) for n in names) or _auto_timestamps(project, table, tables)
        if "consent" in table.name.lower():
            missing = ([] if has_time else ["when it was given"]) + \
                      ([] if any(PURPOSE_COLUMN.search(n) for n in names) else ["the purpose or notice version"])
            if missing:
                source = project.read_text(table.file).splitlines()[table.line - 1].strip()
                hits.append(Hit(rule_id=CON_003, file=table.file, line=table.line, confidence="medium",
                                evidence=f"{source}  [consent table {table.name} ({', '.join(names) or 'no columns'}) "
                                         f"does not record {' or '.join(missing)}]"))
            continue
        for column in table.columns:
            if not CONSENT_FLAG.search(column.name) or TIME_COLUMN.search(column.name):
                continue
            stem = re.sub(r"(_?(flag|given|granted|status))$", "", column.name, flags=re.IGNORECASE).lower()
            if any(n.lower().startswith(stem) and TIME_COLUMN.search(n) for n in names if n != column.name) \
                    or any(re.search(r"consent(ed)?_?(at|on|date|time)", n, re.IGNORECASE) for n in names):
                continue
            source = project.read_text(table.file).splitlines()[column.line - 1].strip()
            hits.append(Hit(rule_id=CON_003, file=table.file, line=column.line, confidence="medium",
                            evidence=f"{source}  [{table.name}.{column.name} keeps consent as a flag only: no time "
                                     f"it was given and no notice version]"))
    return sorted(hits, key=lambda h: (h.file, h.line))


# --- DPDP-NOT-001: personal data collected without a notice ---------------------------------
#
# s.5(1) / Rule 3(b): before or with the consent request, an itemised notice of the data and
# its purpose. Checked on pages (HTML, templates, JSX/TSX, Vue ...): a <form> with
# personal-data inputs (by name, or type email / tel) and nothing on the page that looks like
# a notice: a privacy link, "privacy", "notice", "we collect", "purpose", "personal data",
# "data protection". Login-style forms (only email and password) are left out. Low
# confidence: the notice may be shown in a modal, an earlier step or a linked page.

NOT_001 = "DPDP-NOT-001"
NOTICE_TEXT = re.compile(r"privacy|notice|we collect|we use your|purpose|personal data|data protection", re.IGNORECASE)
_FORM_TAG = re.compile(r"<form\b", re.IGNORECASE)


def _pii_inputs(text: str, matcher) -> list[tuple[int, str]]:
    """(offset, label) of personal-data inputs on a page."""
    found = []
    for offset, tag in input_tags(text):
        kind = (attribute(tag, "type") or "").lower()
        if kind in {"hidden", "submit", "button", "checkbox", "radio"}:
            continue
        match = matcher.match(attribute(tag, "name") or attribute(tag, "id") or "")
        label = match.label if match else {"email": "email", "tel": "phone"}.get(kind)
        if label:
            found.append((offset, label))
    return found


def missing_notice(project: Project) -> list[Hit]:
    matcher = default_matcher()
    hits = []
    for rel in project.files:
        if suffix_of(rel) not in TEMPLATE_SUFFIXES or is_test_file(rel):
            continue
        text = project.read_text(rel)
        form = _FORM_TAG.search(text)
        inputs = _pii_inputs(text, matcher)
        labels = sorted({label for _, label in inputs})
        if form is None or not labels or set(labels) <= {"email", "password"} or NOTICE_TEXT.search(text):
            continue
        line = text.count("\n", 0, form.start()) + 1
        hits.append(Hit(rule_id=NOT_001, file=rel, line=line, pii=labels, confidence="low",
                        evidence=f"{text.splitlines()[line - 1].strip()}  [the form asks for {', '.join(labels)} but "
                                 f"the page shows no notice of what is collected and why; verify manually: the "
                                 f"notice may be in a modal or an earlier step]"))
    return hits


# --- DPDP-CON-005: over-collection beyond the stated purpose ---------------------------------
#
# s.6(1): collect only what the purpose needs. Two signs of data collected for nothing:
# - a personal-data form field whose name appears in no code file (not .html/.jsx pages) and
#   in no table column, so no handler reads or stores it (Model.create(req.body) stores only
#   the fields that are columns)
# - a mobile permission (AndroidManifest.xml, iOS Info.plist) for contacts, location, SMS, call
#   log, microphone, camera, phone state, accounts or calendar with no code using that API
# Low confidence with a "verify manually" note: another service may read the field.

CON_005 = "DPDP-CON-005"
CODE_FILE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs", ".java", ".kt", ".swift", ".dart", ".go", ".rb", ".php",
                      ".cs", ".sql"}
# permission -> (what it gives, code that uses it)
PERMISSIONS = {
    "READ_CONTACTS": ("contacts", r"ContactsContract|react-native-contacts|\bContacts\.|expo-contacts|CNContactStore"),
    "ACCESS_FINE_LOCATION": ("precise location", r"LocationManager|FusedLocation|[Gg]eolocation|expo-location|CLLocationManager"),
    "ACCESS_COARSE_LOCATION": ("location", r"LocationManager|FusedLocation|[Gg]eolocation|expo-location|CLLocationManager"),
    "READ_SMS": ("SMS messages", r"SmsManager|Telephony\.Sms|SmsRetriever|read-sms|content://sms"),
    "RECEIVE_SMS": ("incoming SMS", r"SmsManager|Telephony\.Sms|SmsRetriever|SMS_RECEIVED"),
    "READ_CALL_LOG": ("call log", r"CallLog"),
    "RECORD_AUDIO": ("microphone", r"MediaRecorder|AudioRecord|getUserMedia|expo-av|AVAudioRecorder"),
    "CAMERA": ("camera", r"\bCamera|launchCamera|ImagePicker|getUserMedia|expo-camera|AVCapture"),
    "READ_PHONE_STATE": ("phone state and identifiers", r"TelephonyManager|getDeviceId|getImei"),
    "GET_ACCOUNTS": ("device accounts", r"AccountManager"),
    "READ_CALENDAR": ("calendar", r"CalendarContract|expo-calendar|EKEventStore"),
}
IOS_KEYS = {"NSContactsUsageDescription": "READ_CONTACTS", "NSLocationWhenInUseUsageDescription": "ACCESS_FINE_LOCATION",
            "NSLocationAlwaysAndWhenInUseUsageDescription": "ACCESS_FINE_LOCATION",
            "NSMicrophoneUsageDescription": "RECORD_AUDIO", "NSCameraUsageDescription": "CAMERA",
            "NSCalendarsUsageDescription": "READ_CALENDAR"}
_ANDROID_PERMISSION = re.compile(r"android\.permission\.([A-Z_]+)")


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def over_collection(project: Project) -> list[Hit]:
    matcher = default_matcher()
    code_files = [rel for rel in text_files(project) if suffix_of(rel) in CODE_FILE_SUFFIXES and not is_test_file(rel)]
    code = "\n".join(project.read_text(rel) for rel in code_files)
    words = {_norm(w) for w in re.findall(r"[A-Za-z_][\w-]*", code)}
    columns = {_norm(c.name) for t in find_tables(project) for c in t.columns}
    hits = []
    for rel in project.files:
        if suffix_of(rel) not in TEMPLATE_SUFFIXES or is_test_file(rel):
            continue
        text = project.read_text(rel)
        for offset, tag in input_tags(text):
            name = attribute(tag, "name") or ""
            match = matcher.match(name) if name else None
            if not match or _norm(name) in words or _norm(name) in columns:
                continue
            line = text.count("\n", 0, offset) + 1
            hits.append(Hit(rule_id=CON_005, file=rel, line=line, pii=[match.label], confidence="low",
                            evidence=f"{text.splitlines()[line - 1].strip()}  [the form asks for '{name}' but no code "
                                     f"or table uses it; verify manually: another service may read it]"))
    for rel in project.files:
        filename = rel.rsplit("/", 1)[-1]
        if filename not in {"AndroidManifest.xml", "Info.plist"} or is_test_file(rel):
            continue
        text = project.read_text(rel)
        found = [(m.start(), m.group(1)) for m in _ANDROID_PERMISSION.finditer(text)] + \
                [(m.start(), IOS_KEYS[m.group(0)]) for m in re.finditer("|".join(IOS_KEYS), text)]
        for offset, permission in found:
            if permission not in PERMISSIONS:
                continue
            what, usage = PERMISSIONS[permission]
            if re.search(usage, code):
                continue
            line = text.count("\n", 0, offset) + 1
            hits.append(Hit(rule_id=CON_005, file=rel, line=line, confidence="low",
                            evidence=f"{text.splitlines()[line - 1].strip()}  [the app asks for {what} access but no "
                                     f"code uses it; verify manually: a library may need it]"))
    return sorted(hits, key=lambda h: (h.file, h.line))


# --- DPDP-CON-006: consent request offered in one language only ------------------------------
#
# s.6(3): the request for consent must be available in English or any language of the Eighth
# Schedule, at the person's choice. Reported per page with consent or notice text when the
# project shows no sign of other languages: no i18n library (i18next, react-intl, vue-i18n,
# ngx-translate, Flask-Babel ...), no translation markup ({% trans %}, gettext, _("..."),
# $t(...), useTranslation), no locale files (locales/, i18n/, translations/, *.po), and no
# page in another language (lang="hi", Devanagari, Tamil ... text). Low confidence: the
# translations may be served by a CMS or a separate site.

CON_006 = "DPDP-CON-006"
I18N_PACKAGES = re.compile(r"i18next|react-intl|vue-i18n|@angular/localize|ngx-translate|next-intl|lingui|@formatjs"
                           r"|node-polyglot|flask[-_]babel|django-modeltranslation|python-i18n"
                           r"|(?m:^\s*babel\b)", re.IGNORECASE)  # Python's Babel in requirements, not @babel/core
I18N_MARKUP = re.compile(r"\{%-?\s*(?:trans|blocktrans|translate)\b|\bn?gettext\(|\b_\(\s*['\"]|\$t\(|\bi18n\.t\("
                         r"|useTranslation\(|<FormattedMessage|\|\s*translate\b|\$localize`")
LOCALE_PARTS = {"locales", "locale", "i18n", "translations", "lang", "langs", "l10n"}
LOCALE_SUFFIXES = {".po", ".mo", ".xlf", ".xliff", ".arb", ".resx"}
_OTHER_LANGUAGE = re.compile(r"""lang\s*=\s*["'](?!en)[a-z]{2}|[ऀ-෿]""", re.IGNORECASE)
_CONSENT_WORDS = re.compile(r"\b(?:consent|i agree|agree to|opt[ -]?in|we collect|privacy notice|terms)\b", re.IGNORECASE)


def _supports_other_languages(project: Project) -> bool:
    for rel in project.files:
        parts = {p.lower() for p in rel.split("/")[:-1]}
        if parts & LOCALE_PARTS or suffix_of(rel) in LOCALE_SUFFIXES:
            return True
    for rel in text_files(project):
        if is_test_file(rel):
            continue
        text = project.read_text(rel)
        name = rel.rsplit("/", 1)[-1]
        if name in {"package.json", "pyproject.toml", "Pipfile"} or name.startswith("requirements"):
            if I18N_PACKAGES.search(text):
                return True
        elif I18N_MARKUP.search(text) or (suffix_of(rel) in TEMPLATE_SUFFIXES and _OTHER_LANGUAGE.search(text)):
            return True
    return False


def single_language_consent(project: Project) -> list[Hit]:
    pages = [rel for rel in project.files if suffix_of(rel) in TEMPLATE_SUFFIXES and not is_test_file(rel)]
    found = []
    for rel in pages:
        for number, line in enumerate(project.read_text(rel).splitlines(), start=1):
            visible = re.sub(r"<[^>]*>", " ", line)
            if _CONSENT_WORDS.search(visible):
                found.append((rel, number, line.strip()))
                break
    if not found or _supports_other_languages(project):
        return []
    return [Hit(rule_id=CON_006, file=rel, line=number, confidence="low",
                evidence=f"{text}  [consent text only in English: no translations, i18n library or locale "
                         f"files; verify manually: translations may come from a CMS]")
            for rel, number, text in found]
