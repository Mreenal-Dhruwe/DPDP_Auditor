"""DPDP-SEC-004: hardcoded secrets or credentials in source or committed config.

Three kinds of clue, all reading files only:
1. Python: a string literal assigned to a secret-looking name - assignments, keyword
   arguments (connect(password="...")) and dict entries ({"api_key": "..."}) - via ast.
2. Other text files: NAME = "value" lines; in config files (.env, YAML, INI, Dockerfile ENV)
   also unquoted NAME=value.
3. Any text file: known key formats (AWS, GitHub, Slack, Google, Stripe, Razorpay, JWT),
   private-key blocks, and passwords inside connection URLs.
Placeholders (changeme, ${VAR}, <your-key>, os.environ lookups) and non-ASCII text are not
secrets. In test files, translation files (i18n/, locales/) and .env.example only the
third kind of clue counts (test logins like admin123 are noise), with low confidence in tests.
Evidence is masked here (the detector knows where the secret is) and again by the safety
net in to_finding().
"""

import ast
import re

from scanner.detectors.source import (
    dotted_name, is_config_file, is_example_file, is_test_file, python_trees, string_key, text_files,
)
from scanner.ingest import Project
from scanner.masking import CONNECTION_PASSWORD, KNOWN_SECRET_PATTERNS, PRIVATE_KEY_HEADER, SECRET_NAME, mask_secret
from scanner.models import Hit
from scanner.pii import split_words

SEC_004 = "DPDP-SEC-004"

# Words that show a secret-looking name holds something else: SECRET_NAME, TOKEN_URL,
# PASSWORD_FIELD, AWS_ACCESS_KEY_ID ... (whole words, so ADMIN_PASSWORD is still a secret)
NOT_A_SECRET_WORDS = {
    "hash", "field", "label", "name", "url", "uri", "endpoint", "header", "param", "type", "length",
    "min", "max", "policy", "reset", "prompt", "placeholder", "regex", "pattern", "expiry", "expires",
    "expiration", "ttl", "count", "file", "path", "env", "var", "id", "algorithm", "alg", "scheme",
    "prefix", "format", "input", "location", "address",  # BeeTokenAddress: a public address
}
PLACEHOLDERS = {
    "changeme", "change_me", "change-me", "password", "secret", "token", "xxx", "todo", "none", "null",
    "example", "dummy", "test", "testing", "sample", "placeholder", "redacted", "your-secret-key",
}
_QUOTED = re.compile(r"""(?<![\w.-])([\w.-]+)['"]?\s*[:=]\s*(['"])([^'"]*)\2""")
_UNQUOTED = re.compile(r"^\s*(?:export\s+|ENV\s+|ARG\s+|-\s*)?([\w.-]+)\s*[:= ]\s*([^\s'\"#]+)\s*(?:#.*)?$")
_KNOWN = re.compile("|".join(f"(?:{p})" for p in KNOWN_SECRET_PATTERNS.values()))


def looks_like_secret(name: str, value: str) -> bool:
    words = split_words(name)
    if set(words) & NOT_A_SECRET_WORDS:
        return False
    if not SECRET_NAME.search(name):
        # any other *Key (primaryKey, cacheKey, sortKey) is usually a field name: only a value
        # that looks generated (letters and digits mixed, 16+ characters) counts
        if not (words and words[-1] == "key" and re.search(r"\d", value) and re.search(r"[A-Za-z]", value)
                and len(value) >= 16 and not re.search(r"\s", value)):
            return False
    v = value.strip()
    lowered = v.lower()
    return not (
        len(v) < 8
        or lowered in PLACEHOLDERS
        or lowered.startswith(("your", "http://", "https://", "/", "./"))
        or any(mark in v for mark in ("${", "{{", "%(", "<", ">", "***"))
        or v.startswith("$")
        or re.fullmatch(r"[A-Z][A-Z0-9_]+", v) is not None  # names an env var instead of holding a value
        or re.search(r"\s", v) is not None  # sentences ("Enter your password") are not secrets
        or len(set(v)) <= 2  # "xxxxxxxx", "00000000"
        or not v.isascii()  # translated UI text ("パスワード..."): secrets are ASCII
    )


def is_translation_file(rel: str) -> bool:
    """i18n files map keys like PASSWORD_HINT to UI text, never to secrets."""
    return any(part.lower() in {"i18n", "locale", "locales", "translations", "lang", "l10n"} for part in rel.split("/")[:-1])


def _python_candidates(tree: ast.Module):
    """(line, name, value) for every string literal given to a name in Python code."""
    for node in ast.walk(tree):
        pairs = []
        if isinstance(node, ast.Assign):
            pairs = [(t, node.value) for t in node.targets]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs = [(node.target, node.value)]
        elif isinstance(node, ast.Call):
            pairs = [(kw.arg, kw.value) for kw in node.keywords if kw.arg]
        elif isinstance(node, ast.Dict):
            pairs = [(string_key(k), v) for k, v in zip(node.keys, node.values) if k is not None]
        for target, value in pairs:
            if isinstance(target, ast.Subscript):
                name = string_key(target.slice)  # app.config["SECRET_KEY"] = "..."
            elif isinstance(target, ast.AST):
                name = dotted_name(target).rsplit(".", 1)[-1]
            else:
                name = target  # keyword or dict key: already a string (or None)
            if name and isinstance(value, ast.Constant) and isinstance(value.value, str):
                yield value.lineno, name, value.value


def _masked(line: str, value: str) -> str:
    return line.replace(value, mask_secret(value))


def hardcoded_secrets(project: Project) -> list[Hit]:
    found: dict[tuple[str, int], Hit] = {}  # one hit per file and line

    def report(rel: str, line_no: int, line: str, value: str, why: str, confidence: str) -> None:
        if (rel, line_no) not in found:
            confidence = "low" if is_test_file(rel) else confidence
            found[(rel, line_no)] = Hit(rule_id=SEC_004, file=rel, line=line_no, confidence=confidence,
                                        evidence=f"{_masked(line, value).strip()}  [{why}]")

    trees = dict(python_trees(project))
    for rel in text_files(project):
        lines = project.read_text(rel).splitlines()
        example = is_example_file(rel)
        for n, line in enumerate(lines, 1):
            known = _KNOWN.search(line)
            if known:
                report(rel, n, line, known.group(0), "known key format", "high")
            elif PRIVATE_KEY_HEADER.search(line):
                report(rel, n, line, "", "private key", "high")
            elif (url := CONNECTION_PASSWORD.search(line)) and not looks_like_placeholder(url.group(1)):
                report(rel, n, line, url.group(1), "password in connection URL", "high")
        if example or is_test_file(rel) or is_translation_file(rel):
            # Name-based checks are skipped here: .env.example holds placeholders, tests hold
            # throwaway logins (admin123), translations hold UI text. Real key formats,
            # private keys and connection-URL passwords above are still reported.
            continue
        if rel in trees:
            for n, name, value in _python_candidates(trees[rel]):
                if looks_like_secret(name, value) and n <= len(lines):
                    report(rel, n, lines[n - 1], value, f"literal value for {name}", "high")
            continue
        for n, line in enumerate(lines, 1):
            for m in _QUOTED.finditer(line):
                if looks_like_secret(m.group(1), m.group(3)):
                    report(rel, n, line, m.group(3), f"literal value for {m.group(1)}", "high")
            if is_config_file(rel) and (m := _UNQUOTED.match(line)) and looks_like_secret(m.group(1), m.group(2)):
                report(rel, n, line, m.group(2), f"literal value for {m.group(1)}", "high")
    return sorted(found.values(), key=lambda h: (h.file, h.line))


def looks_like_placeholder(value: str) -> bool:
    return value.lower() in PLACEHOLDERS or value.startswith("$") or "{" in value or len(value) < 4
