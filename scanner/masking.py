"""Mask secrets and personal data in evidence and context before they can reach a report.

Two layers:
1. A detector that finds a secret masks it itself with mask_secret(), because it knows
   exactly where the secret is.
2. RuleCatalogue.to_finding() runs mask_evidence() over the evidence and over every
   context line as a safety net:
     - string values assigned to secret-looking names (SECRET_KEY = "...", DB_PASSWORD=...)
     - known key formats (AWS, GitHub, Slack, Google, Stripe, Razorpay, JWT)
     - passwords inside connection URLs (postgres://user:PASSWORD@host)
     - long random-looking tokens (e.g. the body lines of a private key)
     - personal-data values matched by personal_data.identifiers in rules/dpdp_rules.yml

Over-masking is acceptable; leaking is not. The SEC-004 detector reuses the secret
patterns below, so detection and masking always agree.
"""

import re
from collections.abc import Callable, Iterable
from typing import Protocol

MASK = "********"  # fixed length, so the mask does not reveal how long the secret was

# Known secret formats: name -> regex for the whole secret value.
KNOWN_SECRET_PATTERNS: dict[str, str] = {
    "AWS access key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "Slack token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "Google API key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "Stripe live key": r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b",
    "Razorpay live key": r"\brzp_live_[0-9A-Za-z]{14,}\b",
    "JSON Web Token": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
}
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")
# scheme://user:PASSWORD@host - group 1 is the password
CONNECTION_PASSWORD = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^:/\s@'\"]+:([^@/\s'\"]+)@")
# Names that suggest a secret value (used for assignments)
SECRET_NAME = re.compile(
    r"secret|passw(?:or)?d|passwd|pwd|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|auth[_-]?key|credential"
    r"|(?:crypto|sign(?:ing)?|encrypt(?:ion)?|hmac|jwt|session|cookie|master)[_-]?key|crypto[_-]?(?:salt|pass)",
    re.IGNORECASE,
)


class IdentifierPattern(Protocol):
    name: str
    pattern: str


def mask_secret(value: str) -> str:
    """'sk_live_abc123...' -> 'sk_live_ab********'; long values keep 4 characters, short ones none."""
    if not value or MASK in value:
        return value  # empty or already masked
    prefix = re.match(r"[A-Za-z]{2,8}_(?:live|test|prod)_", value)
    if prefix:
        keep = prefix.end() + 2
    elif len(value) >= 16:
        keep = 4
    else:
        keep = 0
    return value[: min(keep, len(value) // 2)] + MASK


_SECRET_NAME_TEXT = r"[\w.-]*(?:secret|passw(?:or)?d|pwd|token|api[_-]?key|private[_-]?key|access[_-]?key)[\w.-]*"
# SECRET_KEY = "abc", "password": 'abc', api_key: "abc"   (quoted value, any case)
_QUOTED_SECRET = re.compile(rf"""(\b{_SECRET_NAME_TEXT}['"]?\s*[:=]\s*)(['"])(.*?)\2""", re.IGNORECASE)
# DB_PASSWORD=abc, POSTGRES_PASSWORD: abc, ENV API_TOKEN=abc   (.env / compose / Dockerfile style)
_ENV_SECRET = re.compile(
    r"^(\s*(?:-\s*)?(?:export\s+|ENV\s+|ARG\s+)?[A-Z0-9_]*"
    r"(?:SECRET|PASSWORD|PASSWD|PWD|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_]*\s*[:= ]\s*)([^\s'\"]+)\s*$"
)
# cryptoKey: "a_secure_key_for_crypto_here", signingKey = '...': names ending in "key" are only
# masked for long, space-free values (a React `key: "id"` or i18n key is left alone)
_KEY_NAME_VALUE = re.compile(r"""(\b[\w.-]*(?:crypto|sign|encrypt|hmac|jwt|session|cookie|auth|master|private|secret)[\w.-]*key['"]?\s*[:=]\s*)(['"])([^'"\s]{12,})\2""", re.IGNORECASE)
_KNOWN_SECRETS = re.compile("|".join(f"(?:{p})" for p in KNOWN_SECRET_PATTERNS.values()))
_TOKEN_CHARS = r"A-Za-z0-9+/_\-="
_LONG_TOKEN = re.compile(rf"(?<![{_TOKEN_CHARS}])[{_TOKEN_CHARS}]{{32,}}(?![{_TOKEN_CHARS}])")


def _looks_random(token: str) -> bool:
    """Long hex strings, or long mixes of upper case, lower case and digits (base64)."""
    if re.fullmatch(r"[0-9a-fA-F]{32,}", token):
        return True
    return bool(re.search(r"\d", token) and re.search(r"[a-z]", token) and re.search(r"[A-Z]", token))


def _mask_connection_password(m: re.Match) -> str:
    start, end = m.span(1)
    whole = m.group(0)
    offset = m.start(0)
    return whole[: start - offset] + mask_secret(m.group(1)) + whole[end - offset:]


def mask_secrets(text: str) -> str:
    text = _KEY_NAME_VALUE.sub(lambda m: m.group(1) + m.group(2) + mask_secret(m.group(3)) + m.group(2), text)
    text = _QUOTED_SECRET.sub(lambda m: m.group(1) + m.group(2) + mask_secret(m.group(3)) + m.group(2), text)
    text = _ENV_SECRET.sub(lambda m: m.group(1) + mask_secret(m.group(2)), text)
    text = _KNOWN_SECRETS.sub(lambda m: mask_secret(m.group(0)), text)
    text = CONNECTION_PASSWORD.sub(_mask_connection_password, text)
    return _LONG_TOKEN.sub(lambda m: mask_secret(m.group(0)) if _looks_random(m.group(0)) else m.group(0), text)


def secret_values(lines: Iterable[str]) -> set[str]:
    """Secret values assigned anywhere in a file, so the same value can be masked wherever it
    is repeated: in a trailing comment (`"password": "$2a$..", // Admin_123`), a test, a
    neighbouring line. Plain lower-case words ("password", "changeme") are left out: masking
    them everywhere would hide ordinary code."""
    found: set[str] = set()
    for line in lines:
        for rx, group in ((_KEY_NAME_VALUE, 3), (_QUOTED_SECRET, 3)):
            for m in rx.finditer(line):
                value = m.group(group)
                if len(value) >= 6 and MASK not in value and re.search(r"[^a-z]", value):
                    found.add(value)
        for m in _ENV_SECRET.finditer(line):
            value = m.group(2)
            if len(value) >= 6 and MASK not in value and re.search(r"[^a-z]", value):
                found.add(value)
    return found


def mask_values(text: str, values: Iterable[str]) -> str:
    for value in sorted(values, key=len, reverse=True):  # longest first, so a prefix cannot split one
        if value in text:
            text = text.replace(value, mask_secret(value))
    return text


def _mask_email(m: re.Match) -> str:
    return m.group(0).split("@")[0][:2] + "***@***"


def _mask_upi(m: re.Match) -> str:
    local, handle = m.group(0).split("@", 1)
    return local[:2] + "***@" + handle  # the handle is the bank's, not personal


def _mask_aadhaar(m: re.Match) -> str:
    return "XXXX XXXX " + re.sub(r"\D", "", m.group(0))[-4:]


def _keep_last_four(m: re.Match) -> str:
    return "******" + m.group(0)[-4:]


def _mask_mobile(m: re.Match) -> str:
    text = m.group(0)
    return ("+91 " if text.startswith("+91") else "") + "******" + re.sub(r"\D", "", text)[-4:]


# Order matters: emails before UPI ids (an email contains something UPI-shaped),
# Aadhaar before mobile numbers. Identifiers not listed here (e.g. IFSC) are not personal.
PII_MASKERS: list[tuple[str, Callable[[re.Match], str]]] = [
    ("email", _mask_email),
    ("upi_id", _mask_upi),
    ("aadhaar", _mask_aadhaar),
    ("pan", _keep_last_four),
    ("indian_mobile", _mask_mobile),
]


# "firstName": "John", city = 'Pune', address: "12 Main Street": a quoted literal given to a
# personal-data name is a personal value (seed data, fixtures, examples)
_PII_LITERAL = re.compile(r"""(?<![\w.-])([A-Za-z_][\w.-]*)(['"]?\s*[:=]\s*)(['"])([^'"\n]{2,}?)\3""")


def mask_pii_literals(text: str, matcher) -> str:
    """Mask quoted values assigned to names the PII matcher knows (matcher.match(name))."""
    def repl(m: re.Match) -> str:
        value = m.group(4)
        if MASK in value or "***" in value or not matcher.match(m.group(1)):
            return m.group(0)
        return f"{m.group(1)}{m.group(2)}{m.group(3)}{value[0]}{MASK}{m.group(3)}"
    return _PII_LITERAL.sub(repl, text)


def mask_evidence(text: str, identifiers: Iterable[IdentifierPattern], known_values: Iterable[str] = (), matcher=None) -> str:
    """Safety net applied to evidence and every context line by RuleCatalogue.to_finding().

    known_values: secrets found elsewhere in the same file (see secret_values), masked here too."""
    text = mask_secrets(text)
    text = mask_values(text, known_values)
    if matcher is not None:
        text = mask_pii_literals(text, matcher)
    patterns = {i.name: i.pattern for i in identifiers}
    for name, masker in PII_MASKERS:
        if name in patterns:
            text = re.sub(patterns[name], masker, text)
    return text
