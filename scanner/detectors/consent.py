"""Notice and consent detectors: DPDP-NOT-001, DPDP-CON-001 to DPDP-CON-006.

Implemented: DPDP-CON-001 (consent can be given but not withdrawn).
"""

import re

from scanner.detectors.routes import Route, find_routes
from scanner.ingest import Project
from scanner.models import Hit

CON_001 = "DPDP-CON-001"

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
    evidence = (f"{method} {first.path or '?'} ({first.function}) grants consent{more};"
                f" no route anywhere withdraws or revokes it")
    return [Hit(rule_id=CON_001, scope="project", file=first.file, line=first.line,
                evidence=evidence, confidence="high" if strong else "medium")]
