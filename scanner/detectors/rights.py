"""Rights detectors: DPDP-RT-001 to DPDP-RT-003 (access, correction and erasure, grievance)
and DPDP-BR-001 (breach notification).

Implemented: RT-001, RT-002, RT-003. All three are absence checks over the whole project,
and only run when the project holds personal data (a table with personal-data columns) and
is an application (it has web routes, or pages for RT-003). Routes come from routes.py
(Flask, FastAPI, Express), so they are found by path and method:
- RT-001 access:  a route returning the user's own data - /me, /profile, /account, /whoami,
                  /my-data, /export, /userinfo ... (GET, or any method for an export)
- RT-002 correct: PUT / PATCH / POST on such a path (not password, login or consent paths)
         erase:   DELETE on such a path, or any route about erasure / account deletion
- RT-003 grievance: a grievance, complaint, contact, support or feedback route, a page
                  named like that, or a grievance / DPO / privacy@ contact in a page
Each missing right is one project-wide finding, pointing at the first personal-data table.
Medium confidence: the right may be served by another system (a help desk, a CRM).
"""

import re

from scanner.detectors.consent import TEMPLATE_SUFFIXES
from scanner.detectors.routes import Route, find_routes
from scanner.detectors.schemas import Table, find_tables
from scanner.detectors.source import is_test_file, name_of, suffix_of, text_files
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import default_matcher

RT_001 = "DPDP-RT-001"
RT_002 = "DPDP-RT-002"
RT_003 = "DPDP-RT-003"
OWN_DATA_SEGMENTS = {"me", "self", "profile", "profiles", "account", "myaccount", "my-account", "my_account",
                     "my-data", "mydata", "my_data", "whoami", "current-user", "currentuser", "current_user",
                     "userinfo", "user-info", "my-profile", "settings"}
EXPORT_WORDS = ("export", "download-my-data", "data-portability", "takeout")
NOT_CORRECTION = ("password", "login", "logout", "consent", "token", "session", "otp", "2fa", "totp")
ERASE_WORDS = ("erase", "erasure", "delete-account", "deleteaccount", "delete_account", "close-account",
               "deactivate", "forget", "data-deletion", "remove-account")
GRIEVANCE_WORDS = ("grievance", "complaint", "contact", "support", "feedback", "helpdesk", "help-desk", "dpo",
                   "privacy-request", "data-request")
CONTACT_TEXT = re.compile(r"grievance|data protection officer|\bDPO\b|(?:privacy|grievance|dpo|dataprotection)@",
                          re.IGNORECASE)


def personal_data_table(project: Project) -> Table | None:
    """The first table holding personal data, or None."""
    matcher = default_matcher()
    return next((t for t in find_tables(project) if any(matcher.match(c.name) for c in t.columns)), None)


def _segments(route: Route) -> list[str]:
    return [s.lower() for s in route.path.split("/") if s and not s.startswith((":", "<", "{"))]


def _own_data(route: Route) -> bool:
    return bool(set(_segments(route)) & OWN_DATA_SEGMENTS)


def _access(route: Route) -> bool:
    path = route.path.lower()
    return ("GET" in route.methods and _own_data(route)) or any(w in path for w in EXPORT_WORDS)


def _correction(route: Route) -> bool:
    path = route.path.lower()
    return bool(route.methods & {"PUT", "PATCH", "POST"}) and _own_data(route) \
        and not any(w in path for w in NOT_CORRECTION)


def _erasure(route: Route) -> bool:
    path = route.path.lower()
    return ("DELETE" in route.methods and _own_data(route)) or any(w in path for w in ERASE_WORDS)


def _project_hit(rule_id: str, table: Table, evidence: str) -> Hit:
    return Hit(rule_id=rule_id, scope="project", file=table.file, line=table.line, confidence="medium",
               evidence=f"{evidence} (personal data is held, e.g. table {table.name})")


def _app_routes(project: Project) -> list[Route]:
    return [r for r in find_routes(project) if not is_test_file(r.file)]


def no_access_route(project: Project) -> list[Hit]:
    table = personal_data_table(project)
    routes = _app_routes(project)
    if table is None or not routes or any(_access(r) for r in routes):
        return []
    return [_project_hit(RT_001, table, f"None of the {len(routes)} routes lets users see or export their own "
                                         f"data (no GET /me, /profile, /account or /export)")]


def no_correction_or_erasure(project: Project) -> list[Hit]:
    table = personal_data_table(project)
    routes = _app_routes(project)
    if table is None or not routes:
        return []
    missing = ([] if any(_correction(r) for r in routes) else ["correct (PUT/PATCH /me or /profile)"]) + \
              ([] if any(_erasure(r) for r in routes) else ["erase (DELETE /me or /account)"])
    if not missing:
        return []
    return [_project_hit(RT_002, table, f"No route lets users {' or '.join(missing)} their own data")]


def _pages(project: Project) -> list[str]:
    return [rel for rel in project.files if suffix_of(rel) in TEMPLATE_SUFFIXES and not is_test_file(rel)]


def no_grievance_channel(project: Project) -> list[Hit]:
    table = personal_data_table(project)
    routes = _app_routes(project)
    pages = _pages(project)
    if table is None or not (routes or pages):
        return []
    if any(any(w in r.path.lower() for w in GRIEVANCE_WORDS) for r in routes):
        return []
    if any(any(w in name_of(rel).lower() for w in GRIEVANCE_WORDS) for rel in pages):
        return []
    for rel in text_files(project):
        if rel in pages or (suffix_of(rel) in {".js", ".ts", ".md"} and "frontend" in rel.lower()):
            if CONTACT_TEXT.search(project.read_text(rel)):
                return []
    return [_project_hit(RT_003, table, "No grievance, complaint or contact route or page, and no grievance "
                                        "officer, DPO or privacy@ contact in the pages")]
