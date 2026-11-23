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
"""

import ast
import re

from scanner.detectors.consent import TEMPLATE_SUFFIXES, attribute, input_tags
from scanner.detectors.schemas import find_tables
from scanner.detectors.source import is_test_file, python_trees, string_key, suffix_of, text_files
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import split_words

CH_001 = "DPDP-CH-001"
NOT_AN_AGE = {"max", "min", "cache", "cookie", "ttl", "token", "session", "password", "header", "file"}
PARENTAL_FLOW = re.compile(
    r"guardian|parental|parent[\s_-]?(?:email|phone|mobile|consent|verification|verify|approval|otp)|"
    r"verify[\s_-]?parent|verifiable[\s_-]?consent", re.IGNORECASE)


def is_age_field(name: str | None) -> bool:
    words = split_words(name or "")
    if not words or set(words) & NOT_AN_AGE:
        return False
    return "dob" in words or "birth" in words or "birthday" in words or "birthdate" in words or "age" in words


def _first_collection(project: Project) -> tuple[str, int, str] | None:
    """(file, line, how) for the first place a DOB / age is collected, backend first."""
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
            return rel, line, f"the backend reads '{key}'"
    for rel in project.files:
        if suffix_of(rel) in TEMPLATE_SUFFIXES and not is_test_file(rel):
            text = project.read_text(rel)
            for offset, tag in input_tags(text):
                if is_age_field(attribute(tag, "name")) or (attribute(tag, "type") or "").lower() == "date" \
                        and is_age_field(attribute(tag, "id")):
                    return rel, text.count("\n", 0, offset) + 1, f"a form asks for '{attribute(tag, 'name')}'"
    for table in find_tables(project):
        for column in table.columns:
            if is_age_field(column.name):
                return table.file, column.line, f"table {table.name} stores '{column.name}'"
    return None


def no_parental_consent(project: Project) -> list[Hit]:
    collected = _first_collection(project)
    if collected is None:
        return []
    for rel in text_files(project):
        if not is_test_file(rel) and PARENTAL_FLOW.search(project.read_text(rel)):
            return []
    rel, line, how = collected
    return [Hit(rule_id=CH_001, scope="project", file=rel, line=line, pii=["dob"], confidence="medium",
                evidence=f"Date of birth / age is collected ({how}), but no parent or guardian consent "
                         f"flow exists anywhere, so under-18s are processed without a parent's consent")]
