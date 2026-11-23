"""Retention detectors: DPDP-RET-001 to DPDP-RET-003 (no erasure path, immediate hard
delete, no pre-erasure notice).

Implemented: DPDP-RET-001. Every table holding personal data (any sensitivity, protected or
not - an encrypted Aadhaar number still has to be erasable) needs some way to erase or
anonymise it in the application code. Accepted as an erase path, in code files (not .sql
files: a DELETE in a seed or migration file is not a user-erasure path):
- DELETE FROM <table>, TRUNCATE <table>
- UPDATE <table> SET ... NULL (anonymising)
- ORM deletes: <Model>.query...delete(), <Model>.objects...delete(), delete(<Model>),
  session.delete(...) in a file that uses <Model>
- a function whose name mentions anonymise / anonymize / purge / erase / forget in a file
  that mentions the table or model
One finding per table, at its definition. Confidence is medium: erasure may also happen
outside this repository (a database job, another service).
"""

import re

from scanner.detectors.schemas import Table, find_tables
from scanner.detectors.source import suffix_of, text_files
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import default_matcher

RET_001 = "DPDP-RET-001"
_ERASE_FUNCTION = re.compile(r"\b(?:def|function|const|let|var)\s+\w*(?:anonymi[sz]|purge|erase|forget)\w*", re.IGNORECASE)


def _erase_patterns(table: Table) -> list[re.Pattern]:
    name = re.escape(table.name)
    patterns = [
        rf"\bdelete\s+from\s+[`\"\[]?(?:\w+\.)?{name}\b",
        rf"\btruncate\s+(?:table\s+)?[`\"\[]?{name}\b",
        rf"\bupdate\s+[`\"\[]?{name}[`\"\]]?\s+set\b[^;]{{0,300}}?\bnull\b",
    ]
    if table.model:
        model = re.escape(table.model)
        patterns += [rf"\b{model}\.(?:query|objects)\b[^\n]*\.delete\(", rf"\bdelete\(\s*{model}\b"]
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


def _has_erase_path(table: Table, code: dict[str, str]) -> bool:
    patterns = _erase_patterns(table)
    mentions = re.compile(rf"\b(?:{re.escape(table.name)}{'|' + re.escape(table.model) if table.model else ''})\b",
                          re.IGNORECASE)
    for text in code.values():
        if any(p.search(text) for p in patterns):
            return True
        if mentions.search(text) and (_ERASE_FUNCTION.search(text) or (table.model and "session.delete(" in text)):
            return True
    return False


def no_erase_path(project: Project) -> list[Hit]:
    matcher = default_matcher()
    code = {rel: project.read_text(rel) for rel in text_files(project) if suffix_of(rel) not in {".sql", ".md"}}
    hits = []
    for table in find_tables(project):
        labels = sorted({m.label for c in table.columns if (m := matcher.match(c.name))})
        if not labels or _has_erase_path(table, code):
            continue
        lines = project.read_text(table.file).splitlines()
        defined = lines[table.line - 1].strip() if table.line <= len(lines) else table.name
        hits.append(Hit(
            rule_id=RET_001, file=table.file, line=table.line, pii=labels, confidence="medium",
            evidence=f"{defined}  [table {table.name} holds {', '.join(labels)}; no code deletes or anonymises it]",
        ))
    return sorted(hits, key=lambda h: (h.file, h.line))
