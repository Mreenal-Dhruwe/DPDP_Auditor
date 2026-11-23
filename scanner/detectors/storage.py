"""Storage detectors: DPDP-SEC-002 (plaintext sensitive columns) and DPDP-SEC-003 (weak
password hashing).

Implemented: DPDP-SEC-002. A column is reported when its name refers to HIGH-sensitivity
personal data (aadhaar, pan, passport, health, password, card_number, bank_account ... from
the YAML) and nothing shows it is protected:
- the name says so: password_hash, aadhaar_encrypted, pan_token (see scanner/pii.py)
- the type says so: binary columns (BLOB, BYTEA, LargeBinary) usually hold ciphertext,
  and encrypted ORM types (EncryptedType, EncryptedCharField)
Medium-sensitivity data (email, phone) is not reported here: the rule targets the fields
whose leak causes the most harm.
"""

from scanner.detectors.schemas import find_tables
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import default_matcher

SEC_002 = "DPDP-SEC-002"
BINARY_TYPES = {"BLOB", "BYTEA", "VARBINARY", "BINARY", "LARGEBINARY", "BINARYFIELD", "LONGBLOB"}


def plaintext_sensitive_columns(project: Project) -> list[Hit]:
    matcher = default_matcher()
    hits = []
    for table in find_tables(project):
        lines = None
        for column in table.columns:
            match = matcher.match(column.name)
            if not match or match.sensitivity != "high" or match.protected:
                continue
            if column.type in BINARY_TYPES or "ENCRYPT" in column.type:
                continue
            lines = lines or project.read_text(table.file).splitlines()
            evidence = lines[column.line - 1] if column.line <= len(lines) else f"{column.name} {column.type}"
            hits.append(Hit(
                rule_id=SEC_002, file=table.file, line=column.line, pii=[match.label],
                evidence=f"{evidence.strip()}  [{table.name}.{column.name} stored as {column.type}]",
                confidence=match.confidence,
            ))
    return sorted(hits, key=lambda h: (h.file, h.line))
