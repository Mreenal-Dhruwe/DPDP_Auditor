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

import ast

from scanner.detectors.schemas import find_tables
from scanner.detectors.source import dotted_name, python_trees, string_key
from scanner.ingest import Project
from scanner.models import Hit
from scanner.pii import default_matcher, split_words

SEC_002 = "DPDP-SEC-002"
SEC_003 = "DPDP-SEC-003"
BINARY_TYPES = {"BLOB", "BYTEA", "VARBINARY", "BINARY", "LARGEBINARY", "BINARYFIELD", "LONGBLOB"}
# Fast, general-purpose hashes: fine for checksums, far too fast for passwords.
FAST_HASHES = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"}
PASSWORD_WORDS = {"password", "passwd", "pwd", "pw", "passphrase", "pass", "pin"}


def _fast_hash(call: ast.Call) -> str | None:
    """'md5' for hashlib.md5(...), md5(...) or hashlib.new("md5", ...); else None."""
    name = dotted_name(call.func)
    last = name.rsplit(".", 1)[-1].lower()
    if last in FAST_HASHES and (name.startswith("hashlib.") or name == last):
        return last
    if name == "hashlib.new" and call.args and (algo := string_key(call.args[0])) and algo.lower() in FAST_HASHES:
        return algo.lower()
    return None


def _mentions_password(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        name = sub.id if isinstance(sub, ast.Name) else sub.attr if isinstance(sub, ast.Attribute) else (
            string_key(sub.slice) if isinstance(sub, ast.Subscript) else None)
        if name and set(split_words(name)) & PASSWORD_WORDS and "hash" not in split_words(name):
            return True
    return False


def weak_password_hashing(project: Project) -> list[Hit]:
    """DPDP-SEC-003: a fast hash (md5, sha1, plain sha256 ...) applied to a password.

    Reported when the hashed value is password-like (password, user.password, form["pwd"]),
    including h = hashlib.md5(); h.update(password), or when the hash is computed inside a
    function whose name says it handles passwords (hash_password, check_pw). Checksums of
    files and other data are not reported. bcrypt, scrypt, argon2 and pbkdf2_hmac are fine.
    """
    hits: dict[tuple[str, int], Hit] = {}
    for rel, tree in python_trees(project):
        lines = project.read_text(rel).splitlines()
        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        scopes = [(f.name, f) for f in functions] + [("", tree)]
        for scope_name, scope in scopes:
            password_function = bool(set(split_words(scope_name)) & PASSWORD_WORDS)
            hashers: dict[str, str] = {}  # h = hashlib.md5() -> {"h": "md5"}
            for node in ast.walk(scope):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and (algo := _fast_hash(node.value)):
                    hashers.update({t.id: algo for t in node.targets if isinstance(t, ast.Name)})
            for node in ast.walk(scope):
                if not isinstance(node, ast.Call):
                    continue
                algo = _fast_hash(node)
                if algo is None and isinstance(node.func, ast.Attribute) and node.func.attr == "update" \
                        and isinstance(node.func.value, ast.Name):
                    algo = hashers.get(node.func.value.id)
                if algo is None or (rel, node.lineno) in hits:
                    continue
                direct = any(_mentions_password(a) for a in node.args)
                if not (direct or password_function):
                    continue
                why = "password hashed" if direct else f"inside {scope_name}()"
                hits[(rel, node.lineno)] = Hit(
                    rule_id=SEC_003, file=rel, line=node.lineno, pii=["password"],
                    evidence=f"{lines[node.lineno - 1].strip()}  [{algo}: {why} with a fast, unsalted hash]",
                    confidence="high" if direct else "medium",
                )
    return sorted(hits.values(), key=lambda h: (h.file, h.line))


def plaintext_sensitive_columns(project: Project) -> list[Hit]:
    matcher = default_matcher()
    hits = []
    for table in find_tables(project):
        lines = None
        for column in table.columns:
            match = matcher.match(column.name)
            if not match or match.sensitivity != "high" or match.protected:
                continue
            if column.type in BINARY_TYPES or "ENCRYPT" in column.type or column.type.endswith("_HASHED"):
                continue
            lines = lines or project.read_text(table.file).splitlines()
            evidence = lines[column.line - 1] if column.line <= len(lines) else f"{column.name} {column.type}"
            hits.append(Hit(
                rule_id=SEC_002, file=table.file, line=column.line, pii=[match.label],
                evidence=f"{evidence.strip()}  [{table.name}.{column.name} stored as {column.type}]",
                confidence=match.confidence,
            ))
    return sorted(hits, key=lambda h: (h.file, h.line))
