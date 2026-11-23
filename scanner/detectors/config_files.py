"""Config and IaC detectors (.env, Dockerfile, docker-compose, cloud YAML, Terraform):
DPDP-SEC-008 to DPDP-SEC-010. (Hardcoded secrets, DPDP-SEC-004, live in hardcoded_secrets.py.)

Implemented: DPDP-SEC-008, insecure infrastructure configuration:
- Dockerfile: the final stage never sets USER (a whole-file finding), or its last USER is root
- Python: app.run(debug=True), DEBUG = True in settings / config modules, CORS(app) with
  no origins (flask-cors then allows every origin), CORS / CORSMiddleware with "*",
  TLS verification turned off (verify=False)
- config files: DEBUG=true / FLASK_DEBUG=1, NODE_TLS_REJECT_UNAUTHORIZED=0,
  sslmode=disable, privileged: true (compose), public S3 ACLs and public databases (Terraform)
"""

import ast
import re

from scanner.detectors.source import (
    dotted_name, is_config_file, is_example_file, is_test_file, name_of, python_trees, suffix_of, text_files,
)
from scanner.ingest import Project
from scanner.models import Hit

SEC_008 = "DPDP-SEC-008"

# (pattern, what is wrong) for lines of config files
CONFIG_LINE_CHECKS = [
    (re.compile(r"^\s*(?:export\s+|ENV\s+|-\s*)?(?:DEBUG|FLASK_DEBUG|DJANGO_DEBUG|APP_DEBUG)\s*[:=]\s*['\"]?(?:true|1|yes|on)['\"]?\s*$",
                re.IGNORECASE), "debug mode switched on"),
    (re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['\"]?0"), "TLS certificate checks turned off"),
    (re.compile(r"sslmode\s*=\s*disable", re.IGNORECASE), "database connection without TLS"),
    (re.compile(r"^\s*privileged\s*:\s*true\s*$", re.IGNORECASE), "privileged container"),
    (re.compile(r"""\bacl\s*=\s*["']public-read(?:-write)?["']""", re.IGNORECASE), "storage bucket readable by anyone"),
    (re.compile(r"\b(?:block_public_acls|block_public_policy|restrict_public_buckets)\s*=\s*false", re.IGNORECASE),
     "public-access block turned off"),
    (re.compile(r"\bpublicly_accessible\s*=\s*true", re.IGNORECASE), "database reachable from the internet"),
]


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Dockerfile lines with backslash continuations joined: (first line number, text)."""
    result, buffer, start = [], "", 0
    for n, line in enumerate(text.splitlines(), 1):
        if not buffer:
            start = n
        buffer += line.rstrip("\\").strip() + " "
        if not line.rstrip().endswith("\\"):
            result.append((start, buffer.strip()))
            buffer = ""
    if buffer:
        result.append((start, buffer.strip()))
    return result


def _dockerfile(rel: str, text: str) -> list[Hit]:
    final_from, users = None, []
    for n, line in _logical_lines(text):
        word = line.split(" ", 1)[0].upper()
        if word == "FROM":
            final_from, users = (n, line), []
        elif word == "USER":
            users.append((n, line))
    if final_from is None:
        return []
    if not users:
        return [Hit(rule_id=SEC_008, scope="file", file=rel, confidence="high",
                    evidence=f"No USER instruction after '{final_from[1]}': the container runs as root")]
    n, line = users[-1]
    user = line.split(" ", 1)[1].split(":")[0].strip() if " " in line else ""
    if user in {"root", "0"}:
        return [Hit(rule_id=SEC_008, file=rel, line=n, confidence="high",
                    evidence=f"{line}  [the container runs as root]")]
    return []


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _has_star(node: ast.AST | None) -> bool:
    return node is not None and any(isinstance(n, ast.Constant) and n.value == "*" for n in ast.walk(node))


def _python(rel: str, tree: ast.Module, lines: list[str]) -> list[Hit]:
    hits = []
    settings_module = re.search(r"(settings|config)\w*\.py$", name_of(rel)) is not None

    def report(line: int, why: str) -> None:
        hits.append(Hit(rule_id=SEC_008, file=rel, line=line, confidence="high",
                        evidence=f"{lines[line - 1].strip()}  [{why}]"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = dotted_name(node.func)
            last = called.rsplit(".", 1)[-1]
            debug = _keyword(node, "debug")
            if last == "run" and isinstance(debug, ast.Constant) and debug.value is True:
                report(node.lineno, "debug mode switched on")
            elif last == "CORS":
                if _keyword(node, "origins") is None and _keyword(node, "resources") is None:
                    report(node.lineno, "CORS without origins allows every website")
                elif _has_star(_keyword(node, "origins")) or _has_star(_keyword(node, "resources")):
                    report(node.lineno, "CORS allows every website")
            elif last == "add_middleware" and node.args and dotted_name(node.args[0]).endswith("CORSMiddleware") \
                    and _has_star(_keyword(node, "allow_origins")):
                report(node.lineno, "CORS allows every website")
            verify = _keyword(node, "verify")
            if isinstance(verify, ast.Constant) and verify.value is False:
                report(node.lineno, "TLS certificate verification turned off")
        elif settings_module and isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and node.value.value is True and any(isinstance(t, ast.Name) and t.id == "DEBUG" for t in node.targets):
            report(node.lineno, "debug mode switched on")
    return hits


def insecure_infrastructure(project: Project) -> list[Hit]:
    hits = []
    trees = dict(python_trees(project))
    for rel in text_files(project):
        if is_test_file(rel) or is_example_file(rel):
            continue
        text = project.read_text(rel)
        if name_of(rel).startswith("dockerfile"):
            hits += _dockerfile(rel, text)
        if rel in trees:
            hits += _python(rel, trees[rel], text.splitlines())
        elif is_config_file(rel) or suffix_of(rel) in {".tf", ".json"}:
            for n, line in enumerate(text.splitlines(), 1):
                for pattern, why in CONFIG_LINE_CHECKS:
                    if pattern.search(line):
                        hits.append(Hit(rule_id=SEC_008, file=rel, line=n, confidence="high",
                                        evidence=f"{line.strip()}  [{why}]"))
                        break
    return sorted(hits, key=lambda h: (h.file, h.line or 0))
