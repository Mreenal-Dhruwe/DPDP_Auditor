"""File helpers shared by detectors. Everything here reads files; nothing runs them."""

import ast
from collections.abc import Iterator

from scanner.ingest import Project

MAX_TEXT_BYTES = 1_000_000  # bigger files are usually bundles, lockfiles or data dumps
TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go", ".rb", ".php", ".cs",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".xml",
    ".html", ".htm", ".vue", ".svelte", ".sql", ".sh", ".bash", ".ps1", ".tf", ".tfvars",
    ".pem", ".key", ".p8",  # private keys
}
TEXT_NAMES = {"dockerfile", ".env", "procfile", "makefile", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
# Files where KEY=value / KEY: value lines are configuration (unquoted values allowed)
CONFIG_SUFFIXES = {".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml", ".tfvars"}
TEST_DIRS = {"test", "tests", "__tests__", "spec"}


def name_of(rel: str) -> str:
    return rel.rsplit("/", 1)[-1].lower()


def suffix_of(rel: str) -> str:
    name = name_of(rel)
    return name[name.rfind("."):] if "." in name[1:] else ""


def is_env_file(rel: str) -> bool:
    name = name_of(rel)
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def is_example_file(rel: str) -> bool:
    name = name_of(rel)
    return any(word in name for word in ("example", "sample", "template", ".dist"))


def is_config_file(rel: str) -> bool:
    name = name_of(rel)
    return is_env_file(rel) or suffix_of(rel) in CONFIG_SUFFIXES or name.startswith("dockerfile")


def is_test_file(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    return (any(p in TEST_DIRS for p in parts[:-1]) or name.startswith("test_")
            or name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts")))


def text_files(project: Project) -> Iterator[str]:
    """Files worth reading as text (source, config, templates), below MAX_TEXT_BYTES."""
    for rel in project.files:
        name = name_of(rel)
        if suffix_of(rel) in TEXT_SUFFIXES or name in TEXT_NAMES or name.startswith(("dockerfile", ".env")) \
                or name.endswith(".env"):
            if (project.root / rel).stat().st_size <= MAX_TEXT_BYTES:
                yield rel


def python_trees(project: Project) -> Iterator[tuple[str, ast.Module]]:
    """(relative path, syntax tree) for every .py file that parses. Others are skipped:
    one broken or newer-syntax file must not stop the scan."""
    for rel in project.files:
        if rel.endswith(".py"):
            try:
                yield rel, ast.parse(project.read_text(rel), filename=rel)
            except (SyntaxError, ValueError):
                continue


def dotted_name(node: ast.AST) -> str:
    """'app.logger.info' for app.logger.info, 'jsonify' for jsonify(...), '' if not a name."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return ""


def string_key(node: ast.AST) -> str | None:
    """The key of row["email"] or {"email": ...}, when it is a string literal."""
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None
