"""Never name a module or package after a standard-library module: `import logging` or
`import secrets` would silently pick up our file instead (use logs.py, hardcoded_secrets.py)."""

import sys

from scanner.config import PROJECT_ROOT

OUR_CODE = ("scanner", "backend", "scripts", "tests")


def test_no_module_shadows_the_standard_library():
    names = set()
    for top in OUR_CODE:
        for path in (PROJECT_ROOT / top).rglob("*.py"):
            names.add(path.parent.name if path.stem == "__init__" else path.stem)
    clashes = sorted(names & sys.stdlib_module_names)
    assert clashes == [], f"rename these modules: {clashes}"
