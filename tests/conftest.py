"""Shared test fixtures."""

import pytest
import yaml

from scanner.config import PROJECT_ROOT
from scanner.rules_loader import load_rules

RULES_FILE = PROJECT_ROOT / "rules" / "dpdp_rules.yml"


@pytest.fixture(scope="session")
def catalogue():
    """The real rule catalogue (always the repo's file, whatever RULES_FILE says)."""
    return load_rules(RULES_FILE)


@pytest.fixture
def rules_data():
    """A fresh, editable copy of the raw rules YAML, for 'break one thing' tests."""
    return yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def ground_truth():
    """ground_truth.yml as plain data."""
    return yaml.safe_load((PROJECT_ROOT / "ground_truth.yml").read_text(encoding="utf-8"))
