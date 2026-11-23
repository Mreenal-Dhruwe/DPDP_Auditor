"""Settings come from environment variables, with defaults (scanner/config.py)."""

import pytest
from pydantic import ValidationError

from scanner.config import PROJECT_ROOT, Settings


def test_env_example_lists_every_setting_with_the_default_values():
    lines = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    pairs = dict(line.split("=", 1) for line in lines if line.strip() and not line.startswith("#"))
    assert set(pairs) == {name.upper() for name in Settings.model_fields}
    assert Settings.from_env(pairs) == Settings.from_env({})


def test_values_come_from_the_environment():
    settings = Settings.from_env({
        "MAX_FILES": "10",
        "ALLOWED_ORIGINS": "http://a.test, http://b.test",
        "LOG_LEVEL": "debug",
        "REPORT_DIR": "out/reports",
    })
    assert settings.max_files == 10
    assert settings.allowed_origins == ["http://a.test", "http://b.test"]
    assert settings.log_level == "DEBUG"
    assert settings.report_dir == PROJECT_ROOT / "out" / "reports"
    assert settings.rules_file == PROJECT_ROOT / "rules" / "dpdp_rules.yml"


@pytest.mark.parametrize(("name", "value"), [
    ("MAX_UPLOAD_MB", "lots"), ("MAX_FILES", "0"), ("LOG_LEVEL", "LOUD"), ("API_PORT", "70000"),
])
def test_bad_values_fail_loudly(name, value):
    with pytest.raises(ValidationError):
        Settings.from_env({name: value})
