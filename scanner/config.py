"""Settings, read from environment variables (see .env.example), with safe defaults.

    from scanner.config import get_settings
    settings = get_settings()
    settings.rules_file      # absolute Path

A .env file in the project root is loaded first if it exists; real environment variables
win over it. Relative paths are resolved against the project root (the folder that holds
scanner/), not the current folder, so the CLI, the tests and the backend find the same
files wherever they are started from.
"""

import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseModel):
    """One field per environment variable: field `max_files` <- env var MAX_FILES."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    upload_dir: Path = Path("tmp_uploads")
    report_dir: Path = Path("reports")
    max_upload_mb: int = Field(50, gt=0)
    max_files: int = Field(5000, gt=0)
    report_ttl_days: int = Field(7, gt=0)
    rules_file: Path = Path("rules/dpdp_rules.yml")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    api_port: int = Field(8000, ge=1, le=65535)
    allowed_origins: list[str] = ["http://localhost:5173"]
    # Git URLs the backend may clone: https only, these hosts only (no file://, no internal hosts)
    allowed_git_hosts: list[str] = ["github.com", "gitlab.com", "bitbucket.org"]
    git_clone_timeout: int = Field(120, gt=0)  # seconds

    @field_validator("upload_dir", "report_dir", "rules_file")
    @classmethod
    def _from_project_root(cls, path: Path) -> Path:
        return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper_case(cls, value):
        return value.upper() if isinstance(value, str) else value

    @field_validator("allowed_origins", "allowed_git_hosts", mode="before")
    @classmethod
    def _comma_separated(cls, value):
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> "Settings":
        """Build settings from a mapping of environment variables (unset or empty -> default)."""
        values = {name: environ[name.upper()] for name in cls.model_fields if environ.get(name.upper())}
        return cls(**values)


@lru_cache
def get_settings() -> Settings:
    """Settings for this process, read once. Call get_settings.cache_clear() to re-read."""
    try:
        from dotenv import load_dotenv
    except ImportError:  # python-dotenv is optional: real environment variables still work
        pass
    else:
        load_dotenv(PROJECT_ROOT / ".env", override=False)
    return Settings.from_env(os.environ)
