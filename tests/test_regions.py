"""DPDP-TP-002: personal data stored or sent outside India (scanner/detectors/config_files.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.config_files import regions_outside_india
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-TP-002"


def scan(folder):
    return regions_outside_india(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    assert [(h.file, h.line, h.confidence) for h in hits] == [
        ("deploy.env", 1, "low"),  # AWS_REGION=us-east-1
        ("main.tf", 2, "low"),  # AWS eu-west-1
        ("storage.tf", 3, "low"),  # Azure westeurope
    ]
    assert all("s.16" in h.evidence and "verify manually" in h.evidence for h in hits)


def test_fixed_fixture_is_clean():
    """Mumbai, Hyderabad and Central India; `location = "checkout"` is not a region."""
    assert scan(FIXTURES / "fixed") == []


def test_terraform_variable_default(tmp_path):
    """Juice Shop: provider "aws" { region = var.aws_region }, the value is the variable's default."""
    (tmp_path / "schema.sql").write_text("CREATE TABLE users (id INT, email TEXT);\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text('provider "aws" {\n  region = var.aws_region\n}\n', encoding="utf-8")
    (tmp_path / "variables.tf").write_text(
        'variable "aws_region" {\n  type    = string\n  default = "eu-west-1"\n}\n\n'
        'variable "location_label" {\n  default = "checkout"\n}\n', encoding="utf-8")
    [hit] = scan(tmp_path)
    assert (hit.file, hit.line) == ("variables.tf", 3) and "eu-west-1" in hit.evidence


def test_no_personal_data_means_nothing_to_report(tmp_path):
    (tmp_path / "main.tf").write_text('provider "aws" {\n  region = "us-east-1"\n}\n', encoding="utf-8")
    assert scan(tmp_path) == []
