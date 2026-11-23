"""DPDP-SEC-010: log retention shorter than one year (scanner/detectors/config_files.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.config_files import short_log_retention
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-010"


def scan(folder):
    return short_log_retention(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    found = {(h.file, h.line): h.evidence.split("deleted after ")[1].split(";")[0] for h in hits}
    assert found == {
        ("app.py", 4): "2 days",  # hourly files, 48 kept
        ("infra/logrotate.conf", 3): "7 days",  # daily, rotate 7
        ("infra/logs.tf", 3): "30 days",  # CloudWatch retention_in_days
        ("logger.js", 5): "14 days",  # winston daily files, maxFiles 14
        ("logging_conf.py", 4): "30 days",  # dictConfig handler: midnight, backupCount 30
    }


def test_fixed_fixture_is_clean():
    """400 days everywhere (hourly files: 9000 kept); size-based rotation is not judged."""
    assert scan(FIXTURES / "fixed") == []


def test_backup_count_zero_keeps_everything(tmp_path):
    (tmp_path / "log.py").write_text(
        "from logging.handlers import TimedRotatingFileHandler\nh = TimedRotatingFileHandler('a.log', when='D')\n",
        encoding="utf-8")
    assert scan(tmp_path) == []


def test_cloudformation_retention(tmp_path):
    (tmp_path / "logs-stack.yml").write_text(  # not "template.yml": example/template files are skipped
        "Resources:\n  Logs:\n    Type: AWS::Logs::LogGroup\n    Properties:\n      RetentionInDays: 90\n", encoding="utf-8")
    [hit] = scan(tmp_path)
    assert (hit.file, hit.line) == ("logs-stack.yml", 5) and "90 days" in hit.evidence
