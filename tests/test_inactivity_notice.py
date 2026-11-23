"""DPDP-RET-003: no notice before erasing inactive accounts (scanner/detectors/retention.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.retention import no_inactivity_notice
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-RET-003"


def scan(folder):
    return no_inactivity_notice(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    assert [(h.file, h.line, h.confidence) for h in hits] == [
        ("cleanup.js", 1, "low"),  # anonymises idle customers, no notice
        ("cleanup.py", 4, "low"),  # deletes dormant users, no notice
    ]
    assert all("48 hours" in h.evidence and "verify manually" in h.evidence for h in hits)


def test_fixed_fixture_is_clean():
    """Python: the purge calls a same-file helper that emails a warning; JS: only users noticed 48 h ago."""
    assert scan(FIXTURES / "fixed") == []


def test_deleting_without_inactivity_is_not_this_rule(tmp_path):
    (tmp_path / "admin.py").write_text("def remove_spam(db):\n    db.execute('DELETE FROM comments WHERE spam = 1')\n",
                                       encoding="utf-8")
    assert scan(tmp_path) == []
