"""DPDP-RET-002: immediate hard delete (scanner/detectors/retention.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.retention import immediate_hard_delete
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-RET-002"


def scan(folder):
    return immediate_hard_delete(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    assert [(h.line, h.confidence) for h in hits] == [(11, "high"), (17, "medium")]
    assert "also wipes audit_log" in hits[0].evidence


def test_fixed_fixture_is_clean():
    """Soft delete in the route; the yearly purge job is not account deletion."""
    assert scan(FIXTURES / "fixed") == []


def test_deleting_non_personal_rows_is_fine(tmp_path):
    code = ('@app.route("/cart/<int:item>", methods=["DELETE"])\n'
            'def remove_item(item):\n    db.execute("DELETE FROM cart_items WHERE id = ?", (item,))\n')
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    assert scan(tmp_path) == []
