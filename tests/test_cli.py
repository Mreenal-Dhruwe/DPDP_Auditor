"""End to end: python -m scanner.cli <folder> --out <dir>."""

from scanner.cli import main
from scanner.config import PROJECT_ROOT
from scanner.models import Report

TARGET_APP = PROJECT_ROOT / "target_app"


def test_scan_of_target_app_writes_a_valid_report(tmp_path, capsys):
    assert main([str(TARGET_APP), "--out", str(tmp_path)]) == 0
    report = Report.model_validate_json((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report.target == "target_app"
    assert report.files_scanned >= 7
    out = capsys.readouterr().out
    assert "report.json" in out
    assert report.disclaimer in out


def test_report_never_contains_planted_secrets_unmasked(tmp_path, ground_truth):
    """Tripwire for 'evidence is masked from day one'. It passes trivially while there are
    no detectors, and fails as soon as a detector copies a planted secret into report.json."""
    main([str(TARGET_APP), "--out", str(tmp_path)])
    text = (tmp_path / "report.json").read_text(encoding="utf-8")
    assert [value for value in ground_truth["must_not_appear_in_report"] if value in text] == []


def test_missing_folder_exits_with_code_2(tmp_path, capsys):
    assert main([str(tmp_path / "missing"), "--out", str(tmp_path)]) == 2
    assert "not a folder" in capsys.readouterr().err
