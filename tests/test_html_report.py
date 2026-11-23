"""HTML report (scanner/report/html_out.py)."""

import re

import pytest

from scanner.config import PROJECT_ROOT
from scanner.engine import scan_folder
from scanner.models import Hit, Report
from scanner.report.html_out import render_html


@pytest.fixture(scope="module")
def target_report(catalogue):
    return scan_folder(PROJECT_ROOT / "target_app", catalogue)


@pytest.fixture(scope="module")
def html(target_report, catalogue):
    return render_html(target_report, catalogue)


def test_every_finding_has_a_card_grouped_by_severity(target_report, html):
    for finding in target_report.findings:
        assert f'id="f-{finding.id}"' in html
    order = [m.group(1) for m in re.finditer(r'<h2 id="sev-(\w+)"', html)]
    assert order == ["critical", "high", "medium"]  # most severe first; empty groups left out


def test_sections_and_disclaimer(html, target_report):
    for section in ('id="summary"', 'id="coverage"', 'id="findings"', 'id="disclaimer"'):
        assert section in html
    assert target_report.disclaimer in html
    assert "Automated checks ran for" in html and "need a manual review" in html


def test_context_is_shown_masked_with_the_line_highlighted(html):
    assert html.count('class="ln hit"') == 12  # 13 findings, the Dockerfile one is whole-file
    assert "4f9a7c2e81b64d0c9e3a5b7d1f2c8e60" not in html  # the planted secret
    assert "lend********" in html


def test_scanned_code_cannot_inject_html(catalogue):
    hit = Hit(rule_id="DPDP-SEC-001", file="a.js", line=1, confidence="high",
              evidence='console.log("<script>alert(1)</script>", user.email)')
    finding = catalogue.to_finding(hit, ['console.log("<script>alert(1)</script>", user.email)'])
    html = render_html(Report(rules_version="0.1.0", target="x", findings=[finding]), catalogue)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_empty_report(catalogue):
    html = render_html(Report(rules_version="0.1.0", target="clean-app"), catalogue)
    assert "No findings for the rules that were checked." in html
