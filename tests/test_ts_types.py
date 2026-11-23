"""The frontend's TypeScript types are generated from the Pydantic models (scripts/make_ts_types.py)."""

from scripts.make_ts_types import OUT, render


def test_generated_types_are_up_to_date():
    assert OUT.exists(), "run: python -m scripts.make_ts_types"
    assert OUT.read_text(encoding="utf-8") == render(), "contract changed - run: python -m scripts.make_ts_types"


def test_types_cover_the_contract():
    text = render()
    for expected in (
        'export type Severity = "critical" | "high" | "medium" | "low" | "info";',
        'export type Scope = "line" | "file" | "project";',
        "  scope: Scope;",
        "  file: string | null;",
        "  context: Context | null;",
        "  coverage: Coverage | null;",
        "  by_severity: Record<Severity, number>;",
        "  rules_not_checked: string[];",
        "  status: ScanState;",
        "export interface ScanStarted {",
    ):
        assert expected in text, expected
    assert "?:" not in text, "every field is always present in the JSON, so none is optional"
