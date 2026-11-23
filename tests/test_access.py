"""DPDP-SEC-005: personal data on an unauthenticated route (scanner/detectors/access.py)."""

import textwrap

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.access import unauthenticated_pii_routes
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-005"


def scan(folder):
    return unauthenticated_pii_routes(Project.from_folder(folder, max_files=100))


def scan_code(tmp_path, code):
    (tmp_path / "api.py").write_text(textwrap.dedent(code), encoding="utf-8")
    return scan(tmp_path)


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    assert [(h.line, h.pii, h.confidence) for h in hits] == [
        (13, ["email", "phone"], "high"),
        (21, ["all columns of users"], "medium"),
    ]
    assert "IDOR" in hits[0].evidence and "IDOR" not in hits[1].evidence


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


def test_fastapi_routes(tmp_path):
    hits = scan_code(tmp_path, """
        @router.get("/users/{user_id}")
        async def read_user(user_id: int, db=Depends(get_db)):
            user = db.query(User).get(user_id)
            return {"email": user.email, "city": user.city}

        @router.get("/me")
        async def read_me(user=Depends(get_current_user)):
            return {"email": user.email}
    """)
    assert [(h.line, h.pii) for h in hits] == [(3, ["email", "user record"])]


def test_before_request_hook_guards_the_file(tmp_path):
    assert scan_code(tmp_path, """
        @bp.before_request
        def require_login():
            if "user_id" not in session:
                abort(401)

        @bp.route("/staff/<int:staff_id>")
        def staff(staff_id):
            return jsonify(email=lookup(staff_id).email)
    """) == []


@pytest.mark.parametrize("code", [
    '@app.route("/health")\ndef health():\n    return jsonify(status="ok")\n',
    '@app.post("/signup")\ndef signup():\n    user_id = create(request.form)\n    return jsonify(ok=True, user_id=user_id)\n',
])
def test_routes_without_personal_data(tmp_path, code):
    assert scan_code(tmp_path, code) == []
