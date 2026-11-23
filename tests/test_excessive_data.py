"""DPDP-SEC-006: excessive data in API responses (scanner/detectors/access.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.access import excessive_response_data
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-006"
SCHEMA = "CREATE TABLE users (\n  id INTEGER,\n  email TEXT,\n  aadhaar TEXT,\n  password_hash TEXT\n);\n"


def scan(folder):
    return excessive_response_data(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.file, h.line, h.pii) for h in scan(FIXTURES / "vulnerable")]
    assert found == [
        ("app.py", 12, ["pan", "password"]),  # SELECT * row sent whole
        ("app.py", 18, ["pan"]),  # PAN picked by name
        ("serializers.py", 9, ["pan", "password"]),  # DRF fields = "__all__"
        ("server.js", 14, ["aadhaar"]),  # res.json({ member }) from findByPk
        ("server.js", 18, ["aadhaar"]),  # findAll().then(members => res.json(members))
    ]


def test_fixed_fixture_is_clean():
    """Named columns, masked PAN, attributes: [...], explicit DRF fields, .map() to safe fields;
    and a login route that reads password_hash without returning it."""
    assert scan(FIXTURES / "fixed") == []


def test_fastapi_response_model_filters_the_output(tmp_path):
    (tmp_path / "schema.sql").write_text(SCHEMA, encoding="utf-8")
    route = ('from fastapi import FastAPI\napp = FastAPI()\n\n@app.get("/users/{{uid}}"{extra})\n'
             'def read(uid: int):\n    return dict(db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone())\n')
    (tmp_path / "api.py").write_text(route.format(extra=""), encoding="utf-8")
    [hit] = scan(tmp_path)
    assert hit.pii == ["aadhaar", "password"]
    (tmp_path / "api.py").write_text(route.format(extra=", response_model=UserOut"), encoding="utf-8")
    assert scan(tmp_path) == []  # response_model keeps only the schema's fields


def test_orm_record_with_generic_to_dict(tmp_path):
    (tmp_path / "models.py").write_text(
        "class User(db.Model):\n    __tablename__ = 'users'\n    id = db.Column(db.Integer)\n"
        "    aadhaar = db.Column(db.String)\n\n    def to_dict(self):\n"
        "        return {c.name: getattr(self, c.name) for c in self.__table__.columns}\n", encoding="utf-8")
    (tmp_path / "views.py").write_text(
        "from flask import Flask, jsonify\napp = Flask(__name__)\n\n@app.route('/u/<int:i>')\ndef show(i):\n"
        "    user = User.query.get(i)\n    return jsonify(user.to_dict())\n", encoding="utf-8")
    [hit] = scan(tmp_path)
    assert (hit.file, hit.line, hit.confidence, hit.pii) == ("views.py", 7, "medium", ["aadhaar"])


def test_sequelize_model_that_hides_fields(tmp_path):
    (tmp_path / "server.js").write_text(
        "const User = sequelize.define('User', { pan: DataTypes.STRING }, {\n"
        "  defaultScope: { attributes: { exclude: ['pan'] } }\n})\n"
        "app.get('/u/:id', async (req, res) => {\n  const user = await User.findByPk(req.params.id)\n"
        "  res.json(user)\n})\n", encoding="utf-8")
    assert scan(tmp_path) == []
