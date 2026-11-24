"""Raw MongoDB driver (no ORM): the fields come from what the code writes.

SEC-002 (plaintext personal data), SEC-006 (whole record sent), RET-001 (erase path).
"""

import textwrap

from scanner.detectors.access import excessive_response_data
from scanner.detectors.retention import no_erase_path
from scanner.detectors.schemas import find_tables
from scanner.detectors.storage import plaintext_sensitive_columns
from scanner.ingest import Project


def project(tmp_path, code: str) -> Project:
    (tmp_path / "app.js").write_text(textwrap.dedent(code), encoding="utf-8")
    return Project.from_folder(tmp_path, max_files=100)


def lines(hits):
    return sorted(h.line for h in hits)


def test_fields_from_literals_assignments_and_set(tmp_path):
    tables = find_tables(project(tmp_path, """
        const users = db.collection('users')
        function add (name, email, ssn, cb) {
          const user = { name, email }
          if (ssn) { user.ssn = ssn }
          users.insert(user, cb)
        }
        function update (id, bankAcc, cb) {
          const changes = {}
          changes.bankAcc = bankAcc
          users.update({ _id: id }, { $set: changes }, cb)
          db.collection('orders').insertOne({ item: 'x', qty: 1 })
        }
    """))
    by_name = {t.name: {c.name for c in t.columns} for t in tables}
    assert by_name == {"users": {"name", "email", "ssn", "bankAcc"}, "orders": {"item", "qty"}}


def test_plaintext_fields_are_reported_and_hashed_ones_are_not(tmp_path):
    p = project(tmp_path, """
        const users = db.collection('users')
        const bcrypt = require('bcrypt')
        function add (req, res) {
          const { name, ssn, password, bankAcc } = req.body
          users.insertOne({ name, ssn, bankAcc, password: bcrypt.hashSync(password, 12) })
        }
    """)
    hits = plaintext_sensitive_columns(p)
    assert sorted(h.pii[0] for h in hits) == ["bank_account", "ssn"]  # the hashed password is fine


def test_encrypted_assignment_is_protected(tmp_path):
    p = project(tmp_path, """
        const users = db.collection('users')
        function save (id, ssn) {
          const user = {}
          user.ssn = encrypt(ssn)
          users.update({ _id: id }, { $set: user }, () => {})
        }
    """)
    assert plaintext_sensitive_columns(p) == []


def test_whole_record_sent_vs_projection(tmp_path):
    p = project(tmp_path, """
        const users = db.collection('users')
        app.post('/u', (req, res) => { users.insertOne({ name: req.body.name, ssn: req.body.ssn }) })
        app.get('/u/:id', (req, res) => {
          users.findOne({ id: req.params.id }, (err, user) => res.json(user))
        })
        app.get('/u/:id/card', (req, res) => {
          users.findOne({ id: req.params.id }, { projection: { name: 1 } }, (err, user) => res.json(user))
        })
        app.get('/v/:id', async (req, res) => {
          const user = await users.findOne({ id: req.params.id })
          res.send(user.name)
        })
    """)
    assert lines(excessive_response_data(p)) == [5]  # only the findOne without a projection


def test_erase_path_with_delete_one(tmp_path):
    base = """
        const users = db.collection('users')
        function add (ssn) { users.insertOne({ ssn, name: 'x' }) }
    """
    assert no_erase_path(project(tmp_path, base)), "no erase path: reported"
    other = tmp_path / "other"
    other.mkdir()
    fixed = project(other, base + "        function remove (id) { users.deleteOne({ id }) }\n")
    assert no_erase_path(fixed) == []
