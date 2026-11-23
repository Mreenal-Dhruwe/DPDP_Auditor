"""JavaScript / TypeScript support: Express routes, console/logger PII (SEC-001),
unauthenticated Express routes (SEC-005), Sequelize models (SEC-002, RET-001), consent (CON-001)."""

import textwrap

import pytest

from scanner.detectors.access import unauthenticated_pii_routes
from scanner.detectors.consent import consent_withdrawal
from scanner.detectors.logs import pii_in_logs
from scanner.detectors.retention import no_erase_path
from scanner.detectors.routes import find_routes
from scanner.detectors.schemas import find_tables
from scanner.detectors.storage import plaintext_sensitive_columns
from scanner.ingest import Project


def project(tmp_path, files: dict[str, str]) -> Project:
    for name, code in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code), encoding="utf-8")
    return Project.from_folder(tmp_path, max_files=100)


# --- routes ------------------------------------------------------------------------------

def test_express_routes_and_guards(tmp_path):
    routes = find_routes(project(tmp_path, {"server.ts": """
        import express from 'express'
        const api = express.Router()
        const app = express()
        app.use('/admin', requireAuth)
        api.get('/users/:id', getUser)
        app.all('/admin/report', report())
        app.get('view engine')
        axios.get('/api/remote', { timeout: 5 })
    """}))
    assert [(r.path, r.function, sorted(r.methods)[0], r.decorators) for r in routes] == [
        ("/users/:id", "getUser", "GET", ()),
        ("/admin/report", "report", "DELETE", ("requireAuth",)),  # app.all: every method; guarded by app.use
    ]


# --- SEC-001 ------------------------------------------------------------------------------

@pytest.mark.parametrize(("code", "pii"), [
    ("console.log(`new user ${user.email} ${user.phone}`)", ["email", "phone"]),
    ("logger.info('kyc', { aadhaar: body.aadhaar_no })", ["aadhaar"]),
    ("console.error('failed', req.body)", ["request body"]),
    ("this.logger.warn(customer['mobileNo'])", ["mobile"]),
])
def test_js_logs_with_personal_data(tmp_path, code, pii):
    [hit] = pii_in_logs(project(tmp_path, {"svc.js": code + "\n"}))
    assert hit.pii == pii


@pytest.mark.parametrize("code", [
    "console.log(`user ${user.id} created`)",
    "console.log('email sent to customer')",            # literal text only
    "logger.info(maskEmail(user.email))",               # masked before logging
    "cache.info(user.email)",                           # not a logger
])
def test_js_logs_without_personal_data(tmp_path, code):
    assert pii_in_logs(project(tmp_path, {"svc.js": code + "\n"})) == []


# --- SEC-005 ------------------------------------------------------------------------------

def scan_routes(tmp_path, code):
    return unauthenticated_pii_routes(project(tmp_path, {"server.js": code}))


def test_then_callback_and_factory_handlers(tmp_path):
    hits = scan_routes(tmp_path, """
        const app = express()
        app.get('/api/customers/:id', (req, res) => {
          Customer.findByPk(req.params.id).then(customer => res.json(customer))
        })
        app.get('/rest/whoami', whoami())
        function whoami () {
          return (req, res) => {
            res.json({ email: lookup(req).email })
          }
        }
    """)
    assert [(h.line, h.pii) for h in hits] == [(3, ["customer record"]), (6, ["email"])]


def test_sql_in_template_strings(tmp_path):
    [hit] = scan_routes(tmp_path, """
        app.get('/search', async (req, res) => {
          const rows = await db.query(`SELECT name, email, phone FROM users WHERE name LIKE '%${req.query.q}%'`)
          res.json(rows)
        })
    """)
    assert hit.pii == ["email", "phone"]


@pytest.mark.parametrize("code", [
    "app.get('/me', passport.authenticate('jwt'), async (req, res) => res.json(await User.findByPk(1)))",
    "app.get('/me', async (req, res) => { if (!req.user) return res.sendStatus(401); res.json(req.user.email) })",
    "app.post('/echo', (req, res) => res.json(req.body))",                    # echoes what the client sent
    "app.get('/health', (req, res) => res.json({ status: 'ok' }))",
])
def test_routes_that_are_fine(tmp_path, code):
    assert scan_routes(tmp_path, code + "\n") == []


# --- Sequelize: SEC-002, RET-001 -----------------------------------------------------------

MODELS = """
    const Card = sequelize.define('Card', {
      cardNum: DataTypes.INTEGER,
      holder: { type: DataTypes.STRING },
      password: { type: DataTypes.STRING, set (v) { this.setDataValue('password', security.hash(v)) } }
    }, { tableName: 'Cards' })

    class UserModel extends Model {}
    UserModel.init({ email: DataTypes.STRING, passportNo: DataTypes.STRING }, { sequelize, tableName: 'Users' })
"""


def test_sequelize_tables(tmp_path):
    tables = find_tables(project(tmp_path, {"models/index.ts": MODELS}))
    assert [(t.name, t.model, t.line, [(c.name, c.type) for c in t.columns]) for t in tables] == [
        ("Cards", "Card", 2, [("cardNum", "INTEGER"), ("holder", "STRING"), ("password", "STRING_HASHED")]),
        ("Users", "UserModel", 9, [("email", "STRING"), ("passportNo", "STRING")]),
    ]


def test_sequelize_plaintext_columns_and_erase_paths(tmp_path):
    files = {"models/index.ts": MODELS, "routes/user.ts": "export const del = (id) => UserModel.destroy({ where: { id } })\n"}
    p = project(tmp_path, files)
    # cardNum and passportNo are plaintext; password has a hashing setter, so it is protected
    assert [(h.line, h.pii) for h in plaintext_sensitive_columns(p)] == [(3, ["card_number"]), (9, ["passport"])]
    # Users can be erased (UserModel.destroy in another file); Cards cannot
    assert [h.line for h in no_erase_path(p)] == [2]


def test_sequelize_table_without_destroy(tmp_path):
    p = project(tmp_path, {"models/index.ts": MODELS})
    assert [(h.line, h.pii) for h in no_erase_path(p)] == [(2, ["card_number", "password"]), (9, ["email", "passport"])]


# --- CON-001 on Express ------------------------------------------------------------------

def test_consent_withdrawal_on_express(tmp_path):
    grant = "app.post('/api/consent', auth, (req, res) => res.sendStatus(204))\n"
    assert len(consent_withdrawal(project(tmp_path / "a", {"server.js": grant}))) == 1
    withdraw = grant + "app.delete('/api/consent', auth, (req, res) => res.sendStatus(204))\n"
    assert consent_withdrawal(project(tmp_path / "b", {"server.js": withdraw})) == []
