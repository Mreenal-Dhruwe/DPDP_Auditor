# Demo target for the DPDP Compliance Auditor (Hackasol 5.0, CS-01).
# A small micro-lending app with deliberately planted problems; never deploy it.
# The answer key is ../ground_truth.yml.
import functools
import hashlib
import logging
import sqlite3
from datetime import date, datetime, timezone

from flask import Flask, g, jsonify, render_template, request, session
from mixpanel import Mixpanel

import config

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
log = logging.getLogger("lending")
mp = Mixpanel(config.MIXPANEL_TOKEN)

NOTICE_VERSION = "2026-11-v1"


def now():
    return datetime.now(timezone.utc).isoformat()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(config.DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify(error="login required"), 401
        return view(*args, **kwargs)

    return wrapper


def audit(actor_id, action, table, record_id):
    db().execute(
        "INSERT INTO audit_log (actor_id, action, table_name, record_id, at) VALUES (?, ?, ?, ?, ?)",
        (actor_id, action, table, record_id, now()),
    )
    db().commit()


def record_consent(user_id, purpose):
    db().execute(
        "INSERT INTO consents (user_id, purpose, notice_version, granted_at, channel)"
        " VALUES (?, ?, ?, ?, 'web')",
        (user_id, purpose, NOTICE_VERSION, now()),
    )
    db().commit()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def is_adult(dob):
    born = date.fromisoformat(dob)
    today = date.today()
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    return age >= 18


@app.route("/")
def index():
    return render_template("signup.html")


@app.route("/signup", methods=["POST"])
def signup():
    form = request.form
    if not form.get("kyc_consent"):
        return jsonify(error="consent to KYC processing is required"), 400
    full_name, email, phone = form["full_name"], form["email"], form["phone"]
    dob = form["dob"]
    aadhaar, city = form["aadhaar"], form["city"]
    cur = db().execute(
        "INSERT INTO users (full_name, email, phone, dob, aadhaar, city, password_hash, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (full_name, email, phone, dob, aadhaar, city, hash_password(form["password"]), now()),
    )
    db().commit()
    user_id = cur.lastrowid
    audit(user_id, "create", "users", user_id)
    record_consent(user_id, "kyc")
    log.info("New signup: %s, %s, aadhaar %s", email, phone, aadhaar)
    if form.get("marketing_consent"):
        record_consent(user_id, "marketing")
        if is_adult(dob):
            mp.track(str(user_id), "Signed Up", {"$email": email, "$phone": phone, "city": city})
    session["user_id"] = user_id
    return jsonify(ok=True, user_id=user_id)


@app.route("/login", methods=["POST"])
def login():
    row = db().execute(
        "SELECT id, password_hash FROM users WHERE email = ?", (request.form["email"],)
    ).fetchone()
    if row is None or row["password_hash"] != hash_password(request.form["password"]):
        return jsonify(error="wrong email or password"), 401
    session["user_id"] = row["id"]
    audit(row["id"], "login", "users", row["id"])
    log.info("User %s logged in", row["id"])
    return jsonify(ok=True)


@app.route("/consent", methods=["POST"])
@login_required
def give_consent():
    record_consent(session["user_id"], request.form["purpose"])
    return jsonify(ok=True)


@app.route("/api/me")
@login_required
def my_data():
    user_id = session["user_id"]
    audit(user_id, "read", "users", user_id)
    row = db().execute(
        "SELECT full_name, email, phone, dob, city, created_at FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    consents = db().execute(
        "SELECT purpose, notice_version, granted_at FROM consents WHERE user_id = ?", (user_id,)
    ).fetchall()
    return jsonify(profile=dict(row), consents=[dict(c) for c in consents])


@app.route("/api/me", methods=["PATCH"])
@login_required
def update_my_data():
    user_id = session["user_id"]
    changes = request.get_json()
    db().execute(
        "UPDATE users SET full_name = COALESCE(?, full_name), phone = COALESCE(?, phone),"
        " city = COALESCE(?, city) WHERE id = ?",
        (changes.get("full_name"), changes.get("phone"), changes.get("city"), user_id),
    )
    db().commit()
    audit(user_id, "update", "users", user_id)
    return jsonify(ok=True)


@app.route("/api/me", methods=["DELETE"])
@login_required
def delete_account():
    user_id = session.pop("user_id")
    audit(user_id, "delete", "users", user_id)
    db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    db().execute("DELETE FROM consents WHERE user_id = ?", (user_id,))
    db().execute("DELETE FROM audit_log WHERE actor_id = ?", (user_id,))
    db().commit()
    return jsonify(ok=True)


@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    audit(None, "read", "users", user_id)
    row = db().execute(
        "SELECT full_name, email, phone, city FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))


@app.route("/grievance", methods=["POST"])
@login_required
def raise_grievance():
    cur = db().execute(
        "INSERT INTO grievances (user_id, category, message, status, created_at)"
        " VALUES (?, ?, ?, 'open', ?)",
        (session["user_id"], request.form["category"], request.form["message"], now()),
    )
    db().commit()
    return jsonify(ok=True, ticket=cur.lastrowid, reply_within_days=90)


@app.route("/api/kyc/<int:user_id>")
@login_required
def kyc_record(user_id):
    audit(session["user_id"], "read", "users", user_id)
    row = db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(dict(row))


# --- Compliant look-alikes (answer key: ground_truth.yml, "compliant"). Nothing here may be reported.

def file_checksum(path):
    """Integrity check of an uploaded KYC document. Not a password, so a fast hash is fine."""
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def tag_error_context(user_id):
    """Error monitoring gets a pseudonymous id only, never an email or phone."""
    import sentry_sdk

    sentry_sdk.set_user({"id": str(user_id)})


def close_account(user_id):
    """Soft delete: the row is kept for the retention period, then erased by a later job."""
    db().execute("UPDATE users SET deleted_at = ? WHERE id = ?", (now(), user_id))
    db().commit()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
