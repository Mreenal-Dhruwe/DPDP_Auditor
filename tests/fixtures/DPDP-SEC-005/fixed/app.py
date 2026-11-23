import sqlite3

from flask import Flask, abort, jsonify, session
from flask_login import current_user, login_required

app = Flask(__name__)


def db():
    return sqlite3.connect("app.db")


@app.route("/api/customers/<int:customer_id>")
@login_required
def get_customer(customer_id):
    if current_user.id != customer_id:
        abort(403)
    row = db().execute(
        "SELECT name, email, phone_no FROM customers WHERE id = ?", (customer_id,)
    ).fetchone()
    return jsonify(dict(row))


@app.get("/api/me/export")
def export_mine():
    rows = db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/login")
def login():
    row = db().execute("SELECT id, password_hash FROM users WHERE email = ?", ("x",)).fetchone()
    return jsonify(ok=row is not None)
