import sqlite3

from flask import Flask, jsonify

app = Flask(__name__)


def db():
    return sqlite3.connect("app.db")


@app.route("/api/customers/<int:customer_id>")
def get_customer(customer_id):
    row = db().execute(
        "SELECT name, email, phone_no FROM customers WHERE id = ?", (customer_id,)
    ).fetchone()
    return jsonify(dict(row))


@app.get("/api/export")
def export_all():
    rows = db().execute("SELECT * FROM users").fetchall()
    return jsonify([dict(r) for r in rows])
