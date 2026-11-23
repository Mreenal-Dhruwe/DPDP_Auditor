import sqlite3

from flask import Flask, jsonify

app = Flask(__name__)
db = sqlite3.connect("shop.db")


@app.route("/customers/<int:customer_id>")
def get_customer(customer_id):
    row = db.execute("SELECT id, name, email FROM customers WHERE id = ?", (customer_id,)).fetchone()
    return jsonify(dict(row))


@app.route("/customers/<int:customer_id>/tax")
def tax_details(customer_id):
    row = db.execute("SELECT name, pan FROM customers WHERE id = ?", (customer_id,)).fetchone()
    return {"name": row["name"], "pan_last4": row["pan"][-4:]}


@app.route("/login", methods=["POST"])
def login():
    row = db.execute("SELECT id, password_hash FROM customers WHERE email = ?", ("x",)).fetchone()
    return {"ok": row is not None}
