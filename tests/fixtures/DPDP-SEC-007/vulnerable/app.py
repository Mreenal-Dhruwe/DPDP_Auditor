import logging
import sqlite3

from flask import Flask

app = Flask(__name__)
log = logging.getLogger("shop")
db = sqlite3.connect("shop.db")


@app.route("/customers/<int:customer_id>")
def get_customer(customer_id):
    row = db.execute("SELECT name, email FROM customers WHERE id = ?", (customer_id,)).fetchone()
    return {"name": row[0], "email": row[1]}
