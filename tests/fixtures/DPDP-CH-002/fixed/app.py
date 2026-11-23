from datetime import date

import analytics
from flask import Flask, request

app = Flask(__name__)


def is_adult(birth_date):
    born = date.fromisoformat(birth_date)
    return (date.today() - born).days >= 18 * 365


@app.route("/register", methods=["POST"])
def register():
    user_id = save_user(request.form["name"], request.form["birth_date"])
    if not is_adult(request.form["birth_date"]):
        return {"ok": True}  # no tracking for children (s.9(3))
    analytics.track(str(user_id), "Registered")
    return {"ok": True}


def save_user(name, birth_date):
    return 1
