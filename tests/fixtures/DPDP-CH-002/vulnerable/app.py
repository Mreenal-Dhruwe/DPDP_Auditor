import analytics
from flask import Flask, request

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    user_id = save_user(request.form["name"], request.form["birth_date"])
    analytics.track(str(user_id), "Registered")
    return {"ok": True}


def save_user(name, birth_date):
    return 1
