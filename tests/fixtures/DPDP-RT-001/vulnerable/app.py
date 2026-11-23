from flask import Flask, request

app = Flask(__name__)


@app.route("/signup", methods=["POST"])
def signup():
    return {"id": save(request.form["email"], request.form["phone"])}


@app.route("/me", methods=["DELETE"])
def delete_me():
    return {"ok": True}


def save(email, phone):
    return 1
