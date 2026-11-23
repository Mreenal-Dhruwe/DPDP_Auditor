from flask import Flask, jsonify, request

app = Flask(__name__)
users = {}


@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    users[data["email"]] = {"email": data["email"], "phone": data["phone"], "consent": False}
    return jsonify(ok=True)


@app.route("/consent", methods=["POST"])
def give_consent():
    users[request.json["email"]]["consent"] = True
    return jsonify(ok=True)


@app.route("/consent", methods=["DELETE"])
def remove_consent():
    users[request.json["email"]]["consent"] = False
    return jsonify(ok=True)
