from flask import Flask, request, jsonify

app = Flask(__name__)
users = {}

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    users[data["email"]] = {"email": data["email"], "phone": data["phone"], "consent": False}
    return jsonify(ok=True)

@app.route("/consent", methods=["POST"])
def give_consent():
    # user taps "I agree" -> we record consent
    email = request.json["email"]
    users[email]["consent"] = True
    return jsonify(ok=True)

@app.route("/profile/<email>", methods=["GET"])
def profile(email):
    return jsonify(users[email])

# NOTE: there is no route anywhere to withdraw consent

@app.route("/consent", methods=["DELETE"])
def withdraw_consent():
    users[request.json["email"]]["consent"] = False
    return jsonify(ok=True)
