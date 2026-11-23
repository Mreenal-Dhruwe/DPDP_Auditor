import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


def mask_email(email):
    local, _, domain = email.partition("@")
    return local[:2] + "***@" + domain


@app.post("/signup")
def signup():
    user = request.get_json()
    print("New user:", user["user_id"], mask_email(user["email"]))
    logger.info("KYC submitted for user %s", user["user_id"])
    return {"ok": True}


@app.errorhandler(500)
def server_error(error):
    app.logger.error("Request failed: %s %s", request.method, request.path)
    return {"error": "internal"}, 500
