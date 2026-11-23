import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.post("/signup")
def signup():
    user = request.get_json()
    print("New user:", user["email"], user["phone"])
    logger.info(f"KYC submitted for {user['aadhaar']}")
    return {"ok": True}


@app.errorhandler(500)
def server_error(error):
    app.logger.error("Request failed: %s", request.json)
    return {"error": "internal"}, 500
