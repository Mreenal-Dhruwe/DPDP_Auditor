import os

import requests
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://app.example.in"])


def fetch_kyc(url):
    return requests.get(url, timeout=10).json()


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
