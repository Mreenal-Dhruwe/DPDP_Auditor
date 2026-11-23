import requests
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


def fetch_kyc(url):
    return requests.get(url, verify=False).json()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
