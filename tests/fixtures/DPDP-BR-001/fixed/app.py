from flask import Flask

app = Flask(__name__)


@app.route("/customers")
def customers():
    return []
