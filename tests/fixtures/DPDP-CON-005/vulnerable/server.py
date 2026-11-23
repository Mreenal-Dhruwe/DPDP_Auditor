from flask import Flask, request
from location import LocationManager

app = Flask(__name__)


@app.route("/signup", methods=["POST"])
def signup():
    return {"email": request.form["email"], "mobile": request.form["mobile_no"]}
