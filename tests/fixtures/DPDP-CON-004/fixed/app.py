from flask import Flask, request
from mixpanel import Mixpanel

app = Flask(__name__)
mp = Mixpanel("token")


@app.route("/signup", methods=["POST"])
def signup():
    email = request.form["email"]
    wants_offers = request.form.get("marketing_consent")
    save(email, wants_offers)
    if wants_offers and has_marketing_consent(email):
        mp.track(email, "Signed up", {"$email": email})
        send_promo_email(email)
    return {"ok": True}


def save(email, wants_offers):
    return None


def has_marketing_consent(email):
    return True


def send_promo_email(address):
    return None
