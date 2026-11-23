from datetime import date

from flask import Flask, request

app = Flask(__name__)


@app.post("/register")
def register():
    data = request.get_json()
    birth_date = date.fromisoformat(data.get("date_of_birth"))
    if (date.today() - birth_date).days < 18 * 365:
        send_parent_consent_request(data["parent_email"])  # verifiable consent of the guardian (Rule 10)
        return {"status": "waiting_for_parental_consent"}
    save(data["name"], birth_date)
    return {"ok": True}
