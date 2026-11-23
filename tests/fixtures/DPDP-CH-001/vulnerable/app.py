from flask import Flask, request

app = Flask(__name__)
app.config["PERMANENT_SESSION_MAX_AGE"] = 3600


@app.post("/register")
def register():
    data = request.get_json()
    birth_date = data.get("date_of_birth")
    save(data["name"], birth_date)
    return {"ok": True}
