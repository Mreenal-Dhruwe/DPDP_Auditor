from flask import Flask, session

from models import User, db

app = Flask(__name__)


@app.route("/account", methods=["DELETE"])
def close():
    uid = session["user_id"]
    db.engine.execute("DELETE FROM customers WHERE id = %s", (uid,))
    db.engine.execute("DELETE FROM audit_log WHERE user_id = %s", (uid,))
    return {"ok": True}


def remove_user(user_id):
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
