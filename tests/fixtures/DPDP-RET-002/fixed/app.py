from datetime import datetime, timezone

from flask import Flask, session

from models import User, db

app = Flask(__name__)


@app.route("/account", methods=["DELETE"])
def close():
    uid = session["user_id"]
    db.engine.execute("UPDATE customers SET deleted_at = %s WHERE id = %s", (datetime.now(timezone.utc), uid))
    return {"ok": True, "erased_after_days": 365}


def purge_expired_accounts():
    """Nightly job: erase accounts soft-deleted more than a year ago."""
    db.engine.execute("DELETE FROM customers WHERE deleted_at < now() - interval '1 year'")
