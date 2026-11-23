# Nightly retention jobs for the demo lending app. Answer key: ../ground_truth.yml
# Rule 8(2): warn inactive users 48 hours before their data is erased.
from datetime import datetime, timedelta, timezone

INACTIVE_FOR = timedelta(days=3 * 365)
NOTICE_PERIOD = timedelta(hours=48)


def now():
    return datetime.now(timezone.utc)


def send_erasure_notices(db, send_email):
    cutoff = (now() - INACTIVE_FOR).isoformat()
    rows = db.execute(
        "SELECT id, email FROM users WHERE last_login_at < ? AND erasure_notice_sent_at IS NULL", (cutoff,)
    ).fetchall()
    for user_id, address in rows:
        send_email(address, "Your account will be erased in 48 hours unless you log in.")
        db.execute("UPDATE users SET erasure_notice_sent_at = ? WHERE id = ?", (now().isoformat(), user_id))
    db.commit()


def purge_inactive_users(db):
    noticed_before = (now() - NOTICE_PERIOD).isoformat()
    db.execute(
        "DELETE FROM users WHERE erasure_notice_sent_at < ? AND last_login_at < erasure_notice_sent_at",
        (noticed_before,),
    )
    db.commit()
