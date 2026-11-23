from datetime import datetime, timedelta


def warn_dormant_accounts(db, mailer):
    for (address,) in db.execute("SELECT email FROM users WHERE last_login_at < ?", (cutoff(),)):
        mailer.send(address, "Your account will be erased in 48 hours")


def purge_dormant_accounts(db, mailer):
    warn_dormant_accounts(db, mailer)
    db.execute("DELETE FROM users WHERE last_login_at < ? AND warned_at < ?", (cutoff(), datetime.utcnow() - timedelta(hours=48)))


def cutoff():
    return datetime.utcnow() - timedelta(days=1095)
