from datetime import datetime, timedelta


def purge_dormant_accounts(db):
    cutoff = datetime.utcnow() - timedelta(days=1095)
    db.execute("DELETE FROM users WHERE last_login_at < ?", (cutoff,))
