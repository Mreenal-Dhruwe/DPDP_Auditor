"""Breach response: tell affected users without delay, report to the Board within 72 hours."""


def notify_affected_users(user_ids, what_happened):
    return [(user_id, what_happened) for user_id in user_ids]
