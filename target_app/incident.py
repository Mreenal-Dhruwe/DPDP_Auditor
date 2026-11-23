"""Breach response for the lending app (DPDP Rules 2025, Rule 7).

Affected users are told without delay; the Data Protection Board gets a detailed report
within 72 hours of the breach becoming known.
"""
from datetime import datetime, timedelta, timezone

BOARD_REPORT_WINDOW = timedelta(hours=72)


def notify_affected_users(db, user_ids, what_happened, what_you_can_do):
    created_at = datetime.now(timezone.utc).isoformat()
    body = f"{what_happened}\n\nWhat you can do: {what_you_can_do}"
    for user_id in user_ids:
        db.execute(
            "INSERT INTO notifications (user_id, kind, body, created_at) VALUES (?, 'breach', ?, ?)",
            (user_id, body, created_at),
        )
    db.commit()


def board_report(incident_id, became_aware_at, description, affected_users, measures_taken):
    return {
        "incident_id": incident_id,
        "became_aware_at": became_aware_at.isoformat(),
        "report_due_by": (became_aware_at + BOARD_REPORT_WINDOW).isoformat(),
        "description": description,
        "affected_users": affected_users,
        "measures_taken": measures_taken,
    }
