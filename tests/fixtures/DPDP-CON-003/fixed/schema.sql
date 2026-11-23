CREATE TABLE user_consents (
    id             INTEGER PRIMARY KEY,
    user_id        INTEGER NOT NULL,
    purpose        TEXT NOT NULL,
    notice_version TEXT NOT NULL,
    accepted       BOOLEAN NOT NULL,
    granted_at     TEXT NOT NULL
);

CREATE TABLE customers (
    id                   INTEGER PRIMARY KEY,
    email                TEXT NOT NULL,
    marketing_consent    BOOLEAN DEFAULT 0,
    marketing_consent_at TEXT
);
