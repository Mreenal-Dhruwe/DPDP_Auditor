CREATE TABLE user_consents (
    id       INTEGER PRIMARY KEY,
    user_id  INTEGER NOT NULL,
    accepted BOOLEAN NOT NULL
);

CREATE TABLE customers (
    id                INTEGER PRIMARY KEY,
    email             TEXT NOT NULL,
    marketing_consent BOOLEAN DEFAULT 0
);
