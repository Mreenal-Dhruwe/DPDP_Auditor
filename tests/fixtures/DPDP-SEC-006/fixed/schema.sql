CREATE TABLE customers (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL,
    pan           TEXT NOT NULL,
    password_hash TEXT NOT NULL
);
