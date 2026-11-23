CREATE TABLE customers (
    id      INTEGER PRIMARY KEY,
    email   TEXT NOT NULL,
    phone   TEXT
);

CREATE TABLE orders (
    id          INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    amount      INTEGER NOT NULL
);
