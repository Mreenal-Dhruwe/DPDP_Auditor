-- KYC tables
CREATE TABLE IF NOT EXISTS customers (
    id          INTEGER PRIMARY KEY,
    full_name   TEXT NOT NULL,
    aadhaar_no  CHAR(12) NOT NULL, -- needed for e-KYC
    pan_number  VARCHAR(10),
    password    TEXT NOT NULL,
    email       TEXT
);
