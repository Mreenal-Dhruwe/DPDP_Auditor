-- KYC tables
CREATE TABLE IF NOT EXISTS customers (
    id              INTEGER PRIMARY KEY,
    full_name       TEXT NOT NULL,
    aadhaar_token   CHAR(36) NOT NULL, -- token from the Aadhaar data vault
    pan_encrypted   BLOB,
    password_hash   TEXT NOT NULL,
    email           TEXT
);
