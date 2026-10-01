-- Tree server schema. The server stores only what it needs to forward ciphertext.
-- No sender identity, no IP addresses, no plaintext. Dates of creation are kept
-- at day granularity, message arrival at minute granularity.

CREATE TABLE accounts (
    id          TEXT PRIMARY KEY,
    created_day INTEGER NOT NULL
);

CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    auth_pub    BLOB NOT NULL UNIQUE,
    created_day INTEGER NOT NULL
);
CREATE INDEX devices_account ON devices(account_id);

-- One-time MLS key packages (opaque to the server).
CREATE TABLE key_packages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    data      BLOB NOT NULL
);
CREATE INDEX key_packages_device ON key_packages(device_id, id);

-- Message ciphertext, stored once per send and referenced by each recipient mailbox.
CREATE TABLE blobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    body        BLOB NOT NULL,
    received_at INTEGER NOT NULL
);
CREATE INDEX blobs_received ON blobs(received_at);

-- Mailbox entries: one per recipient device. `id` is the public random message id.
CREATE TABLE deliveries (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    id        TEXT NOT NULL UNIQUE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    blob_id   INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE
);
CREATE INDEX deliveries_device ON deliveries(device_id, seq);
CREATE INDEX deliveries_blob ON deliveries(blob_id);

-- Operator feature flags (server scope).
CREATE TABLE features (
    key        TEXT PRIMARY KEY,
    state      TEXT NOT NULL CHECK (state IN ('applied', 'released')),
    changed_at INTEGER NOT NULL
);

-- Operator audit trail for flag changes (operator actions, not user data).
CREATE TABLE feature_audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    key    TEXT NOT NULL,
    state  TEXT NOT NULL,
    at     INTEGER NOT NULL,
    reason TEXT
);
