-- Encrypted media objects.
-- body is already encrypted by the client. The server never sees the
-- file key. Capability is a random bearer secret; only its SHA-256 digest
-- is stored.

CREATE TABLE files (
    id               TEXT PRIMARY KEY,
    owner_device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    body             BLOB NOT NULL,
    size_bytes       INTEGER NOT NULL,
    body_sha256      BLOB NOT NULL,
    capability_hash  BLOB NOT NULL UNIQUE,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL
);
CREATE INDEX files_expiry ON files(expires_at);
