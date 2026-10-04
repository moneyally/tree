-- Deterministic account recovery public key.
-- The corresponding private key is derived only on a device from the user's
-- recovery phrase. The server stores no recovery phrase or recovery entropy.

CREATE TABLE recovery_keys (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    recovery_pub BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);
