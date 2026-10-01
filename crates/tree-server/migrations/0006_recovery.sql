-- Account recovery key (docs/PROTOCOL.md 8.6): the Ed25519 public key
-- derived from the user's recovery phrase. The phrase itself never reaches
-- the server.
CREATE TABLE account_recovery (
    account_id   TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    recovery_pub BLOB NOT NULL UNIQUE,
    set_day      INTEGER NOT NULL
);
