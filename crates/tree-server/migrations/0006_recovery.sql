-- Account recovery key (docs/PROTOCOL.md 8.6): the Ed25519 public key
-- derived from the user's recovery phrase. The phrase itself never reaches
-- the server. A change not signed with the current key waits
-- (pending_*) so a stolen device cannot lock the owner out at once.
CREATE TABLE account_recovery (
    account_id     TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    recovery_pub   BLOB UNIQUE,              -- NULL: none active
    set_day        INTEGER NOT NULL,
    pending_action TEXT,                     -- 'replace' | 'release' | NULL
    pending_pub    BLOB,
    pending_since  INTEGER
);
