-- Device linking sessions (docs/PROTOCOL.md 8.10). The server relays opaque
-- messages between an existing device and a new one and adds the new
-- device only with both devices' signatures over the same transcript hash.
-- It never computes or chooses the confirmation code.
CREATE TABLE link_sessions (
    link_id         TEXT PRIMARY KEY,          -- chosen by the new device (16 random bytes, base64url)
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    owner_device    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    new_auth_pub    BLOB NOT NULL,             -- the new device's request-signing key
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,          -- created_at + 10 minutes
    state           TEXT NOT NULL CHECK (state IN ('offered', 'revealed', 'confirmed', 'linked', 'cancelled')),
    offer           BLOB NOT NULL,             -- existing device -> new device (opaque)
    reveal          BLOB,                      -- new device -> existing device (opaque)
    transcript_hash BLOB,                      -- as the new device confirmed it
    new_signature   BLOB,                      -- the new device's confirmation
    sealed          BLOB,                      -- HPKE-sealed account data for the new device
    new_device_id   TEXT
);
CREATE INDEX link_sessions_account ON link_sessions(account_id, created_at);
CREATE INDEX link_sessions_expiry ON link_sessions(expires_at);
