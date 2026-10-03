-- Ephemeral two-sided device-link sessions.
-- The numeric verification code is derived from the challenge and both
-- public keys. Only the hash of the challenge is needed server-side for
-- expiration/replay bookkeeping; the session row itself is short-lived.

CREATE TABLE device_link_sessions (
    id                    TEXT PRIMARY KEY,
    initiator_device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    challenge             BLOB NOT NULL,
    joiner_auth_pub       BLOB,
    initiator_confirmed   INTEGER NOT NULL DEFAULT 0 CHECK (initiator_confirmed IN (0,1)),
    joiner_confirmed      INTEGER NOT NULL DEFAULT 0 CHECK (joiner_confirmed IN (0,1)),
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    used                  INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0,1))
);
CREATE INDEX device_link_expiry ON device_link_sessions(expires_at);
