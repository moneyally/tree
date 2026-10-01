-- @usernames: the server keeps only a hash of the normalised name
-- (docs/PROTOCOL.md 8.4). One name per account.
CREATE TABLE usernames (
    hash         BLOB PRIMARY KEY,
    account_id   TEXT NOT NULL UNIQUE REFERENCES accounts(id) ON DELETE CASCADE,
    discoverable INTEGER NOT NULL DEFAULT 1,
    created_day  INTEGER NOT NULL
);
