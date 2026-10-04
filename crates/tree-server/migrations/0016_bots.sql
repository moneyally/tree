-- Bot platform (PROTOCOL.md 8.16, Wave 5).
--
-- A bot is an account that an existing human account created. It has no
-- recovery key, no device links and no @username of the user kind; its
-- devices are registered by the bot's gateway with the bot token. The
-- token itself is never stored: only an HMAC of it under a server key.

CREATE TABLE bots (
    account_id    TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    -- The human account that created the bot (its owner).
    owner_account TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- Plaintext: bots are public. a-z, 0-9, _; ends with "bot".
    username      TEXT NOT NULL UNIQUE,
    -- SHA-256("tree/username/v1" || username), as people's @usernames are
    -- stored: one namespace, a person cannot take a bot's name and back.
    username_hash BLOB NOT NULL UNIQUE,
    description   TEXT NOT NULL DEFAULT '',
    -- JSON array of {"command", "description"}.
    commands      TEXT NOT NULL DEFAULT '[]',
    -- HMAC-SHA-256 of the current token under the bot token key; NULL:
    -- revoked (no token works).
    token_mac     BLOB,
    -- Counts token changes. A gateway device works only while it was
    -- registered (or re-registered) under the current generation.
    token_gen     INTEGER NOT NULL DEFAULT 1,
    -- Bot features (bot.privacy_mode, bot.join_groups, bot.inline,
    -- bot.directory); the money features are permanently released.
    privacy_mode  INTEGER NOT NULL DEFAULT 1,
    join_groups   INTEGER NOT NULL DEFAULT 1,
    inline        INTEGER NOT NULL DEFAULT 0,
    directory     INTEGER NOT NULL DEFAULT 0,
    created_day   INTEGER NOT NULL
);
CREATE INDEX bots_owner ON bots(owner_account);

-- The bot's gateway device and the token generation it was registered
-- under. A device of a bot account without a row here never authenticates.
CREATE TABLE bot_devices (
    device_id   TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    bot_account TEXT NOT NULL REFERENCES bots(account_id) ON DELETE CASCADE,
    token_gen   INTEGER NOT NULL
);
CREATE INDEX bot_devices_bot ON bot_devices(bot_account);

-- People who contacted a bot (claimed its key packages: started a chat
-- with it or added it to a group). A bot may only reach these accounts
-- outside the groups it is in. Deleted when the person stops the bot.
CREATE TABLE bot_contacts (
    bot_account TEXT NOT NULL REFERENCES bots(account_id) ON DELETE CASCADE,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    since_day   INTEGER NOT NULL,
    PRIMARY KEY (bot_account, account_id)
);
CREATE INDEX bot_contacts_account ON bot_contacts(account_id);

-- Proof-of-work inputs already used to create a bot (no replay).
CREATE TABLE bot_pow (
    key BLOB PRIMARY KEY,
    day INTEGER NOT NULL
);

-- A message sent by a bot's device carries the bot's account id, so
-- receivers can label it as a bot whatever the bot claims inside the
-- group. Messages of people never carry their sender.
ALTER TABLE blobs ADD COLUMN from_bot TEXT;

-- An owner's bots go with the owner's account. (Recursive triggers are
-- off, and bots cannot own bots.)
CREATE TRIGGER bots_follow_owner BEFORE DELETE ON accounts
BEGIN
    DELETE FROM accounts WHERE id IN (SELECT account_id FROM bots WHERE owner_account = OLD.id);
END;
