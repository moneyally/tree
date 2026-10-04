-- Public spaces (PROTOCOL.md 8.15): public groups and public channels.
--
-- NOT end-to-end encrypted. Everything in these tables is plaintext the
-- server can read: names, handles, descriptions, posts, comments, who is
-- subscribed and who posted. They are a separate data path: nothing here
-- refers to MLS groups, mailboxes or deliveries, and no private group can
-- be turned into a public space (chat.private_to_public is AlwaysOff).

CREATE TABLE public_spaces (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('group', 'channel')),
    -- Normalised @handle (a-z, 0-9, _), unique over all public spaces.
    handle        TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    -- An attachment id (the avatar is a public file; its key travels in
    -- the space description the client publishes, so the server can read it).
    avatar        TEXT,
    owner_account TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- chat.public_listing: shown in the directory and in search.
    listed        INTEGER NOT NULL DEFAULT 0,
    -- channel.comments: subscribers may comment on posts (channels only).
    comments      INTEGER NOT NULL DEFAULT 0,
    -- channel.signatures: the posting admin's name is shown (channels only).
    signatures    INTEGER NOT NULL DEFAULT 0,
    -- chat.slow_mode: seconds between two posts of a non-admin (0: off).
    slow_mode     INTEGER NOT NULL DEFAULT 0,
    created_day   INTEGER NOT NULL
);
CREATE INDEX public_spaces_owner ON public_spaces(owner_account);
CREATE INDEX public_spaces_listed ON public_spaces(listed, handle);

CREATE TABLE public_members (
    space_id     TEXT NOT NULL REFERENCES public_spaces(id) ON DELETE CASCADE,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role         TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    -- The subscriber wants a content-free wake-up for new posts.
    notify       INTEGER NOT NULL DEFAULT 0,
    -- Unix seconds of this member's last post (slow mode).
    last_post_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (space_id, account_id)
);
CREATE INDEX public_members_account ON public_members(account_id);
CREATE INDEX public_members_notify ON public_members(space_id, notify);

CREATE TABLE public_bans (
    space_id   TEXT NOT NULL REFERENCES public_spaces(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    PRIMARY KEY (space_id, account_id)
);

-- Posts and comments. `seq` orders by creation (newest-first pages);
-- `rev` grows with every change (insert, edit, delete), so a client asking
-- "everything after rev N" also learns edits and deletions.
CREATE TABLE public_posts (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Chosen by the client (random), so a retried post is stored once.
    id             TEXT NOT NULL UNIQUE,
    space_id       TEXT NOT NULL REFERENCES public_spaces(id) ON DELETE CASCADE,
    author_account TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- The display name the author published with the post (public).
    author_name    TEXT,
    -- A comment: the post it answers.
    reply_to       TEXT,
    text           TEXT NOT NULL,
    attachment     TEXT,
    created_at     INTEGER NOT NULL,
    edited_at      INTEGER,
    deleted        INTEGER NOT NULL DEFAULT 0,
    rev            INTEGER NOT NULL
);
CREATE INDEX public_posts_space_seq ON public_posts(space_id, seq);
CREATE INDEX public_posts_space_rev ON public_posts(space_id, rev);
CREATE INDEX public_posts_reply ON public_posts(reply_to);
