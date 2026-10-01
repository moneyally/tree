-- Commit ordering (docs/PROTOCOL.md 7.4): the first commit per (group, epoch) wins.
-- The server learns which devices are in a group; it already sees that through
-- recipient lists (PROTOCOL.md 11).

CREATE TABLE groups (
    group_id   BLOB PRIMARY KEY,
    last_epoch INTEGER NOT NULL
);

-- Devices allowed to take the next commit slot of a group.
CREATE TABLE group_devices (
    group_id  BLOB NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, device_id)
);
CREATE INDEX group_devices_device ON group_devices(device_id);

-- Accepted commits of the last 64 epochs, for idempotent retries and conflicts.
CREATE TABLE group_winners (
    group_id BLOB NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    epoch    INTEGER NOT NULL,
    sha256   BLOB NOT NULL,
    id       TEXT NOT NULL,
    PRIMARY KEY (group_id, epoch)
);
