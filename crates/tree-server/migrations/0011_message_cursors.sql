-- Durable per-device inbox cursor. Cursor advances only in the same
-- transaction that acknowledges every delivery up to that sequence.
CREATE TABLE message_cursors (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    cursor INTEGER NOT NULL DEFAULT 0 CHECK (cursor >= 0)
);
