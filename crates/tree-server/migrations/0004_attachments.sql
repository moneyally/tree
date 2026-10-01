-- Encrypted attachments (docs/PROTOCOL.md 6.12): opaque blobs on disk, named by
-- a random id. No uploader, no name, no type; arrival rounded to the minute.
CREATE TABLE attachments (
    id         TEXT PRIMARY KEY,
    size       INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX attachments_created ON attachments(created_at);
