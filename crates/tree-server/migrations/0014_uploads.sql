-- Chunked, resumable attachment uploads (PROTOCOL.md 6.12, SERVER_API.md).
--
-- An upload in progress is tied to the device that started it (only it may
-- add parts) and holds the declared padded ciphertext size, the number of
-- parts received and the minute it started. When the last part arrives the
-- row is deleted and the blob becomes an `attachments` row with the same id
-- and no uploader. Unfinished uploads are deleted after 24 hours, with
-- their partial file.
CREATE TABLE uploads (
    id         TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    size       INTEGER NOT NULL,
    received   INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX uploads_created ON uploads(created_at);

-- Bytes an account declared for uploads per day (UPLOAD_QUOTA_BYTES_PER_DAY).
-- Only today's row is needed; older rows go with the purge task.
CREATE TABLE upload_quota (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    day        INTEGER NOT NULL,
    bytes      INTEGER NOT NULL,
    PRIMARY KEY (account_id, day)
);
