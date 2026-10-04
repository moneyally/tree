-- Idempotent sends (PROTOCOL.md 8.10): a retried POST /v1/messages carrying
-- the same idempotency key gets the first answer again and delivers nothing.
-- Only what a retry needs is kept: the sending device (for the per-device
-- cap and so a key never collides across devices), the key, a hash of the
-- request and the delivered count. Never the body, the recipients or the
-- message id. The day is kept, not the time. Rows go with the message TTL
-- (purge task), the oldest beyond MAX_IDEMPOTENCY_KEYS per device go at once,
-- and all of a device's rows go with the device.
CREATE TABLE idempotency_keys (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key          BLOB NOT NULL,
    request_hash BLOB NOT NULL,
    delivered    INTEGER NOT NULL,
    created_day  INTEGER NOT NULL,
    UNIQUE (device_id, key)
);
CREATE INDEX idempotency_keys_device ON idempotency_keys(device_id, seq);
CREATE INDEX idempotency_keys_day ON idempotency_keys(created_day);
