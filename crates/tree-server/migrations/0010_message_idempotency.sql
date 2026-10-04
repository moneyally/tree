-- Server-side idempotency for application-message fan-out.
-- The request hash binds the key to the exact group/body/recipient set.
CREATE TABLE message_idempotency (
    sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    idempotency_key BLOB NOT NULL,
    request_hash BLOB NOT NULL,
    response_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (sender_device_id, idempotency_key)
) WITHOUT ROWID;
CREATE INDEX message_idempotency_expiry ON message_idempotency(created_at);
