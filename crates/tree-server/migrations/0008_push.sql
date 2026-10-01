-- Push wake-up endpoints (docs/PROTOCOL.md 8.8): one per device, at an
-- allowed gateway host. Nothing about messages is sent there.
CREATE TABLE push_endpoints (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    endpoint  TEXT NOT NULL,
    set_day   INTEGER NOT NULL
);
