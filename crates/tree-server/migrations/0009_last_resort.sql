-- Last-resort key packages (docs/PROTOCOL.md 5.3): at most one per device,
-- handed out only when the device has no one-time key package left, and
-- never deleted by a claim.
CREATE TABLE last_resort_key_packages (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    data      BLOB NOT NULL
);
