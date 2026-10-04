-- Resumable opaque media objects. The server stores ciphertext chunks only.
CREATE TABLE media_objects (
    id                TEXT PRIMARY KEY,
    owner_device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    capability_hash   BLOB NOT NULL,
    manifest          BLOB NOT NULL,
    manifest_sha256   BLOB NOT NULL,
    key_commitment    BLOB NOT NULL,
    plaintext_size    INTEGER NOT NULL,
    chunk_size        INTEGER NOT NULL,
    chunk_count       INTEGER NOT NULL,
    finalized         INTEGER NOT NULL DEFAULT 0 CHECK (finalized IN (0,1)),
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL
);
CREATE INDEX media_objects_expiry ON media_objects(expires_at);
CREATE INDEX media_objects_owner ON media_objects(owner_device_id);

CREATE TABLE media_chunks (
    media_id    TEXT NOT NULL REFERENCES media_objects(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    ciphertext  BLOB NOT NULL,
    sha256      BLOB NOT NULL,
    PRIMARY KEY (media_id, chunk_index)
);
