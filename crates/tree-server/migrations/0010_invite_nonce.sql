-- A join request carries a random value from the joining device (16 bytes).
-- Only the link owner's device gets it back; it names it in the roster so the
-- joiner knows the group really comes from the device that took its request
-- (docs/PROTOCOL.md 8.7). Older clients send none (NULL).
ALTER TABLE invite_requests ADD COLUMN nonce BLOB;
