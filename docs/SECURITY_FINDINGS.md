# Security findings

Issues found by testing Tree's own design. Each one has a regression test.

## F-001: tampered copy could make a genuine message undecryptable

- **Found:** 2026-10-01, `crates/tree-core/tests/key_burn.rs`
- **What:** if a copy of a message with a modified content area arrived first, the
  receiver rejected it but had already consumed that message's key. The genuine
  message then failed with `SecretReuseError` and was lost. Confidentiality and
  integrity were never affected; this was a targeted message-deletion issue.
- **Who could do it:** anyone able to put bytes into a recipient's mailbox before
  the genuine message.
- **Fix:** every message and commit now carries an outer seal
  (HMAC-SHA-256 keyed by an MLS exporter secret of the current epoch), checked
  *before* the message reaches MLS. Forged copies are dropped without touching
  the key schedule.
- **Residual risk:** a current group member knows the exporter secret and can
  still do this to other members' messages. Raising with the MLS library
  maintainers whether keys should only be consumed after successful decryption.
- **Test:** `tampered_copy_does_not_burn_genuine_message` (10 byte positions).
