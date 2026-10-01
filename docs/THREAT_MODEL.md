# Threat model (draft)

## Security goals

| Goal | How |
| --- | --- |
| Confidentiality of messages | MLS (RFC 9420), hybrid ML-KEM-768 + X25519 key exchange |
| Integrity and authenticity | MLS signatures + AEAD, outer envelope seal |
| Forward secrecy | message keys deleted after use |
| Post-compromise security | periodic key refresh (`Group::refresh_keys`) |
| Harvest-now-decrypt-later resistance | post-quantum hybrid key exchange, 256-bit symmetric keys |
| Removed members lose access | new epoch after every removal |

**Not provided:** deniability. MLS messages carry sender signatures, so a member
who leaks a conversation can prove it is genuine.

## Adversaries

| Adversary | Defense | Residual risk |
| --- | --- | --- |
| Network eavesdropper, incl. future quantum computer | TLS 1.3 + hybrid PQ MLS | message size and timing (padding reduces size leakage) |
| The Tree server (breach, insider, legal compulsion) | stores only ciphertext; outer seal blocks forged inputs | sees mailbox, approximate time; can drop messages |
| Outsider who can write to a mailbox | outer envelope seal checked before MLS | none known |
| Malicious group member | MLS authentication | can leak what they read; can make one message undecryptable (see findings) |
| Removed member with a modified client | new epoch keys after removal | none known (tested) |
| Device thief | encrypted local storage (below); (planned) hardware-wrapped keys | an unlocked phone; a weak passphrase until the hardware keystore is used |
| Spyware on the device | out of scope | no messenger can protect a compromised OS |

## Local storage

Each device keeps its identity (signing key, name, credential, ciphersuite)
and the full group state in one database file, `crates/tree-core/src/storage`.

| Part | Choice |
| --- | --- |
| File encryption | SQLCipher 4 (AES-256 per page, HMAC-SHA512 page authentication), compiled in |
| Database key | 256 bits, never stored; rebuilt at every unlock by a `KeySource` |
| Passphrase stretching | Argon2id (RFC 9106), 64 MiB, 3 passes, 1 lane, 32-byte random salt per database |
| Key header | `<db>.hdr` next to the database: salt and Argon2id parameters only, no secret |
| Group state | OpenMLS storage tables (`openmls_sqlite_storage`) inside the encrypted file |
| Crash safety | every send/receive/add/remove/refresh is one transaction |

What it protects against: someone who copies the files (stolen phone with
the app locked, backup, forensic image) learns nothing without the
passphrase; each guess costs 64 MiB and 3 Argon2 passes. A wrong passphrase
and a modified file are both refused (page authentication), never half-read.

Details:

- The key is handed to SQLCipher in raw form through `sqlite3_key`, never in
  SQL text. Passphrase and key buffers are wiped after use (`zeroize`).
- The app refuses to start if SQLite was built without SQLCipher, so a build
  mistake cannot silently write plaintext.
- `secure_delete` is on: deleted rows (old epoch secrets, used one-time keys)
  are overwritten inside the file, so a later key leak does not bring them back.
  Temporary tables stay in memory.
- Files are created owner-only (0600) on Unix.
- Header parameters below 19 MiB / 2 passes or above 1 GiB / 16 passes are
  refused, so a tampered header can neither weaken nor exhaust memory.
- Tests check the raw files: no SQLite header, no name, no signing key bytes,
  no message text, compared against an unencrypted control file where the
  same scan does find them.

Residual risks:

- The passphrase is the only secret until the hardware keystore wraps the key
  (`KeySource` is the hook). A short passphrase can be guessed offline.
- While the app is unlocked, the key and decrypted pages are in process memory
  (SQLCipher's `cipher_memory_security` is off for speed). Spyware on the
  device remains out of scope.
- Flash storage may keep old copies of pages (wear levelling, deleted journal
  files). They are encrypted with the same key, so they matter only if the
  passphrase is also obtained.
- Losing `<db>.hdr` makes the database unrecoverable (by design; backup is a
  separate feature).
- File sizes and modification times show roughly how much the device is used.

## Out of scope for now

Metadata protection beyond padding, contact discovery (there is none: no phone
numbers), and the server, which does not exist yet.
