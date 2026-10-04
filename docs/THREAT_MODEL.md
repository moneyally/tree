# Threat model (draft)

## Security goals

Short overview. The precise statements, adversaries, assumptions and
exceptions are the numbered claims C1-C11 in [PROTOCOL.md](PROTOCOL.md),
section 9; this table does not replace them.

| Goal | How | Claim |
| --- | --- | --- |
| Confidentiality of messages | MLS (RFC 9420), hybrid ML-KEM-768 + X25519 key exchange | C2, C8 |
| Integrity and authenticity | MLS signatures + AEAD; outer envelope seal against non-members | C1, C3 |
| Forward secrecy | message keys deleted after use; exactly which messages a device compromise exposes is in C4 | C4 |
| Post-compromise security | the compromised device's own commit (key refresh) or its removal by an honest member, after the attacker lost access; not against an attacker who uses the signature key | C5 |
| Harvest-now-decrypt-later resistance | post-quantum hybrid key exchange, 256-bit symmetric keys; signatures are not post-quantum | C8 |
| Removed members lose access | new epoch after every removal; messages of the removal epoch stay readable to the removed member | C6 |

Recovery (recovery phrase, PIN, passkeys) has its own threat model:
[RECOVERY_THREAT_MODEL.md](RECOVERY_THREAT_MODEL.md).

**Not provided:** deniability. MLS messages carry sender signatures, so a member
who leaks a conversation can prove it is genuine.

## Adversaries

| Adversary | Defense | Residual risk |
| --- | --- | --- |
| Network eavesdropper, incl. future quantum computer | TLS 1.3 + hybrid PQ MLS | message size and timing (padding reduces size leakage) |
| The Tree server (breach, insider, legal compulsion) | stores only ciphertext; outer seal blocks forged inputs | sees mailbox, approximate time; can drop messages |
| Outsider who can write to a mailbox | outer envelope seal checked before MLS | none known |
| Malicious group member | MLS authentication; proposals rejected (F-007); only admins remove or change settings, checked by every device (PROTOCOL.md 6.11) | can leak what they read; can make one message undecryptable (F-001); a modified client can ignore chat settings for itself (keep copies, show expired messages) |
| Malicious reporter | message franking: a report verifies only for content the reported account really sent in that group (PROTOCOL.md 8.5, `formal/franking.pv`) | can report genuine messages out of context; at most 20 reports a day (F-012) |
| Thief with an unlocked device | recovery-key changes without the old phrase wait 7 days and are shown on every device; the owner's phrase recovers meanwhile and removes the thief's device (F-010) | can read and send as the owner until then; can delete the account |
| Holder of an invite link | the server enforces expiry and use limit; the owner's admin device adds only while `chat.invite_link` is applied; blocked accounts are refused | anyone with the link can ask to join while it is valid |
| Phisher who gets a user to scan a device-link QR code, or a server that swaps keys during a device link | both devices show a six-digit code from their own transcript with a commit-then-reveal nonce, the person confirms on both, the server adds a device only with the new device's confirmation and the existing device's signature over the same transcript hash, account data is HPKE-sealed to the key in the QR code (PROTOCOL.md 8.11, `formal/device_link.pv`) | a person who confirms a code read to them by someone else still links that device (the app says to confirm only while holding both); 1 in 10^6 per link that a swapped key gives equal codes |
| Push gateway operator | receives only the word `wake`, coalesced (PROTOCOL.md 8.8) | learns when a device gets something, roughly how often |
| GIF provider, map tile server (relays, off by default) | the Tree server fetches for the device with a fresh request: no client address, forwarding header or device id (PROTOCOL.md 8.12) | learns search words, chosen GIFs and viewed areas from the server's address; a provider that returns hostile URLs is limited to https image/video answers of bounded size, no redirects, no local addresses |
| The Tree server, for relay users | relays only signed requests, stores and logs nothing of them (PROTOCOL.md 8.12) | sees each device's GIF search words and the map tiles it views while the request runs; the apps say so next to the GIF search |
| Holder of a sticker pack link | the link is the manifest's key, like a file reference (APP_PROTOCOL.md 8.1) | anyone with the link can open the pack; packs cannot be revoked, only no longer shared |
| Member who sees a profile photo or per-chat name | photos go only to chats `user.profile_photo_visibility` allows; removal deletes receivers' copies on honest devices (APP_PROTOCOL.md 8.6, 8.7) | can keep a copy; a per-chat name does not hide that it is the same member (same keys) |
| Spammer | signup proof of work, per-device and per-IP rate limits, message requests and blocking, reports and suspension | a determined spammer with many accounts still reaches request inboxes, within the new-account and report limits (PROTOCOL.md 8.9) |
| The operator (moderation) | sees only what a user reports, with the franking result; can suspend accounts | reported messages are readable by the operator by design; a file report hands over that file's key |
| Removed member with a modified client | new epoch keys after removal | none known for later epochs (attack-scenario tests; formal model `formal/removal_secrecy.pv` under abstractions); can burn keys of messages from epochs it knew while they are in the past-epoch window |
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

Metadata protection beyond padding and contact discovery (there is none: no phone
numbers). What the server sees at stage 1 is classified item by item in
[PROTOCOL.md](PROTOCOL.md), section 11. What the server stores, and what it does
not, is listed in [SERVER_API.md](SERVER_API.md).
