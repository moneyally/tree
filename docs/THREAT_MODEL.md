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
| The Tree server, looking at attachment sizes | files are padded before encryption to 1 KiB, powers of two up to 1 MiB, Padmé buckets above (PROTOCOL.md 6.12); name, type, real size, picture size and previews are only inside the encrypted message; the uploader is known only while an upload is unfinished | learns the bucket (a few bits: "about 3 MB"), upload and fetch times, which devices fetch a blob, and the bytes an account uploads per day; can withhold or delete blobs (the receiver detects a changed one) |
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
| Device thief | encrypted local storage (below); app lock with passphrase, PIN (10 attempts) or biometric; on Android the PIN's derivation includes a keystore-held secret and the biometric key lives in the keystore | an unlocked phone; a weak passphrase; on a computer, a PIN can be guessed offline from copied files (PROTOCOL.md 8.13) |
| Another account trying to change a user's settings | settings sync only inside the account's own self group, from its members (PROTOCOL.md 8.14) | a device of the account that was linked by the user (by definition trusted) |
| Someone looking at the screen or the lock screen | notifications show the chat's name only unless `user.notification_content`; never a request's or screenshot-blocked chat's text; secure window flags and capture exclusion (APP_PROTOCOL.md 6.3) | cameras; systems without a capture-exclusion call (Linux, macOS); keyboards that ignore the no-learning request |
| The Tree server, for public groups and channels (PROTOCOL.md 8.15) | **nothing: public spaces are not end-to-end encrypted, by design.** The apps badge every public object "Public" and warn before creating or posting; a separate API and tables, so nothing from private chats can flow in; a private group can never become public (`chat.private_to_public` AlwaysOff, no field names a private group) | reads, changes, withholds or deletes any public post, name, @handle, subscriber list and the display name published with a post; sees which device reads which space when |
| Anyone signed in, for public spaces | rules enforced by the server: channels admins only, bans, slow mode, comments only while applied, rate and anti-spam limits, unlisted spaces only by exact @handle | reads every public post and the names published with them; can copy them anywhere |
| A subscriber of a public channel, about who posted | `channel.signatures` released: the server shows posts without the author to non-admins | the server and the channel's admins know the author |
| A member of a private channel who is not an admin (modified client) | every receiver drops posts from non-admins and comments while `channel.comments` is released, judged by the MLS-authenticated sender (PROTOCOL.md 6.11.2, `crates/tree-client/tests/public_channels.rs`) | can still send reactions, votes and its own comments as allowed; learns which admin device posted even with `channel.signatures` released (MLS authenticates the sender; signatures are a display rule) |
| A bot in a group, and whoever runs its gateway (PROTOCOL.md 8.16) | bot lanes: with `bot.privacy_mode` applied, members' devices send it only commands, mentions and replies to it, button presses meant for it, and the member list; never shared history or others' button presses; `chat.bots` lets admins keep bots out (devices refuse adds, send nothing, drop what bots send) | reads in plaintext everything it is sent (in a 1:1 chat, or with privacy mode released, everything); sees member list, names, account labels, group name and settings; holds the group's keys, so a member's modified client could forward anything to it |
| Gateway compromise (the bot's server is broken into) | the gateway is the bot's device: its profile is SQLCipher-encrypted under the operator's passphrase; the token is not on disk (only its SHA-256), the local API listens on loopback with the token; the owner rotates the token: the device is cut off at once, its key packages deleted; removing the bot from groups removes its MLS member | the attacker reads what the bot was sent and can send as the bot until the rotation or removal, within the bot's limits (it reaches only people who contacted it and its groups, every message labelled "bot"); past messages in the profile are exposed |
| Token theft (a leaked bot token) | the token alone registers a gateway device: one device per bot, so the owner's gateway is cut off the moment a thief registers (noticed); the owner rotates: the old token and the thief's device stop at once, also an open long-poll, and the thief's device is deleted when the owner's gateway registers again (`rotate_and_revoke_cut_off_the_old_token_and_its_devices_at_once`); the server keeps only an HMAC of the token (`BOT_TOKEN_KEY` can live outside the database) | between theft and rotation the thief is the bot: reads what members send it from then on (not earlier messages, which stay in the owner's gateway profile) and sends as the bot |
| A malicious bot | it is labelled "bot" by the server's word whatever its roster claims, and shown by its server-known username; buttons only on bots' messages; presses only for its own message's real buttons; answers only to the presser; it cannot start a chat with anyone who did not contact it (`BOT_NO_CONTACT`), and its first chat with someone is a request; per-bot rate limit; reports name its owner; people can block (and stop) it; bots never pay out points, payments and tips are locked off | can still spam people who contacted it and the groups it is in, within the limits, until blocked, removed or reported |
| A server that colludes with a bot | none against the server itself (it chooses mailboxes) | the server could copy other members' ciphertext into the bot's mailbox, defeating privacy mode; a lane MLS group per bot would close this (not in v1) |
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

PIN and biometric unlock (opt-in, `user.app_lock`; PROTOCOL.md 8.13):

| Part | Choice |
| --- | --- |
| PIN file | `<db>.pin`: the database key, AES-256-GCM under Argon2id(PIN, salt, device secret); parameters and salt authenticated |
| Attempt limit | 10; counted before each try; then the file is wiped and only the passphrase opens |
| Device secret (Android) | 32 random bytes encrypted by a non-exportable keystore key, Argon2's secret input |
| Biometric (Android 11+) | the database key under a keystore key usable only after a strong biometric check, invalidated by new enrolments |

The PIN does not weaken the passphrase: both unwrap the same key, and the
passphrase path is unchanged. It does add a second, weaker door. Through
the app, 10 tries of a million is 1 in 100,000. Offline, with the files
copied: on Android the keystore secret is missing from the copy, so the
PIN cannot be tried; on a computer the PIN file falls to 10^6 Argon2id
guesses (about a day on one core). Users who need protection against that
should keep the passphrase only on computers; the app says so.

Residual risks:

- Without PIN or biometric, the passphrase is the only secret (`KeySource`
  is the hook for a hardware-wrapped key on every unlock). A short
  passphrase can be guessed offline.
- A PIN on a computer can be guessed offline from copied files (above).
- While the app is unlocked, the key and decrypted pages are in process memory
  (SQLCipher's `cipher_memory_security` is off for speed). Spyware on the
  device remains out of scope.
- Flash storage may keep old copies of pages (wear levelling, deleted journal
  files). They are encrypted with the same key, so they matter only if the
  passphrase is also obtained.
- Losing `<db>.hdr` makes the database unrecoverable (by design; backup is a
  separate feature).
- File sizes and modification times show roughly how much the device is used.
- The search index (`user.search_index`) is a second copy of message texts
  inside the same encrypted file; releasing the setting drops it
  (`secure_delete` overwrites the freed pages; flash may keep old copies,
  encrypted like the rest).

### Plaintext outside the encrypted database (F-034)

The database is the only encrypted store. These files hold plaintext (or
are kept on purpose) and are protected only by the operating system's file
permissions and its own storage encryption:

| Where | What | How it goes away |
| --- | --- | --- |
| the app's media folder (`download_to_cache`; Android `cacheDir/downloads`) | decrypted files the user opened | `user.storage_clean` deletes them after its period (every sync, at most hourly, and `clean_storage`); the app's cache can be cleared by the system; deleting the account deletes the profile, not this folder (the app clears its cache) |
| `<destination>.tree-part` next to a file being saved (`fetch_to`) | the decrypted file while it is written | renamed to the destination when complete; deleted on any error or cancel; one left by a crash or a kill is deleted the next time the profile is opened (noted in `<profile>.media/partial/`) |
| exports (`export_chat_to`, apps: a place the user chooses) | the chat's text and a JSON copy | the user's own files; Tree never deletes them. `chat.export` lets a group forbid it on honest devices |
| `<profile>.media/in`, `<profile>.media/out` | attachment ciphertext being downloaded or uploaded | not plaintext; deleted when done, and with the account |
| saved files the user chose (`fetch_to` destination) | the decrypted file | the user's own file |

Android keeps none of these in backups (`no_backup.xml`). Spyware or
someone with the unlocked device can read them, as anything the user sees.

## Out of scope for now

Metadata protection beyond padding and contact discovery (there is none: no phone
numbers). What the server sees at stage 1 is classified item by item in
[PROTOCOL.md](PROTOCOL.md), section 11. What the server stores, and what it does
not, is listed in [SERVER_API.md](SERVER_API.md).
