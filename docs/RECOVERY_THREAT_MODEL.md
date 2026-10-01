# Recovery threat model

Status: 2026-10-01. **The recovery phrase is implemented** (section 2.2,
PROTOCOL.md 8.6); PIN, passkey and social recovery are not. The secrets a
user handles are the local passphrase that unlocks the device database and
the recovery phrase. This document fixes the threat model and the requirements
before any recovery code is written, because recovery is where an attacker
can bypass everything else: whoever completes a recovery is, for the server
and possibly for contacts, the user.

Related: [PROTOCOL.md](PROTOCOL.md) (messaging protocol, claims C1-C11),
[THREAT_MODEL.md](THREAT_MODEL.md) (device storage).

## 1. What recovery can and cannot restore

| Asset | Can be recovered? | Why |
| --- | --- | --- |
| Group secrets of past epochs (old MLS keys) | **never** | that would undo forward secrecy (C4); a recovered account gets a new device identity and must be added to groups again |
| Membership in groups | no, by re-adding | the new device is a new MLS leaf with a new signature key; contacts see a key change (`user.key_change_warning`, always on) |
| Server account (ability to register devices for the account) | yes, with the phrase | the server keeps only an Ed25519 public key derived from the phrase and checks a signature (PROTOCOL.md 8.6) |
| Message history | only from an encrypted backup (stage 3) | the backup key comes from the recovery secret, so **the recovery secret protects the whole backed-up history**: whoever learns it can read every backup |
| Long-term identity key (future SLH-DSA root, PROTOCOL.md 3.2) | planned | the most sensitive asset: it would let the holder certify new devices that contacts accept without warning |

Consequence: the strength of the recovery secret, and of every path that can
release it, bounds the confidentiality of backups and (once it exists) the
authenticity of the user's identity.

## 2. Secrets involved

### 2.1 Local passphrase (implemented)

Protects the device database at rest ([THREAT_MODEL.md](THREAT_MODEL.md)).
It is not a recovery mechanism: without the device files it restores nothing.

Parameters in code (`crates/tree-core/src/storage/key.rs`):

| Item | Value |
| --- | --- |
| KDF | Argon2id, version 1.3 (RFC 9106) |
| Default cost | memory 65,536 KiB (64 MiB), 3 passes, 1 lane |
| Output | 32-byte SQLCipher raw key |
| Salt | 32 random bytes per database |
| Accepted header range | memory 19 MiB .. 1 GiB, passes 2 .. 16, lanes 1 .. 4; anything else is refused |
| Header file | `<db>.hdr`, 54 bytes: `"TREEKEY\0"`, version 1, kdf 1, memory, passes, lanes (u32 little-endian), salt |
| Passphrase policy | any non-empty string (**no strength check yet**) |

Offline guessing: an attacker with the database file and header can test
guesses at the cost of one Argon2id evaluation each (64 MiB, 3 passes). That
is slow per guess but has no limit on the number of guesses. A 4- or 6-digit
PIN falls in minutes to hours on one machine (the earlier prototype measured
about 20 guesses per second on a small server: 4 digits in about 8.5
minutes, 6 digits in about 14 hours; specialised hardware is faster). Only a
high-entropy passphrase (for example 6 or more random words) resists offline
guessing. **A PIN must never be the passphrase** unless the key is wrapped by
a hardware keystore that enforces attempt limits (`KeySource` hook, planned).

### 2.2 Recovery phrase (implemented)

- Generated on the device by the system random generator, never chosen by
  the user. At least 128 bits of entropy (12 words from a 2048-word list);
  24 words (256 bits) recommended.
- Never sent to the server. Shown once, confirmed by the user, then held only
  in the user's records.
- Keys are derived from it with HKDF (RFC 5869) and fixed labels; a slow KDF
  adds nothing at this entropy. The account recovery key: salt
  `"tree/recovery/v1"`, info `"account-recovery-key"` (PROTOCOL.md 8.6). The
  backup key will use another info label.
- Losing it means losing recovery (stated on the sign-up screen).

### 2.3 PIN with server-side guess limiting (planned, stage 4)

A PIN is short, so it can only be safe if every guess needs the cooperation
of a party that counts guesses. Requirements:

1. **Never use a PIN directly as an encryption key**, and never as the only
   input to a key that protects data an attacker can copy. Stretching a PIN
   with Argon2id does not change this: 10^6 PINs times any affordable KDF
   cost is still feasible offline.
2. The PIN is combined with secrets held by **independent realms**: at least
   3 realms run by different operators in different jurisdictions, with a
   threshold of 2 (or more) needed to recover.
3. Each realm enforces a per-account guess counter (for example 10 attempts
   in total) and deletes its share for that account when the counter runs
   out. A realm must not be able to test PIN guesses offline from what it
   stores.
4. The protocol must be a **published, analysed construction** (for example
   an oblivious PRF as in RFC 9497 used in a password-protected secret
   sharing scheme from the literature), implemented with an audited library.
   Tree does not design its own (hard rule 1).
5. Realms run in hardware-isolated environments with remote attestation and
   reproducible builds, so that operators cannot quietly read state or reset
   counters. This raises the bar; it is not a substitute for (2)-(4).
6. Recovery through a PIN registers a new device but SHOULD NOT silently
   take over: existing devices of the account are notified and can cancel
   during a waiting period (length to be decided), and contacts see a key
   change.

### 2.4 Passkey (planned option, stage 4)

A platform passkey (WebAuthn / FIDO2 credential) with a PRF extension can
derive a wrapping key for the recovery secret. Strength then equals the
security of the passkey and, for synced passkeys, of the user's account at
the passkey sync provider: a compromise of that account is a compromise of
Tree recovery. Hardware security keys avoid the sync provider but can be
lost. Offered as an option, never the only path.

### 2.5 Social recovery (planned, stage 4)

Shares of the recovery secret given to chosen contacts (Shamir secret
sharing over a standard implementation). Threats: collusion of a threshold of
contacts, contacts being phished or coerced, contacts losing their devices.
Needs its own section before implementation.

## 3. Attacks and required defenses

| Attack | Applies to | Required defense | Status |
| --- | --- | --- | --- |
| Offline guessing from stolen device files | local passphrase | high-entropy passphrase or hardware-wrapped key with attempt limits; Argon2id cost 64 MiB / 3 passes minimum, bounded header | Argon2id: done; strength check: **not done**; hardware wrapping: **planned** |
| Offline guessing of the phrase | recovery phrase | >= 128 bits from the system random generator | done (128 to 256 bits; 256 by default) |
| Offline guessing after one realm is compromised | PIN | threshold across independent realms; one realm alone learns nothing testable | not implemented |
| Realm collusion (threshold reached) | PIN | threshold >= 2 of >= 3 independent operators; waiting period and notification to existing devices; contacts see key change | not implemented |
| Counter reset / rollback by an operator | PIN | attested isolated execution, counters in rollback-protected storage | not implemented |
| Online guessing against realms | PIN | per-account counter, share deleted when exhausted; then only the phrase recovers | not implemented |
| Lock-out by an attacker burning the counter | PIN | accepted trade-off; phrase remains as fallback; notify the user | not implemented |
| Phishing (fake recovery screen, "support" asking for the phrase, fake site) | phrase, PIN, passkey | the app never asks for the phrase except in the local recovery flow; the phrase is never typed into a web page; the server never asks for it; clear wording on the screen; passkeys are origin-bound | wording: not done |
| Device-link phishing (QR code relayed by an attacker) | device linking | confirmation code on both devices (`user.device_link_code`, always on) | feature locked on; flow not implemented |
| Coercion (forced to reveal PIN or phrase, or to unlock) | all | duress PIN (stage 3) that must be indistinguishable in timing and storage; waiting period gives a window to cancel | not implemented |
| Malicious server registers a device for the account | server account | adding a device requires a signature by an existing device (`POST /v1/devices`); contacts see a key change; key transparency (stage 4) | signature: done; key transparency: planned |
| Phrase leaked through screenshots, cloud photo backups, clipboard | phrase | block screenshots on the phrase screen; never place it on the clipboard | not implemented |
| Backup exposure if the recovery secret leaks | backups | state clearly that the recovery secret protects all backed-up history; backups off by default; per-backup key rotation does not help if the root secret leaks | not implemented |
| Malware on the device | all | out of scope (as for messaging) | — |

## 4. Rules that already hold for code written now

- No code may derive a database or backup key from a PIN alone.
- `KeySource` implementations must not cache passphrases or keys beyond one
  unlock (existing rule in `storage/key.rs`).
- Recovery code must not export MLS epoch secrets, secret-tree state or
  key-package private keys. A recovered account always starts with a new
  device identity.
- Anything legal (data-retention duties for realm operators, jurisdiction of
  realms): **변호사 확인 필요**.
