# Tree Protocol v1

Status: draft for stage 1, 2026-10-01. Not audited.

This document specifies what a Tree client and a Tree server must do so that
two independent implementations interoperate and are equally secure. It also
states, as numbered claims, what security Tree v1 is meant to provide, under
which assumptions, and what it does not provide.

Conventions:

- MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119 / RFC 8174.
- "RFC 9420 §x" refers to sections of the MLS protocol specification.
- **(in progress)** marks behaviour that this specification requires but that
  the code on `main` does not implement yet. The text next to the marker says
  what `main` does today. Everything not marked is implemented on `main`.
- Byte strings are written in hex (`0x01`); `||` is concatenation; integers
  are big-endian unless stated otherwise; `"text"` means the UTF-8 bytes of
  the text without a terminating zero.

Related documents: [THREAT_MODEL.md](THREAT_MODEL.md) (adversaries and local
storage), [RECOVERY_THREAT_MODEL.md](RECOVERY_THREAT_MODEL.md) (account
recovery), [SERVER_API.md](SERVER_API.md) (HTTP API),
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) (known issues),
[`formal/`](../formal/README.md) (machine-checked models).

---

## 1. Layering decision

**Tree v1 is MLS (RFC 9420) with one fixed post-quantum hybrid ciphersuite.
MLS's key schedule, TreeKEM and secret tree are Tree's ratchet. Tree defines
no ratchet, no key exchange and no key-derivation chain of its own.**

```
 application content (text, media keys, receipts, ...)
 ─────────────────────────────────────────────────────
 MLS PrivateMessage (RFC 9420 §6.3)        ← confidentiality, sender
   key schedule (§8), secret tree (§9),       authentication, forward
   TreeKEM (§7), hybrid KEM via HPKE          secrecy, post-compromise
 ─────────────────────────────────────────────────────  security
 Tree outer envelope (section 4)           ← drops non-member input before
                                             MLS touches any key
 ─────────────────────────────────────────────────────
 Tree server API: request signatures,      ← availability, abuse limits,
   commit ordering, mailboxes (sections 5-8)  ordering; never confidentiality
 ─────────────────────────────────────────────────────
 TLS 1.3
```

What Tree adds on top of MLS is limited to the following, each built from a
standard primitive used in its standard way:

| Addition | Construction | Purpose |
| --- | --- | --- |
| Outer envelope seal | HMAC-SHA-256 keyed by an MLS exporter secret (RFC 9420 §8.5) | reject non-member input before MLS consumes keys (finding F-001) |
| Commit ordering | server accepts the first commit per (group, epoch) | one linear epoch history (RFC 9420 §14) |
| Server request authentication | Ed25519 signature over a fixed signing string | protect server resources and mailboxes |
| Signup proof of work | SHA-256 with leading zero bits | make mass signup expensive |
| Local storage key | Argon2id (RFC 9106) + SQLCipher | protect the device database at rest |

None of these provides message confidentiality. If every Tree addition were
removed, message confidentiality and authenticity would still rest entirely
on MLS.

Earlier internal drafts described a separate "triple hybrid" key exchange
(ML-KEM + HQC + X25519, prototyped only in a Python model) alongside MLS, with
its own root/epoch/chain keys. **That layer is not part of Tree v1** and
there is no second key hierarchy next to MLS. Section 3 explains the decision
on HQC.

---

## 2. Ciphersuite

### 2.1 Mandatory ciphersuite

| Item | Value |
| --- | --- |
| Name | `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519` |
| Code point | `0x004E` (provisional, IETF draft `draft-ietf-mls-pq-ciphersuites`) |
| KEM (HPKE) | ML-KEM-768 + X25519 hybrid, X-Wing construction (`draft-connolly-cfrg-xwing-kem`, HPKE KEM id `0x004D`, draft-06 as implemented by the library) |
| AEAD | AES-256-GCM |
| Hash / KDF | SHA-384 / HKDF-SHA384 |
| Signature | Ed25519 |
| Library | OpenMLS 0.9 with the `draft-ietf-mls-pq-ciphersuites` feature; crypto provider `openmls_rust_crypto` 0.6 (RustCrypto `x-wing` / `ml-kem` crates) |

Rules:

- A client MUST create every group with this ciphersuite.
- A client MUST refuse a key package whose ciphersuite differs from the
  group's (checked in `Group::add`; test `ciphersuite_downgrade_rejected`).
- A client MUST refuse to open stored state whose recorded ciphersuite its
  provider does not support (`Client::open_with_key`).
- The ciphersuite of a group never changes. Changing it requires a new group
  (ReInit commits are rejected, section 6.4).
- Because the code point is provisional, a future final RFC may assign a
  different number. Tree will then define Tree v2 with the final code point;
  v1 and v2 groups do not mix. A client MUST NOT reinterpret `0x004E` if its
  meaning changes in a later draft.

### 2.2 Tested alternative

`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (`0x004D`) on the libcrux
provider (`openmls_libcrux_crypto` 0.4) uses the **same X-Wing KEM** with
ChaCha20-Poly1305 and SHA-256. It is exercised by the test
`xwing_suite_on_libcrux_works`. It is not used by Tree v1. The libcrux
provider does not offer `0x004E` in the version used. Which provider ships at
stage 1 is open question Q1 (section 12).

### 2.3 Classical fallback

Building `tree-core` without the `pq` feature selects
`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`. Such a build is **not
Tree v1** and cannot join v1 groups (key packages are refused for ciphersuite
mismatch). Release builds MUST enable `pq`.

### 2.4 Signatures are classical

All MLS signatures (leaf nodes, key packages, message framing) use Ed25519.
Tree v1 authentication is therefore **not** post-quantum: a future quantum
adversary could forge signatures. This does not let it decrypt recorded
traffic (confidentiality rests on the hybrid KEM), but it would allow active
impersonation once such an adversary exists. See claim C8 and section 3.2.

---

## 3. What is deliberately not in v1

### 3.1 Third KEM (HQC): not in v1

Decision: Tree v1 uses ML-KEM-768 + X25519 only. HQC is not used anywhere.

Reasons:

1. **No standard way to combine it with MLS.** No MLS ciphersuite, final or
   draft, includes HQC. Adding it would require Tree to define its own
   three-way KEM combiner and its own ciphersuite, i.e. a home-made protocol
   construction (hard rule 1). The security of the X-Wing combiner rests on a
   published analysis; a Tree-defined three-way combiner would have none.
2. **No audited implementation in the stack.** HQC was selected by NIST in
   2025 for standardisation; there is no final FIPS standard yet, and neither
   MLS provider used by Tree implements it.
3. **More attack surface.** Timing side channels have been published against
   HQC implementations (for example key recovery through rejection-sampling
   timing). Every extra primitive is extra code that must be constant-time,
   verified and audited. Three-way hybrids are not automatically stronger
   than two-way ones in a real implementation.
4. **Size.** HQC-192 ciphertexts are about 9 KB (8,978 bytes measured in the
   earlier Python prototype; a triple ciphertext was 10,110 bytes, against
   1,088 bytes for ML-KEM-768 alone). In MLS every commit carries one HPKE
   ciphertext per node in the copath resolution (about log2(n) for a group
   of n members) and every tree node carries a public key, so commits would
   grow roughly tenfold and key packages several-fold.
5. **Limited benefit.** HQC would only help if both ML-KEM-768 and X25519
   were broken at the same time. Against a quantum adversary X25519 is
   already assumed broken, so the third KEM only hedges against a break of
   module lattices (ML-KEM). That is a real but speculative risk, and it is
   better addressed by switching ciphersuite when needed (MLS supports this
   through new groups) than by carrying the cost in every commit.

HQC (or another non-lattice KEM) will be reconsidered when **all** of the
following hold, or when the last one holds alone:

- HQC is published as a final NIST standard;
- an IETF document (CFRG or MLS working group) defines an HPKE KEM or MLS
  ciphersuite that includes it, with a published security analysis of the
  combiner;
- an implementation with independent review of constant-time behaviour is
  available in the Rust stack and supported by the MLS library;
- or: significant published cryptanalytic progress against ML-KEM.

If adopted, it will be a new MLS ciphersuite (Tree v2 groups), never a
separate layer next to MLS.

### 3.2 SLH-DSA root identity: not in v1

Status: **not implemented and not part of v1 MLS credentials.** v1 uses
`BasicCredential` with the device's Ed25519 key; there is no account-level
root key.

Possible later design (stage 4 or later, needs its own specification and
review): a long-term SLH-DSA (FIPS 205) identity key per account that signs
("certifies") each device's MLS signature key, with the certificate carried
in an MLS credential type other than `BasicCredential`. That would give a
post-quantum, hash-based anchor for "these devices belong to the same
person", which v1 does not have. Open points: credential format, revocation,
SLH-DSA signing cost (about 1.6 s per signature in the earlier prototype, so
only on device addition), and how it interacts with key transparency.
Separately, the MLS library already offers ciphersuites with ML-DSA
signatures (for example `0x0052`, ML-KEM-768+X25519 with ML-DSA-44); moving
to such a suite is the simpler path to post-quantum authentication and would
be a Tree v2 decision.

### 3.3 Deniability

Not provided. MLS messages carry the sender's signature, so a member who
leaks a message can prove it is genuine.

---

## 4. Outer envelope seal

### 4.1 Format

Every MLS message that Tree sends to existing group members (application
messages and commits) is wrapped as:

```
envelope = 0x01 || tag || mls_bytes
  0x01      1 byte, envelope version 1
  tag       32 bytes
  mls_bytes the complete TLS-serialised MLSMessage (RFC 9420 §6),
            wire_format = mls_private_message (0x0002)
```

Welcome messages are **not** sealed (the new member has no exporter secret
yet). They are sent as the bare TLS-serialised `MLSMessage` with
`wire_format = mls_welcome (0x0003)`. Because an `MLSMessage` starts with the
protocol version `0x0001`, its first byte is `0x00`, so a receiver and the
server can tell a welcome (`0x00…`) from an envelope (`0x01…`) by the first
byte.

### 4.2 Key and tag

For the epoch `e` in which the message was created:

```
K_e = MLS-Exporter("tree/envelope/v1", group_id, 32)          (RFC 9420 §8.5)
    = ExpandWithLabel(DeriveSecret(exporter_secret_e, "tree/envelope/v1"),
                      "exported", Hash(group_id), 32)
tag = HMAC-SHA-256(K_e, mls_bytes)                            (full 32 bytes)
```

- `Hash` is the ciphersuite hash (SHA-384); `ExpandWithLabel` and
  `DeriveSecret` are as in RFC 9420 §8 (label prefix `"MLS 1.0 "`).
- `group_id` is the raw MLS group id (16 random bytes for groups created by
  Tree).
- The HMAC input is the **entire** `mls_bytes`, including the cleartext
  header (group id, epoch, content type, authenticated data).
- A commit is sealed with the key of the epoch it was **created** in (the
  epoch every receiver still holds), not the epoch it creates.

### 4.3 Check-before-MLS rule

A receiver MUST verify the seal before passing `mls_bytes` to MLS, and MUST
NOT write any state if the check fails:

1. If `len(envelope) < 33` or `envelope[0] != 0x01`: reject (malformed).
2. Compute the expected tag under each envelope key the receiver holds for
   this group: current epoch `N`, then `N-1`, `N-2` (section 6.2). Compare in
   constant time over all 32 bytes.
3. If no key matches: reject, or hold the envelope for a later retry
   (section 6.7). Nothing has been consumed.
4. If key `K_e` matches: parse `mls_bytes` exactly (no trailing bytes). The
   `PrivateMessage.group_id` MUST equal this group's id and
   `PrivateMessage.epoch` MUST equal `e`; otherwise reject.
5. Only then hand the message to MLS.

On `main`: all steps are implemented; in step 3 the envelope is rejected
(holding it for a retry is **(in progress)**, section 6.7). Step 4 also
requires `wire_format = mls_private_message`.

### 4.4 Why

OpenMLS deletes a message's generation key when it looks it up, before the
AEAD tag has been verified. A modified copy that arrived before the genuine
message therefore made the genuine one undecryptable (finding F-001). The
seal ensures that only someone who knows the epoch's exporter secret, i.e. a
member of that epoch, can make MLS consume a key. It also keeps arbitrary
bytes away from the MLS parser.

The seal authenticates **group membership in an epoch**, not the sender: any
member of epoch `e` can seal anything for epoch `e`. Sender authentication is
MLS's job (claim C3). A member, or a removed member during the past-epoch
window, can still burn keys (claim C11).

Machine-checked: `formal/envelope_seal.pv` (claim C1).

---

## 5. Identities, members and key packages

### 5.1 Device identity

Each device has:

- an **MLS signature key** (Ed25519), stored in the encrypted database; it
  signs the device's key packages, leaf nodes and MLS messages;
- a separate **server authentication key** (Ed25519) used only for HTTP
  request signatures (section 8). The server does not know the MLS key and
  the MLS layer does not know the server key.

The MLS credential is a `BasicCredential` whose identity bytes are exactly
the device's MLS signature public key. It carries **no display name**: key
packages are public and stored on the server, so anything in the credential
is readable by the server (finding F-009). A client MUST refuse a key package
whose credential is anything else (`Group::add`), and MUST reject a commit
that adds one (section 6.4). Display names travel only inside the group,
end-to-end encrypted, as application payloads ([APP_PROTOCOL.md](APP_PROTOCOL.md)).
They are not authenticated beyond "this member says so" and MUST NOT be used
for any security decision (F-008).

### 5.2 Member id

Members are identified by a value derived from their MLS signature key:

```
member_id = SHA-256("tree/member-id/v1" || signature_key)
```

where `signature_key` is the raw `LeafNode.signature_key` bytes (32 bytes for
Ed25519). RFC 9420 §7.3 requires signature keys to be unique among the
leaves of a group, so member ids are unique in a group.

Rules: `Incoming::Message` reports the sender's `member_id`; `Group::remove`
takes member ids, several in one commit (all devices of a person);
`Group::members` returns member ids; the app shows names (learned inside the
group) only next to a member id and flags two members using the same name. The safety number
a user compares out of band is derived from the member ids of a person's
devices (section 5.4).

For an application message of a past epoch (section 6.2) the sender's
member id is taken from the members of **that** epoch, which the receiver
keeps together with the epoch's envelope key: a leaf index may belong to a
different member in the current epoch.

### 5.3 Key packages

- Format: the TLS-serialised `KeyPackage` struct (RFC 9420 §10), **not**
  wrapped in an `MLSMessage`.
- Content: ciphersuite `0x004E`, `BasicCredential` holding the signature
  key (no name), the device's MLS signature key, a fresh HPKE init key, lifetime `not_before = now - 1 h`,
  `not_after = now + 84 days` (library default).
- One-time use: each key package is used for at most one add.
- Upload: at most 100 per request, 16 KiB each, 200 stored per device
  (server limits, [SERVER_API.md](SERVER_API.md)). The client keeps 20 on
  the server and uploads 20 more when `GET /v1/keypackages/count` is below
  10: at sign-up, after joining a group, and during sync at most once an
  hour (others may have claimed some meanwhile).
- Last resort (RFC 9420 §16.8): each device also keeps one key package with
  the `last_resort` extension on the server (`PUT
  /v1/keypackages/last-resort`). The server hands it out only when the
  device has no one-time key package left, and keeps it, so claiming all
  one-time key packages (claims cost 5 rate tokens) cannot stop others from
  adding the device. Its private part is not deleted on join, so welcomes to
  it lose some forward secrecy until it is replaced: the client replaces it
  every 7 days and then deletes the private part of the one before the
  previous one (the previous one stays for welcomes still on their way).
- Claim: `POST /v1/keypackages/claim` returns one key package per device of
  an account and deletes it in the same statement, oldest first; for a
  device without one, its last-resort key package (`last_resort: true`).
- Validation by the adder (RFC 9420 §10.1, done by `KeyPackageIn::validate`):
  signatures, lifetime, protocol version, `init_key != encryption_key`,
  extension support; plus Tree's ciphersuite check. The adder SHOULD also
  check that the key package's signature key is the one it expects for that
  contact (pinned or verified) and warn on change (`user.key_change_warning`
  is always on): the client pins each contact's device keys at the first
  add and reports a change as `KeyChanged`.
- Joining: the library deletes the private part of a key package as soon as
  it finds its reference in a welcome, before verifying the welcome. Tree
  keeps a copy and writes it back if the join fails (finding F-006, fixed).
- Expiry: a device MUST NOT use expired key packages and SHOULD delete the
  private parts of its own expired key packages **(in progress)**.
- After a suspected compromise a device MUST treat all of its unused key
  packages as exposed: their private init keys let an attacker read welcomes
  sent to them. There is no API yet to delete one's own key packages on the
  server short of removing the device (open question Q6).

The server cannot check key packages (it does not parse them) and does not
bind them to the uploading device's identity beyond the upload request
signature. A malicious server can hand out key packages it generated. This is
only detected by comparing safety numbers or, later, by key transparency
(stage 4). See claim C3.

### 5.4 Safety numbers

What two people compare out of band. A person is the set of their devices'
member ids. Per side:

```
fingerprint = SHA-256("tree/safety-number/v1" || uint32 n || member_id_1 || ... || member_id_n)
              (member ids sorted, duplicates removed)
digits      = for each of the first 6 five-byte chunks of fingerprint:
              (chunk as a 40-bit big-endian integer) mod 100000, as 5 digits
```

The safety number is the two 30-digit strings, the smaller first, as 12
groups of 5 digits; both people see the same 60 digits. The QR code is
`0x01 || fingerprint(shower) || fingerprint(scanner)`; the scanner checks that
the second half is its own fingerprint and the first the one it holds for the
contact (`crates/tree-core/src/safety.rs`). About 100 bits per side: a
substituted key would have to match 30 decimal digits.

Pinning (`tree-client`): the first set of devices learned for an account
(from a key-package claim, or from a roster inside a group) is trusted as it
is; any later member id not seen before for that account raises a key-change
warning (`user.key_change_warning`, permanently on) and clears "verified".
A new member id that only a group roster claimed (not the server, in a
key-package claim) stays *unconfirmed* until the user verifies the safety
number or invites the account: it is warned about but does not count as the
contact when deciding requests (APP_PROTOCOL.md 5, F-018).
This is trust on first use; key transparency (stage 4) removes the first-use
gap. Today a person's side contains only the devices the other side has
seen; with several devices per person (stage 3) the safety number changes
whenever a device is added, which is the intended warning.

---

## 6. Groups

### 6.1 Group creation

`MlsGroupCreateConfig`:

| Setting | Value |
| --- | --- |
| ciphersuite | `0x004E` |
| wire format policy | pure ciphertext (library default): all application messages, proposals and commits are `PrivateMessage` |
| ratchet tree extension | on: the welcome carries the ratchet tree (RFC 9420 §12.4.3.3) |
| padding size | 256 (section 6.8) |
| sender ratchet | out-of-order tolerance 32, maximum forward distance 1000 |
| past epochs | 2 |
| resumption PSKs kept | 0 (library default) |
| group id | 16 random bytes (library default) |

A one-to-one chat is a two-member group; there is no separate 1:1 protocol.

### 6.2 Parameters

| Parameter | Value | Meaning |
| --- | --- | --- |
| Out-of-order window | 32 | keys up to 32 generations behind a sender's ratchet head are kept; in practice the 31 messages before the newest one received from that sender can still arrive late |
| Maximum forward distance | 1000 | a receiver derives keys at most 1000 generations ahead of the head; a message further ahead is rejected |
| Past-epoch window | 2 | application messages of epochs `N-1` and `N-2` are still decrypted after the receiver moved to `N`; commits never (section 6.6) |
| Padding | 256 bytes | see section 6.8 |
| Key refresh cadence | at least every 24 h of activity, and on suspicion | see section 6.9 |
| Envelope keys kept | `N`, `N-1`, `N-2` | see section 4.3 |

Cost of the past-epoch window: the secrets that decrypt epoch `N` stay on the
device until it reaches `N+3` instead of being deleted at `N+1`, so a device
compromise exposes not-yet-read messages of up to three epochs (claim C4).
Two epochs cover a message in flight while one or two commits pass, which is
the normal case with server ordering; a longer window would only widen that
exposure.

### 6.3 Key derivation and deletion (by reference)

Tree uses MLS's derivations unchanged:

- epoch secrets: RFC 9420 §8 (`init_secret`, `commit_secret` from the
  UpdatePath, `joiner_secret`, `epoch_secret`, and the secrets derived from
  it: `sender_data_secret`, `encryption_secret`, `exporter_secret`,
  `external_secret`, `confirmation_key`, `membership_key`,
  `resumption_psk`, `epoch_authenticator`, next `init_secret`);
- per-sender message keys: secret tree, RFC 9420 §9 and §9.1 (separate
  application and handshake ratchets per leaf);
- exporter: RFC 9420 §8.5 (used only for the envelope key);
- epoch authenticator: RFC 9420 §8.7 (shown as the group verification code).

Deletion schedule (RFC 9420 §9.2 plus Tree parameters):

1. A message key and nonce are deleted as soon as the message has been
   encrypted or decrypted. A secret-tree node is deleted once both children
   are derived; a ratchet secret is deleted once the next one is derived.
2. Keys for skipped generations are kept only inside the out-of-order
   window (32) and only for the current and retained past epochs.
3. When a commit moves the device from epoch `N` to `N+1`, the epoch secrets
   of `N` are deleted, except: the secret tree state needed to decrypt
   application messages of `N` is kept while `N` is inside the past-epoch
   window, and Tree keeps the 32-byte envelope key `K_N` for the same time
   (not the exporter secret). When `N` leaves the window (the device reaches
   `N+3`), both are deleted.
4. Tree's own records of sent envelopes (for echo recognition, section 6.6)
   are hashes only and are deleted with the epoch.
5. Deleted rows are overwritten inside the database file (`secure_delete`).
   Copies that flash storage keeps outside the file are encrypted with the
   database key (see [THREAT_MODEL.md](THREAT_MODEL.md)).
6. Message plaintext history kept by the app is **not** covered by this
   schedule: whatever the app stores is exposed if the database is opened.
   Forward secrecy protects messages in transit and key material, not the
   app's own history (disappearing messages are a separate feature).

### 6.4 Allowed commits

Every Tree commit is created by the committer for itself, with its proposals
inline. Allowed commit contents in v1:

| Content | Allowed |
| --- | --- |
| inline Add proposals | yes, if the added credential is the signature key (section 5.1) |
| inline Remove proposals (not of the committer itself) | yes, by an admin (section 6.11) |
| GroupContextExtensions with exactly Tree's settings (section 6.11) | yes, by an admin |
| UpdatePath | required, except in a commit that contains only Add proposals (RFC 9420 §12.4 allows that). Tree's own adds carry **no** UpdatePath (`add_members_without_update`: 3 KB instead of 30 KB to 2.3 MB at 2,000 leaves, [BENCHMARKS.md](BENCHMARKS.md)); its removes and key refreshes always carry one |
| proposals by reference | no |
| Update proposals | no (key refresh is a commit with an UpdatePath and no proposals) |
| PreSharedKey, ReInit, ExternalInit, other GroupContextExtensions, custom proposals | no |
| external commits / external senders | no |

A receiver MUST reject a commit that violates this table, after MLS has
staged it and before merging it (`check_commit` in `group.rs`). A commit
whose committer is not a member (external commit) is rejected as well.

Because an add carries no UpdatePath, it does not refresh the adder's own
keys; its next key refresh does (section 6.9).

Any member may add members; only admins may remove others or change the
group settings (section 6.11). Finer roles are stage 3.

### 6.5 Proposals from others

A receiver MUST reject standalone proposal messages (`content_type =
proposal`) and external join proposals, and MUST NOT store them. The server
MUST refuse them as well (section 7.4). Reason: finding F-007 (a member could
get changes committed in an honest member's name, and a commit arriving
before the proposal it references was lost).

Consequence: a member cannot leave by proposing its own removal. In v1 a
leaving device sends an application-level leave request and deletes its
group state; any remaining member then commits the Remove. Until then the
leaving device's leaf stays in the tree (it no longer holds any group
secrets, so this does not affect confidentiality unless an attacker had
copied its state earlier).

A leaving device: Tree v1 has no leave call in the core. The app sends an
ordinary application message that its peers' apps understand as a leave
request, then stops using the group; a remaining member's app calls
`Group::remove` with the leaving device's member id. A self-remove without
proposals is open question Q9.

### 6.6 Receiving

For each envelope taken from the mailbox, in mailbox order (all steps are
implemented on `main` except the "already processed" set in step 2):

1. If the first byte is `0x00`: welcome path (`Client::join`).
2. Duplicate check: if `SHA-256(envelope)` equals the hash of this device's
   pending commit, the server accepted it: merge it and return
   `OwnCommitMerged` (section 7.1 step 6). If it is in the set of commit
   envelopes this device has itself merged and still retains (epochs `N`,
   `N-1`, `N-2`), return `OwnEcho` without processing. Own application
   messages are recognised by MLS (sender = own leaf) and also give
   `OwnEcho`. If it is in the set of envelopes already processed,
   acknowledge and ignore **(in progress: no such set; a replayed
   application message is rejected by MLS, a replayed commit by the epoch
   rule in step 4)**.
3. Seal check, section 4.3. The matching key identifies the epoch `e`.
4. By `content_type`:
   - application: decrypt with MLS if `e ∈ {N, N-1, N-2}`;
   - commit: only if `e == N`; MLS stages and verifies it; Tree checks
     section 6.4; then merge. If this device has a pending commit of its own
     for epoch `N` and the incoming commit differs, discard the pending commit
     first (section 7.1, step 6);
   - proposal: reject (section 6.5).
5. Persist the new state in one transaction, then acknowledge the mailbox
   message. A failed message is acknowledged too, unless it is held for retry
   (section 6.7).

A message from a member removed in epoch `N+1`, sent while it was still a
member of `N`, is a valid epoch-`N` message and is accepted inside the
past-epoch window.

### 6.7 Messages from a future epoch

An envelope sealed with `K_{N+1}` that arrives before the commit creating
`N+1` fails the seal check and has consumed nothing. With an honest server
this does not normally happen: an accepted commit (and its welcome) is
inserted into every recipient's mailbox before any message of the new epoch
can be sent, and mailboxes are delivered in insertion order. As a safety net
a client SHOULD hold up to 64 such envelopes per group (and per unknown group
id, for a device waiting for its welcome) for up to 7 days and retry them
after each merged commit or join **(in progress)**.

### 6.8 Padding

MLS pads the `PrivateMessageContent` with zero bytes (RFC 9420 §6.3.1,
§15.1) so that

```
(len(content and signature encoding) + len(padding) + 16) mod 256 == 0
```

where 16 is the AES-GCM tag length; that is, the AEAD ciphertext length is a
multiple of 256 bytes (OpenMLS `padding_size(256)`). The cleartext
`PrivateMessage` header and the encrypted sender data are not padded.

`authenticated_data` (sent in clear) MUST be empty in v1. Receivers SHOULD
reject a non-empty value; `main` rejects it on application messages.

### 6.9 Key refresh

`Group::refresh_keys` commits an UpdatePath with no proposals: the device
gets a fresh leaf HPKE key and fresh path secrets. It keeps its signature key
and credential.

- A device SHOULD refresh its keys in a group at least once every 24 hours
  in which the group had traffic, and MUST refresh in every group after a
  suspected compromise, after restoring from backup or recovery, and after
  re-installation. Implemented in `crates/tree-client/src/refresh.rs`: a
  device refreshes during `sync` once 24 hours passed since its last
  refresh and the group had traffic since; `refresh_all` refreshes every
  group at once; removes and settings changes count as refreshes.
- A device that has just joined SHOULD refresh its keys soon: its leaf key
  came from a one-time key package that waited on the server. The core sets
  `Group::should_refresh_keys` on join and clears it with the device's first
  merged commit that carries an UpdatePath. The client refreshes after a
  random delay of 1 to 10 minutes, so the first refreshes of a freshly
  built large group are staggered ([BENCHMARKS.md](BENCHMARKS.md)).
- A refresh does **not** replace the signature key. Recovering from a
  compromised signature key requires removing the device and adding a new
  device identity (claim C5).
- A remove by a device also refreshes that device's own path (it carries an
  UpdatePath); an add does not.

### 6.10 Verification code

`Group::verification_code` returns the epoch authenticator (RFC 9420 §8.7).
Two members who see the same value are in the same epoch with the same group
state. It changes every epoch and is not an identity check. The identity
check is the safety number (section 5.4).

### 6.11 Admins and group settings

The group settings are one MLS group-context extension, so every member
holds the same value, every commit's transcript covers it, and the server
never sees it:

| Item | Value |
| --- | --- |
| Extension type | `0xF2E0` (RFC 9420 §17.3 private-use range) |
| Content | JSON: `admins` (member ids, hex), optional `name` (at most 128 characters), optional `features` (chat-scope key -> `{applied, option}`) |
| Size | at most 16 KiB |
| Required capabilities | the group context also carries RequiredCapabilities naming `0xF2E0`, so every added device must support it (Tree key packages declare it) |

Rules every receiver checks before merging a commit, judged by the settings
**before** the commit:

1. A commit with a GroupContextExtensions proposal or any Remove proposal must
   come from an admin.
2. A new group context must hold exactly the RequiredCapabilities extension
   (naming only `0xF2E0`) and the settings.
3. The settings after the commit must name at least one admin who is a
   member after the commit, only `chat.*` feature keys, and a name of at most
   128 characters.
4. No feature entry may contradict a permanent lock (`chat.e2e` released,
   `chat.private_to_public` applied). An option that does not fit the
   feature's option format (table below) is not a reason to refuse: a newer
   client may know more values, and refusing a commit the others accept
   would split the group. Such an option reads as the default. A device
   never writes one itself (`check_own`).

The creator is the first admin. Admins appoint and drop admins, rename the
group and apply or release chat features (checked against the feature
registry: permanent locks such as `chat.e2e` cannot be released; an honest
client never writes a locked key at all). An admin who is removed drops out
of the admin list automatically. A leave request (section 6.5) is carried
out by an admin. Reading the settings also drops any entry that contradicts
a permanent lock (a group joined with one in its first settings, which no
commit check saw): a locked key always has its locked value.

Feature options, one table for every scope (`option_format` in
`crates/tree-core/src/features.rs`; applying anything else returns
`INVALID_OPTION` with the accepted format):

| Key | Option | Without an option |
| --- | --- | --- |
| `chat.disappearing` | duration, 1 s to 365 days | `1d` is stored |
| `chat.edit`, `chat.delete_for_all` | duration, 1 s to 30 days | 24 hours |
| `chat.mention_all` | `admins` or `all` | `admins` |
| `user.group_add` | `contacts` or `nobody` | `contacts` |
| `user.app_lock` | `passphrase`, `pin` or `bio` | `passphrase` |
| every other standard feature (also `user.drafts`, `user.unarchive_on_message`, `user.username_link`) | none | |

Mute durations are not a feature option: muting is a per-chat action
(1 hour, 8 hours, 1 week or until unmuted, APP_PROTOCOL.md 6.1).

A duration is whole seconds (`90`) or a whole number with one unit `s`, `m`,
`h`, `d`, `w` (`30m`, `1d`, `2w`). The apps offer a few values per key
(`option_choices`).

Chat features are stored here; what they enforce on each device (media off,
edit window, disappearing timer, ...) is implemented feature by feature.

### 6.12 Attachments

Each file is encrypted with its own key and uploaded as an opaque blob
(`POST /v1/attachments`); the reference travels in an end-to-end encrypted
application message ([APP_PROTOCOL.md](APP_PROTOCOL.md) `file`).

| Item | Value |
| --- | --- |
| Cipher | AES-256-GCM in the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár, CRYPTO 2015), RustCrypto `aead::stream::StreamBE32` |
| Chunks | 64 KiB of plaintext + 16-byte tag; nonce = 7-byte random prefix ‖ 32-bit big-endian chunk counter ‖ last-chunk flag; an empty file is one empty last chunk |
| Key | 32 random bytes per file, never reused |
| Commitment | the reference carries SHA-256 of the ciphertext and of the plaintext; the receiver checks the first before decrypting and the second (and the size) after |
| Retention | the server deletes the blob after the mailbox TTL (30 days) |

Why the hashes: AES-GCM is not key-committing, so one ciphertext can be made
to decrypt under two keys to two different files. Every member of a group
receives the same reference, so within a group this cannot show different
files to different members; the plaintext hash also binds the content for
later reporting. Chunk reordering, dropping and truncation are detected by
STREAM itself.

The server learns the size of each ciphertext and when it was uploaded and
fetched (and by which device, while the request runs); not its name, type,
uploader (not stored) or content. A device that has the id can fetch the
ciphertext; it is useless without the key from the message.

The group's `chat.media` setting (section 6.11) is enforced by every device:
when released, sending is refused and received references are dropped.

### 6.13 Outbox: reliable sending

A send that meets a network error must neither be lost nor, when only the
answer was lost, arrive twice. Every application message except typing and
presence signals goes through a durable outbox in the device's encrypted
database (`tree_outbox`, SCHEMA.md 1.2; `crates/tree-core/src/storage/outbox.rs`,
`crates/tree-client/src/outbox.rs`).

States: `queued -> sending -> sent | retry -> sending ... | failed`.

1. **Enqueue.** One transaction stores the history entry (shown at once,
   with status pending), the outbox item and, when the message is sealed
   now, the group's advanced key state. An item has a random 16-byte local
   id; enqueue is idempotent by it (a second enqueue of the same id changes
   nothing, also after the item was sent).
2. **Seal once.** The MLS message is produced exactly once and stored with
   the item. Every attempt sends exactly these bytes; the device never
   re-encrypts on retry (that would use new message keys and put a second,
   different ciphertext of the same message into the group). Normally the
   item is sealed at enqueue. A chat message is franked first (8.5), which
   needs the server; if the server cannot be reached for the tag, the
   encoded payload waits in the outbox and the first attempt that obtains
   the tag seals it, once. The unsealed payload is erased when sealed.
3. **Idempotency key.** Fixed when the item is sealed:

   ```text
   key = SHA-256( lp("tree/outbox/idempotency/v1") || lp(group_id)
                  || lp(sender member id) || lp(local_id) || lp(sealed message) )
   lp(x) = uint32 big-endian length of x || x
   ```

   It binds the group, the sender, the item and its content with length
   prefixes and a domain label, so two different items (other group, other
   sender, other local id or other bytes) cannot share a key; the server
   additionally scopes keys per sending device (8.10). It is an identifier,
   not a secret. Sent with every attempt.
4. **Attempt.** The item is stored as `sending` before the request leaves.
   The answer `200` makes it `sent`: the ciphertext and recipient list are
   erased, only ids and state stay (for 30 days, then the record goes).
   A passing error (network, server `5xx`, `408`, `425`, `429`) makes it
   `retry` with a wait of 5 s after the first counted failure, doubling to at
   most 1 h; after 8 counted attempts it is `failed`. Any other refusal
   (`4xx`, for example `SUSPENDED`) makes it `failed` at once.
5. **Order.** Items of one group go out in the order they were made: an item
   waiting for its next attempt holds back the later items of its group.
   Typing and presence signals are not queued and are not sent while
   messages of the group wait, so they never overtake them.
6. **User sends.** A new message makes its group's waiting items go now,
   in order, before it. Such an early attempt does not count against an
   item's 8 attempts (a user typing while offline does not use them up).
7. **Crash.** An item found in `sending` when the profile is opened was cut
   off: it becomes `retry`, due at once, and the interrupted attempt counts.
   Whether or not the server had received it, the resend carries the same
   key and bytes, so the server delivers it at most once (8.10).
8. **Sync** sends every due item after receiving; it reports `Sent` for a
   message that reached the server and `SendFailed` for an item given up.
9. **User actions on failed items.** Retry: a fresh budget of attempts and
   one attempt now. Cancel: the item and its ciphertext are deleted and the
   message leaves this device's history. A cancelled item may still have
   reached others if an earlier attempt arrived and only the answer was
   lost.

An item sealed in epoch `N` and resent after the group moved on is read by
the others as long as `N` is within the 2 past epochs they keep (6.2, F-002);
older items fail to decrypt there and are dropped. If the server's record
had expired and a copy did arrive twice, the second copy is still not shown
twice: its MLS message key was deleted after the first decryption (6.3), and
text and file payloads carry a message id the history stores only once.

Commits do not use the outbox: a pending commit is stored with the group
state and resubmitted with the same bytes (7.1 steps 5 and 7); the server
answers a retry from the winner hash it stores per epoch (7.4), so commits
are idempotent without a key.

---

## 7. Commit ordering

MLS requires that all members apply the same sequence of commits (RFC 9420
§14). Tree uses the server as the sequencer: **the server accepts the first
commit it receives for each (group, epoch); clients merge a commit only after
the server accepted it.**

On `main`: the client side below is implemented in the core
(`PendingCommit`, `Group::confirm_commit`, `Group::discard_commit`,
`Group::pending_commit`); the steps that talk to the server belong to the
app. The server side (section 7.4) is implemented in `tree-server`
(`POST /v1/commits`).

### 7.1 Client: two-phase commit

1. **Create pending.** Build the commit for current epoch `N` without merging
   it (OpenMLS pending commit). Seal it with `K_N`. While a commit is pending
   the device MUST NOT create another commit for this group. It MAY keep
   sending application messages in epoch `N`.
2. **Submit** it to the server (section 7.4) together with the recipient list
   (all other devices of epoch `N`, including members being removed), the
   welcome (if the commit adds devices) and the devices being added. The
   welcome travels in the same request so that the server releases it only
   if the commit wins, and inserts it before any message of epoch `N+1` can
   exist.
3. **Accepted** (`200`): merge the pending commit (now epoch `N+1`) and
   record `SHA-256(envelope)` for echo recognition. A welcome MUST NOT be
   sent by any other path.
4. **Rejected** (`409 COMMIT_CONFLICT`): if `winner_sha256` equals
   `SHA-256` of this device's own envelope, the device actually won (a
   previous response was lost): treat as accepted. Otherwise discard the
   pending commit and its welcome, process the winning commit when it
   arrives from the mailbox, then decide again in epoch `N+1` (for example,
   the member to be removed may already be gone). A key package used in a
   discarded commit MAY be reused for the retry of the same add, since its
   welcome was never delivered; it MUST NOT be used for another group.
5. **No answer** (timeout, network error): resubmit the **same bytes**. The
   server answers idempotently. The device MUST NOT build a different commit
   for epoch `N` while the outcome is unknown.
6. **Winner arrives first.** If a commit for epoch `N` arrives from the
   mailbox while this device's own commit is pending, it is the winner (the
   server only delivers accepted commits). If its hash equals the pending
   envelope's hash, this device won: merge the pending commit. Otherwise
   discard the pending commit and process the winner.
7. **Crash.** The pending commit and its envelope are stored with the group
   state, in the same transaction as the MLS state. After a restart with a
   pending commit (`Group::pending_commit`), the device resubmits the same
   bytes (step 5) before doing anything else in the group. If the server
   had accepted it before the crash, the idempotent answer is `200` and the
   device confirms; if the accepted commit's echo is fetched from the
   mailbox first, step 6 merges it. Either way a crash between acceptance
   and merge ends with the commit merged.

### 7.2 Own echoes

If the committer lists its own other devices as recipients, they receive the
commit normally. If the committing device itself receives its commit back,
it recognises it by hash (section 6.6 step 2) and reports `OwnEcho`.

### 7.3 What a client never does

- merge its own commit before acceptance;
- merge a commit that did not come through the server's mailbox (for example
  one received over another transport);
- process a commit for an epoch other than its current one.

### 7.4 Server: ordering rules

Endpoint `POST /v1/commits` (signed like every request, section 8):

```json
{
  "group_id": "<base64 MLS group id>",
  "epoch": 17,
  "recipients": ["<device_id>", ...],
  "body": "<base64 envelope>",
  "added": ["<device_id>", ...],
  "welcome": "<base64 MLSMessage welcome, present iff added is non-empty>",
  "removed": ["<device_id>", ...]
}
```

Limits: commit and welcome 4 MiB each, recipients plus added at most 2048
devices (a 1,000-member group with two devices each; sizes from
[BENCHMARKS.md](BENCHMARKS.md)). The epoch must fit a signed 64-bit integer.

The server:

1. Parses the start of `body`: byte `0x01`, 32 tag bytes, then
   `uint16 version = 0x0001`, `uint16 wire_format = 0x0002`,
   `opaque group_id<V>` (RFC 9420 §2.1.2 variable-length integer prefix),
   `uint64 epoch`, `uint8 content_type`. It requires `group_id` and `epoch`
   to equal the JSON fields and `content_type = 3` (commit), else
   `BAD_REQUEST`. It does not verify the tag (it has no key). The length
   prefix of `group_id` must use the minimum encoding.
2. Within one database transaction, looks up the group record
   `(group_id) -> (last_epoch, eligible devices, winner hashes of the last 64
   accepted epochs)` and applies the first matching rule:
   1. no record: accept and create the record;
   2. `epoch <= last_epoch`: if `SHA-256(body)` equals the stored winner hash
      for that epoch, answer `200` as accepted again (idempotent retry);
      otherwise `409 COMMIT_CONFLICT` with `winner_sha256` (lowercase hex, or
      `null` if that epoch is older than the stored 64);
   3. sender's device not in `eligible`: `403 NOT_ELIGIBLE`;
   4. `epoch == last_epoch + 1`: accept;
   5. otherwise (`epoch > last_epoch + 1`): `409 EPOCH_MISMATCH` with
      `last_epoch`.
3. On accept, in the same transaction: stores `last_epoch = epoch`, the
   winner hash, `eligible = ({sender} ∪ recipients ∪ added) \ removed`;
   inserts the body into every recipient's mailbox and the welcome into every
   added device's mailbox (mailbox semantics of section 8.3). Response
   `200 {"accepted": true, "id": "...", "epoch": ..., ...}`; an idempotent
   retry returns the same `id`. Only registered devices enter `eligible`. If the welcome starts with a byte
   other than `0x00` or does not carry `wire_format = 0x0003`, the request is
   refused with `BAD_REQUEST` before anything is stored.

`POST /v1/messages` MUST refuse bodies that are envelopes with
`content_type` commit (use `/v1/commits`) or proposal (not allowed in v1),
and all bodies starting with `0x00` (welcomes travel only with their commit).

Why the eligibility set: without it, anyone who knows a group id and its
next epoch number (both in the cleartext MLS header, and epochs count up by
one) could submit a junk commit first and freeze the group, because the
server cannot check the seal. With it, only devices the server saw in the
group can take the slot. A removed device is excluded by the `removed` list.
A malicious **current** member can still freeze the group by submitting a
commit that the others reject (claim C11); the v1 recovery is to start a new
group.

Records are kept for the life of the group. A group whose last device is
deleted has its record deleted.

Machine-checked (abstract model, honest server): `formal/commit_ordering.pv`
(claim C9).

---

## 8. Server API security

The full API is in [SERVER_API.md](SERVER_API.md). This section fixes the
security-relevant constructions byte for byte.

### 8.1 Request authentication

Each device has an Ed25519 authentication key registered with the server.
Every authenticated request carries `X-Tree-Device`, `X-Tree-Timestamp`
(unix seconds, decimal digits only, at most 12), `X-Tree-Nonce` (16 to 64
characters of `[A-Za-z0-9_-]`) and `X-Tree-Signature` (standard base64 of the
64-byte Ed25519 signature) over:

```
"tree-auth-v1" \n METHOD \n PATH_AND_QUERY \n TIMESTAMP \n NONCE \n DEVICE_ID \n hex(SHA-256(body))
```

- fields joined by a single `0x0A`, no trailing newline;
- `PATH_AND_QUERY` exactly as sent (for example `/v1/messages?wait=25`);
- `DEVICE_ID` empty for signup;
- `hex` is lowercase; the body hash covers the raw body (empty body allowed).

Server checks, in order: header syntax; device exists; `|timestamp - now| <=
300 s`; `verify_strict` (rejects non-canonical signatures and small-order
keys); the signature has not been seen while inside the window (replay
cache); then the per-device rate limit (so forged requests cannot drain a
device's budget).

Replay cache: in memory, keyed by the 64 signature bytes, entry kept until
`timestamp + 300 s`. Ed25519 signatures are deterministic and strictly
verified, so a replay is byte-identical and is caught. Limits: the cache is
lost on restart (a request captured in the last 300 s could be replayed
once after a restart) and is not shared between server instances. Both are
open items (Q7). TLS 1.3 is required, so only the server or a TLS-breaking
attacker can capture requests in the first place.

Signed authentication protects server resources and mailbox access (fetch,
acknowledge, delete). Message confidentiality and authenticity never depend
on it.

### 8.2 Signup proof of work

```
SHA-256("tree-signup-v1" || auth_pub (32 bytes) || pow_nonce (8 bytes, big-endian))
```

must start with `POW_BITS` zero bits (default 20, about a million hashes on
average). It binds the work to the new key, so it cannot be reused for
another account. It is a cost, not a security property; it is combined with
a per-address signup rate limit (kept in memory only).

### 8.3 Mailbox semantics

- One mailbox per device. `POST /v1/messages` stores the body once and adds
  one entry per recipient device. The sender is not stored with the
  message; a send with an idempotency key leaves a separate record (8.10).
- Delivery is at least once, in insertion order per mailbox, until the
  recipient acknowledges. Clients MUST tolerate duplicates (section 6.6).
- Unacknowledged entries are purged after 30 days. A device that is offline
  longer loses messages and, if it missed a commit, cannot continue in that
  group; it must be removed and added again.
- A malicious server can drop, delay, reorder or withhold anything (claim
  C11). A dropped or reordered commit shows up as a stalled or failing epoch,
  not as wrong content.

### 8.4 Usernames

An account may register one @username. The client normalises it (trim, drop
a leading `@`, ASCII lower case; 3 to 32 characters of `a-z`, `0-9`, `_`,
starting with a letter) and sends only

```
username_hash = SHA-256("tree/username/v1" || normalised name)
```

The server stores the hash with the account id and answers lookups by hash.
Usernames are short and guessable, so the hash keeps them out of plain view
but does not hide them from a server that tries a dictionary: lookups cost 10
rate-limit tokens each, and an account can hide its name from lookups
(`user.discoverable` released) while keeping it reserved. The client
registers the name with `discoverable` taken from `user.discoverable`, and
applying or releasing that setting re-registers the name first (the setting
changes only once the server agreed). A lookup of a hidden name gets the same
`404` as a name nobody has; registering a hidden name for another account
still gets `409 USERNAME_TAKEN` (the name is reserved, the account is not
revealed). Non-ASCII names are not supported in v1.

**Username links and QR codes** (`user.username_link`, user scope,
released by default; `crates/tree-client/src/links.rs`). Applying it makes a
16-byte random token and the link `tree://u/<base64url token>`; the QR code
is the same text. The server stores only
`SHA-256("tree/ulink/v1" || token)` with the account (one per account) and
answers a lookup by that hash only while the account's @username is
registered and discoverable, with the same `404` otherwise. Resetting the
link registers a new token: the old link stops working, the @username
stays. Releasing the setting deletes the link; releasing the @username
deletes it too (and releases the setting on the device). The link does not
spell the name, so a reset link cannot be traced back by guessing names. A
device that opens or scans a link adds the account as a contact the user
chose. What the server learns: that the account has a link, and which
accounts look one up (as for name lookups, 10 rate tokens each).

### 8.5 Reports with message franking, account suspension

The server never sees messages, so a report is a member's device handing
over messages it decrypted, by the user's choice (`user.report` is always
on). Franking lets the server check that a reported message is genuine and
was sent by the reported account, without storing anything per message
(`crates/tree-server/src/reports.rs`, `crates/tree-client/src/franking.rs`):

1. **Sender.** For every `text`, `edit` and `file` payload `P` (exact JSON
   bytes), a fresh random 32-byte key `k` and
   `com = HMAC-SHA-256(k, "tree/franking/v1" || u32(len(group_id)) || group_id || P)`.
   `POST /v1/franking {com}` returns
   `tag = HMAC-SHA-256(K_server, "tree/franking-tag/v1" || com || u32(len(account)) || account || i64(minute))`
   and `minute`, where `account` is the signed request's account. The server
   learns only that this account franked something at this minute, which it
   already knows from the send; `com` is random to it. Nothing is stored.
2. **Message.** The sender sends `{"t":"franked","p":P,"k":k,"tag":tag,"m":minute}`
   inside MLS (APP_PROTOCOL.md 1). The receiver takes `P` as the message and
   keeps `(P, k, tag, minute)` with it in its encrypted history
   (`tree_messages.franking`); it is erased with the message (deletion for
   everyone, disappearing messages).
3. **Report.** `POST /v1/reports` with the reported account, a reason and
   up to 20 messages `(P, k, tag, minute, group_id)`, all of one sender. The
   server recomputes `com` and `tag` and stores the report with the plaintext
   and a `verified` flag per message for operator review.
4. **Operator.** Lists open reports, resolves them, and can suspend an
   account (`apply` / `release`): every signed request of a suspended
   account is refused with `403 SUSPENDED`.

Receivers drop `text`, `edit` and `file` that arrive unfranked (F-013).
Limits: 20 reports per account per day, 16 KiB per message, only existing
accounts; resolved reports are deleted 30 days after resolution (F-012).
Reporting a `file` hands the operator its file key, so the operator can
read that attachment; apps say so before the user sends the report.

What a valid tag proves: the reported account's device asked for a tag on
exactly `P` for this group. A reporter cannot frame another account (the
tag binds the account), alter the text (binds `P` through `com`) or move it
to another group. What it does not prove: who else saw it, or that the
sender's client was honest about anything else. A sender that does not
frank (a modified client) makes its own messages unverifiable, which the
operator sees; the report still carries the text the reporter's device
received. `K_server` is 32 random bytes created on first start in the
server database (`server_secrets`); losing it makes older tags unverifiable,
nothing more. HMAC-SHA-256 as commitment and MAC follows the published
franking constructions; nothing new is built here. Symbolic model:
`formal/franking.pv` (no framing, altering or moving of a verified message;
server key secret), with a negative control showing why the tag must bind the
account.

### 8.6 Recovery phrase and account recovery

The recovery phrase restores the **account** (the ability to register a
device for it), never MLS state (RECOVERY_THREAT_MODEL.md 1). Code:
`crates/tree-core/src/recovery.rs`, `crates/tree-server/src/recovery.rs`.

- **Phrase.** BIP-39: 128 to 256 bits from the system random generator as 12
  to 24 words with checksum, standard English or Korean word list (`bip39`
  crate). 24 words is the default. Generated on the device, shown once,
  never stored by Tree, never sent anywhere.
- **Recovery key.** `seed = HKDF-SHA-256(salt "tree/recovery/v1", ikm = BIP-39
  entropy, info "account-recovery-key", 32)`, Ed25519 key pair from `seed`
  (RFC 8032). Test vector for the all-zero 128-bit entropy ("abandon … about"):
  public key `c5dda56a7105f6429ee484c58047cff5f59701f7ebb53a95d9f899597a02efed`.
- **Registration.** A device of the account sends the public key with a
  proof of possession, `Sig_new("tree-recovery-set-v1" || u32 len || account
  || new_pub)` (`POST /v1/recovery/apply`). One key belongs to at most one
  account. While a key is active, replacing it or releasing it
  (`user.recovery_phrase`) is immediate only with
  `Sig_current("tree-recovery-change-v1" || u32 len || account || new_pub or
  32 zero bytes)`, i.e. the old phrase; without it the change is pending for
  7 days, shown to every device (`GET /v1/recovery`), and the old phrase
  still recovers meanwhile. A recovery cancels any pending change. This
  keeps a stolen unlocked device from locking the owner out (F-010).
  On the device, `user.recovery_phrase` shows what the server reports:
  applied while a key can recover the account, so a release without the
  phrase stays applied with "release pending until <date>"
  (`Session::release_pending`, FFI `Feature.release_pending_until`) and
  reads released once the server dropped the key. Every answer from the
  server (`apply`, `release`, `GET /v1/recovery`) updates it.
- **Recovery.** A new device generates its request key, solves the signup
  proof of work and sends, signed with its new key (as signup),
  `recovery_pub`, its `auth_pub`, `ts` and
  `Sig_recovery("tree-recover-v1" || auth_pub || revoke_others || i64 ts)`.
  The server checks the proof of work, the request signature, that `ts` is
  within the clock-skew window (F-011), the recovery signature
  (`verify_strict`) and finds the account whose active key is
  `recovery_pub`; then adds the device. With `revoke_others` it first deletes every other device of the
  account with its mailbox and key packages (lost or stolen phone). Wrong
  key and unknown key get the same answer, `403 RECOVERY_REFUSED`. Per-IP
  limit as for signup.
- **After recovery.** The device is a new MLS member: groups, history and
  contacts' trust are not restored. Contacts add the device again and see a
  key change (`user.key_change_warning`, always on). The @username and any
  suspension stay with the account.

What the phrase protects: whoever has it can take over the account (and,
with `revoke_others`, cut off the owner's devices). It cannot read past
messages. Not yet: notifying the other devices of a recovery and a waiting
period in which they can cancel it (RECOVERY_THREAT_MODEL.md 2.3 item 6 asks
this for PINs; for the phrase it is planned with the apps), encrypted
backups keyed from the phrase (stage 3).

### 8.7 Group invite links

`chat.invite_link` (chat scope, admins; released by default). Code:
`crates/tree-client/src/invites.rs`, `crates/tree-server/src/invites.rs`.

1. An admin device makes a 16-byte random secret; the link is
   `tree://join/<base64url secret>`. It registers
   `SHA-256("tree/invite/v1" || secret)` with a lifetime (1 minute to 30
   days) and a use limit (1 to 10,000), and keeps locally which group the
   link is for. Making a link applies `chat.invite_link` in the group
   settings (a commit) if it was released.
2. A device that opens the link sends the secret and a fresh 16-byte random
   nonce (`POST /v1/invites/join`, 5 rate tokens). The server checks expiry
   and uses, counts one use per account, queues a join request (with the
   nonce) for the owner's device and returns the owner's account id. The
   joining device remembers (for one day) that the user asked to join,
   keyed by the nonce, with the owner's account.
3. The owner's device, on sync, fetches its requests and adds the requester
   through the normal path (key-package claim, commit, welcome, and a roster
   naming the nonce; the joiner accepts the group without a request only if
   the nonce is one it sent to that account, once: F-014, F-018) only if the
   link is still in its store, the group's settings still apply
   `chat.invite_link`, the device is still an admin, and the requester is not
   blocked. Otherwise it drops the request. Requests are acknowledged
   (deleted) either way.

Consent, in both directions (F-018):

- **The joiner** chose this group by opening the link, so the group is
  accepted although the joiner's `user.group_add` (even `nobody`) and
  message requests would otherwise refuse or hold it. Only the joiner's
  blocked list still applies. The exemption covers exactly one group: the
  one the owner's device adds for that request.
- **Nobody else can use the exemption.** Everyone who saw a published link
  knows its secret and hash, so neither identifies the owner. The nonce does:
  only the owner's device receives it, from the server, with the request. A
  stranger who claims the owner's account in a roster without the nonce is
  judged as any stranger (APP_PROTOCOL.md 5).
- **The owner** publishes the link and adds only accounts that asked to
  join through it; nobody is put into a group on the owner's side, so
  `user.group_add` (a setting about being added) has nothing to decide
  there. The owner's admins control the link with `chat.invite_link`, and
  the owner's blocked accounts are refused.
- The marker lives on the device that opened the link. The joiner's other
  devices are added too and see the group as from a stranger (a request or
  declined), which errs on the safe side.
4. Revoking deletes the device's links on the server and releases
   `chat.invite_link` for the group, which makes every admin device refuse
   requests for its links too.

The server never learns the group: only the hash of the secret, the owner
account and device, the limits, and which accounts asked. Whoever holds the
link can ask to join; the limits and the admin's control of the setting
bound that. The joiner sees the members once it is in (and contacts' key
changes as usual); it cannot learn anything about the group before. Expired
links stay 7 days on the server so requests made in time are still
handled, then are purged.

### 8.8 Push wake-ups without content

Phones stop background connections, so the app needs a push to sync. Tree
sends **no content in push**: a device registers an endpoint URL that a push
gateway gave its app (UnifiedPush style), and when anything arrives in its
mailbox the server POSTs the fixed body `wake` there. The app then syncs
over its own authenticated connection and decrypts locally. Code:
`crates/tree-server/src/push.rs`.

- What the gateway learns: that this endpoint got a wake-up at this time.
  Not the sender, group, size, type or content. Wake-ups are coalesced (at
  most one per device per `PUSH_INTERVAL_SECS`, default 5 s), which also
  blurs message counts.
- Server-side request forgery: the server only accepts and only contacts
  hosts listed in `PUSH_ALLOWED_HOSTS` (`host` = default port only,
  `host:port` for another; https only, no credentials in the URL, no
  redirects followed, 10 s timeout). At most 16 gateways are contacted at
  once and the queue is bounded, so a slow gateway delays nobody else. Push
  is off when the list is empty.
- The vendor push services of the phone platforms need a gateway with the
  operator's credentials; that gateway receives the same `wake` only.
  Setting one up is part of deployment (HANDOFF 3.5, needs the owner).

### 8.9 Anti-spam limits

Two operator flags, both applied by default (`crates/tree-server/src/limits.rs`):

| Flag | Who | Limit |
| --- | --- | --- |
| `server.new_account_limits` | accounts created today or yesterday | requests that reach others (send, commit, key-package claim, username lookup, invite-link join) cost 5 times the rate tokens; at most 50 devices per message or commit |
| `server.report_limits` | accounts with verified reports from 3 or more different accounts in the last 7 days | 10 times the tokens; at most 20 devices per message or commit |

These limit, they do not suspend: suspension stays a human decision.
Verified reports need genuine messages (8.5), so a group of people cannot
limit an account that sent them nothing. Reading the mailbox is never
limited. Paid or attested sign-up (design) and the stranger deposit (stage
3) are not implemented.

### 8.10 Idempotent sends

`POST /v1/messages` accepts an optional `idempotency_key` (base64, 16 to 64
bytes; the client sends the 32-byte key of 6.13). In the same database
transaction as the delivery the server keeps the record

```text
(sending device id, key) -> request hash, delivered count, day
request hash = SHA-256( lp("tree/send-request/v1") || lp(body)
                        || uint32 n || lp(r_1) ... lp(r_n) )
```

with `r_1 ... r_n` the recipient ids sorted and de-duplicated (`lp` as in
6.13), and applies, before anything is delivered:

1. no record for (device, key): deliver, store the record;
2. a record with the same request hash: answer `200` with the stored
   `delivered` count and `"replayed": true`; nothing is delivered or
   charged again;
3. a record with another request hash: `409 IDEMPOTENCY_KEY_REUSE`; nothing
   is delivered.

The lookup and the delivery are one `BEGIN IMMEDIATE` transaction, so
concurrent copies of one request deliver once. Keys are scoped per sending
device: the same key bytes from another device are another record.
Duplicate recipient ids in one request are delivered once (they always were).

Metadata. The record is new metadata: the server keeps, for up to the
message TTL (30 days), that a device sent a keyed message on a given day,
with a hash of the request. It does not keep the body, the recipients, the
message id or the time of day; the replayed answer therefore has empty
`unknown_devices` / `full_devices` (keeping them would link sender and
recipients). Once the body is acknowledged and erased, the request hash
cannot be checked against anything. Records are deleted by the purge task
after the message TTL, with their device, and beyond `MAX_IDEMPOTENCY_KEYS`
(default 10,000) per device the oldest are dropped at once, so they cannot
grow without bound; a client retries within minutes, far inside both.

---

## 9. Security claims

These are **claims with stated assumptions and reductions**, written so that
they can be checked and attacked. They are not machine-checked proofs, except
where the table in section 10 says a formal model checks a stated part of
them under stated abstractions. Attack-scenario tests on the reference
implementation (`crates/tree-core/tests`) exercise many of them but prove
none.

### 9.1 Adversaries

- **Network / server (A-net).** Dolev-Yao: reads, drops, delays, reorders,
  replays and injects on every network path; runs or controls the Tree
  server; can register any number of devices and write into any mailbox.
- **Insider (A-ins).** One or more current members of a group, running
  modified clients.
- **Removed member (A-rem).** A former member that keeps everything it had
  at removal time and acts as A-net afterwards.
- **State compromise (A-cmp).** At a time `t` obtains the complete local
  state of one device: database key, MLS signature key, HPKE private keys of
  its leaf and path, epoch secrets, secret-tree state, retained past-epoch
  state, envelope keys, unused key-package private keys.
- **Quantum (A-q).** Records traffic today and later has a large quantum
  computer (breaks X25519 and Ed25519, not ML-KEM-768, AES-256 or SHA-2 at
  the assumed levels).

### 9.2 Assumptions

- **A1 (MLS).** RFC 9420 provides confidentiality, authentication, forward
  secrecy and post-compromise security as analysed in the published
  literature, for example: Alwen, Coretti, Dodis, Tselekounis, "Security
  analysis and improvements for the IETF MLS standard for group messaging"
  (CRYPTO 2020); Brzuska, Cornelissen, Kohbrok, "Security analysis of the MLS
  key derivation" (IEEE S&P 2022); Cremers, Hale, Kohbrok, "The complexities
  of healing in secure group messaging: why cross-group effects matter"
  (USENIX Security 2021); Wallez, Protzenko, Beurdouche, Bhargavan,
  "TreeSync: authenticated group management for messaging layer security"
  (USENIX Security 2023). These analyses cover the protocol (some of them
  earlier drafts), not the OpenMLS implementation, and each has its own model
  and limits.
- **A2 (HPKE KEM).** The X-Wing KEM is IND-CCA secure if ML-KEM-768 is
  IND-CCA secure **or** X25519 satisfies the strong Diffie-Hellman
  assumption, in the random-oracle model for SHA3-256, as shown in Barbosa,
  Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan, "X-Wing: the hybrid
  KEM you've been looking for" (IACR Communications in Cryptology, 2024).
  Tree does not re-prove this.
- **A3 (symmetric).** AES-256-GCM is a secure AEAD; HKDF-SHA384 and the MLS
  labelled derivations behave as PRFs; HMAC-SHA-256 keyed with a uniformly
  random 32-byte key is a PRF (hence a MAC); SHA-256 is collision resistant.
- **A4 (signatures).** Ed25519 (strict verification) is EUF-CMA secure
  against classical adversaries.
- **A5 (implementation).** OpenMLS 0.9 and its crypto providers implement
  RFC 9420 and the primitives correctly, in constant time where required,
  and erase deleted secrets. **Tree has not verified this.** Their audit
  status must be recorded before stage 1 (Q2).
- **A6 (randomness).** The operating system's random generator is secure and
  its output is not available to the attacker.
- **A7 (deletion).** Deleted keys cannot be recovered from the device (see
  section 6.3 item 5 for the limits).

Notation: `G` group, `N` epoch, "member of `G` in epoch `e`" = holds a leaf
in the tree of epoch `e`; "honest" = not controlled by the adversary and not
compromised at the relevant time.

### C1. Envelope authenticity against non-members

**Statement.** If an honest device accepts an envelope past the seal check
for group `G` and epoch `e` (and therefore passes its `mls_bytes` to MLS),
then those exact `mls_bytes` were sealed by a member of `G` in epoch `e`.

**Adversary.** A-net that is not a member of `G` in epoch `e` (it may be a
member of other groups or of other epochs of `G`, and it may know
envelope keys of those).

**Assumptions.** A1 (the exporter secret of `e` is known only to members of
`e`), A3 (HMAC-SHA-256 PRF, exporter as PRF).

**Reduces to.** Unforgeability of HMAC under a key indistinguishable from
random; secrecy of the MLS exporter secret.

**Not claimed.** Sender authentication (any member of `e` can seal); replay
protection (a replayed envelope passes the seal; MLS rejects it); protection
against members or removed members during the past-epoch window; welcomes
(not sealed, F-006 handles damaged welcomes).

**Checked:** `formal/envelope_seal.pv` (symbolic; abstractions in
`formal/README.md`).

### C2. Message confidentiality

**Statement.** An application message sent by an honest member in epoch `e`
of `G` reveals nothing beyond its padded length (section 6.8), its cleartext
header (group id, epoch, content type) and its timing, to an adversary that
is not a member of `G` in epoch `e`, unless (a) some member of `e` was
compromised while it still held key material for that message (C4), or
(b) a compromise of a member before `e` had not healed by `e` (C5), or (c)
the adversary controls a member of `e` (including through a key package it
substituted and the adder accepted without verification, C3).

**Adversary.** A-net, A-rem, A-cmp, A-q (for recorded traffic).

**Assumptions.** A1, A2, A3, A5, A6.

**Reduces to.** MLS key indistinguishability of epoch and message keys, with
the HPKE KEM used in TreeKEM and in welcomes being IND-CCA (A2), and AEAD
security.

**Not claimed.** Metadata protection (section 11). Confidentiality against
members. Confidentiality of stored plaintext history on a compromised device.

### C3. Authentication and agreement

**Statement.** If an honest device accepts an application message in epoch
`e` of `G` attributed to member id `X`, then it was created in epoch `e` of
`G` by the holder of `X`'s signature key. Honest members that accept the same
epoch of `G` agree on its group context (membership, tree, ciphersuite,
transcript).

**Adversary.** A-net, A-ins (other than `X`), A-rem.

**Assumptions.** A1, A3, A4 (classically), A5.

**Reduces to.** MLS framing signatures and AEAD; transcript hash and
confirmation tag agreement (RFC 9420 §8.2).

**Not claimed.**
- That member id `X` belongs to a particular person. v1 has no
  authentication service beyond the user comparing safety numbers; a
  malicious server can substitute key packages (section 5.3). Key
  transparency is planned for stage 4.
- That display names are genuine (F-008); they are claims made inside the group.
- Authentication against A-q: Ed25519 is not post-quantum (section 2.4).
- Deniability (the opposite holds).
- Global ordering of messages from different senders.

### C4. Forward secrecy

**Statement.** Let device `D` be compromised at time `t` while in epoch `N`
of `G` (A-cmp). With the deletion schedule of section 6.3:

- **Not exposed:** every application message of `G` that `D` had already
  encrypted or decrypted before `t`; every message of epochs `<= N-3`.
- **Exposed:** every application message of epochs `N`, `N-1`, `N-2` that
  `D` had not yet decrypted at `t` (the compromise reveals the ratchet heads,
  so all later generations of those epochs, and the retained skipped keys
  inside the out-of-order window); all messages of later epochs until healing
  (C5); welcomes addressed to `D`'s unused key packages; and any plaintext
  history stored by the app.
- **Exposed for integrity only:** envelope keys `K_N`, `K_{N-1}`, `K_{N-2}`
  (the attacker can burn keys, not read).

**Adversary.** A-cmp plus A-net (which recorded all ciphertext).

**Assumptions.** A1, A3, A5, A7.

**Reduces to.** One-wayness of the secret-tree ratchet (RFC 9420 §9) and
effective deletion (§9.2).

**Not claimed.** A bound in wall-clock time: a message waiting in an offline
device's mailbox stays exposed to a compromise of that device for as long as
it waits (up to 30 days). Protection against forensic recovery of deleted
pages together with the database key.

**Checked:** the within-epoch part, `formal/forward_secrecy_chain.pv`.

### C5. Post-compromise security

**Statement.** Let device `D` be compromised at time `t` in epoch `N` of `G`
(A-cmp). Messages of epoch `M > N` of `G` are again confidential (C2) if all
of the following hold:

1. **Healing commit.** Between `t` and epoch `M` the server accepted, and
   honest members merged, either
   (a) a commit created by `D` itself that carries an UpdatePath (a key
   refresh or a removal; Tree's adds carry none, section 6.4), with path
   secrets drawn from randomness the attacker does not know; or
   (b) a commit by an honest member that removes `D`.
   Healing applies from the epoch that commit creates.
2. **Access ended.** The attacker had no access to `D`'s state or randomness
   after `t` up to and including the creation of that commit.
3. **No active use of the signature key.** The attacker did not use `D`'s
   signature key to inject its own commit for `D` before (1). A refresh does
   not replace the signature key, so an attacker who uses it can install a
   leaf key of its choice and is **not** healed by `D`'s later refreshes
   (`D` sees a commit from its own leaf that it did not make and MUST alert
   the user). In that case only (1b) followed by adding a new device identity
   heals.
4. **No other unhealed compromise.** No other member of epoch `M` is
   compromised without its own healing commit.
5. **Per group.** `D`'s compromise affects every group `D` is in; each group
   heals only through a commit in that group (cross-group effects, A1).
6. **Key packages.** Welcomes using `D`'s key packages from before `t` are
   exposed regardless; `D` must stop using them (Q6).

A commit by another honest member that does not remove `D` (for example that
member's own key refresh) does **not** heal `D`'s compromise: its path
secrets are encrypted to `D`'s current, compromised leaf key.

**Adversary.** A-cmp then A-net (passive w.r.t. `D`'s signature key unless
stated).

**Assumptions.** A1, A2, A3, A5, A6.

**Reduces to.** TreeKEM post-compromise security of the published analyses
(A1).

**Not claimed.** Healing of authentication (signature key) by key refresh.
Healing while `D` stays offline: if `D` never commits and nobody removes it,
the group never heals; a removal policy for inactive devices is open (Q5).

**Checked:** `formal/pcs.pv` (healing by own refresh; no healing by another
member's refresh) and `formal/pcs_signing_key_leaked.pv` (no healing when
the signature key is used).

### C6. Removed members

**Statement.** Let `R` be removed by a commit created by an honest member,
accepted for epoch `N` (so it creates `N+1`). `R`, keeping everything it had
and acting as A-net afterwards, learns nothing about application messages
encrypted in epochs `> N`.

`R` can read: messages of epochs `<= N`, including epoch-`N` messages that
honest members sent before merging the removal and that are still accepted
inside the past-epoch window.

**Conditions.** No current member colludes with `R` or is compromised
without healing; all of `R`'s devices are removed (a person with several
devices has several leaves); honest members never **send** in a past epoch
(the past-epoch window is receive-only).

**Assumptions.** A1, A2, A3, A5.

**Checked:** `formal/removal_secrecy.pv`; the negative control
`formal/removal_secrecy_send_in_past_epoch.pv` shows that sending in a past
epoch would leak to `R`.

### C7. Downgrade resistance

**Statement.** A v1 group's ciphersuite is `0x004E` for its whole life, and
no honest member adds a device whose key package uses another ciphersuite.

**Adversary.** A-net (including the server substituting key packages),
A-ins.

**Assumptions.** A1, A4, A5.

**Reduces to.** The ciphersuite is part of the MLS group context (bound by
the key schedule and signatures); key packages are signed and carry their
ciphersuite; Tree checks the key-package ciphersuite on add, and rejects
ReInit commits (section 6.4).

**Not claimed.** Protection if a release build is made without the `pq`
feature (section 2.3) or if the provisional code point changes meaning
(section 2.1).

### C8. Hybrid KEM security

**Statement.** Confidentiality of everything MLS protects with HPKE (path
secrets in commits, group secrets in welcomes) holds as long as **either**
ML-KEM-768 **or** X25519 holds, to the extent stated by the X-Wing analysis
(A2). Recorded traffic stays confidential against A-q if ML-KEM-768 holds.

This is **inherited from the ciphersuite's combiner analysis; Tree does not
prove it** and adds no combiner of its own.

**Not claimed.** Post-quantum authentication (section 2.4). Security if both
KEMs fail.

### C9. Commit agreement

**Statement.** With an honest server, two honest members never merge
different commits for the same (group, epoch); every merged commit was
accepted by the server.

**Adversary.** A-net except that it cannot impersonate the server on the
TLS-authenticated client-server channel; A-ins may submit arbitrary commits.

**Assumptions.** TLS server authentication; the client rules of section 7.

**Not claimed.** Agreement against a malicious server: it can show different
commits to different members (a fork). Members then end up in different
group states and can no longer read each other; the fork shows as a mismatch
of the verification code (section 6.10). Confidentiality is not affected
(C2), only availability.

**Checked:** `formal/commit_ordering.pv` (bounded to three epochs, unbounded
members); negative control `formal/commit_ordering_merge_early.pv` (the
stage-0 behaviour forks).

### C10. Server request authentication

**Statement.** Within one running server instance, a request is accepted
for device `D` only if it was signed by `D`'s authentication key within
300 seconds of the server's clock, and each signed request is accepted at
most once.

**Assumptions.** A4, A3 (SHA-256), honest server.

**Not claimed.** Replay protection across a server restart or across
instances (section 8.1, Q7). Anything about message content.

### C11. Availability: what is not provided

- The server (or anyone controlling the network) can drop, delay, reorder or
  withhold any message, commit, welcome or key package, and can refuse
  service. Reordering beyond the out-of-order window or across a commit makes
  messages fail; it does not make wrong content accepted.
- A malicious server can fork a group (C9).
- A current member can make specific messages undecryptable for others by
  sealing a modified copy that arrives first (F-001 residual), can freeze a
  group by winning the commit slot with a commit the others reject, and can
  leak anything it reads.
- A removed member can burn keys of messages of the epochs it knew while they
  are inside the past-epoch window.
- Anyone who can write to a mailbox can fill it (10,000 entries) or exhaust a
  device's key packages through claims (rate limited, not prevented).

---

## 10. What is machine-checked

Tool: ProVerif 2.05 (symbolic model, Dolev-Yao attacker). Commands and full
results: [`formal/README.md`](../formal/README.md).

| Model | Claim | Result |
| --- | --- | --- |
| `envelope_seal.pv` | C1: no forged or modified MLS bytes are accepted or reach MLS key consumption in an epoch the attacker is not a member of; honest envelope keys stay secret | verified |
| `envelope_seal_check_after_mls.pv` | negative control: checking the seal after MLS lets forged input consume keys (F-001) | attack found, as expected |
| `commit_ordering.pv` | C9: same (state, epoch) => same merged commit; merged => accepted | verified (3 epochs) |
| `commit_ordering_merge_early.pv` | negative control: merging own commit at once forks (F-003) | attack found, as expected |
| `removal_secrecy.pv` | C6: removed member learns no later-epoch message | verified |
| `removal_secrecy_send_in_past_epoch.pv` | negative control: sending in a past epoch leaks | attack found, as expected |
| `pcs.pv` | C5: own refresh heals, another member's refresh does not | verified / attack found, as expected |
| `pcs_signing_key_leaked.pv` | C5 condition 3: no healing when the signature key is used | attack found, as expected |
| `forward_secrecy_chain.pv` | C4 within one sender chain | verified / exposure found, as expected |

These models check the **Tree-specific logic** under abstractions (MLS key
schedule and TreeKEM as ideal one-way functions and ideal encryption). They
do not check MLS itself, the libraries, or the implementation. Claims C2, C3,
C7, C8, C10 and C11 are not machine-checked by Tree.

---

## 11. Metadata at stage 1

"Server" includes anyone who compromises or compels it. "Protected" means
the server cannot learn it from what it sees or stores.

| Item | Stage 1 | What the server sees | Later |
| --- | --- | --- | --- |
| Message content, media keys, group name and settings, admin list | protected | ciphertext only (section 6.11) | — |
| Display names | protected | nothing: not in key packages or credentials (F-009), only inside the group | — |
| @usernames | **partially protected** | a hash per account; guessable names can be found by trying (section 8.4) | — |
| Sender identity | **not protected** from the server | the authenticated device id of every send request (not stored) and the connection address | stage 4: sealed sender with anonymous delivery tokens |
| Sender identity towards other members | not hidden (by design) | — | — |
| Recipient device | **not protected** | mailbox id = device id, stored with each entry | stage 4: rotating mailbox ids |
| Group membership | **not protected** | the cleartext MLS group id in every message header plus the recipient list of each send; commit endpoint keeps an eligibility set | stage 4: group mailboxes with anonymous subscription |
| Group size | **not protected** | number of recipients; commit and welcome sizes grow with the tree | stage 4 reduces (group mailbox); not fully hidden |
| Group epoch and message type | **not protected** | cleartext `epoch` and `content_type` (application or commit) | none planned in MLS framing |
| Message size | **partially protected** | ciphertext padded to multiples of 256 bytes; attachments sized separately (exact ciphertext size, section 6.12) | larger padding buckets (open) |
| Timing | **not protected** | exact arrival time live; stored rounded to the minute | stage 4-5: cover traffic (optional) |
| Sending activity per device | **not protected** | idempotency records (8.10): sending device, day, request hash per keyed send, kept up to the message TTL; no recipients, body or time of day | sealed sender (stage 4) removes the device id |
| IP address | **not protected** from the server or network | live only; not stored (signup limiter keeps it in memory) | stage 4: relayed requests for sensitive endpoints; stage 5: independent proxies |
| Online status | **not protected** | long-poll and fetch times per device; acknowledgements | partly with relays; push providers learn wake-ups |
| Contact graph | **not protected** (derivable) | sender device -> recipient devices per request, group ids linking them, key-package claims; the address book is never uploaded | stage 4: sealed sender, anonymous credentials |
| Key package claims | **not protected** | which device claimed key packages of which account, and when | stage 4: anonymous credentials for claims |
| Account <-> device linkage | **not protected** | which device ids belong to an account | — |
| Feature flags: server scope | public | — | — |
| Feature flags: chat and user scope | **partially protected** | values are kept on devices / inside the group, never sent to the server in clear; their effects (typing indicators, read receipts) create observable traffic | — |
| Push notifications | **not protected** from push providers | a content-free wake-up per device | optional push without a platform provider (planned) |

---

## 12. Open questions

- **Q1 Provider.** `0x004E` is available only on the RustCrypto-based
  provider; the formally verified libcrux ML-KEM is available only with
  `0x004D`. Which provider and suite ship at stage 1?
- **Q2 Library assurance.** Record the review/audit status of OpenMLS 0.9,
  `openmls_rust_crypto`, the `x-wing` and `ml-kem` crates and libcrux before
  stage 1; Tree relies on them for every claim (A5).
- **Q3 Two-phase commit details.** Answered for the client in section 7.1
  step 7 (pending commit stored in the same transaction; resubmit after a
  restart). Remaining: how long a client keeps retrying before it gives up
  and discards.
- **Q4 Safety number format.** Decided for v1 in section 5.4 (needs the
  external review like everything else).
- **Q5 Inactive devices.** Policy for removing devices that never come back
  online (they block healing, C5, and lose mailbox messages after 30 days).
- **Q6 Key-package revocation.** An API to delete one's own unused key
  packages after a compromise.
- **Q7 Replay cache.** Persist the replay cache or shard it so restarts and
  multiple instances keep C10.
- **Q8 Device id binding.** v1 has no in-band binding between an MLS member
  and its server device id (needed to address mailboxes). Decided for v1: the
  app keeps the mapping as a roster that the adding member sends inside the
  group ([APP_PROTOCOL.md](APP_PROTOCOL.md)). A wrong entry misroutes
  messages (availability) but reveals nothing. An in-band binding stays a
  possible v2 change.
- **Q9 Leaving a group** without proposals (section 6.5): a self-remove
  mechanism once a standard one exists.
- **Q10 Commit freezing by insiders** (C11): a recovery path short of a new
  group.
