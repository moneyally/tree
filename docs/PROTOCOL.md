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
- One-time use: each key package is used for at most one add. There is no
  last-resort key package in v1; a device with none left cannot be added
  until it uploads more.
- Upload: at most 100 per request, 16 KiB each, 200 stored per device
  (server limits, [SERVER_API.md](SERVER_API.md)). A device SHOULD keep at
  least 50 on the server and SHOULD upload more when `GET
  /v1/keypackages/count` is lower **(in progress: no client logic yet)**.
- Claim: `POST /v1/keypackages/claim` returns one key package per device of
  an account and deletes it in the same statement, oldest first.
- Validation by the adder (RFC 9420 §10.1, done by `KeyPackageIn::validate`):
  signatures, lifetime, protocol version, `init_key != encryption_key`,
  extension support; plus Tree's ciphersuite check. The adder SHOULD also
  check that the key package's signature key is the one it expects for that
  contact (pinned or verified) and warn on change (`user.key_change_warning`
  is always on) **(in progress: no pinning yet)**.
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
| inline Remove proposals (not of the committer itself) | yes |
| UpdatePath | required, except in a commit that contains only Add proposals (RFC 9420 §12.4 allows that). Tree's own adds carry **no** UpdatePath (`add_members_without_update`: 3 KB instead of 30 KB to 2.3 MB at 2,000 leaves, [BENCHMARKS.md](BENCHMARKS.md)); its removes and key refreshes always carry one |
| proposals by reference | no |
| Update proposals | no (key refresh is a commit with an UpdatePath and no proposals) |
| PreSharedKey, ReInit, ExternalInit, GroupContextExtensions, custom proposals | no |
| external commits / external senders | no |

A receiver MUST reject a commit that violates this table, after MLS has
staged it and before merging it (`check_commit` in `group.rs`). A commit
whose committer is not a member (external commit) is rejected as well.

Because an add carries no UpdatePath, it does not refresh the adder's own
keys; its next key refresh does (section 6.9).

Any member may add or remove members in v1 (no roles; roles are stage 3).

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
  re-installation **(in progress: no scheduler yet)**.
- A device that has just joined SHOULD refresh its keys soon: its leaf key
  came from a one-time key package that waited on the server. The core sets
  `Group::should_refresh_keys` on join and clears it with the device's first
  merged commit that carries an UpdatePath. In a freshly built large group
  these first refreshes should be staggered ([BENCHMARKS.md](BENCHMARKS.md)).
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
  one entry per recipient device. The sender is not stored.
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
(`user.discoverable` released) while keeping it reserved. Non-ASCII names
are not supported in v1.

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
| Message content, media keys, group name and settings | protected | ciphertext only | — |
| Display names | protected | nothing: not in key packages or credentials (F-009), only inside the group | — |
| @usernames | **partially protected** | a hash per account; guessable names can be found by trying (section 8.4) | — |
| Sender identity | **not protected** from the server | the authenticated device id of every send request (not stored) and the connection address | stage 4: sealed sender with anonymous delivery tokens |
| Sender identity towards other members | not hidden (by design) | — | — |
| Recipient device | **not protected** | mailbox id = device id, stored with each entry | stage 4: rotating mailbox ids |
| Group membership | **not protected** | the cleartext MLS group id in every message header plus the recipient list of each send; commit endpoint keeps an eligibility set | stage 4: group mailboxes with anonymous subscription |
| Group size | **not protected** | number of recipients; commit and welcome sizes grow with the tree | stage 4 reduces (group mailbox); not fully hidden |
| Group epoch and message type | **not protected** | cleartext `epoch` and `content_type` (application or commit) | none planned in MLS framing |
| Message size | **partially protected** | ciphertext padded to multiples of 256 bytes; attachments sized separately | larger padding buckets (open) |
| Timing | **not protected** | exact arrival time live; stored rounded to the minute | stage 4-5: cover traffic (optional) |
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
