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

## F-002: messages in flight during a commit are lost (open)

- **Found:** 2026-10-01, verification pass, `tests/delivery.rs`
- **What:** the envelope key and MLS keys come from the receiver's *current*
  epoch. A message sent in epoch N that arrives after the receiver merged a
  commit to N+1 fails the seal check and cannot be read.
- **Severity:** medium (availability). No confidentiality impact.
- **Fix direction:** keep the previous epoch's envelope key and MLS secrets for
  a short window, or have the sender resend after it sees the commit.
- **Test:** `message_from_previous_epoch_after_commit_is_lost`.

## F-003: two simultaneous commits fork the group (open)

- **Found:** 2026-10-01, `tests/delivery.rs`
- **What:** `add`, `remove` and `refresh_keys` merge their own commit at once.
  If two members commit in the same epoch, each refuses the other's commit and
  the group splits into two states that cannot read each other.
- **Severity:** high (availability), needs no attacker, only bad timing.
- **Fix direction:** the server must order commits per group, and clients
  merge their own commit only after the server accepted it.
- **Test:** `concurrent_commits_fork_the_group`.

## F-004: an echoed own commit is reported as a seal failure (open)

- **Found:** 2026-10-01, `tests/delivery.rs`
- **What:** echoed own application messages return `Incoming::OwnEcho`, but an
  echoed own commit returns `Rejected("envelope seal mismatch")`, because it was
  sealed with the previous epoch's key. The app cannot tell it from a forgery.
- **Severity:** low.
- **Test:** `own_echoes`.

## F-005: `Registry::define` could remove a permanent lock (fixed)

- **Found:** 2026-10-01, `tests/registry.rs`
- **What:** `define` replaced any definition, so redefining `chat.e2e` or
  `points.send_to_user` with `Lock::None` made them releasable / applicable.
  Relevant once bots or plugins can register features.
- **Severity:** medium (breaks a hard rule of the feature registry).
- **Fix:** `define` now returns `Result` and refuses to redefine a feature with
  a permanent lock.
- **Test:** `define_cannot_override_permanent_locks`.

## F-006: a damaged welcome destroyed the one-time key package (fixed)

- **Found:** 2026-10-01, `tests/welcome_burn.rs`, `tests/robustness.rs`
- **What:** the MLS library deletes the one-time key package as soon as it finds
  its reference in a welcome, before decrypting or verifying anything. A
  damaged or forged copy delivered first therefore made the genuine welcome
  fail with `NoMatchingKeyPackage`: the new member could never join.
  Welcomes carry no outer seal, so anyone who can write to the mailbox could
  do this.
- **Severity:** medium (targeted denial of joining).
- **Fix:** `Client::join` keeps a copy of the matching key package and writes it
  back if the join fails. A successful join still consumes it.
- **Test:** `damaged_welcome_does_not_burn_key_package`,
  `join_mutated_welcome_never_accepted`.

## F-007: proposals from other members are trusted blindly (open)

- **Found:** 2026-10-01, `tests/membership.rs`
- **What:** `receive` stores every proposal, and the next commit made by this
  device (`add`, `remove`, `refresh_keys`) silently includes all of them.
  1. A member (or anyone they relay for) can get a device added or a member
     removed through someone else's key refresh; the others see the change as
     authored by the honest committer, and the committer is not told.
     For an external join request the welcome is thrown away.
  2. If a commit arrives before a proposal it refers to, it is refused and its
     key is consumed (same root cause as F-001), so it can never be processed.
     A member who sends a proposal to only some devices can cut the others off.
- **Severity:** medium-high (insider only; availability and misattribution).
- **Fix direction:** do not accept standalone proposals until there is an
  explicit policy, or show them to the app and commit only approved ones.
- **Test:** `insider_remove_proposal_carried_by_honest_commit`,
  `external_join_proposal_folded_into_key_refresh`,
  `commit_before_its_proposal_is_lost`.

## F-008: member names are not authenticated identities (open)

- **Found:** 2026-10-01, `tests/membership.rs`
- **What:** names are whatever the key package says. Two members can share a
  name, `Incoming::Message.from` cannot tell them apart, and `remove(name)`
  removes the first match, which may be the real person.
- **Severity:** medium until an identity layer exists (safety numbers from
  `signature_public_key` must be compared out of band).
- **Fix direction:** identify members by signature key / leaf, not by name.
- **Test:** `duplicate_names_are_possible`.
