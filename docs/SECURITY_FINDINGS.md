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

## F-002: messages in flight during a commit were lost (fixed)

- **Found:** 2026-10-01, attack-scenario test pass, `tests/delivery.rs`
- **What:** the envelope key and MLS keys came from the receiver's *current*
  epoch. A message sent in epoch N that arrived after the receiver merged a
  commit to N+1 failed the seal check and could not be read.
- **Severity:** medium (availability). No confidentiality impact.
- **Fix:** the core keeps the MLS secrets (`max_past_epochs(2)`), the envelope
  key and the leaf-to-member-id map of the last 2 epochs (`group_state.rs`,
  stored with the group). Application messages of N-1 and N-2 are read; a
  commit for any epoch other than the current one is rejected before MLS.
  The PrivateMessage header must name this group and the epoch whose key
  matched.
- **Cost / residual risk:** forward secrecy: unread messages of up to three
  epochs are exposed by a device compromise (PROTOCOL.md 6.2, C4). A removed
  member whose client ignores its removal can keep sending epoch-N messages
  that members accept until N leaves the window, and can burn keys in that
  window (C11). Messages are not attributed wrongly: the sender is the member
  of that epoch.
- **Tests:** `message_from_previous_epoch_after_commit_is_read`,
  `past_epoch_window_is_two_epochs`, `past_epoch_sender_is_the_member_of_that_epoch`,
  `removed_members_old_epoch_messages`, `past_epoch_commit_rejected`,
  `past_epoch_message_after_restart`.

## F-003: two simultaneous commits forked the group (fixed in the client)

- **Found:** 2026-10-01, `tests/delivery.rs`
- **What:** `add`, `remove` and `refresh_keys` merged their own commit at once.
  If two members committed in the same epoch, each refused the other's commit
  and the group split into two states that could not read each other.
- **Severity:** high (availability), needs no attacker, only bad timing.
- **Fix (client):** two-phase commits (PROTOCOL.md 7.1). The three calls return
  a `PendingCommit` and change nothing; `confirm_commit` merges after the
  server accepted, `discard_commit` drops it after a conflict. While pending no
  other commit can be made; sending and receiving continue. A winning commit
  arriving while ours is pending discards ours (`own_commit_discarded`); our
  own commit arriving from the mailbox is merged (`OwnCommitMerged`). The
  pending commit is stored with the group and survives a restart.
- **Still open:** the server side (first commit per group and epoch wins,
  PROTOCOL.md 7.4) is HANDOFF 3.2. Until then nothing orders commits.
- **Tests:** `concurrent_commits_no_longer_fork`, `pending_commit_changes_nothing`,
  `one_pending_commit_at_a_time`, `discard_and_confirm_without_pending`,
  `own_pending_commit_arriving_is_merged`, `lost_add_retried_with_same_key_package`,
  `pending_commit_survives_restart`.

## F-004: an echoed own commit was reported as a seal failure (fixed)

- **Found:** 2026-10-01, `tests/delivery.rs`
- **What:** echoed own application messages returned `Incoming::OwnEcho`, but
  an echoed own commit returned `Rejected("envelope seal mismatch")`, because
  it was sealed with the previous epoch's key. The app could not tell it from
  a forgery.
- **Severity:** low.
- **Fix:** the SHA-256 of each own merged commit envelope is kept while its
  epoch is retained; an identical envelope returns `OwnEcho` before any other
  processing. Hashes are compared in constant time.
- **Tests:** `own_echoes`, `own_commit_echo_forgotten_with_its_epoch`.

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

## F-007: proposals from other members were trusted blindly (fixed)

- **Found:** 2026-10-01, `tests/membership.rs`
- **What:** `receive` stored every proposal, and the next commit made by this
  device (`add`, `remove`, `refresh_keys`) silently included all of them.
  1. A member (or anyone they relay for) could get a device added or a member
     removed through someone else's key refresh; the others saw the change as
     authored by the honest committer, and the committer was not told.
     For an external join request the welcome was thrown away.
  2. If a commit arrived before a proposal it referred to, it was refused and
     its key was consumed (same root cause as F-001), so it could never be
     processed.
- **Severity:** medium-high (insider only; availability and misattribution).
- **Fix:** standalone proposals (`content_type = proposal`) and any message
  that is not a PrivateMessage (external join proposals are PublicMessages)
  are rejected after the seal check and before MLS, and never stored. Own
  commits clear the proposal store first. Incoming commits are checked against
  PROTOCOL.md 6.4 before merging (inline Add/Remove only, no removal of the
  committer, UpdatePath unless add-only, committer is a member). A commit
  that refers to a proposal by reference fails cleanly.
- **Consequence:** a member cannot leave by proposing its own removal;
  leaving is an application-level request (PROTOCOL.md 6.5, Q9).
- **Tests:** `insider_proposal_rejected_not_stored`,
  `insider_remove_proposal_not_carried_by_honest_commit`,
  `external_join_proposal_rejected`, `commit_with_proposal_by_reference_fails_cleanly`,
  `commit_with_disallowed_proposal_rejected`, `add_without_path_from_others_accepted`.

## F-008: member names were not authenticated identities (fixed)

- **Found:** 2026-10-01, `tests/membership.rs`
- **What:** names are whatever the key package says. Two members could share
  a name, `Incoming::Message.from` could not tell them apart, and
  `remove(name)` removed the first match, which could be the real person.
- **Severity:** medium until an identity layer exists.
- **Fix:** members are identified by member id,
  `SHA-256("tree/member-id/v1" || signature_key)` (PROTOCOL.md 5.2).
  `Incoming::Message` carries `from` (member id) and `name`; `members()` returns
  id, name and a duplicate-name flag; `remove` takes member ids, several in one
  commit.
- **Residual risk:** a member id says which key, not which person. Safety
  numbers must still be compared out of band (Q4) until key transparency.
- **Tests:** `duplicate_names_told_apart_by_member_id`, `member_id_derivation`,
  `several_members_removed_in_one_commit`.

## F-009: display names were readable by the server (fixed)

- **Found:** 2026-10-01, `crates/tree-client/tests/end_to_end.rs` (the first
  test that runs a real server and searches its database for plaintext)
- **What:** the MLS credential held the display name. Key packages carry the
  credential in the clear and are uploaded to the server, so the server
  stored every user's name next to their device id. The design says the
  server never knows profile names.
- **Severity:** medium (metadata: links a chosen name to an account and,
  through recipient lists, to groups).
- **Fix:** the credential now holds only the signature key; `Group::add`
  refuses other key packages and receivers reject commits that add them.
  Names are sent inside the group as an end-to-end encrypted `profile`
  payload (APP_PROTOCOL.md). The core no longer knows names.
- **Test:** `key_package_carries_no_name`, `name_credentials_refused`, and the
  end-to-end test's search of the server database (names and message texts).

## F-010: a stolen device could replace the recovery key (fixed)

- **Found:** 2026-10-01, internal review of the stage-1 server additions.
- **What:** any signed device of an account could replace or delete the
  recovery key at once. A thief with an unlocked phone could register a
  phrase of their own, recover with it, revoke the owner's devices, and the
  owner's real phrase would no longer work: recovery failed in exactly the
  case it exists for.
- **Severity:** high.
- **Fix:** a new key needs a proof of possession; while a key is active,
  replacing or releasing it is immediate only with a signature by the
  current key (the old phrase), otherwise it waits 7 days, visible to every
  device (`GET /v1/recovery`). During the wait the old phrase still
  recovers, and recovering cancels the pending change (PROTOCOL.md 8.6).
- **Test:** `crates/tree-server/tests/recovery.rs` (stolen-device scenario,
  delay, signed changes), `crates/tree-client/tests/recovery.rs`.

## F-011: recovery signatures could be replayed later (fixed)

- **Found:** 2026-10-01, same review.
- **What:** the recovery signature covered only the new request key and the
  revoke flag. Whoever kept an old device's request key and the signature it
  once sent could repeat the recovery after that device was removed, until
  the phrase changed.
- **Severity:** low to medium.
- **Fix:** the signed message includes the time; the server accepts it only
  within the clock-skew window.
- **Test:** `recovery_rules` (an hour-old signature gets `TIMESTAMP_SKEW`, a
  changed time does not verify).

## F-012: reports could fill the server's disk (fixed)

- **Found:** 2026-10-01, same review.
- **What:** up to 20 × 64 KiB per report, about two reports per second per
  device, never deleted, for any account id.
- **Severity:** medium (availability).
- **Fix:** 20 reports per account per day, 16 KiB per message, only existing
  accounts, resolved reports deleted after 30 days.
- **Test:** `reports_per_day_are_limited_and_resolved_ones_purged`.

## F-013: unfranked messages were accepted (fixed)

- **Found:** 2026-10-01, same review.
- **What:** receivers accepted `text`, `edit` and `file` without franking, so
  a modified client could make all its messages unreportable as verified.
- **Severity:** medium.
- **Fix:** receivers drop them. Remaining limit (documented in PROTOCOL.md
  8.5): a receiver cannot check the server's tag (it is a MAC), so a sender
  with a garbage tag is only exposed when a report fails to verify.
- **Test:** `franking::tests::unfranked_messages_are_dropped`.

## F-014: an invite-link owner could pull the user into other groups (fixed)

- **Found:** 2026-10-01, same review.
- **What:** opening a link marked the owner's account as "asked to join" for
  a day, so any group from that account skipped the request inbox and the
  `user.group_add` setting.
- **Severity:** low.
- **Fix:** the marker is tied to the link use, the adding device names it in
  its roster, and the marker is used once. (Since F-016 the marker is a
  nonce only the owner's device learns, not the link's hash.)
- **Test:** `strangers_join_through_a_link` (a second group from the owner
  arrives as a request).

## F-015: push hardening (fixed)

- **Found:** 2026-10-01, same review.
- **What:** allowed push hosts were matched without the port; one slow
  gateway delayed every wake-up; the queue was unbounded. Also: a damaged
  franking key was silently replaced (old reports would stop verifying), and
  one failing invite request blocked the acknowledgement of the others.
- **Severity:** low.
- **Fix:** host entries allow the default port only (`host:port` for
  others); at most 16 gateways contacted at once; a bounded queue; a damaged
  franking key is an error; invite requests are handled one by one and
  always acknowledged.
- **Test:** `push::tests::endpoints_are_checked`, `wakeups_are_contentless_*`,
  `a_damaged_franking_key_is_an_error_not_a_new_key`.

## F-016: a crash could lose a received message (fixed)

- **Found:** 2026-10-04, comparing with another implementation's review.
- **What:** receiving a message saved the group's new key state in one
  write and the message in the history in a later one. A crash in between
  left the message unacknowledged on the server, but its keys were used up,
  so the redelivered copy could no longer be read: the message was lost.
- **Severity:** medium (data loss, no confidentiality impact).
- **Fix:** each mailbox entry is handled inside one savepoint
  (`Client::begin_batch` / `end_batch`); the entry is acknowledged only
  after it.
- **Test:** `batch_is_all_or_nothing` (fails without the batch).

## F-017: a recovery key could block another account's recovery (fixed)

- **Found:** 2026-10-04, mutation testing (part 2).
- **What:** `POST /v1/recovery/apply` refused a key already active or
  pending on another account only for delayed changes. An account could set
  such a key immediately; the other account's pending change then failed on
  the unique index at every request, and its recovery was stuck.
- **Severity:** medium (denial of recovery; needs the victim's pending
  public key, which a thief who started the change has).
- **Fix:** the check runs on every path.
- **Test:** `a_key_pending_elsewhere_cannot_be_applied`.

## F-018: a stranger could add the user to groups as one of their contacts (fixed)

- **Found:** 2026-10-04, feature-switch audit.
- **What:** the adder of a group is the roster's sender under the account it
  claims, and that claim was taken as it is. (a) A stranger's device that
  claimed to be one of the user's contacts skipped message requests and
  `user.group_add`; the key-change warning appeared, but the group was
  accepted, and the claimed device was pinned so later groups passed
  silently. (b) Anyone who saw a published invite link knew its hash, so
  within a day of the user opening it they could claim the owner's account,
  name the hash and pull the user into their own group.
- **Severity:** medium (consent; no message content exposed).
- **Fix:** (a) a device counts as a contact only if it was pinned before and
  is not an unconfirmed key change; devices that only a roster claims for an
  account that already had devices stay unconfirmed (warned, no contact
  trust) until the user verifies the safety number or the server names them
  in a key-package claim. (b) The joiner sends a random nonce with its join
  request; only the owner's device gets it from the server and names it in
  the roster. Residual: trust on first use. A device that claims an account
  the user has no pinned device for (a contact added by hand, or none) is
  taken as that account; key transparency (stage 4) closes this.
- **Test:** `requests::tests::a_device_claiming_a_contacts_account_is_a_stranger`,
  `requests::tests::a_public_link_does_not_let_others_pull_the_joiner_in`.

## F-019: feature switches that did not do what they said (fixed)

- **Found:** 2026-10-04, feature-switch audit.
- **What:** `user.discoverable` was never read (names were always findable);
  a modified admin client could write `chat.e2e` released into the group
  settings and every member displayed it; `read_by` showed receipts after
  `user.read_receipts` was released; releasing `user.recovery_phrase`
  without the phrase showed "released" while the server kept the key for 7
  days; options were never validated and `chat.disappearing` silently
  ignored `1d`.
- **Severity:** low to medium (users were told a protection was on or off
  when it was not).
- **Fix:** the client registers the username with the discoverable flag
  and re-registers when the setting changes; settings contradicting a
  permanent lock or holding an invalid option are rejected in commit
  validation and dropped on read; `read_by` checks the setting; the recovery
  setting follows the server (applied with "release pending until" while
  the key still works); one option table in `features.rs` with
  `INVALID_OPTION`.
- **Test:** `crates/tree-client/tests/feature_switches.rs`,
  `a_pending_release_is_reported_until_the_server_drops_the_key`,
  `locked_keys_and_bad_options_in_settings_rejected`, `options_are_validated`.

## F-020: a relay could grind the device-link code through the key packages (fixed)

- **Found:** 2026-10-04, security review of wave 2.
- **What:** the device-link invitation committed to the nonce only. The new
  device's key packages travelled in the reveal and entered the transcript,
  but nothing bound them, so a relay that had seen the reveal could serve
  the existing device the same nonce with N's own key packages reordered or
  repeated (about 9^9 lists, any number from 1 to 9 accepted) and search,
  in milliseconds, for one whose code equals the code the new device shows
  for an offer of the relay's own. The person then saw equal codes, the new
  device joined the relay's account and trusted its device as its own.
- **Severity:** high (defeats the code comparison toward the new device).
- **Fix:** invitation version 2: the new device makes its key packages
  before showing the invitation, which carries its member id and commits to
  `SHA-256(lp("tree/link/commit/v2", nonce, kp_digest))`. The existing
  device shows no code unless the reveal matches the commitment and the key
  packages are exactly 9, distinct, valid, all naming the invitation's
  member id, with only the last one last-resort. PROTOCOL.md 8.11 lists
  every field a relay could change toward either device and why none can
  be ground. The ProVerif model now has the key packages and grinding
  equations for the code; negative controls find the attack without the
  key-package commitment and when the reveal comes first.
- **Test:** `link::tests::a_relay_cannot_grind_the_reveal_after_seeing_it`
  (over 20,000 reorderings, repeats, substitutions, removals and additions:
  all refused before a code exists; the old commitment accepted every
  reordering), `link::tests::key_packages_are_checked_one_by_one`,
  `a_reordered_repeated_or_substituted_key_package_list_is_refused`
  (through a real server), `formal/device_link_kp_uncommitted.pv`.

## F-021: a contact with no pinned device vouched for any device (fixed)

- **Found:** 2026-10-04, security review of wave 2.
- **What:** `Contact::vouches_for` was true for every device when no device
  was pinned for the contact. A contact added by hand or by username link has
  none, so a stranger who put that account next to its own device in a group
  roster skipped message requests and `user.group_add`, and its device was
  pinned as the contact's first device without a warning (the residual
  first-use gap of F-018, made easy to reach by username links).
- **Severity:** high (consent and identity: a stranger is shown as a contact).
- **Fix:** roster claims never pin and never count as the contact. A device
  is pinned only when the server names it in a key-package claim this device
  made (invite, or the new `confirm_contact`), when it comes with a
  confirmed device link, or when the user verifies a safety number covering
  it; roster-claimed devices are recorded as unconfirmed (in the safety
  number, warned about for a known account). `vouches_for` is false for an
  empty contact; the roster handler, `decide_request`, auto-download and
  photo visibility all go through it. Accepting a request does not pin.
  Consequence: a contact added by hand or by link, until the server names its
  devices or the safety number is verified, adds the user to chats as a
  request.
- **Test:** `requests::tests::a_contact_without_pinned_devices_vouches_for_nobody`
  (fails before: the stranger's group was accepted), `tests::pinning_rules`.

## F-022: roster account labels from any member were trusted (fixed)

- **Found:** 2026-10-04, security review of wave 2.
- **What:** every roster overwrote the receiver's member-to-account map
  for every member. A blocked member relabelled its device as a fresh
  account and its messages passed the block; any member labelled its device
  with the receiver's own account and was then treated as one of the
  receiver's devices (its files downloaded by themselves, a "contacts only"
  profile photo was sent to its chats); a member could move another member
  to its own account.
- **Severity:** medium.
- **Fix:** a label is taken only for a current member other than this
  device, never for this device's own account unless the member is in
  `own/members` (from a confirmed device link), only as the member's first
  label, and from the sender for itself or for others only if the sender is
  trusted (own device or pinned). Blocking also matches by member id: a
  device ever seen for a blocked account stays blocked. Auto-download and
  photo visibility use `own/members` and `vouches_for`, never a label.
- **Test:** `requests::tests::relabelling_does_not_escape_a_block`,
  `requests::tests::claiming_the_receivers_own_account_gets_nothing` (both
  fail before the fix).

## F-023: idempotency records linked the sender to the stored message (fixed)

- **Found:** 2026-10-04, security review of wave 2.
- **What:** the idempotency record stored the sending device with
  `SHA-256(label, body, sorted recipients)`. The body is in `blobs` and the
  recipients in `deliveries` until acknowledged (up to 30 days), so anyone
  with a copy of the database could recompute the hash for every stored
  message and learn its sender, which the server otherwise never stores.
  SERVER_API said the records hold "never recipients", which was not true
  in effect.
- **Severity:** medium (metadata privacy against a database copy).
- **Fix:** the record holds a key id and an HMAC-SHA-256 of the request
  under a random per-day key held only in the server's memory; keys are
  forgotten after the next day and their records purged (lifetime one to
  two days, down from 30); records in the old format are purged at once; a
  record whose key is gone (restart) is answered as a replay. What remains
  (documented in PROTOCOL.md 8.10): the running process can link while it
  holds the key.
- **Test:** `records_do_not_link_the_sender_to_a_stored_body` (fails before:
  the stored value was the recomputable hash), `records_are_bounded_and_purged`.
