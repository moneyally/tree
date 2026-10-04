# Product plan: from working core to a full messenger

This is the build plan for every user-facing feature in the design (feature
list, additional features, bots, Pro). It orders the work into waves; each
wave ends merged into `main` with the merge checks of `HANDOFF.md` 3.4
(build, tests, clippy with 0 warnings, mutation testing on core and server,
formal models, public-text check, demos).

Rules that apply to every item:

- Every feature has a key in `crates/tree-core/src/features.rs` with apply
  AND release, and a test that toggles it and checks the effect through a
  real client and server. A switch that changes nothing is a bug.
- Everything a chat member can see is inside MLS (application messages or
  the group context). The server stores ciphertext, routing data and
  limits only. Where a feature needs the server to see something (public
  groups, channels, bots, map tiles, GIF search), the app labels it.
- Standards and audited libraries only. No home-made cryptography.
- Money, points, payments, store rules, age checks: designed, but switched
  off and marked "lawyer check needed" until the owner decides.

Status words: **done** (built, tested, in `main`), **built** (on a branch,
tested), **next**, **later**, **owner** (needs a decision or an account
the owner holds).

## Wave 0 — harden what exists (in progress)

| Item | Status |
| --- | --- |
| Crash between receiving and storing a message (F-016) | built |
| Recovery key pending elsewhere (F-017) | built |
| Mutation testing part 2 (core, server) | built |
| Last-resort key packages | built |
| Feature switches that did nothing: `user.discoverable`, locked chat keys, read receipts after release, recovery release state, option validation, disappearing timer from the desktop app | next |
| Merge the stage-1 stack into `main` | next |

## Wave 1 — finish stage 1 (the product people can use daily)

1. **Reliable sending.** A durable outbox on the device (queued, sending,
   retry with backoff, sent, failed), the same idempotency key on every
   retry, and server-side idempotency per sending device (same key and
   same request: same answer; same key, other request: refused). The key
   binds the group, the sender and the content, so two events can never
   share it. Idempotency records expire with the messages.
2. **Chat list basics.** Mute (with duration), archive, pin chats,
   silent send, quiet leave, unread markers, drafts.
3. **Contacts.** Username links and QR codes (reset gives a new link, the
   name stays), QR friend add, stranger labels in the UI.
4. **Device linking with a two-sided code.** Both devices compute the code
   from their own keys and the link transcript; the server never chooses
   it. QR alone never links. **built** (PROTOCOL.md 8.10)
5. **Media.** Chunked encrypted upload and download for large files (2 GB
   free limit per design), resumable; thumbnails made by the sender inside
   the encrypted message; images, video, voice notes, files; view-once;
   auto-download per network type (`user.auto_download`); padding of sizes
   to buckets so the server learns less.
6. **Media editor.** Crop, rotate, draw, text, blur (faces and regions) on
   the device before sending; the original never leaves the device.
7. **Notifications.** Push wake-up only (no content through the gateway);
   the app fetches and shows a local notification, with or without the
   text per `user.notification_content`.
8. **Device protections.** Incognito keyboard (Android), screen capture
   protection on desktop where the system allows it, app switcher blur,
   app lock with PIN and biometrics.
9. **Search.** On-device full-text index inside the encrypted database
   (`user.search_index`), release deletes the index.
10. **Settings sync across a person's own devices** (user scope), inside
    the person's own device group.

## Wave 2 — rich chats (design stage 3, chat side)

Pinned messages with expiry, scheduled messages, polls (`chat.polls`),
stickers and custom emoji packs (`chat.stickers`; packs are encrypted
blobs, shared by link), GIF search through a server relay
(`chat.gifs`, the search provider never sees the user), forwarding control
(`chat.forwarding`), round video notes (`chat.video_notes`), location and
live location (`chat.location`, map tiles through a relay), events with
replies (`chat.events`), reminders, chat export (`chat.export`), storage
clean-up (`user.storage_clean`), profile photos (encrypted, shared with
contacts and groups only), per-chat profiles.

## Wave 3 — groups and communities

Topics (`chat.topics`), roles and member tags (`chat.roles`), admin log
(`chat.admin_log`), welcome message (`chat.welcome`), history sharing for
new members (`chat.history_share`, re-encrypted by an existing member's
device), owner succession, join approval, slow mode, restricting members,
groups up to 1,000 (benchmark first), communities (several chats under
one roof).

## Wave 4 — public groups and channels (not end-to-end, labelled)

Public groups (10,000+ members), channels (one-way broadcast), channel
comments, author signatures, public listing, private channels up to 1,000
subscribers end-to-end. Public spaces are a separate data path on the
server and are never mixed with private groups (a private group cannot be
turned public).

## Wave 5 — bot platform (design stage 2)

Bot factory, tokens (HMAC-stored, rotate and revoke remove the gateway
device too), the gateway with the Bot API, bot lanes (privacy mode: a bot
sees only messages addressed to it), buttons, bot reports and rate limits.
Bot accounts are created only by an existing account, count against a
per-owner limit and pay the sign-up cost.

## Wave 6 — calls

1:1 voice and video over WebRTC with keys from MLS (SFrame-style media
encryption), call relay to hide IP (`user.call_relay`), call links with
approval, noise suppression on the device, group calls later.

## Wave 7 — security extras (design stages 3-4)

Duress PIN, hidden profiles, hidden chats, lockdown mode (one switch that
applies the safe set and restores the previous settings on release),
silence unknown callers, encrypted backup, proxy support, social and PIN
recovery, passkey-wrapped recovery key, key transparency, sealed sender.

## Wave 8 — Pro and points (owner)

Pro limits and extras (larger files, more folders and pins, chat themes,
custom emoji status, longer voice transcripts on the device, …) are
entitlement flags checked by the server. Payments, points, creator
earnings and payouts need the owner's company, store accounts and legal
review: **lawyer check needed**. Points never move between people, and
bots never pay out points (`Lock::AlwaysOff`).

## Not built (from the design's exclusion list)

Built-in AI, collectible gifts and their exchange, money transfer, feeds
and short-video tabs, ads, server-stored chats, password log-in, server-side
call transcription.
