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
   Status: **built** (branch `claude/outbox`; PROTOCOL.md 6.13 and 8.10).
2. **Chat list basics** — **built** (`claude/chat-basics`; APP_PROTOCOL.md
   6.1). Mute (with duration), archive, pin chats, silent send, quiet leave,
   unread markers, drafts. Device-local; sync to the user's own devices is
   item 10.
3. **Contacts** — **built** (`claude/chat-basics`; PROTOCOL.md 8.4).
   Username links and QR codes (reset gives a new link, the name stays),
   QR friend add (add by link), stranger labels in the UI. The desktop app
   shows the link text; drawing the QR image waits for a QR library in the
   app builds.
4. **Device linking with a two-sided code.** Both devices compute the code
   from their own keys and the link transcript; the server never chooses
   it. QR alone never links. **built** (PROTOCOL.md 8.11)
5. **Media.** Chunked encrypted upload and download for large files (2 GB
   free limit per design), resumable; thumbnails made by the sender inside
   the encrypted message; images, video, voice notes, files; view-once;
   auto-download per network type (`user.auto_download`); padding of sizes
   to buckets so the server learns less.
   Status: **built** (branch `claude/media`; PROTOCOL.md 6.12 and 6.13,
   SERVER_API.md attachments, migration `0014`).
6. **Media editor.** Crop, rotate, draw, text, blur (faces and regions) on
   the device before sending; the original never leaves the device.
   Status: **built** (branch `claude/media`; `apps/shared/.../media`, desktop
   editor screen; export without metadata). Automatic face finding is not
   in: the user marks the regions.
7. **Notifications.** Push wake-up only (no content through the gateway);
   the app fetches and shows a local notification, with or without the
   text per `user.notification_content`.
   Status: **built** (branch `claude/device-safety`; APP_PROTOCOL.md 6.3,
   PROTOCOL.md 8.8). Android: open distributor protocol, periodic job
   without one; a locked profile gets a content-free notification only.
8. **Device protections.** Incognito keyboard (Android), screen capture
   protection on desktop where the system allows it, app switcher blur,
   app lock with PIN and biometrics.
   Status: **built** (branch `claude/device-safety`; APP_PROTOCOL.md 6.3,
   PROTOCOL.md 8.13). Capture exclusion works on Windows only (Linux and
   macOS say "not available"); biometrics need Android 11+.
9. **Search.** On-device full-text index inside the encrypted database
   (`user.search_index`), release deletes the index.
   Status: **built** (branch `claude/device-safety`; FTS5 inside SQLCipher).
10. **Settings sync across a person's own devices** (user scope), inside
    the person's own device group.
    Status: **built** (branch `claude/device-safety`; APP_PROTOCOL.md 6.4,
    PROTOCOL.md 8.14).

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

Part A, **built** (branch `claude/rich-chats-a`; APP_PROTOCOL.md 6.2):

| Item | Status |
| --- | --- |
| Pinned messages with expiry (24 h, 7 d, 30 d, until unpinned; at most 10; `chat.pins`) | built |
| Scheduled messages (device only; list, edit, cancel) | built |
| Polls (single / multiple choice, anonymous in the apps, close time; `chat.polls`) | built |
| Forwarding control (`chat.forwarding`) | built |
| Reminders (device only, local notification) | built |
| Chat export, plain text and JSON (`chat.export`) | built |
| Storage clean-up of downloaded media (`user.storage_clean`) | built |

Part B, **built** (branch `claude/rich-chats-b`; APP_PROTOCOL.md 8,
PROTOCOL.md 8.12): stickers and custom emoji packs, GIF search through the
relay, location and live location with the optional map tile relay,
events with replies, round video notes, profile photos, per-chat profiles
(display name and photo; separate keys per chat are a later step). Both
parts are merged in `claude/wave2`.

## Wave 3 — groups and communities

**Built** (branch `claude/groups`; APP_PROTOCOL.md 9, PROTOCOL.md 6.11.1,
BENCHMARKS.md "Groups of 1,000 through the core API"):

| Item | Status |
| --- | --- |
| Topics: threads in a group, create / rename / close by admins (option: members create), per-topic unread counts (`chat.topics`) | built |
| Roles and member tags with permissions `pin`, `delete`, `add`, `topics` in the group settings (`chat.roles`; adds by permission: `chat.member_adds`) | built |
| Admin log, device-local, actor authenticated by MLS (`chat.admin_log`) | built |
| Welcome message in the group settings (`chat.welcome`, up to 500 characters) | built |
| History for new members: one MLS message from the adding device, authors as its claims, "shared by" label and notice (`chat.history_share`, 25 to 100) | built |
| Owner succession: the last admin names the lowest-leaf member before leaving (`chat.owner_succession`) | built |
| Join approval for invite links (`chat.join_approval`) | built |
| Slow mode, sender and receivers, server arrival minute (`chat.slow_mode`, 10 s to 1 h) | built |
| Restricting members until a time (`chat.restrict`) | built |
| Groups up to 1,000: server limits checked, an O(n^2) member list fixed, settings lookups cached per epoch, benchmark | built |
| Communities: a root group listing chats, join a chat through the community's admins | built |

The desktop app has the screens (topic bar, roles editor, member tags,
restrict action, admin log, welcome text, history-sharing switch with its
notice, slow-mode choices, join requests, community sidebar); Android
shares the model (no screens for these yet).

## Wave 4 — public groups and channels (not end-to-end, labelled) — built (branch `claude/channels`)

Public groups (10,000+ members), channels (one-way broadcast), channel
comments, author signatures, public listing, private channels up to 1,000
subscribers end-to-end. Public spaces are a separate data path on the
server and are never mixed with private groups (a private group cannot be
turned public).

Built: server `public.rs` (create with a unique @handle, join / leave,
posts and comments, newest-first pages and a change cursor, edit / delete,
admins, bans, slow mode, directory and search while `chat.public_listing`
is applied, reports into the existing queue, wake-ups at most once a
minute per space for subscribers who asked; all behind
`server.public_spaces`), client `public.rs` (cache in the encrypted
profile, unread counts, `is_public` on every object) and `channel.rs`
(private channels: the `channel` flag fixed at creation, only admins post,
comments with `channel.comments`, `channel.signatures`, at most 1,000
members), FFI, desktop screens with the "Public" badge
(PROTOCOL.md 6.11.2, 8.15; APP_PROTOCOL.md 10). Not yet: Android screens
(the shared model compiles), avatars uploaded from the apps (the API takes
a reference), attachments in public posts from the apps.

## Wave 5 — bot platform (design stage 2) — built

Bot factory, tokens (HMAC-stored, rotate and revoke remove the gateway
device too), the gateway with the bot API, bot lanes (privacy mode: a bot
sees only messages addressed to it), buttons, bot reports and rate limits.
Bot accounts are created only by an existing account, count against a
per-owner limit and pay the sign-up cost.

Built: server `bots.rs` (factory, tokens as HMACs, gateway registration
with proof of the device key, one gateway device per bot, rotate / revoke
cut off at once, directory, switches, per-bot rate limit, a bot reaches only
people who contacted it and its groups, messages of bots marked by the
server, all behind `server.bot_platform`, released by default), client
`bots.rs` (label from the server's word, lanes on the senders' devices,
buttons and callbacks, `chat.bots`, block / stop, a bot's first chat is a
request), the gateway crate `tree-bot-gateway` (encrypted profile, local
API: getUpdates, sendMessage with buttons, answerCallbackQuery, getMe,
leaveChat, webhooks), FFI, desktop factory screen and bot label / buttons
(PROTOCOL.md 8.16, APP_PROTOCOL.md 11, BOT_GATEWAY.md). Not yet: inline
queries, a separate MLS lane group per bot, Android screens. Bot payments
and tips: locked off until stage 4 (identity verification, **변호사 확인
필요**).

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
