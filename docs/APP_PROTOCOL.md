# Tree app protocol v1 (inside MLS application messages)

What Tree apps put inside end-to-end encrypted MLS application messages, and
what a client keeps next to its groups. Implemented in `crates/tree-client`
and used by every app. The layers below (MLS, envelope, server) are in
[PROTOCOL.md](PROTOCOL.md).

Everything here is end-to-end encrypted and authenticated by MLS: the sender
is the MLS member id the receiving core reports, never a field of the
payload. The server sees none of it.

## 1. Payloads

One JSON object per application message, UTF-8, field `t` names the type:

| `t` | Fields | Meaning | Who may send |
| --- | --- | --- | --- |
| `text` | `id` (16 random bytes, hex), `text`; optional `fmt` (true: Tree markup, 1.1), `mentions` (member ids, at most 50), `all` (@all), `preview` (`url`, `title`, `description`: made by the sender's app, which fetched the page; receivers never fetch it; shown only while the receiver's `user.link_preview` is applied), `silent` (true: silent send, receivers' apps do not notify, 6.1), `fwd` (true: forwarded from another chat, 6.2; the original sender is not named), `topic` (a topic id, 9.1) | a chat message | any member not restricted (9.9), within slow mode (9.8); `fmt` only while `chat.formatting` is applied; `all` as `chat.mention_all` allows; `topic` while `chat.topics` is applied and the topic is open (or the sender manages topics) |
| `edit` | `id`, `text` | replaces the text of the sender's own message `id` | its sender, if `chat.edit` is applied, within the window |
| `delete` | `id` | deletes message `id` for everyone | its sender, if `chat.delete_for_all` is applied, within the window; or, for another member's message, an admin or a member whose role has `delete` (9.2), at any age |
| `react` | `id`, `emoji` (1 to 8 characters), `remove` (optional), `sticker` (optional: `pack` (blob reference of the pack manifest), `index`; a custom emoji, 8.1) | adds or takes back a reaction | any member, if `chat.reactions` is applied; `sticker` counts only while `chat.stickers` is applied (otherwise the plain `emoji`) |
| `profile` | `name`; `chat` (optional; true: a name for this chat only, 8.7) | the sender's own display name | any member, about itself; `chat` only while `chat.allow_per_chat_profiles` is applied |
| `roster` | `devices`: member id (hex) -> device id; `names` (optional): member id -> name; `accounts` (optional): member id -> account id; `link` (optional): the nonce (hex) the new member's device sent with its invite-link request (PROTOCOL.md 8.7) | who is reachable at which server device, the sender's view of names, and which account each device belongs to | the member that just added devices (others may too) |
| `leave` | `quiet` (optional; true: quiet leave, no "left" line, 6.1) | the sender asks to be removed (PROTOCOL.md 6.5) | any member |
| `remove_device` | `members` (member ids, hex) | the sender unlinked these devices of its own account and asks the admins to remove them (PROTOCOL.md 8.11); shown to admins as a removal request for each named member whose known account is the sender's; an admin decides, apps never carry it out automatically (unlike `leave`), as the account labels are other members' claims | a member that is not an admin |
| `read` | `ids` (at most 100 message ids) | the sender read these messages | any member, while its `user.read_receipts` is applied; shown only while the receiver's is applied too |
| `typing` | `on` | the sender started or stopped typing; never stored | any member, both sides `user.typing` |
| `seen` | — | the sender's app is open; the receiver records its own time | any member, both sides `user.last_seen` (released by default) |
| `file` | `msg_id`, `fwd` (optional: forwarded), `view_once` (optional), `voice` (optional), `duration_ms` (optional: voice, video, video note), `gif` (optional, a GIF found through the relay, 8.2), `video_note` (optional, with `duration_ms`, 8.5), `id`, `key` (base64, the 32-byte file secret), `size` (plaintext bytes), `pt_sha256` (hex), `name` (at most 255 characters), `mime` (at most 127), `v` (format, 2), `width` and `height` (optional, pixels), `thumb` (optional, base64 JPEG or PNG preview made by the sender, at most 32 KiB) | an encrypted attachment (PROTOCOL.md 6.12); a reference that does not fit is dropped | any member, if `chat.media` is applied (and `chat.view_once` for view-once, `chat.voice` for voice, `chat.gifs` for `gif`, `chat.video_notes` for `video_note`) |
| `pin` | `id`, `ttl` (optional: seconds, 1 s to 365 days, counted from arrival on each device; none: until unpinned), `remove` (optional: unpin) | pins or unpins message `id` for the whole chat (6.2) | an admin, or either member of a 1:1 chat, if `chat.pins` is applied |
| `poll` | `id`, `q` (question, at most 300 characters), `opts` (2 to 10 options, 1 to 100 characters each), `multi` (optional: several choices), `anon` (optional: apps do not show who voted), `close_in` (optional: seconds, 1 s to 30 days from arrival) | a poll; franked like a text (it can be reported) | any member, if `chat.polls` is applied |
| `vote` | `id` (the poll), `choices` (option indexes; empty: take the vote back) | the sender's whole vote; the latest one per member counts | any member, if `chat.polls` is applied, before the poll closed |
| `poll_close` | `id` | closes the poll for everyone | the poll's creator, if `chat.polls` is applied |
| `sticker` | `id`, `pack` (blob reference of the pack manifest: `id`, `key`, `size`, `pt_sha256`, `v`), `index`, `emoji` (the item's plain emoji, 1 to 8 characters) | a sticker (8.1) | any member, if `chat.stickers` is applied |
| `location` | `id`, `lat_e7`, `lon_e7` (integers, 10^-7 degrees), `accuracy_m`, `label` (optional, at most 200 characters), `live_secs` (optional, at most 28800: a live location) | a place or the start of a live location (8.3) | any member, if `chat.location` is applied |
| `live_location` | `id` (of the sender's own live `location`), `lat_e7`, `lon_e7`, `accuracy_m` (optional), `stop` (optional) | a new position, or the end | the location's sender, while it is live, if `chat.location` is applied |
| `chat_event` | `id`, `title` (1 to 200 characters), `starts_at` (unix seconds), `ends_at`, `place` (at most 200), `description` (at most 2000) (optional) | an event to answer (8.4) | any member, if `chat.events` is applied |
| `event_edit` | `event` (as `chat_event`, same `id`), `cancelled` (optional) | changes or cancels the event | its creator, if `chat.events` is applied |
| `rsvp` | `id`, `answer` (`going`, `maybe` or `not`) | the sender's answer; the newest counts | any member, if `chat.events` is applied and the event is not cancelled |
| `profile_photo` | `photo` (blob reference, optional: none = removed), `mime`, `chat` (optional; for this chat only) | the sender's profile photo (8.6) | any member, about itself; `chat` only while `chat.allow_per_chat_profiles` is applied |
| `topic` | `id` (1 to 32 letters and digits), `name` (optional, 1 to 64 characters), `closed` (optional) | creates topic `id` (new id, with a name), renames, closes or reopens it (9.1) | while `chat.topics` is applied: creating by an admin or a role with `topics`, or any member with the option `all`; the rest by an admin or a role with `topics` |
| `topics` | `list` (`id`, `name`, `closed`) | the topics the sender knows; sent after it added members (9.1) | an admin or a role with `topics`; receivers take only unknown entries |
| `history` | `to` (member ids), `msgs` (`id`, `from`, `name`, `at`, `kind` = `text` or `file`, `text` or `file`, `topic`) | recent messages for the new members `to` (9.5); `from`, `name`, `at` are the sharer's claims | the member that added `to`, while `chat.history_share` is applied |
| `join_chat` | `chat` (group id, hex), `account` | in a community root: the sender asks to be added to `chat` (9.7) | any member of the community |
| `franked` | `p` (the inner `text`, `edit`, `file`, `poll`, `sticker`, `location` or `chat_event` payload as a JSON string), `k` (base64), `tag` (base64), `m` (minute) | how every franked kind is sent: the inner payload with its franking (PROTOCOL.md 8.5); the receiver keeps `p`, `k`, `tag`, `m` to be able to report it | any member |

```json
{"t":"text","text":"안녕"}
{"t":"profile","name":"bob"}
{"t":"roster","devices":{"0678…":"TRUiLpZjKr-CUgfUf_ry8w"},"names":{"0678…":"alice"}}
{"t":"leave"}
{"t":"leave","quiet":true}
{"t":"text","id":"…","text":"늦은 밤","silent":true}
{"t":"text","id":"…","text":"worth sharing","fwd":true}
{"t":"pin","id":"…","ttl":86400}
{"t":"poll","id":"…","q":"Lunch?","opts":["noodles","rice"],"anon":true}
{"t":"vote","id":"…","choices":[1]}
{"t":"poll_close","id":"…"}
```

Older apps read a `text` or `file` with `fwd` or `topic` as an ordinary
message (unknown fields are ignored; a topic's message shows in the main
chat), drop `topic`, `topics`, `history` and `join_chat` as unsupported types
and drop another member's `delete` (only the sender may change a message), and drop `pin`, `poll`, `vote` and `poll_close` as
unsupported types (a franked `poll` as a malformed franked payload).

`silent` and `quiet` are per message: there is no setting for them, the
sender chooses each time. Both are inside the end-to-end encrypted payload,
so the server cannot tell a silent or quiet message from any other. Older
apps ignore both fields (they notify, and show a "left" line).

A `franked` payload whose `p` is not a `text`, `edit`, `file`, `poll`,
`sticker`, `location` or `chat_event` is dropped, and so are those sent
without franking. Older apps drop the new kinds (they cannot decode them)
and ignore the new optional fields (`gif`, `video_note`, `fwd`, `sticker`
in `react`, `chat` in `profile`), which are left out when unused.

### 1.1 Formatting markup (`fmt: true`)

`**bold**`, `_italic_`, `~~strike~~`, `||spoiler||`, `` `code` ``, a line
starting with `> ` is a quote, a line starting with `- ` a list item. Apps
render it; the text itself is sent unchanged, so a device that shows plain
text loses nothing. With `chat.formatting` released the sender sends no
`fmt` and receivers ignore one (plain text).

Unknown types or malformed JSON are dropped and shown as "unsupported", never
as text. Message padding (256 bytes) is applied by MLS below this layer.

## 2. Rules

- **Roster (PROTOCOL.md Q8).** After a commit that adds devices is accepted,
  the adder sends a `roster` to everyone, including the new devices. A
  receiver takes only entries for current members and never overwrites its
  own entry. A false entry misroutes messages to a wrong mailbox, where they
  cannot be decrypted by anyone outside the group; it does not reveal
  anything. Removed members' entries are dropped when the removal is merged.
- **Names (F-009).** A member's `profile` always wins for that member. Names
  in a `roster` are hints for members whose own `profile` has not arrived;
  the roster sender's entry for itself counts as its own word. A device that
  joined sends its `profile` once it knows where the others are. Two members
  with the same name are flagged; the app tells them apart by member id.
- **Accounts and pinning.** `accounts` lets every member, not only the
  adder, pin a contact's devices (PROTOCOL.md 5.4). Entries are taken for
  current members only; a new member id for a known account is reported as
  a key change. A false entry can at worst raise a warning or attach a
  device to the wrong contact, which the safety-number comparison exposes.
- **Leave.** An admin that receives `leave` from X removes X (only admins
  may remove, PROTOCOL.md 6.11). Several
  members doing so race for the same epoch; the server's ordering keeps one.
- **Recipients.** Every message goes to the devices in the roster except the
  sender's own device. Commits also go to devices being removed.

## 3. Chat settings every device enforces

Set by admins in the group settings (PROTOCOL.md 6.11), checked by the
sending device before sending and by every receiving device on arrival
(`crates/tree-client/src/messages.rs`):

| Setting | Default | Effect |
| --- | --- | --- |
| `chat.media` | applied | files allowed |
| `chat.edit` | applied, option = window, a duration of 1 s to 30 days (default 24 h) | the sender may edit its own text |
| `chat.delete_for_all` | applied, option = window, as `chat.edit` (default 24 h) | the sender may delete its own message for everyone; a placeholder stays so a late edit cannot revive it |
| `chat.reactions` | applied | reactions allowed |
| `chat.view_once` | applied | view-once files allowed; the reference is deleted after the first successful download (and the sender keeps none) |
| `chat.disappearing` | released; option = a duration of 1 s to 365 days (default `1d`) | every message expires that long after it arrives on each device and is deleted from its history |
| `chat.voice` | applied | voice messages (files with `voice`) allowed |
| `chat.formatting` | applied | markup shown; released: plain text |
| `chat.mention_all` | applied, option `admins` (default) or `all` | who may send @all; a refused @all is ignored by receivers (the text still arrives); released: nobody |
| `chat.pins` | applied | admins (or either member of a 1:1 chat) pin messages for everyone (6.2); released: pins are refused and dropped, stored pins are not shown |
| `chat.polls` | applied | polls, votes and closing (6.2); released: refused when sending, dropped when received |
| `chat.forwarding` | applied | messages of this chat may be forwarded, saved and copied; released: the client refuses to forward them and the apps hide forward, save and copy (6.2). Binds honest apps only: a modified app or a screenshot cannot be stopped |
| `chat.export` | applied | the chat's history may be exported to a local file (6.2); released: refused |
| `chat.screenshot_block` | released | apps block screenshots of the chat for every member; a user can also block them for themselves (`screenshot/<group>`). It stops honest apps' screenshot function, not cameras or modified apps |
| `chat.stickers` | applied | stickers; custom emoji reactions (released: shown as their plain emoji) |
| `chat.gifs` | applied | files flagged `gif` (the server must also offer the GIF relay for the button to show) |
| `chat.location` | applied | places, live locations and their updates |
| `chat.events` | applied | events, changes and answers |
| `chat.video_notes` | applied | files flagged `video_note` |
| `chat.allow_per_chat_profiles` | applied | `profile` / `profile_photo` with `chat`; released: receivers ignore them and members' devices go back to their main name and photo |

Durations are whole seconds (`90`) or a whole number with one unit, `s`,
`m`, `h`, `d` or `w` (`30m`, `1d`, `2w`). Every option is checked against
one table (`tree_core::features::option_format`); anything else is refused
with `INVALID_OPTION` when applied, and a commit whose settings hold an
invalid option is rejected by every device (PROTOCOL.md 6.11). Permanently
locked keys (`chat.e2e` on, `chat.private_to_public` off) always show and
act as locked, whatever the settings hold.

Windows and expiry are measured with the device's own clock from when it
received (or sent) the original, never from a time the sender claims. A
modified client can still keep copies of anything it received; these
settings bind honest devices, not a member who wants to keep evidence.

History is kept in the encrypted device database (`tree_messages`) and can be
searched on the device while `user.search_index` is applied.

## 4. Reporting

`Session::report(group, ids, reason)` sends the stored franking records of
messages of one sender (never the device's own) with the sender's account
(from the `roster` accounts) to `/v1/reports` (PROTOCOL.md 8.5) and returns
the report id and whether the server verified every message. A message
deleted for everyone or expired has no record left and is reported as
unverified text, or not at all once its row is gone.

## 5. Requests, blocking, who may add me

A welcome is always processed (MLS needs it), but the group starts as a
request until the adder's account is known from its `roster`. Then
(`crates/tree-client/src/requests.rs`):

| Adder | 1:1 chat (2 members) | Group (3 or more) |
| --- | --- | --- |
| a contact the user chose (invited, accepted, added) | accepted | accepted, unless `user.group_add` = `nobody` |
| blocked | declined | declined |
| stranger, `user.stranger_block` applied | declined | declined |
| stranger | request if `user.message_requests` applied (default), else accepted | declined if `user.group_add` applied (default: contacts only), else as for a 1:1 chat |

The adder is the roster's sender under the account its roster claims. The
claim counts only if that device is already pinned for the account and is
not an unconfirmed key change (a device that only a roster claimed for an
account that already had devices; confirmed when the user verifies the
safety number or the server names it in a key-package claim), or if no
device is pinned for the account yet (trust on first use). Otherwise the
adder is judged as a stranger, and the key-change warning is shown (F-018).

A group whose adder names, in its roster, the nonce this device sent with
an invite-link request to that adder in the last day (PROTOCOL.md 8.7) is
accepted after the blocked check, once: the user asked to join that group,
so the joiner's own `user.group_add` and message requests do not apply.
The nonce reaches only the link owner's device, so nobody else who saw a
published link can use it.

`user.group_add` takes the option `contacts` (default) or `nobody`;
`user.read_receipts` released also hides receipts stored earlier
(`read_by` is empty) and sends none.

Messages in a request are shown as such (`request: true`) until accepted.
Declining sends `leave` and ignores the group from then on; it can also
block the adder. Messages from a blocked account are dropped in every group.
All of this is enforced on the device: the server cannot know contacts, by
design, so it still delivers.

User settings (`apply` / `release` of user-scope features) are kept in the
device database and checked against the registry (permanent locks such as
`user.key_change_warning` cannot be released).

## 6. Client behaviour (`tree_client::Session`)

| Step | Behaviour |
| --- | --- |
| Create | encrypted profile (`Client::create`), new Ed25519 request key, signup with proof of work, upload 20 key packages |
| Open | reopen the profile; resubmit every pending commit (PROTOCOL.md 7.1 step 7) |
| Commit | `add` / `remove` / `refresh_keys` create a pending commit, submit it to `/v1/commits`; `200`, or `409` naming our own hash: confirm; `409` with another winner: discard and report "lost"; other errors: discard; network error: keep pending for a resubmit |
| Sync | fetch the mailbox (optionally long-poll), process in order, acknowledge everything processed, then send the due outbox items |
| Send | every payload except `typing` and `seen` goes through the outbox (PROTOCOL.md 6.13): sealed once, stored with the history entry, sent with its idempotency key, retried with backoff; `typing` / `seen` go directly and only when nothing of the group waits |
| Welcome | join; start a roster with the own device; announce the own `profile` when the roster lists others |
| Envelope for an unknown group, or failing the seal check | hold it (at most 256), retry after every epoch change or join (PROTOCOL.md 6.7) |
| Key packages | top up to 20 when fewer than 10 remain (checked at creation and after joins) |

Not yet: holding expiry (7 days), retry limits for commits, contacts and
safety numbers, message history.

### 6.1 The chat list (`crates/tree-client/src/organize.rs`)

Everything here is kept on this device only, in the encrypted profile
(section 7); it is not synced to the user's other devices yet, and the
server learns none of it.

| Behaviour | Rule |
| --- | --- |
| Mute | `mute_for(group, seconds)`: 1 hour, 8 hours, 1 week (`MUTE_CHOICES`) or until unmuted; any 1 s to a year is accepted. A timed mute ends by itself. `is_muted`, `muted_until`. A muted chat never notifies and is listed in the quiet folder (`user.quiet_folder`) |
| Notify | apps notify for a new message only if `should_notify(group, silent)`: not muted, not a silent message, not a declined chat. The text is shown only while `user.notification_content` is applied |
| Silent send | `TextOptions.silent`: the `silent` flag of the `text` payload. Receivers store it with the message (`message_meta`) and report it (`Event::Text.silent`); the message is unread as usual |
| Archive | `archive_chat`: the chat leaves the main list (apps show an archive section). A new text or file brings it back if the chat is not muted, the message is not silent and `user.unarchive_on_message` is applied (default); released, archived chats stay archived until the user takes them out. Archiving drops a pin |
| Pin | `pin_chat`: at most 5, in the order pinned, on top of the list; `move_pinned_chat` reorders. Pinning an archived chat brings it back |
| Order | `chat_list`: pinned chats in pin order, then the others by last activity (the newest message, or when the chat started), newest first |
| Drafts | `set_draft` keeps the unsent text per chat (at most 64 KiB), `draft` restores it when the chat opens, sending a text clears it. `user.drafts` released: nothing is kept and stored drafts are deleted |
| Unread | `mark_unread` sets a marker (the chat is in the `unread` folder); `mark_read` (opening the chat) clears it and the count |
| Quiet leave | `leave_quietly` sends `leave` with `quiet`. Every member's device remembers who asked to leave; when the removal arrives it stores a `left` line (kind `left`, the member's name in `data`) for a normal leave, nothing for a quiet one, and a `removed` line for a removal nobody asked for. Honest limit: MLS still removes the member in a commit every device sees, so the member list changes for everyone and a member who looks at it notices; the admin who removes sees the request; a modified app can still show a line. Quiet only means honest apps do not announce it in the chat |
| Stranger labels | `stranger_labels(account)`: not a contact, no group in common (other than this one), name not verified; `None` while `user.stranger_labels` is released. Apps show them in a 1:1 chat's header and next to requests |
| Username link | `user.username_link` (PROTOCOL.md 8.4): `username_link` / `username_qr` (the same text, `tree://u/<token>`), `reset_username_link`, `find_by_link`, `add_contact_by_link` |

### 6.2 Rich chats, wave 2 part A

Modules `pins.rs`, `polls.rs`, `schedule.rs`, `forward.rs`,
`storage_clean.rs` and `rich.rs` in `crates/tree-client/src`. Everything a
member sees travels inside MLS application messages (section 1); the
server learns nothing new from any of it (it sees ciphertext of the usual
padded sizes, as for any message).

| Feature | Rule |
| --- | --- |
| Pinned messages (`chat.pins`) | `pin_message(group, id, ttl)` with the choices 24 h, 7 days, 30 days, until unpinned (`PIN_CHOICES`), `unpin_message`, `pins` (newest first), `may_pin`. Shared state: every device applies the same `pin` messages in the server's order, checking the sender (admin, or a chat of two members), `chat.pins`, and that the message is in its history and not deleted. At most 10 per chat: the sender refuses an eleventh, a receiver that would hold more drops the oldest. Expiry is counted from arrival on each device's own clock; expired pins drop off when read. A member who joins later does not learn earlier pins (no history sharing yet) |
| Polls (`chat.polls`) | `create_poll` (question, 2-10 options, single or multiple choice, anonymous or not, optional close time), `vote` (the whole vote; empty takes it back), `retract_vote`, `close_poll` (creator only), `poll` (tally). Each device counts from the authenticated MLS votes it received: one vote state per member, the latest wins; votes that do not fit the poll or arrive after it closed on this device are dropped; members who left are not counted. **Anonymous** only means the apps do not show who voted for what: every vote is still an MLS message authenticated as its sender and delivered to every member's device, so each device (and a modified app) knows who voted for what. The server sees ciphertext only |
| Scheduled messages | `schedule_text(group, text, at, silent)`, `scheduled`, `edit_scheduled`, `cancel_scheduled`. Kept on this device only (`sched/<id>`) until the time; then the text enters the outbox (PROTOCOL.md 6.13) and is sealed, franked and sent like any message. The server never holds the plaintext and does not schedule: the app must be running at that time, or the next sync after it sends the message (late). Not in the history until sent. If it cannot be sent when due (left the chat, a setting forbids it) sync reports `SendFailed` with the schedule id. Texts only, at most a year ahead |
| Forwarding (`chat.forwarding`) | `forward(from, id, to)` sends a text, or a file reference (the same encrypted attachment, not view-once), as a new message with `fwd`, sent by the forwarding member; the original sender is not named. While the source chat released `chat.forwarding` the client refuses, and the apps hide forward, save and copy for its messages (`forwarding_allowed`). This binds honest apps only: a modified app, a screenshot or a camera cannot be prevented, and the destination cannot tell where a forwarded message came from |
| Reminders | `remind_me(group, id, at)`, `reminders`, `cancel_reminder`, `due_reminders` (each due reminder once; the app shows a local notification). Device only (`remind/<id>`); the message text is read when the reminder fires, never copied |
| Chat export (`chat.export`) | `export_chat` (plain text and JSON), `export_chat_to(group, prefix)` writes `<prefix>.txt` and `<prefix>.json`; any member may export while applied, refused while released. The files are not encrypted; franking records, keys and file contents are not exported. The setting is changed by the chat's admins, as every chat key (PROTOCOL.md 6.11) |
| Storage clean-up (`user.storage_clean`) | `download_to_cache(file, dir)` opens a file into the app's media folder and records it (`media/<attachment id>`); while the setting is applied (option: duration 1 s to 365 days, default `90d`, the apps offer 30 days, 90 days, a year), every sync (at most once an hour) and `clean_storage` delete cached files downloaded longer ago, and their records. Message texts and file references stay (a file can be downloaded again while the server keeps the blob, 30 days); files the user saved elsewhere are never touched. Released (default): nothing is deleted |

## 7. What the client stores

In the same encrypted database as the core (`tree_app` table, SCHEMA.md):

| Key | Value |
| --- | --- |
| `server/url`, `server/account_id`, `server/device_id` | text |
| `server/auth_key` | the 32-byte Ed25519 request-signing seed (secret) |
| `roster/<group hex>` | JSON member id -> device id |
| `names/<group hex>` | JSON member id -> display name |
| `pending/<group hex>` | JSON: added (member id, device id) pairs, removed device ids of the pending commit |
| `announce/<group hex>` | present until the own profile was sent |
| `held/<20-digit counter>` | a held message body |
| `accounts/<group hex>` | JSON member id -> account id |
| `contact/<account id>` | JSON: pinned member ids, verified, accepted (chosen by the user), blocked, unconfirmed (key changes only a roster claimed) |
| `gstatus/<group hex>` | request (with adder account) or declined; absent = accepted |
| `feature/<key>` | the user's setting: applied or released, option |
| `profile/username` | the own @username |
| `file/<attachment id>` | a received `file` reference and its group (deleted after a view-once download) |
| `upload/<outbox local id>` | an upload in progress: group, message id, blob size, server upload id, done, paused (PROTOCOL.md 6.12, 6.13) |

Next to the profile, `<profile>.media/out/<local id>.blob` holds a file's
ciphertext until it is uploaded, and `<profile>.media/in/<attachment id>.part`
the ciphertext of a download in progress. Neither holds a key or plaintext;
both are deleted when done and with the account.
| `screenshot/<group hex>` | this user's own screenshot block for the chat |
| `reads/<group hex>` | JSON message id -> member ids that sent a read receipt |
| `unread/<group hex>` | messages received since the user last read the chat |
| `seen/<group hex>` | member id -> when this device last got that member's `seen` |
| `note/self` | the notes group (one member) |
| `folders` | the user's chat folders (name -> group ids) |
| `muted` | JSON group id (hex) -> end of the mute (unix seconds; 0 = until unmuted). Older profiles hold a list of group ids, read as muted until unmuted |
| `archived`, `pinned` | archived chats (set of group ids); pinned chats (ordered list, at most 5) |
| `draft/<group hex>` | the unsent text of the chat (`user.drafts`) |
| `unreadmark/<group hex>` | present while the user marked the chat unread |
| `leaving/<group hex>` | member id -> quiet, for members that asked to leave and are not removed yet |
| `profile/link` | the username link token (base64url) while `user.username_link` is applied |
| `refresh/<group hex>`, `traffic/<group hex>` | when this device last refreshed its keys in the group, and when the group last had traffic (PROTOCOL.md 6.9) |
| `keypackages/last_resort`, `keypackages/last_resort_prev`, `keypackages/last_resort_at`, `keypackages/checked` | current and previous last-resort key package as published, when the current one was made, when the server supply was last checked (PROTOCOL.md 5.3) |
| `invite/<link hash hex>` | a link this device made: group, expiry, use limit (PROTOCOL.md 8.7) |
| `linkjoin/<nonce hex>` | the user opened a link of this owner and sent this nonce: owner account and time (one day, used once) |
| `feature/user.recovery_phrase` | applied while the server holds a recovery key for the account, as last reported by the server (the phrase itself is never stored) |
| `recovery/release_at` | when the server drops the recovery key after a release without the phrase (unix seconds) |
| `pins/<group hex>` | the chat's pins: message id, who pinned, when this device received it, until when (6.2) |
| `poll/<group hex>/<poll id>` | the votes counted on this device (member id -> option indexes) and whether the creator closed it; the poll itself is a history message of kind `poll` |
| `sched/<id>` | a scheduled message: group, text, time, silent (until sent) |
| `remind/<id>` | a reminder: group, message id, time |
| `media/<attachment id>` | a downloaded file in the app's media folder: path, when, size (`user.storage_clean`) |
| `media_clean/last` | when the storage clean-up last ran |
| `stickerpack/<manifest id>`, `stickermanifest/<id>`, `stickerref/<id>`, `stickerimg/<id>/<index>` | installed packs; manifests seen; pack references learned from messages; cached sticker images (8.1) |
| `liveout/<group hex>/<id>` | a live location this device shares: end, last update, coordinates waiting for the 30 s interval (8.3) |
| `location/min_interval` | only in tests: a shorter live-update interval |
| `profile/photo` | the own profile photo: blob reference, type, upload time, the image (to upload it again) (8.6) |
| `photoshared/<group hex>` | what the group was last sent: photo attachment id ("" = removed), per-chat or not, the members then |
| `photo/<group hex>/<member hex>`, `photocache/<attachment id>` | a member's photo reference in the group; the fetched photo |
| `chatprofile/<group hex>` | the own name and photo for this chat only (8.7) |
| `topics/<group hex>`, `topicunread/<group hex>` | the group's topics (id, name, closed, creator, when received); unread messages per topic (9.1) |
| `adminlog/<group hex>` | the admin log: when, actor (member id), action, target, detail; at most 500 (9.3) |
| `shared/<group hex>`, `histtaken/<group hex>` | message id -> member that shared it; present once a history bundle was taken (9.5) |
| `joined/<group hex>`, `adder/<group hex>` | when this device joined the group; the member that added it (the sender of the first roster after joining) |
| `joinreq/<group hex>/<account>` | a join request waiting for an admin: account, nonce, when (9.6) |
| `slow/<group hex>`, `slowseen/<group hex>` | when this device last sent a counted message; per member, the server minutes of its last accepted messages (9.8) |
| `commjoin/<chat hex>` | this device asked to join the chat through a community, when (9.7) |
| table `tree_messages` | message history with franking records (SCHEMA.md 1.2); also `left` / `removed` lines about members who went (6.1); kinds `sticker`, `location`, `event` keep their state in `data` (8) |
| table `tree_outbox` | messages being sent: sealed bytes, recipients, idempotency key, state (SCHEMA.md 1.2) |

## 8. Rich chats (Wave 2 part B)

Code: `crates/tree-client/src/stickers.rs`, `relay.rs`, `location.rs`,
`chat_events.rs`, `rich_media.rs` (video notes, routing), `profile.rs`.
Everything below travels inside MLS application messages; the server sees
ciphertext and, for stickers and photos, opaque encrypted blobs uploaded
with the attachment upload API (PROTOCOL.md 6.12, format v2: a fresh file
secret per blob, padding, key commitment, the plaintext hash checked). Each chat key is checked by the
sending device and again by every receiving device (section 3); a payload
a released key forbids is dropped and reported as `Dropped`.

### 8.1 Stickers and custom emoji (`chat.stickers`)

A pack is a set of images (at most 120, each at most 512 KiB, `image/*`),
each uploaded as an encrypted blob, plus a manifest, itself an encrypted
blob:

```json
{"v":1,"title":"…","emoji_pack":false,
 "items":[{"name":"…","emoji":"😀","mime":"image/png","file":{"id":"…","key":"…","size":123,"pt_sha256":"…","v":2}}]}
```

The pack is shared by a link that carries the manifest's reference and
key, like a file reference: `tree://stickers/<base64url(JSON blob
reference)>`. Who has the link can open the pack; the server holds
blobs it cannot open and never learns names, images or who installed
what. Installing fetches the manifest and every image (kept on the device);
removing forgets them on this device only.

A `sticker` message names the pack (its manifest reference with key) and
the index; a receiver fetches the manifest and the image with those keys
(cached), whether or not it installed the pack. A custom emoji reaction is a
`react` with `sticker` and the item's plain `emoji`; it is stored under the
reaction key `sticker:<manifest id>:<index>` (apps draw the image), or under
the plain emoji while the chat releases `chat.stickers` (and by older apps).

Blobs expire on the server after the mailbox TTL (30 days): a sticker from
an older pack opens only on devices that cached it. Re-uploading a pack
(a new link) is the creator's job; automatic refresh is not built.

### 8.2 GIFs (`chat.gifs`, server `server.gif_relay`)

Search goes through the server's relay (PROTOCOL.md 8.12): the provider
never sees the user's address; the Tree server sees the search words. The
user picks a result; the sender's device fetches it through the relay and
sends it as a normal encrypted attachment flagged `gif`. Receivers open the
attachment like any file and never contact the relay or the provider. When
the server offers no GIF relay (`GET /v1/relay` says `gif: false`, the
search answers `503 RELAY_UNAVAILABLE`), apps hide the GIF button; they also
hide it while the chat releases `chat.gifs`.

### 8.3 Location and live location (`chat.location`)

`location` carries latitude and longitude as integers in 10^-7 degrees
(every device reads the same value), the accuracy in metres and an optional
label. A live location adds `live_secs`: the apps offer 15 minutes, 1 hour
and 8 hours; receivers accept up to 8 hours and measure it with their own
clock from when the start arrived. The app hands the client new
coordinates whenever it has them; the client sends a `live_location` at
most every 30 seconds (newer coordinates replace waiting ones and go out
with a later sync) and stops at the end or when the user stops (`stop`).
Receivers take updates only from the location's sender and only while it
is live; an expired or stopped live location keeps its last position and
shows as ended. Map tiles come through the server's optional tile relay
(`server.map_relay`, PROTOCOL.md 8.12); without one, apps show the
coordinates and an "open in maps app" action (`geo:` link).

### 8.4 Events with replies (`chat.events`)

`chat_event` (title, start, optional end, place, description), `rsvp`
(going / maybe / not; the newest answer of a member counts) and
`event_edit` (only from the creator; `cancelled` ends answering). Every
device keeps the tally itself from the answers it received, counting
current members only. Times are what the creator entered (they are content,
not a clock the protocol relies on).

### 8.5 Round video notes (`chat.video_notes`)

A short (at most 60 s), square video sent as a file with `video_note` and
`duration_ms`. Apps record and play it as a round video; the desktop app
attaches a short video file and shows a placeholder to save and play it.

### 8.6 Profile photos (`user.profile_photo_visibility`)

The photo (an image of at most 2 MiB) is uploaded as an encrypted blob;
the reference goes only inside MLS in `profile_photo`, to the chats the
setting allows: `chats` (default: every accepted chat), `contacts` (chats
whose other members are all contacts the user chose and has not blocked,
each device vouched for as in 5), `nobody` (or released). Every sync
compares what each chat should have with what it was last sent and sends the
difference: the photo, or "removed" where it was removed or is no longer
allowed, and again when members were added. Receivers keep the reference per
chat and member, fetch the photo once, cache it, and delete both on
removal. The photo is uploaded again after 20 days, as blobs expire after
30. Honest limit: a member who already fetched the photo keeps it.

### 8.7 Per-chat profiles (`user.per_chat_profile`, `chat.allow_per_chat_profiles`)

With `user.per_chat_profile` applied (released by default) and the chat
allowing it, a user can set a display name and photo for one chat only;
they go to that chat as `profile` / `profile_photo` with `chat: true`. When
either switch is released, the device sends its main name (and photo) to
that chat again, and receivers ignore per-chat names and photos while the
chat releases them. This is a presentation layer: the member keeps the
same keys and MLS member id in every chat, so someone in two of the user's
chats can link the names (member ids, safety numbers, the account in
rosters). A separate cryptographic identity per chat (new keys per chat,
full unlinkability) is a later step.

## 9. Groups and communities (Wave 3)

Code: `crates/tree-client/src/groups.rs` (roles, permissions, restricted
members, slow mode, welcome text, the next admin), `topics.rs`,
`admin_log.rs`, `history_share.rs`, `invites.rs` (join approval),
`community.rs`; the commit rules in `crates/tree-core/src/group.rs` and
`group_settings.rs` (PROTOCOL.md 6.11.1). FFI `crates/tree-ffi/src/groups.rs`,
apps `apps/shared/.../Groups.kt`, desktop `GroupsView.kt`.

Every decision below is made by every receiving device with the sender MLS
authenticated (the committer of a commit, the sender of an application
message), never with an id written inside a payload. The server learns
nothing new: settings live in the MLS group context, everything else is an
ordinary MLS application message or stays on the device. The only server
data the client now reads is the arrival minute the mailbox already
returned (`received_at`), used by slow mode.

| Key | Scope | Default | Option | Effect |
| --- | --- | --- | --- | --- |
| `chat.topics` | chat (admins) | released | `admins` (default) or `all`: who creates topics | topics (9.1) |
| `chat.roles` | chat (admins) | applied | | roles grant their permissions and show as member tags (9.2) |
| `chat.member_adds` | chat (admins) | applied | | any member adds members; released: admins and roles with `add` only (9.2) |
| `chat.admin_log` | chat (admins) | applied | | the device-local admin log (9.3) |
| `chat.welcome` | chat (admins) | released | a text of 1 to 500 characters | new members see it once (9.4) |
| `chat.history_share` | chat (admins) | released | 25 to 100 (default 50) | new members get that many recent messages (9.5) |
| `chat.owner_succession` | chat (admins) | applied | | the last admin names the next one before leaving (9.10) |
| `chat.join_approval` | chat (admins) | released | | invite-link joins wait for an admin (9.6) |
| `chat.slow_mode` | chat (admins) | released | 10 s to 1 h (default `30s`) | members who are not admins send one message per interval (9.8) |
| `chat.restrict` | chat (admins) | applied | | restrictions are enforced (9.9) |

### 9.1 Topics (`chat.topics`)

Threads inside a group. A `topic` message creates (a new random id with a
name), renames, closes or reopens a topic; every device, the sender's
included, applies it to its own list after the checks in section 1. At most
100 topics per group, names 1 to 64 characters. Texts and files carry the
topic id (`topic`); other kinds belong to the main chat. A receiver keeps a
message under its topic, or drops it when the topic is closed and the
sender may not manage topics; while `chat.topics` is released no topics are
shown and a topic on a message is ignored (the message shows in the main
chat). Unread counts are kept per topic on the device (`mark_topic_read`).
After adding members, an adder that may manage topics sends a `topics`
list so they learn the names; a message in a topic a device was never told
about is kept under that id and shown as an unnamed topic.

### 9.2 Roles, member tags and permissions (`chat.roles`, `chat.member_adds`)

Admins create roles (name, `#rrggbb` colour, permissions) and give them to
members; roles and assignments are in the group settings (PROTOCOL.md
6.11.1) so every member holds the same ones. Permissions, each also held by
every admin:

| Permission | Allows | Enforced by |
| --- | --- | --- |
| `pin` | pin and unpin (`chat.pins`) | the sender and every receiver (`pins.rs`) |
| `delete` | delete another member's message for everyone (`delete`) | the sender and every receiver (`messages.rs`) |
| `add` | add members while `chat.member_adds` is released | the sender and every device's core, which rejects the add commit before merging it (PROTOCOL.md 6.11.1) |
| `topics` | create, rename, close and reopen topics | the sender and every receiver (`topics.rs`) |

While `chat.roles` is released roles grant nothing and are not shown (they
stay in the settings). A payload a permission does not cover is dropped by
every honest receiver; the tests send such payloads with the sending
device's own checks bypassed (`send_unchecked`) and with raw MLS commits.

### 9.3 Admin log (`chat.admin_log`)

Each device records the admin actions it observes, with the actor MLS
authenticated: settings changes (name, admins, chat features, roles and
assignments, restrictions, community chats; as a difference of the
settings before and after each merged commit), members added and removed
(by the committer), pins and unpins, messages deleted by moderators, topic
changes, join requests approved or declined on this device. Nothing is sent
for it; a device that joined later has no earlier entries, and an action a
device dropped is not logged. At most 500 entries per group. Shown to
admins (`NOT_ADMIN` otherwise). Released: nothing is recorded and nothing
is shown.

### 9.4 Welcome message (`chat.welcome`)

Stored in the group settings as the option of `chat.welcome` (at most 500
characters), so it is the admins' text, authenticated by the group context
the new member receives in its welcome, and not something the adding device
chose. A device that joins shows it once (`Event::Welcome` and a `welcome`
line in its history); members already in the group see no line. Released:
new members see nothing.

### 9.5 History for new members (`chat.history_share`)

Chosen design: the device whose commit added the new members re-sends its
newest N texts and files (N = the option, 25 to 100) in one `history`
application message to the group, naming the new members in `to`. It is
end-to-end encrypted like any message; other members' devices ignore a
bundle not addressed to them; the server sees one more ciphertext. A
separate group would cost commits and gain nothing.

A receiver takes a bundle only if its own member id is in `to`,
`chat.history_share` is applied, the authenticated sender is a current
member and the member that added this device (the sender of the first
roster after joining), it is the first bundle, and it arrives within a day
of joining. At most 200 KiB per bundle (oldest messages give way); texts are
cut at 4096 characters; view-once files, deleted messages and messages that
were themselves shared are never re-sent.

Honest limit: the original messages' MLS authentication cannot be carried.
Authors, names and times inside a bundle are the sharer's claims; apps show
every shared message with "shared by X" (X the authenticated sharer,
`Message.shared_by`). Shared messages are not franked again (they cannot be
reported as their claimed author's), do not count as unread, and get the
group's disappearing timer from when they arrive. While the key is applied
the apps show "new members see the recent conversation".

### 9.6 Join approval (`chat.join_approval`)

With the key applied, an invite-link request (PROTOCOL.md 8.7) is not
carried out at once by the link owner's device: it waits there as a join
request (`Event::JoinRequest`, `join_requests`) for 30 days until an admin
approves it (`approve_join`: the account is added as for any link join, its
device accepts the group because the nonce matches) or declines it
(nothing is sent). The joiner's device accepts the group by itself only
within a day of using the link (section 5); approved later, the group
arrives there as a request. Requests live on the device that made the link. The
server sees the same request as without approval.

### 9.7 Communities

A community is a group (the root) whose settings carry `community.chats`
(group id and name of each chat, at most 50). Its members are the
community's members, its admins the community's admins. An admin creates
it (`create_community`), invites members like to any group, and adds or
removes chats it is in. A member asks to join a chat with `join_chat` in
the root, naming its own account; each admin device of the root that is in
the chat and may add members there claims the account's key packages and
adds them only if one of the claimed devices is the requesting device
itself (its member id is the authenticated sender), so nobody can get
another account added. The joining device accepts the chat at once (it
asked). Limits: a chat none of the community's admins is in cannot be
joined this way; each chat keeps its own admins and settings.

### 9.8 Slow mode (`chat.slow_mode`)

Members who are not admins send at most one new message (text, file,
sticker, poll, place, event) per interval. The sending device refuses
earlier ones (`SLOW_MODE`, `slow_mode_wait`). Receivers check with the
server's arrival minute, which every receiver sees the same: with interval
`i`, at most `ceil(60 / i)` messages of one member in one server minute, and
messages at least `i - 60` seconds apart in server minutes. An honest
sender always passes; a modified one gets at most about twice the rate. A
message that breaks it is hidden; admins get `Event::SlowModeHidden`. Limit:
messages that waited in the outbox and reach the server together may be
hidden by receivers.

### 9.9 Restricted members (`chat.restrict`)

An admin restricts a member until a time (`restrict_member`): the member
may read but not send anything except its name, photo, read receipts,
typing, presence and a leave request. Restrictions are in the group
settings (at most 50; admins cannot be restricted); every receiver drops
what a restricted member sends until the time passes by its own clock.
Released: restrictions are not enforced.

### 9.10 The next admin (`chat.owner_succession`)

When the group's only admin leaves (`leave`, `leave_quietly`, account
deletion) and the key is applied, its device first commits a settings
change naming the successor admin, then sends its leave request, which the
new admin's app carries out. The successor is the member in the lowest leaf
of the ratchet tree, other than the leaving device and not restricted
(`Group::successor`): every device computes the same one from the same
tree, and MLS puts each added device into the leftmost free leaf, so it is
the longest-standing member unless a removal freed an earlier leaf. A last
admin cannot be removed by anyone else (only admins remove, and no device
removes itself), so leaving is the only way the last admin goes. Released:
nobody is named; the group keeps the departed device as its only admin and
its leaf stays, since nobody else may remove it.
