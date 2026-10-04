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
| `text` | `id` (16 random bytes, hex), `text`; optional `fmt` (true: Tree markup, 1.1), `mentions` (member ids, at most 50), `all` (@all), `preview` (`url`, `title`, `description`: made by the sender's app, which fetched the page; receivers never fetch it; shown only while the receiver's `user.link_preview` is applied), `silent` (true: silent send, receivers' apps do not notify, 6.1), `fwd` (true: forwarded from another chat, 6.2; the original sender is not named) | a chat message | any member; `fmt` only while `chat.formatting` is applied; `all` as `chat.mention_all` allows |
| `edit` | `id`, `text` | replaces the text of the sender's own message `id` | its sender, if `chat.edit` is applied, within the window |
| `delete` | `id` | deletes the sender's own message `id` for everyone | its sender, if `chat.delete_for_all` is applied, within the window |
| `react` | `id`, `emoji` (1 to 8 characters), `remove` (optional) | adds or takes back a reaction | any member, if `chat.reactions` is applied |
| `profile` | `name` | the sender's own display name | any member, about itself |
| `roster` | `devices`: member id (hex) -> device id; `names` (optional): member id -> name; `accounts` (optional): member id -> account id; `link` (optional): the nonce (hex) the new member's device sent with its invite-link request (PROTOCOL.md 8.7) | who is reachable at which server device, the sender's view of names, and which account each device belongs to | the member that just added devices (others may too) |
| `leave` | `quiet` (optional; true: quiet leave, no "left" line, 6.1) | the sender asks to be removed (PROTOCOL.md 6.5) | any member |
| `remove_device` | `members` (member ids, hex) | the sender unlinked these devices of its own account and asks the admins to remove them (PROTOCOL.md 8.11); shown to admins as a removal request for each named member whose known account is the sender's; an admin decides, apps never carry it out automatically (unlike `leave`), as the account labels are other members' claims | a member that is not an admin |
| `read` | `ids` (at most 100 message ids) | the sender read these messages | any member, while its `user.read_receipts` is applied; shown only while the receiver's is applied too |
| `typing` | `on` | the sender started or stopped typing; never stored | any member, both sides `user.typing` |
| `seen` | — | the sender's app is open; the receiver records its own time | any member, both sides `user.last_seen` (released by default) |
| `file` | `msg_id`, `view_once` (optional), `voice` and `duration_ms` (optional, voice message), `id`, `key` (base64), `nonce` (base64, 7 bytes), `size`, `ct_sha256`, `pt_sha256` (hex), `name`, `mime`, `fwd` (optional, forwarded, 6.2) | an encrypted attachment (PROTOCOL.md 6.12) | any member, if `chat.media` is applied (and `chat.view_once` for view-once, `chat.voice` for voice) |
| `pin` | `id`, `ttl` (optional: seconds, 1 s to 365 days, counted from arrival on each device; none: until unpinned), `remove` (optional: unpin) | pins or unpins message `id` for the whole chat (6.2) | an admin, or either member of a 1:1 chat, if `chat.pins` is applied |
| `poll` | `id`, `q` (question, at most 300 characters), `opts` (2 to 10 options, 1 to 100 characters each), `multi` (optional: several choices), `anon` (optional: apps do not show who voted), `close_in` (optional: seconds, 1 s to 30 days from arrival) | a poll; franked like a text (it can be reported) | any member, if `chat.polls` is applied |
| `vote` | `id` (the poll), `choices` (option indexes; empty: take the vote back) | the sender's whole vote; the latest one per member counts | any member, if `chat.polls` is applied, before the poll closed |
| `poll_close` | `id` | closes the poll for everyone | the poll's creator, if `chat.polls` is applied |
| `franked` | `p` (the inner `text`, `edit`, `file` or `poll` payload as a JSON string), `k` (base64), `tag` (base64), `m` (minute) | how every `text`, `edit` and `file` is sent: the inner payload with its franking (PROTOCOL.md 8.5); the receiver keeps `p`, `k`, `tag`, `m` to be able to report it | any member |

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

Older apps read a `text` or `file` with `fwd` as an ordinary message (unknown
fields are ignored), and drop `pin`, `poll`, `vote` and `poll_close` as
unsupported types (a franked `poll` as a malformed franked payload).

`silent` and `quiet` are per message: there is no setting for them, the
sender chooses each time. Both are inside the end-to-end encrypted payload,
so the server cannot tell a silent or quiet message from any other. Older
apps ignore both fields (they notify, and show a "left" line).

A `franked` payload whose `p` is not a `text`, `edit`, `file` or `poll` is
dropped, and so are `text`, `edit`, `file` and `poll` sent without franking.

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
| table `tree_messages` | message history with franking records (SCHEMA.md 1.2); also `left` / `removed` lines about members who went (6.1) |
| table `tree_outbox` | messages being sent: sealed bytes, recipients, idempotency key, state (SCHEMA.md 1.2) |
