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
| `text` | `id` (16 random bytes, hex), `text`; optional `fmt` (true: Tree markup, 1.1), `mentions` (member ids, at most 50), `all` (@all) | a chat message | any member; `fmt` only while `chat.formatting` is applied; `all` as `chat.mention_all` allows |
| `edit` | `id`, `text` | replaces the text of the sender's own message `id` | its sender, if `chat.edit` is applied, within the window |
| `delete` | `id` | deletes the sender's own message `id` for everyone | its sender, if `chat.delete_for_all` is applied, within the window |
| `react` | `id`, `emoji` (1 to 8 characters), `remove` (optional) | adds or takes back a reaction | any member, if `chat.reactions` is applied |
| `profile` | `name` | the sender's own display name | any member, about itself |
| `roster` | `devices`: member id (hex) -> device id; `names` (optional): member id -> name; `accounts` (optional): member id -> account id; `link` (optional): hash of the invite link the new member used | who is reachable at which server device, the sender's view of names, and which account each device belongs to | the member that just added devices (others may too) |
| `leave` | — | the sender asks to be removed (PROTOCOL.md 6.5) | any member |
| `file` | `msg_id`, `view_once` (optional), `voice` and `duration_ms` (optional, voice message), `id`, `key` (base64), `nonce` (base64, 7 bytes), `size`, `ct_sha256`, `pt_sha256` (hex), `name`, `mime` | an encrypted attachment (PROTOCOL.md 6.12) | any member, if `chat.media` is applied (and `chat.view_once` for view-once, `chat.voice` for voice) |
| `franked` | `p` (the inner `text`, `edit` or `file` payload as a JSON string), `k` (base64), `tag` (base64), `m` (minute) | how every `text`, `edit` and `file` is sent: the inner payload with its franking (PROTOCOL.md 8.5); the receiver keeps `p`, `k`, `tag`, `m` to be able to report it | any member |

```json
{"t":"text","text":"안녕"}
{"t":"profile","name":"bob"}
{"t":"roster","devices":{"0678…":"TRUiLpZjKr-CUgfUf_ry8w"},"names":{"0678…":"alice"}}
{"t":"leave"}
```

A `franked` payload whose `p` is not a `text`, `edit` or `file` is dropped,
and so are `text`, `edit` and `file` sent without franking.

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
| `chat.edit` | applied, option = window in seconds (default 86400) | the sender may edit its own text |
| `chat.delete_for_all` | applied, option = window (default 86400) | the sender may delete its own message for everyone; a placeholder stays so a late edit cannot revive it |
| `chat.reactions` | applied | reactions allowed |
| `chat.view_once` | applied | view-once files allowed; the reference is deleted after the first successful download (and the sender keeps none) |
| `chat.disappearing` | released; option = seconds | every message expires that long after it arrives on each device and is deleted from its history |
| `chat.voice` | applied | voice messages (files with `voice`) allowed |
| `chat.formatting` | applied | markup shown; released: plain text |
| `chat.mention_all` | applied, option `admins` (default) or `all` | who may send @all; a refused @all is ignored by receivers (the text still arrives); released: nobody |
| `chat.screenshot_block` | released | apps block screenshots of the chat for every member; a user can also block them for themselves (`screenshot/<group>`). It stops honest apps' screenshot function, not cameras or modified apps |

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

A group whose adder names, in its roster, an invite link the user opened
from that adder in the last day (PROTOCOL.md 8.7) is accepted after the
blocked check, once: the user asked to join that group.

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
| Sync | fetch the mailbox (optionally long-poll), process in order, acknowledge everything processed |
| Welcome | join; start a roster with the own device; announce the own `profile` when the roster lists others |
| Envelope for an unknown group, or failing the seal check | hold it (at most 256), retry after every epoch change or join (PROTOCOL.md 6.7) |
| Key packages | top up to 20 when fewer than 10 remain (checked at creation and after joins) |

Not yet: holding expiry (7 days), retry limits for commits, contacts and
safety numbers, message history.

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
| `contact/<account id>` | JSON: pinned member ids, verified, accepted (chosen by the user), blocked |
| `gstatus/<group hex>` | request (with adder account) or declined; absent = accepted |
| `feature/<key>` | the user's setting: applied or released, option |
| `profile/username` | the own @username |
| `file/<attachment id>` | a received `file` reference and its group (deleted after a view-once download) |
| `screenshot/<group hex>` | this user's own screenshot block for the chat |
| `invite/<link hash hex>` | a link this device made: group, expiry, use limit (PROTOCOL.md 8.7) |
| `linkjoin/<link hash hex>` | the user opened this link: owner account and time (one day, used once) |
| `feature/user.recovery_phrase` | applied once a recovery phrase was made (the phrase itself is never stored) |
| table `tree_messages` | message history with franking records (SCHEMA.md 1.2) |
