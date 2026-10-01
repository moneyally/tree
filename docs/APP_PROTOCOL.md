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
| `text` | `text` | a chat message | any member |
| `profile` | `name` | the sender's own display name | any member, about itself |
| `roster` | `devices`: member id (hex) -> device id; `names` (optional): member id -> name | who is reachable at which server device, and the sender's view of names | the member that just added devices (others may too) |
| `leave` | — | the sender asks to be removed (PROTOCOL.md 6.5) | any member |

```json
{"t":"text","text":"안녕"}
{"t":"profile","name":"bob"}
{"t":"roster","devices":{"0678…":"TRUiLpZjKr-CUgfUf_ry8w"},"names":{"0678…":"alice"}}
{"t":"leave"}
```

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
- **Leave.** A member that receives `leave` from X may remove X. Several
  members doing so race for the same epoch; the server's ordering keeps one.
- **Recipients.** Every message goes to the devices in the roster except the
  sender's own device. Commits also go to devices being removed.

## 3. Client behaviour (`tree_client::Session`)

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

## 4. What the client stores

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
