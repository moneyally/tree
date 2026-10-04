# Bot gateway

Tree runs no bots. A bot's developer runs the **bot gateway**
(`crates/tree-bot-gateway`, binary `tree-bot-gateway`) on their own server.
The gateway is the bot's device: it holds the bot's MLS keys and device key
in an encrypted profile, receives and decrypts what members send the bot,
and offers the bot's own code a small local HTTP API in a widely used bot
HTTP API style. Protocol: PROTOCOL.md 8.16; payloads: APP_PROTOCOL.md 11.

**Whoever runs the gateway reads everything the bot is sent**, in
plaintext: that is what a bot is. With `bot.privacy_mode` applied (the
default) members' devices send a bot in a group only what is addressed to
it (commands, mentions, replies to its messages, presses of its buttons)
plus the member list and names; in a 1:1 chat everything; with the switch
released, everything in its groups. Never shared history, never people's
recovery data (bots have none) or phone numbers (Tree has none).

## Setting up

1. In the app: Bots → create a bot (`…bot` username). The token is shown
   once. Keep it secret: it is the bot.
2. On your server, register the gateway (secrets come from the environment
   or standard input, never the command line):

   ```sh
   export TREE_GATEWAY_PASSPHRASE='…'   # encrypts the gateway's profile
   export TREE_BOT_TOKEN='…'            # from step 1
   tree-bot-gateway init --server https://your.tree.server --profile bot.db
   unset TREE_BOT_TOKEN
   ```

   The gateway makes a device key, asks the server for a challenge, signs it
   with the key and registers the device with the token. The token is not
   written to disk; the profile keeps only its SHA-256, to check the local
   API.
3. Run it: `tree-bot-gateway run --profile bot.db` (listens on
   `127.0.0.1:8081`; `--listen`, `--poll`). A non-loopback address needs
   `--allow-remote`; then put TLS and a firewall in front: the token is the
   API's only protection.

**One gateway per bot.** Registering removes every other device of the bot.
If the token leaks, rotate it in the app: the old token and the gateway
device registered with it stop at once (also a thief's). Then register
again with the same profile, which keeps the device and its waiting
messages:

```sh
TREE_BOT_TOKEN='<new token>' tree-bot-gateway reregister --profile bot.db
```

## Local API

Every call carries the token: `Authorization: Bearer <token>` on
`/v1/<method>`, or the path `/bot<token>/<method>` (keep such URLs out of
logs). Parameters as a JSON body or a query string. Answers are
`{"ok": true, "result": …}` or `{"ok": false, "error_code": …, "description": …}`.
Ids are strings: a chat id is the group id in hex, a user id the member id
in hex, a message id the message's hex id.

| Method | Parameters | Result |
| --- | --- | --- |
| `getMe` | — | `id` (bot account), `username`, `is_bot`, `can_join_groups`, `can_read_all_group_messages` (privacy mode released), `supports_inline_queries` |
| `getUpdates` | `offset`, `limit` (1-100), `timeout` (0-50 s, long poll) | updates with `update_id` ≥ `offset`; updates before `offset` are confirmed and dropped. Refused (`409`) while a webhook is set |
| `sendMessage` | `chat_id`, `text`, `reply_to_message_id`, `reply_markup: {"inline_keyboard": [[{"text", "callback_data"}]]}` | the message |
| `answerCallbackQuery` | `callback_query_id`, `text` (≤ 200), `show_alert` | `true`; shown to the presser only, once |
| `leaveChat` | `chat_id` | `true` |
| `setWebhook` | `url` (`https://`, or `http://` to this machine), `secret_token` | `true`; updates are then posted there with `X-Tree-Bot-Api-Secret-Token` |
| `deleteWebhook`, `getWebhookInfo` | — | `true`; `url`, `pending_update_count`, `last_error_message` |

Updates:

```json
{"update_id": 7, "message": {"message_id": "…", "from": {"id": "<member>", "is_bot": false, "first_name": "Alice", "account": "<account, as the group's roster names it>"}, "chat": {"id": "<group hex>", "type": "group", "title": null}, "date": 1790000000, "text": "/start@quiz_bot"}}
{"update_id": 8, "callback_query": {"id": "…", "from": {…}, "message": {"message_id": "…", "chat": {…}}, "data": "vote:yes"}}
```

Updates are kept in the encrypted profile until confirmed (at most
10,000). Only chats the bot's device accepted give updates: chats people
start with it, and groups while `bot.join_groups` is applied.

## Limits

- No inline queries yet (`bot.inline` is a switch only), no files from the
  gateway, no edits or deletions of the bot's messages through the API.
- Bot payments and tips are locked off (`AlwaysOff`) until identity
  verification and legal review (stage 4, 변호사 확인 필요). Bots never pay
  out points.
