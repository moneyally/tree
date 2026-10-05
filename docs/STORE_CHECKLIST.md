# App store checklist (stage 1)

What the iOS and Android stores expect from a chat app with user-generated
content, and where Tree stands. Store rules change; every item marked
**변호사 확인 필요** needs the owner's lawyer before submission, and the
wording of the store forms must be checked against the stores' current
rules at submission time.

| Requirement | Status | Where |
| --- | --- | --- |
| Report abusive content and users from inside the app | done | message "report" (PROTOCOL.md 8.5); the server checks the report is genuine (franking) |
| Block abusive users | done | requests inbox: decline and block; `block`/`unblock` (APP_PROTOCOL.md 5) |
| Act on reports (moderation by the operator) | done (tools) | operator review, resolve, account suspension (`deploy/README.md`); the response time and process: **변호사 확인 필요** |
| Filter objectionable content | by design: reports + blocking + message requests; no server-side scanning (end-to-end encryption) | how to describe this to the stores: **변호사 확인 필요** |
| Account deletion inside the app | done | settings → delete account (server `DELETE /v1/accounts`, local profile removed) |
| Contact information for users | missing | owner to provide a support address |
| Privacy policy (in the app and on the store page) | missing | text: **변호사 확인 필요**; the facts are in SERVER_API.md "What the server stores" |
| Terms of use (with rules on abuse) | missing | **변호사 확인 필요** |
| Age rating questionnaire | missing | owner; **변호사 확인 필요** |
| Data safety / privacy labels (what is collected) | facts ready | no phone, e-mail or contacts collected; account id, device ids, username hash, ciphertext in transit; reports when a user files one; **변호사 확인 필요** for the form |
| Encryption export rules (standard algorithms, end-to-end messaging) | missing | **변호사 확인 필요** (export classification and any filing) |
| No content in push notifications | done | push carries only `wake` (PROTOCOL.md 8.8) |
| Backups do not leak keys | done (Android) | profile excluded from cloud backup and device transfer |
| Screenshots of protected chats | done (Android) | `FLAG_SECURE` for `chat.screenshot_block`; iOS: with the iOS app |
| Signed release builds | missing | signing keys are the owner's; never in git |
| iOS build | missing | needs macOS and a developer account |
| Public groups and channels (Wave 4): user-generated public content | built: reports of public posts into the operator queue (the server holds the text), deletion by authors and admins, bans, slow mode, suspension of accounts, the operator can switch the whole feature off (`server.public_spaces`) | moderation duties for public content (response times, notice-and-takedown, keeping or handing over deleted content, illegal content reporting duties in each country, age limits for public spaces): **변호사 확인 필요** |
| Public spaces are not end-to-end encrypted | "Public" badge on every public object, warning before creating and posting, the display name is published with posts | how to describe this in the privacy policy and store data forms (plaintext public posts, published names, subscriptions): **변호사 확인 필요** |
| Directory and search of public spaces | only spaces whose admins applied `chat.public_listing` | whether the directory needs operator review or age gating: **변호사 확인 필요** |

Submission itself (accounts, payments, forms) is the owner's.
| Bots (Wave 5): third-party bots run by their makers | built: every bot labelled "bot" by the server's word, reports of a bot's messages into the operator queue with its owner named, blocking a bot also stops it on the server, per-bot rate limits, a bot cannot start a chat with anyone who did not contact it, admins can keep bots out of a group (`chat.bots`), the operator can switch the whole platform off (`server.bot_platform`, off by default) | bot moderation duties (who answers for a bot's content: the maker or the operator; response times; suspending a bot and its owner; developer terms for bot makers): **변호사 확인 필요** |
| Bots read what they are sent | the apps say that whoever runs a bot reads the messages it gets; privacy mode by default (in groups only messages addressed to the bot) | how to describe this in the privacy policy and store data forms: **변호사 확인 필요** |
| Bot payments and tips | locked off (`bot.payments`, `bot.tips` AlwaysOff; bots never pay out points, `bot.pay_out_points` AlwaysOff) | stage 4, needs identity verification of bot makers and the payment rules of the stores and the law: **변호사 확인 필요** |
| Location permission (Android) | asked only when the person taps "Location" in a chat; one fix, never in the background; the place goes end-to-end encrypted to that chat; map pictures only through the operator's relay when it has one | store location declaration and privacy policy wording: **변호사 확인 필요** |
| Bundled font (Pretendard) | SIL Open Font License 1.1, licence text in `apps/ui/FONT_LICENSE.txt` | how to show the licence notice in the app and store listing: **변호사 확인 필요** |
| Microphone permission (Android) | asked only when the person taps the mic to record a voice message; nothing recorded otherwise; the note goes end-to-end encrypted | store declaration wording: **변호사 확인 필요** |
