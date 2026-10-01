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

Submission itself (accounts, payments, forms) is the owner's.
