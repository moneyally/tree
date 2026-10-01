# Threat model (draft)

## Security goals

| Goal | How |
| --- | --- |
| Confidentiality of messages | MLS (RFC 9420), hybrid ML-KEM-768 + X25519 key exchange |
| Integrity and authenticity | MLS signatures + AEAD, outer envelope seal |
| Forward secrecy | message keys deleted after use |
| Post-compromise security | periodic key refresh (`Group::refresh_keys`) |
| Harvest-now-decrypt-later resistance | post-quantum hybrid key exchange, 256-bit symmetric keys |
| Removed members lose access | new epoch after every removal |

**Not provided:** deniability. MLS messages carry sender signatures, so a member
who leaks a conversation can prove it is genuine.

## Adversaries

| Adversary | Defense | Residual risk |
| --- | --- | --- |
| Network eavesdropper, incl. future quantum computer | TLS 1.3 + hybrid PQ MLS | message size and timing (padding reduces size leakage) |
| The Tree server (breach, insider, legal compulsion) | stores only ciphertext; outer seal blocks forged inputs | sees mailbox, approximate time; can drop messages |
| Outsider who can write to a mailbox | outer envelope seal checked before MLS | none known |
| Malicious group member | MLS authentication | can leak what they read; can make one message undecryptable (F-001); can get changes committed in an honest member's name or cut members off through proposals (F-007) |
| Removed member with a modified client | new epoch keys after removal | none known (tested) |
| Device thief | (planned) encrypted local storage, hardware-wrapped keys | an unlocked phone |
| Spyware on the device | out of scope | no messenger can protect a compromised OS |

## Out of scope for now

Metadata protection beyond padding and contact discovery (there is none: no phone
numbers). What the server stores, and what it does not, is listed in
[SERVER_API.md](SERVER_API.md).
