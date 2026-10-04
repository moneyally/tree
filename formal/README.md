# Formal models

Small symbolic models of the parts of Tree Protocol v1 that Tree adds on top
of MLS, checked with **ProVerif 2.05**. They back claims C1, C4, C5, C6 and C9
of [docs/PROTOCOL.md](../docs/PROTOCOL.md) under the abstractions listed
below. They are not proofs of MLS, of the libraries, or of the Rust code.

## Run

```sh
formal/run.sh                       # uses `proverif` from PATH
PROVERIF=/path/to/proverif formal/run.sh
```

`run.sh` runs every `*.pv` file, prints the `RESULT` lines and compares them
with `expected_results.txt`. It exits 0 only if every result matches. All
models finish in well under a second each.

Single model: `proverif formal/envelope_seal.pv`.

### Installing ProVerif

Used here (Ubuntu 24.04, 2026-10-01):

```sh
apt-get install opam ocaml-nox ocaml-findlib libgtk2.0-dev pkg-config
export OPAMROOT=/opt/opam
opam init --disable-sandboxing --bare -n
opam switch create default ocaml-system      # OCaml 4.14.1
opam install --switch=default proverif       # proverif 2.05
/opt/opam/default/bin/proverif -help | head -1
```

`libgtk2.0-dev` is only needed because the opam package also builds the
interactive simulator. Tamarin was not used: its prebuilt release binaries
could not be downloaded in this environment. The commit-ordering property
needs linear state, which Tamarin expresses natively; porting
`commit_ordering.pv` to Tamarin (unbounded epochs) is future work.

## Models

How to read results: `RESULT ... is true` means ProVerif proved the property
for all executions of the model (unbounded sessions unless stated).
`RESULT not attacker(x) is false` or `... is false` means ProVerif found an
attack trace. Every model has either a reachability query or a negative
control, so that a "true" cannot come from a model in which nothing happens.

| File | Property | Expected and obtained |
| --- | --- | --- |
| `envelope_seal.pv` | (a) C1. A non-member cannot get forged or modified MLS bytes accepted past the seal, or into MLS key consumption, in an epoch it is not a member of; honest envelope keys stay secret | 3 x true; reachability: honest acceptance happens |
| `envelope_seal_check_after_mls.pv` | negative control: seal checked after MLS consumed the key (pre-F-001 behaviour) | key-consumption query false (attack) |
| `commit_ordering.pv` | (b) C9. Server accepts the first commit per epoch; clients merge only accepted commits: two members never merge different commits for the same epoch state; every merged commit was accepted | 2 x true; reachability: a member reaches the third epoch |
| `commit_ordering_merge_early.pv` | negative control: clients merge their own commit at once (stage-0 behaviour, F-003) | agreement false (fork) |
| `removal_secrecy.pv` | (c) C6. A removed member (full state at removal + Dolev-Yao) learns no message of later epochs | epoch-0 message: learned (sanity); 4 later secrets: secret; reachability ok |
| `removal_secrecy_send_in_past_epoch.pv` | negative control: a member sends in the old epoch after the removal | that message is learned (attack) |
| `pcs.pv` | (d) C5. After compromise of B's decryption state: A's own refresh does not heal B's compromise; B's refresh does, also for the following epoch | other-refresh secret learned; own-refresh secrets secret; reachability ok |
| `pcs_signing_key_leaked.pv` | (d') C5 condition 3: compromise also reveals B's signature key | next-epoch secret learned (attack) |
| `forward_secrecy_chain.pv` | (e) C4 inside one sender chain: compromise after two messages were decrypted | first two messages secret; third (not yet decrypted) learned |
| `franking.pv` | (h) Reports (PROTOCOL.md 8.5). A verified report against an honest account names exactly a group and payload that account franked: no framing, no altered text, no moved message, even when the reporter holds its own accounts and receives every franked message; the server key stays secret | 2 x true; reachability: an honest account's message is verified |
| `franking_tag_without_account.pv` | negative control: the server tag does not bind the account | framing found (attack) |
| `device_link.pv` | (i) Device linking (PROTOCOL.md 8.11). A new device that accepts account data got exactly what the account's existing device sent it; the existing device authorises only a new device that confirmed the same transcript; the server adds a device only with both; the account data stays secret; the existing device adds to groups only the key packages the new device committed to. The relay controls the network and can grind the six-digit code over any input it still chooses | 5 x true; reachability: a link completes |
| `device_link_no_code.pv` | negative control: the person confirms on both devices without comparing the codes (QR code alone) | the relay gives the new device data of its choice (attack) |
| `device_link_kp_uncommitted.pv` | negative control: the commitment covers the nonce only (invitation version 1, before F-020); the relay reorders the key packages toward the existing device until the codes match | the relay gives the new device data of its choice (attack) |
| `device_link_reveal_first.pv` | negative control: the new device reveals before the offer arrives; the relay grinds the offer toward the new device | the relay gives the new device data of its choice (attack) |

### Output summary (ProVerif 2.05, 2026-10-01)

```
== commit_ordering.pv
RESULT event(Merged(a,s,c1)) && event(Merged(b,s,c2)) ==> c1 = c2 is true.
RESULT event(Merged(a,s,x)) ==> event(Accepted(s,x)) is true.
RESULT not event(Reach3(a)) is false.
== commit_ordering_merge_early.pv
RESULT event(Merged(a,s,c1)) && event(Merged(b,s,c2)) ==> c1 = c2 is false.
== envelope_seal.pv
RESULT event(Accepted(g_1,es_5,m_4)) ==> event(Sealed(g_1,es_5,m_4)) || event(Leaked(g_1,es_5)) is true.
RESULT event(ConsumeKey(g_1,es_5,m_4)) ==> event(Sealed(g_1,es_5,m_4)) || event(Leaked(g_1,es_5)) is true.
RESULT not event(AcceptedHonest(g_1,es_5,m_4)) is false.
RESULT event(HonestEpoch(g_1,es_5)) && attacker(exporter(es_5,envlabel,g_1)) ==> event(Leaked(g_1,es_5)) is true.
== envelope_seal_check_after_mls.pv
RESULT ... ConsumeKey ... is false.          (other queries as in envelope_seal.pv)
== forward_secrecy_chain.pv
RESULT not attacker(m0[]) is true.
RESULT not attacker(m1[]) is true.
RESULT not attacker(m2[]) is false.
== pcs.pv
RESULT not attacker(secretOther[]) is false.
RESULT not attacker(secretOwn[]) is true.
RESULT not attacker(secretOwnNext[]) is true.
RESULT not event(ReachA3) is false.
== pcs_signing_key_leaked.pv
RESULT not attacker(secretOwnNext[]) is false.  (others as in pcs.pv)
== franking.pv
RESULT event(Verified(a,g,p)) ==> event(Franked(a,g,p)) || event(AttackerAccount(a)) is true.
RESULT not attacker(ks[]) is true.
RESULT not event(VerifiedHonest(a)) is false.
== franking_tag_without_account.pv
RESULT event(Verified(a,g,p)) ==> ... is false.  (others as in franking.pv)
== device_link.pv
RESULT event(NLinked(kN,a,d)) ==> event(ESent(a,kN,d)) is true.
RESULT event(EAuthorised(a,kN,t)) ==> event(NConfirmed(kN,t)) is true.
RESULT event(DeviceAdded(a,kN)) ==> event(EAuthorised(a,kN,t)) && event(NConfirmed(kN,t)) is true.
RESULT not attacker(accountData[]) is true.
RESULT event(EAddsKeyPackages(kN,k)) ==> event(NCommitted(kN,k)) is true.
RESULT not event(NLinkedHonest) is false.
== device_link_kp_uncommitted.pv, device_link_no_code.pv, device_link_reveal_first.pv
RESULT event(NLinked(kN,a,d)) ==> event(ESent(a,kN,d)) is false.  (others as in device_link.pv)
== removal_secrecy.pv
RESULT not attacker(pre[]) is false.
RESULT not attacker(secretA1[]) is true.
RESULT not attacker(secretB1[]) is true.
RESULT not attacker(secretA2[]) is true.
RESULT not attacker(secretB2[]) is true.
RESULT not event(ReachA2) is false.
RESULT not event(ReachB2) is false.
== removal_secrecy_send_in_past_epoch.pv
RESULT not attacker(secretB1[]) is false.       (others as in removal_secrecy.pv)
```

The exact expected output is `expected_results.txt`.

## What is abstracted

Common to all models:

- **Symbolic (Dolev-Yao) model.** Cryptographic primitives are perfect:
  HMAC, hashes, KDFs and the MLS exporter are one-way free functions;
  encryption and signatures can only be undone with the right key. Nothing
  is said about computational security, key lengths, side channels or
  implementation bugs. The computational assumptions are listed in
  PROTOCOL.md section 9.2.
- **MLS is not modelled.** Where MLS matters it is replaced by its intended
  effect: an epoch secret is a fresh name known only to that epoch's members
  (`envelope_seal.pv`); epoch secrets form a one-way chain
  `e' = kdf(e, commit_secret)`, and TreeKEM is "the commit secret encrypted to
  each remaining member's current public key" (`removal_secrecy.pv`,
  `pcs.pv`); the tree structure, blank nodes, parent hashes, confirmation and
  membership tags, sender-data encryption and PrivateMessage framing are not
  modelled.
- **Byte formats** are tuples. The real envelope `0x01 || 32-byte tag ||
  body` is injective because version and tag length are fixed.

Per model:

- `envelope_seal.pv`: unbounded groups and epochs; the attacker chooses group
  ids and is a member (knows the epoch secret) of some epochs. Honest members
  act as a sealing oracle for **attacker-chosen** content, which is stronger
  than reality. Replay is not excluded by the seal and is not modelled (MLS
  rejects replays), so the properties are non-injective.
- `commit_ordering.pv`: one group, **three consecutive epochs** (the server is
  unrolled per epoch), unbounded members. The client-server TLS channel is
  abstracted as a server signature over (state, accepted commit). The server
  is **honest**. "First commit wins" is expressed by a non-replicated server
  process per epoch whose input is `[precise]` (receives exactly one value).
  Unbounded epochs are not modelled because ProVerif's abstraction cannot
  express a slot that is consumed once by a replicated process. The
  eligibility rule of PROTOCOL.md 7.4 (denial of service) is not modelled;
  the property is agreement, not liveness.
- `removal_secrecy.pv`: three members, fixed roles (A removes R, B refreshes
  later), unbounded messages per epoch. Ordering is assumed (A's removal is
  the merged commit).
- `device_link.pv`: one honest account with one existing device, unbounded
  link sessions in parallel; the attacker is the relay and may run devices
  of its own. The QR code is an authentic channel that the attacker reads;
  the person comparing the codes is an authentic channel to both screens
  that lets each continue, with the value it showed, only if both codes
  are equal. The code is a function of the transcript hash with two
  grinding equations: a relay that knows every other input of a transcript
  can pick the key-package list (toward the existing device) or a free
  offer field (toward the new device) so that the code hits any target.
  This captures the commit-then-reveal order (the negative controls find
  the attack when the key packages are not committed or the reveal comes
  first); the 10^-6 chance of equal codes by luck is not modelled. The new
  device's input of the offer is `[precise]` (one execution), without which
  ProVerif cannot separate a session's nonce from a second offer to the
  same session. Key packages are one value naming the device's signature
  key; their MLS checks are in the Rust code. HPKE Auth mode is an ideal
  authenticated public-key encryption. Phishing (the person confirms on
  purpose for an attacker's device) is outside the model.
- `pcs.pv`: two members, one compromise; the two continuations from epoch 1
  (A refreshes / B refreshes) are independent branches of the same model.
  A's input in epoch 2 is `[precise]` (one execution), which ProVerif needs to
  terminate on the signature-key variant.
- `forward_secrecy_chain.pv`: one sender chain of three messages, no tree, no
  out-of-order window, no past epochs.

## What is proven, and what is not

Proven (in the symbolic model, under the abstractions above):

- the seal blocks forged and modified input from non-members before MLS
  consumes keys, in every epoch the attacker is not a member of;
- with an honest first-commit-wins server and clients that merge only
  accepted commits, members agree on each epoch's commit (three epochs);
- a removed member learns nothing from later epochs, if nobody sends in the
  old epoch;
- a compromised member's own refresh heals its decryption-state compromise;
  another member's refresh does not;
- within one sender chain, already-decrypted messages stay secret after a
  state compromise.

Not proven:

- anything about MLS itself (relied on through published analyses), the
  hybrid KEM, the libraries or the Rust implementation;
- commit agreement against a malicious server (it can fork; this is a known
  non-claim), and agreement for more than three epochs;
- liveness and denial of service (the server or a member can always stop
  progress);
- confidentiality and authentication of application messages in general
  (claims C2, C3), downgrade resistance (C7), server request
  authentication (C10);
- recovery and local storage.

The attack-scenario tests in `crates/tree-core/tests` exercise the reference
implementation against many of the same scenarios. Tests and these models
complement each other; neither is a proof of the implementation's security.
