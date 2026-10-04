"""Two Tree devices chat through a real server via the UniFFI bindings.

Run with scripts/ffi_demo.sh (builds the library, generates the bindings,
starts a server). Proves the binding layer the apps use: sign-up,
@username lookup, a group, text both ways, a file, a safety number, a
report, an invite link and recovery.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.environ["TREE_PY_BINDINGS"])
import tree_ffi as t  # noqa: E402

URL = os.environ["TREE_URL"]
BITS = 12
d = tempfile.mkdtemp()


def ev(session, kind):
    """Events of one kind from a sync (kind as in TreeEvent, e.g. "text")."""
    return [e for e in session.sync(0) if getattr(e, f"is_{kind}")()]


alice = t.TreeSession.create(f"{d}/alice.db", "alice pass", "alice", URL, BITS)
bob = t.TreeSession.create(f"{d}/bob.db", "bob pass", "bob", URL, BITS)
print("accounts:", alice.account_id(), bob.account_id())

bob.set_username("bob_ffi")
found = alice.find("@bob_ffi")
assert found == bob.account_id(), found
bob.add_contact(alice.account_id())

g = alice.create_group()
commit = alice.invite(g, "@bob_ffi")
assert commit.accepted, commit
assert ev(bob, "joined"), "bob joined"
alice.sync(0)

alice.send_text(g, "hello from the Python binding")
texts = ev(bob, "text")
assert texts and texts[-1].text == "hello from the Python binding", texts
print("bob got:", texts[-1].text)
mid = bob.send_text(g, "and back")
assert ev(alice, "text")[-1].text == "and back"

f = alice.send_file(g, b"file bytes", "a.txt", "text/plain", False)
files = ev(bob, "file")
assert bob.download(files[-1].file) == b"file bytes"

a_num = alice.safety_number(bob.account_id())
b_num = bob.safety_number(alice.account_id())
assert a_num == b_num and len(a_num.replace(" ", "")) == 60, (a_num, b_num)
print("safety number:", a_num[:17], "...")

spam = alice.send_text(g, "spam")
bob.sync(0)
r = bob.report(g, [spam], "spam")
assert r.verified, r

carol = t.TreeSession.create(f"{d}/carol.db", "carol pass", "carol", URL, BITS)
link = alice.create_invite_link(g, 3600, 1)
carol.join_invite_link(link)
assert ev(alice, "invite_link_used")
assert ev(carol, "joined")
print("carol joined by link; members:", len(alice.members(g)))

phrase = alice.new_recovery_phrase(24, True, None).words
assert len(phrase.split()) == 24
alice2 = t.TreeSession.recover(f"{d}/alice2.db", "pw2", "alice", URL, phrase, True, BITS)
assert alice2.account_id() == alice.account_id()
try:
    alice.sync(0)
    raise SystemExit("old device still works")
except t.TreeError.Server as e:
    print("old device cut off:", e)

try:
    t.TreeSession.open(f"{d}/bob.db", "wrong")
    raise SystemExit("wrong passphrase opened the profile")
except t.TreeError.WrongKey:
    pass

feats = {f.key: f for f in bob.features()}
assert feats["user.key_change_warning"].locked_by.startswith("always")
print("features:", len(feats), "user settings")
print("FFI demo: all checks passed")
