#!/usr/bin/env python3
"""Public-text check: fails if public files name other messengers or companies.

The blocked names are stored only as SHA-256 prefixes, so this public file does
not spell them out. Words are compared case-insensitively, except entries in
CASED, which are ordinary English words and only count when capitalized.

  python3 .claude/skills/tree-deploy/scripts/check_public_text.py
"""
import hashlib, pathlib, re, sys

LOWER = {
    "3f40462915a3e602", "ec8202b6f9fb16f9", "30cd4a85fc09f695", "699a5e2f3f410152",
    "e1ba4807a15d8579", "570f73605251d439", "8c4bc1c232019873", "8c9101702979738b",
    "2a82e52f9257715a", "998ba664f4d67e09", "a649dab5b07b1005", "2c38fed6649ab2bb",
}
CASED = {"d041924c15885af6"}  # a common English word; blocked only when capitalized

ROOT = pathlib.Path(__file__).resolve().parents[4]
PUBLIC = ["README.md", "SECURITY.md", "CLAUDE.md", "THIRD_PARTY_LICENSES.md", "docs", ".claude", "crates"]
SKIP_DIRS = {"target", ".git"}
EXT = {".md", ".rs", ".toml", ".py", ".txt", ".kt", ".swift", ".ts"}


def h(word: str) -> str:
    return hashlib.sha256(word.encode()).hexdigest()[:16]


def files():
    for entry in PUBLIC:
        p = ROOT / entry
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix in EXT and not SKIP_DIRS & set(f.parts):
                    yield f


hits = []
for f in files():
    for n, line in enumerate(f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        for w in re.findall(r"[A-Za-z]+", line):
            if h(w.lower()) in LOWER or (w[0].isupper() and h(w.lower()) in CASED):
                hits.append(f"{f.relative_to(ROOT)}:{n}: {w}")

if hits:
    print("Public text names another company or messenger:")
    print("\n".join(hits))
    sys.exit(1)
print("public-text check: ok")
