---
name: tree-deploy
description: Push a branch, open and merge pull requests on moneyally/tree with the session's own GitHub access, and (later) deploy the server. Use whenever work on Tree needs to reach GitHub.
---

# Tree: push, PR, merge

GitHub access comes from this session itself. Never ask the owner for keys or tokens.

## Steps

1. **Branch.** Never commit straight to `main`. Use `claude/<short-topic>`.
2. **Check before pushing.**
   - `cargo test -p tree-core` must pass.
   - `cargo run -p tree-core --example demo` must run.
   - Public text (README, docs, code, commit messages) must not name other companies or messengers:
     `python3 .claude/skills/tree-deploy/scripts/check_public_text.py`
     (names are stored as hashes, so do not write them out anywhere in the repo)
3. **Push.** `git push -u origin <branch>` (the session proxy authenticates).
4. **Open the PR.**
   `python3 .claude/skills/tree-deploy/scripts/pr.py create --title "..." --body-file <file>`
   Body: Korean, short. End with the attribution lines the session asks for.
5. **Check.** `python3 .claude/skills/tree-deploy/scripts/pr.py status <number>`
6. **Merge** once checks are green (or there are none and the local checks in step 2 passed):
   `python3 .claude/skills/tree-deploy/scripts/pr.py merge <number>`
7. `git checkout main && git pull --ff-only origin main`

## If something fails

- **Repository not visible / push rejected:** attach it with the `add_repo` tool
  (owner `moneyally`, repo `tree`, access `push`), then retry once.
- **API answers 415:** the request needs `Content-Type: application/json` (pr.py already sends it).
- **GH_TOKEN missing:** say so plainly. Do not ask for a token.
- **Shallow clone cannot see the branch on the remote:**
  `git config --add remote.origin.fetch '+refs/heads/<branch>:refs/remotes/origin/<branch>' && git fetch origin`

## Deploy (not active yet)

Tree has no server yet, so merging to `main` deploys nothing. When the server exists it
will run on the owner's Hetzner machine; the deploy steps will be added here then.
