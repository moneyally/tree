#!/usr/bin/env python3
"""Pull request helper for the Tree repository.

Uses the session's GH_TOKEN (a placeholder the session proxy swaps for a real
token). Never print, store or ask the owner for a token.

  pr.py create --title "..." [--body-file FILE] [--base main]   # from current branch
  pr.py status [NUMBER]                                         # state, mergeable, checks
  pr.py merge NUMBER [--method squash|merge|rebase]
  pr.py list
"""
import argparse, json, os, subprocess, sys, urllib.error, urllib.request

REPO = "moneyally/tree"
API = f"https://api.github.com/repos/{REPO}"


def call(method, path, payload=None):
    token = os.environ.get("GH_TOKEN")
    if not token:
        sys.exit("GH_TOKEN is not set in this session. Read docs on GitHub access; do not ask the owner for a token.")
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",  # required, or the proxy answers 415
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            data = r.read()
            return json.loads(data) if data else {}
    except urllib.error.HTTPError as e:
        sys.exit(f"GitHub API {e.code}: {e.read().decode()[:500]}")


def current_branch():
    return subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()


def cmd_create(a):
    head = current_branch()
    if head == a.base:
        sys.exit(f"You are on {a.base}. Create a branch first.")
    body = open(a.body_file, encoding="utf-8").read() if a.body_file else ""
    r = call("POST", "/pulls", {"title": a.title, "head": head, "base": a.base, "body": body})
    print(r["number"], r["html_url"])


def cmd_status(a):
    if a.number is None:
        prs = call("GET", f"/pulls?head={REPO.split('/')[0]}:{current_branch()}&state=open")
        if not prs:
            sys.exit("No open PR for this branch.")
        a.number = prs[0]["number"]
    pr = call("GET", f"/pulls/{a.number}")
    print(f"#{pr['number']} {pr['state']} merged={pr['merged']} mergeable={pr.get('mergeable')} "
          f"state={pr.get('mergeable_state')}  {pr['html_url']}")
    checks = call("GET", f"/commits/{pr['head']['sha']}/check-runs").get("check_runs", [])
    for c in checks:
        print(f"  check {c['name']}: {c['status']} {c.get('conclusion')}")
    if not checks:
        print("  (no CI checks configured)")


def cmd_merge(a):
    r = call("PUT", f"/pulls/{a.number}/merge", {"merge_method": a.method})
    print("merged" if r.get("merged") else r, r.get("sha", ""))


def cmd_list(_):
    for pr in call("GET", "/pulls?state=open"):
        print(f"#{pr['number']} {pr['head']['ref']} -> {pr['base']['ref']}  {pr['title']}")


p = argparse.ArgumentParser()
s = p.add_subparsers(dest="cmd", required=True)
c = s.add_parser("create"); c.add_argument("--title", required=True); c.add_argument("--body-file"); c.add_argument("--base", default="main"); c.set_defaults(f=cmd_create)
c = s.add_parser("status"); c.add_argument("number", nargs="?", type=int); c.set_defaults(f=cmd_status)
c = s.add_parser("merge"); c.add_argument("number", type=int); c.add_argument("--method", default="squash", choices=["squash", "merge", "rebase"]); c.set_defaults(f=cmd_merge)
c = s.add_parser("list"); c.set_defaults(f=cmd_list)
a = p.parse_args()
a.f(a)
