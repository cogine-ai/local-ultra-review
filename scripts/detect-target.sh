#!/usr/bin/env bash
set -u

if ! command -v python3 >/dev/null 2>&1; then
  printf '{"ok":false,"error":"python3 is required"}\n'
  exit 2
fi

python3 - "$@" <<'PY'
import json
import re
import subprocess
import sys


def run(args):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def git_ok(ref):
    return run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"]).returncode == 0


def default_base():
    proc = run(["git", "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"])
    refs = []
    if proc.returncode == 0 and proc.stdout.strip():
        refs.append(proc.stdout.strip())
    refs.extend(["origin/main", "origin/master", "main", "master"])
    seen = set()
    for ref in refs:
        if ref in seen:
            continue
        seen.add(ref)
        if git_ok(ref):
            return ref
    return ""


args = sys.argv[1:]
mode = "deep"
base = None
target = None
target_type = None
include_uncommitted = True
include_untracked = False
errors = []

i = 0
while i < len(args):
    arg = args[i]
    if arg == "--mode" and i + 1 < len(args):
        mode = args[i + 1]
        i += 2
    elif arg.startswith("--mode="):
        mode = arg.split("=", 1)[1]
        i += 1
    elif arg == "--base" and i + 1 < len(args):
        base = args[i + 1]
        i += 2
    elif arg.startswith("--base="):
        base = arg.split("=", 1)[1]
        i += 1
    elif arg == "--include-untracked":
        include_untracked = True
        i += 1
    elif arg == "--no-uncommitted":
        include_uncommitted = False
        i += 1
    elif arg == "pr" and i + 1 < len(args):
        target_type = "pr"
        target = args[i + 1]
        include_uncommitted = False
        i += 2
    elif re.fullmatch(r"#?\d+", arg):
        target_type = "pr"
        target = arg.lstrip("#")
        include_uncommitted = False
        i += 1
    elif "github.com/" in arg and "/pull/" in arg:
        target_type = "pr"
        target = arg.rstrip("/").split("/")[-1]
        include_uncommitted = False
        i += 1
    elif ".." in arg:
        target_type = "range"
        target = arg
        include_uncommitted = False
        i += 1
    else:
        target_type = "base"
        base = arg
        target = arg
        i += 1

if mode not in {"light", "deep", "max"}:
    errors.append(f"unsupported mode: {mode}")

if target_type is None:
    target_type = "working_tree"
    base = base or default_base()
elif target_type == "base":
    base = base or target
elif target_type == "range":
    parts = re.split(r"\.{2,3}", target, maxsplit=1)
    if len(parts) == 2:
        base = parts[0]

head_proc = run(["git", "rev-parse", "--short", "HEAD"])
branch_proc = run(["git", "branch", "--show-current"])

result = {
    "ok": not errors,
    "target_type": target_type,
    "target": target or "",
    "base": base or "",
    "head": head_proc.stdout.strip() if head_proc.returncode == 0 else "",
    "branch": branch_proc.stdout.strip() if branch_proc.returncode == 0 else "",
    "mode": mode,
    "include_uncommitted": include_uncommitted,
    "include_untracked": include_untracked,
    "errors": errors,
}

if result["base"]:
    result["base_exists"] = git_ok(result["base"])
else:
    result["base_exists"] = False

print(json.dumps(result, indent=2, sort_keys=True))
sys.exit(0 if result["ok"] else 2)
PY

