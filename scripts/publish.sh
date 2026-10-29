#!/usr/bin/env bash
# Export only the checked HEAD tree; local history contains private source names.
# Default preserves the established publication command. --branch prepares a PR.
set -euo pipefail
msg=${1:?commit message}
shift
branch=""
if [ "$#" -gt 0 ]; then
  [ "$#" -eq 2 ] && [ "$1" = --branch ] || { echo 'usage: publish.sh MESSAGE [--branch NAME]' >&2; exit 1; }
  branch=$2
  git check-ref-format --branch "$branch" >/dev/null
  [ "$branch" != main ] || { echo 'PR branch must differ from main' >&2; exit 1; }
fi
root=$(git rev-parse --show-toplevel)
pub=${SSRD_PUBLIC_DIR:-$HOME/scratch/ssrd-public}
[ "$pub" != "$root" ] || { echo 'public checkout must be separate' >&2; exit 1; }
if [ ! -d "$pub/.git" ]; then
  [ ! -e "$pub" ] || { echo 'public checkout path already exists without git' >&2; exit 1; }
  git clone -q https://github.com/RahilBhavan/ssrd.git "$pub"
fi
[ -z "$(git -C "$pub" status --porcelain)" ] || { echo 'public checkout is dirty; refusing to replace files' >&2; exit 1; }
git -C "$pub" fetch -q origin
if [ -n "$branch" ]; then
  # A fresh branch means another actor's branch is never overwritten.
  if git -C "$pub" show-ref --verify --quiet "refs/remotes/origin/$branch"; then
    echo 'remote branch already exists; reconcile it explicitly' >&2; exit 1
  fi
  git -C "$pub" switch -q -c "$branch" origin/main
else
  git -C "$pub" pull -q --ff-only
fi
find "$pub" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
git -C "$root" archive HEAD | tar -x -C "$pub"
deny="$root/config/publish-deny.txt"
[ -s "$deny" ] || { echo 'missing local deny patterns; not publishing' >&2; exit 1; }
if grep -rIlE -f "$deny" "$pub" --exclude-dir=.git; then
  echo 'private identifiers found in the files above; not publishing' >&2
  exit 1
fi
(cd "$root" && uv run python - "$pub" <<'PY'
import os, subprocess, sys
sys.path.insert(0, "scripts")
import privacy_check as pc
pub = sys.argv[1]
priv = pc.private_domains()
subprocess.run(["git", "add", "-A"], cwd=pub, check=True)
files = subprocess.run(["git", "ls-files", "-z"], cwd=pub, capture_output=True, text=True, check=True).stdout.split("\0")
bad = [f for f in files if f and (f.startswith("data/") or
       {t.lower() for t in pc.TOKEN.findall(open(os.path.join(pub, f), errors="ignore").read().replace("[.]", "."))} & priv)]
if bad:
    sys.exit(f"privacy scan failed, not publishing: {bad}")
PY
)
git -C "$pub" commit -qm "$msg"
if [ -n "$branch" ]; then
  git -C "$pub" push -qu origin "$branch"
else
  git -C "$pub" push -q
fi
echo "published: $msg"
