#!/usr/bin/env bash
# Publish the current HEAD tree to the public repo (github.com/RahilBhavan/ssrd) as one new commit.
# Never pushes this repo's history (commit 95356d0 names seed domains). Runs the privacy scan on
# every published file first and aborts on any hit.
#   scripts/publish.sh "readme: final results"
set -euo pipefail
msg=${1:?commit message}
root=$(git rev-parse --show-toplevel)
pub=${SSRD_PUBLIC_DIR:-$HOME/scratch/ssrd-public}
[ -d "$pub/.git" ] || git clone -q https://github.com/RahilBhavan/ssrd.git "$pub"
git -C "$pub" pull -q --ff-only
find "$pub" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
git -C "$root" archive HEAD | tar -x -C "$pub"
# Home-network identifiers were scrubbed from the public history on 2026-10-25; never republish them.
# Patterns live in the git-ignored config/publish-deny.txt (one extended regex per line).
deny="$root/config/publish-deny.txt"
[ -s "$deny" ] || { echo "missing $deny, not publishing" >&2; exit 1; }
if grep -rIlE -f "$deny" "$pub" --exclude-dir=.git; then
  echo "home-network identifiers found in the files above, not publishing" >&2
  exit 1
fi
(cd "$root" && uv run python - "$pub" <<'EOF'
import os, subprocess, sys
sys.path.insert(0, "scripts")
import privacy_check as pc
pub = sys.argv[1]
priv = pc.private_domains()
subprocess.run(["git", "add", "-A"], cwd=pub, check=True)
files = subprocess.run(["git", "ls-files"], cwd=pub, capture_output=True, text=True, check=True).stdout.split()
bad = [f for f in files if f.startswith("data/") or
       {t.lower() for t in pc.TOKEN.findall(open(os.path.join(pub, f), errors="ignore").read().replace("[.]", "."))} & priv]
if bad:
    sys.exit(f"privacy scan failed, not publishing: {bad}")
EOF
)
git -C "$pub" commit -qm "$msg" && git -C "$pub" push -q && echo "published: $msg"
