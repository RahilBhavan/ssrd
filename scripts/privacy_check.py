"""Block commits/pushes that contain private domains (CLAUDE.md "Data handling").

Compares every domain-like token in the staged diff (pre-commit) or in the commits being pushed
(pre-push) against domains in data/ssrd.sqlite: seeds, harvested and live pages. Exits 1 on a hit.

    uv run python scripts/privacy_check.py --staged
    uv run python scripts/privacy_check.py --range origin/main..HEAD
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])", re.I)
# Public infrastructure that legitimately appears in code and docs.
ALLOW = {"urlscan.io", "web.archive.org", "archive.org", "brooklynda.org", "cbr.ru", "github.com", "cloudflare.com",
         "google.com", "googleusercontent.com", "x.com", "example.com", "example.test", "dfpi.ca.gov",
         "t.me", "wa.me"}


def private_domains() -> set[str]:
    db = ROOT / "data" / "ssrd.sqlite"
    if not db.exists():
        return set()
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    out = {r[0].lower() for r in conn.execute("SELECT domain FROM seeds UNION SELECT domain FROM pages "
                                              "WHERE source IN ('urlscan','wayback','seedlive','live')")}
    return out - ALLOW


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def main() -> int:
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--staged", action="store_true")
    g.add_argument("--range")
    a = p.parse_args()
    text = git("diff", "--cached", "-U0") if a.staged else git("log", "-p", a.range)
    added = "\n".join(line for line in text.splitlines() if line.startswith("+") or not a.staged)
    hits = sorted({t.lower() for t in TOKEN.findall(added)} & private_domains())
    if hits:
        print(f"privacy check: {len(hits)} private domain(s) would be committed/pushed, e.g. "
              f"{', '.join(h[:3] + '…' for h in hits[:5])}. Remove them (see CLAUDE.md Data handling).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
