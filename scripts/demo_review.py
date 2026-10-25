"""Render the review queue to docs/review-demo.svg from synthetic fixtures only (no real data).

uv run python scripts/demo_review.py
"""

from __future__ import annotations

import gzip
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="ssrd-demo-"))
cfg = (ROOT / "config" / "ssrd.toml").read_text()
cfg = cfg.replace('data_dir = "data"', f'data_dir = "{TMP}"').replace(
    'db = "data/ssrd.sqlite"', f'db = "{TMP}/demo.sqlite"'
)
cfg = re.sub(r"(?m)^enabled = .*$", "enabled = false", cfg)
(TMP / "ssrd.toml").write_text(cfg)
os.environ["SSRD_CONFIG"] = str(TMP / "ssrd.toml")
sys.path.insert(0, str(ROOT))

from rich.console import Console  # noqa: E402

from ssrd import db, kits, review, score  # noqa: E402
from ssrd import fingerprint as fp  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def kit_page(brand: str, wallet: str) -> bytes:
    t = (FIX / "kit_template.html").read_text()
    return t.replace("{BRAND}", brand).replace("{WALLET}", wallet).replace("{EXTRA}", "").encode()


def add(conn, source: str, domain: str, body: bytes) -> int:
    f = fp.html_features(body, f"https://{domain}/", "text/html", 200, [])
    (TMP / "captures").mkdir(exist_ok=True)
    (TMP / "captures" / f"{f['body_sha256']}.gz").write_bytes(gzip.compress(body))
    cur = conn.execute(
        "INSERT INTO pages(source,ref,domain,observed_at,page_class,features) VALUES(?,?,?,?,?,?)",
        (source, domain, domain, db.now(), f["page_class"], db.dumps(f)),
    )
    conn.commit()
    return cur.lastrowid


def main() -> None:
    conn = db.connect()
    for i in range(4):
        add(conn, "urlscan", f"example-seed{i}.test", kit_page(f"Seed{i} Capital", "0x" + f"{i:02d}" * 20))
    kits.build(conn)
    pid = add(conn, "live", "demo-newbrand.test", kit_page("Newbrand Capital", "0x" + "77" * 20))
    score.score_page(conn, pid)
    console = Console(record=True, width=110, force_terminal=True)
    rows = review.queue(conn, "demo")
    console.print(
        f"{len(rows)} pages to review as [bold]demo[/]. Keys: "
        + ", ".join(f"{k}={v}" for k, v in review.KEYS.items())
        + ", q=quit, enter=skip"
    )
    review.show(console, conn, rows[0])
    console.print("label> s")
    out = ROOT / "docs" / "review-demo.svg"
    console.save_svg(str(out), title="ssrd review (synthetic data)")
    shutil.rmtree(TMP)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
