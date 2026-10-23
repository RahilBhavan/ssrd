"""Per-recipient lead exports for regulators (`ssrd export`).

Only pages a human reviewer labeled scam-kit are exported; assistant suggestions never are.
Domains are defanged. Files are written 0600 under data/drafts/reports/ and are private until
Rahil sends them.
"""

from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from . import config, names

FIELDS = ["domain", "first_alert_utc", "kit", "lang", "title", "capture_sha256"]


def _utc(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M")


def routes(lang: str) -> list[str]:
    cfg = config.load()["export"]
    out = list(cfg["always"])
    for prefix, recipients in cfg["by_lang"].items():
        if lang == prefix or lang.startswith(prefix + "-"):
            out += recipients
    return out


def reports(conn, reviewer: str) -> dict[str, list[dict]]:
    if reviewer == config.load()["review"]["assist_reviewer"]:
        raise ValueError("assistant suggestions are never exported")
    out: dict[str, list[dict]] = defaultdict(list)
    for r in conn.execute(
        "SELECT a.first_alert_at, a.kit_name, p.domain, p.features FROM alert_log a "
        "JOIN pages p ON p.id=a.page_id JOIN labels l ON l.page_id=p.id "
        "WHERE l.reviewer=? AND l.label='scam-kit' ORDER BY a.first_alert_at",
        (reviewer,),
    ):
        f = json.loads(r["features"])
        lang = (f.get("lang") or "").lower()
        row = {
            "domain": names.defang(r["domain"]),
            "first_alert_utc": _utc(r["first_alert_at"]),
            "kit": r["kit_name"],
            "lang": lang,
            "title": (f.get("title") or "")[:100],
            "capture_sha256": f.get("body_sha256", ""),
        }
        for recipient in routes(lang):
            out[recipient].append(row)
    return out


def write(conn, reviewer: str) -> list[tuple[Path, int]]:
    folder = Path(config.load()["paths"]["data_dir"]) / "drafts" / "reports"
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    written = []
    for recipient, rows in sorted(reports(conn, reviewer).items()):
        path = folder / f"{recipient}.csv"
        with open(path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(rows)
        os.chmod(path, 0o600)
        written.append((path, len(rows)))
    return written
