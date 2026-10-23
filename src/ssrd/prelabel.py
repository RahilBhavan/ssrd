"""Rule-based assistant suggestions for alerting pages (config [prelabel]).

Writes only under [review].assist_reviewer, never overwrites an existing suggestion, and never
touches human labels. Pages no rule matches are left for a human (or the daily assistant run).
"""

from __future__ import annotations

import json
import re
from functools import cache

from . import config, db, review


@cache
def _rules() -> list[dict]:
    out = []
    for r in config.load().get("prelabel", {}).get("rules", []):
        out.append({**r, **{k: re.compile(r[k]) for k in ("title", "text", "kit") if k in r}})
    return out


def match(features: dict, text: str, kit: str | None) -> dict | None:
    for r in _rules():
        if "title" in r and not r["title"].search(features.get("title") or ""):
            continue
        if "text" in r and not r["text"].search(text):
            continue
        if "kit" in r and not r["kit"].search(kit or ""):
            continue
        if features.get("invest_terms", 0) < r.get("min_invest_terms", 0):
            continue
        return r
    return None


def apply(conn, page_id: int) -> str | None:
    """Suggest a label for one alerting page; returns the label written, if any."""
    assist = config.load()["review"]["assist_reviewer"]
    if conn.execute("SELECT 1 FROM labels WHERE page_id=? AND reviewer=?", (page_id, assist)).fetchone():
        return None
    row = conn.execute(
        "SELECT p.features, a.kit_name FROM pages p JOIN alert_log a ON a.page_id=p.id WHERE p.id=?", (page_id,)
    ).fetchone()
    if row is None:
        return None
    f = json.loads(row["features"])
    rule = match(f, review.body_text(f), row["kit_name"])
    if rule is None:
        return None
    with db.tx(conn, "prelabel"):
        conn.execute(
            "INSERT OR IGNORE INTO labels(page_id,reviewer,label,note,labeled_at) VALUES(?,?,?,?,?)",
            (page_id, assist, rule["label"], rule["note"], db.now()),
        )
    return rule["label"]


def run(conn) -> dict:
    """Backfill: suggest labels for every alerting page that has none yet."""
    assist = config.load()["review"]["assist_reviewer"]
    counts: dict[str, int] = {}
    for (pid,) in conn.execute(
        "SELECT page_id FROM alert_log a WHERE NOT EXISTS"
        "(SELECT 1 FROM labels l WHERE l.page_id=a.page_id AND l.reviewer=?)",
        (assist,),
    ).fetchall():
        lab = apply(conn, pid)
        counts[lab or "left for review"] = counts.get(lab or "left for review", 0) + 1
    return counts
