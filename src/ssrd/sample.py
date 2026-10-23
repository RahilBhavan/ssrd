"""Frozen random samples of alerts (SPEC R8a).

Precision is estimated from a uniform random sample of the alerts in a window, so a reviewer labels
a fixed n instead of every alert. A sample is drawn once and never redrawn: its members and
population size are stored, which keeps the estimate honest and lets two labelers see the same pages.
"""

from __future__ import annotations

import random

from . import db


class SampleExists(Exception):
    pass


def draw(conn, name: str, n: int, since: int, until: int, seed: int) -> dict:
    if conn.execute("SELECT 1 FROM samples WHERE name=?", (name,)).fetchone():
        raise SampleExists(f"sample {name!r} already drawn; samples are never redrawn")
    pop = [
        r[0]
        for r in conn.execute(
            "SELECT page_id FROM alert_log WHERE first_alert_at>=? AND first_alert_at<? ORDER BY page_id",
            (since, until),
        )
    ]
    chosen = random.Random(seed).sample(pop, min(n, len(pop)))
    with db.tx(conn, "sample"):
        conn.execute(
            "INSERT INTO samples(name,since,until,seed,population,drawn_at) VALUES(?,?,?,?,?,?)",
            (name, since, until, seed, len(pop), db.now()),
        )
        conn.executemany(
            "INSERT INTO sample_members(name,page_id,position) VALUES(?,?,?)",
            [(name, pid, i) for i, pid in enumerate(chosen)],
        )
    return {"name": name, "population": len(pop), "drawn": len(chosen)}


def info(conn, name: str) -> dict | None:
    r = conn.execute("SELECT * FROM samples WHERE name=?", (name,)).fetchone()
    return dict(r) if r else None


def members(conn, name: str) -> list[int]:
    return [r[0] for r in conn.execute("SELECT page_id FROM sample_members WHERE name=? ORDER BY position", (name,))]
