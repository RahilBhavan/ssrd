"""Seed list import (SPEC R5): Bank of Russia blacklist, KCDA seized domains, manual lists.

Seeds are "listed by <source>": indicators, not adjudications.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

from . import config, db, names

CBR_URL = "https://www.cbr.ru/inside/warning-list/black-list-json"
SOCIAL = {
    "t.me",
    "telegram.me",
    "vk.com",
    "vk.ru",
    "ok.ru",
    "dzen.ru",
    "instagram.com",
    "youtube.com",
    "facebook.com",
    "fb.com",
    "twitter.com",
    "x.com",
    "tiktok.com",
    "wa.me",
    "whatsapp.com",
    "rutube.ru",
    "yandex.ru",
    "google.com",
    "linkedin.com",
    "pinterest.com",
    "taplink.cc",
    "play.google.com",
    "apps.apple.com",
    "github.com",
    "medium.com",
    "teletype.in",
    "tgstat.ru",
}
INCLUDE_SIGNS = ("пирамид", "ценных бумаг", "инвестиц", "инвестиционной платформы")


def split_sites(field: str) -> list[str]:
    out = []
    for raw in re.split(r"[,;\s]+", field or ""):
        raw = re.sub(r"^[a-z]+://", "", raw.strip().lower()).split("/")[0].split("?")[0]
        if not raw or raw.startswith("@"):
            continue
        reg = names.registrable(raw)
        if reg and reg not in SOCIAL and raw not in SOCIAL:
            out.append(reg)
    return sorted(set(out))


def download_cbr(dest: Path | None = None) -> Path:
    dest = dest or Path(config.load()["paths"]["data_dir"]) / "raw" / "cbr_blacklist.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = httpx.get(CBR_URL, timeout=120, headers={"User-Agent": "ssrd-research/0.1"})
    r.raise_for_status()
    dest.write_bytes(r.content)
    return dest


def parse_cbr(path: Path, since: str = "2025-07-01") -> list[dict]:
    items = json.loads(Path(path).read_text())["RC"]
    out = []
    for it in items:
        if (it.get("DT") or "") < since or not it.get("Site"):
            continue
        sign = (it.get("Sign") or "").lower()
        if not any(s in sign for s in INCLUDE_SIGNS):
            continue
        for dom in split_sites(it["Site"]):
            out.append(
                {
                    "domain": dom,
                    "source": "cbr",
                    "listed_at": it["DT"],
                    "name": it.get("Name"),
                    "note": f"cbr:{it.get('Id')} {it.get('Sign')}",
                }
            )
    return out


def upsert(conn, seeds: list[dict]) -> int:
    before = conn.total_changes
    conn.executemany(
        "INSERT OR IGNORE INTO seeds(domain,source,listed_at,name,note) VALUES(:domain,:source,:listed_at,:name,:note)",
        seeds,
    )
    conn.commit()
    return conn.total_changes - before


def enqueue_refresh(conn, source: str, limit: int, priority: int = -10) -> int:
    """Queue seed domains for a guarded live visit (raw HTML, favicon, assets for the kit library).

    Low priority: the fetcher only reaches them when the CT queue is empty. Seed visits never
    expire, are stored as source='seedlive', and are never scored or reviewed.
    """
    rows = conn.execute(
        "SELECT DISTINCT domain FROM seeds WHERE source=? AND domain NOT IN (SELECT domain FROM candidates) "
        "ORDER BY listed_at DESC LIMIT ?",
        (source, limit),
    ).fetchall()
    for (dom,) in rows:
        conn.execute(
            "INSERT OR IGNORE INTO candidates(domain,first_seen,ct_ts,log_url,names,keywords,priority,origin) "
            "VALUES(?,?,NULL,'seed','[]','[]',?,'seed')",
            (dom, db.now(), priority),
        )
        conn.execute("INSERT OR IGNORE INTO visits(domain,attempt,due_at) VALUES(?,1,?)", (dom, db.now()))
        conn.commit()
    return len(rows)


def import_manual(conn, path: Path, source: str) -> int:
    """One domain per line; '#' comments allowed."""
    seeds = []
    for line in Path(path).read_text().splitlines():
        line = line.split("#")[0].strip()
        for dom in split_sites(line):
            seeds.append({"domain": dom, "source": source, "listed_at": None, "name": None, "note": str(path)})
    return upsert(conn, seeds)
