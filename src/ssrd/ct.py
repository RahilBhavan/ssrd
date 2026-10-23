"""Static-CT names-tile tailer (SPEC R1).

Reads the compact JSONL `tile/names/<N>` tiles that Sunlight-based logs serve, instead of
running certstream-server-go. Only full tiles (256 entries) are read, so worst-case added
latency is one tile-fill time (about 10 s on a Let's Encrypt log). Position is saved per log
in SQLite so the tailer resumes after the box sleeps; it never backfills further back than
where it first started.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import zlib

import httpx

from . import config, db, names
from .metrics import Counters

log = logging.getLogger("ssrd.ct")
TILE_WIDTH = 256
UA = "ssrd-research/0.1 (+https://github.com/RahilBhavan; passive CT monitor)"


def tile_path(n: int) -> str:
    """tlog-tiles index encoding: 1234067 -> x001/x234/067."""
    s = f"{n:03d}"
    s = "0" * ((3 - len(s) % 3) % 3) + s
    groups = [s[i : i + 3] for i in range(0, len(s), 3)]
    return "/".join([f"x{g}" for g in groups[:-1]] + [groups[-1]])


def parse_checkpoint(text: str) -> int:
    return int(text.splitlines()[1])


def parse_names_tile(body: bytes) -> list[dict]:
    return [json.loads(line) for line in body.splitlines() if line.strip()]


class Tailer:
    def __init__(self, conn, client: httpx.Client | None = None):
        self.cfg = config.load()["ct"]
        self.conn = conn
        self.client = client or httpx.Client(timeout=30, headers={"User-Agent": UA}, http2=False)
        self.counters = Counters("ingest")
        self.seen: dict[str, None] = {}  # bounded in-memory LRU of registrable domains

    def _state(self, log_url: str) -> int | None:
        row = self.conn.execute("SELECT next_index FROM ct_state WHERE log_url=?", (log_url,)).fetchone()
        return row[0] if row else None

    def _save(self, log_url: str, idx: int) -> None:
        self.conn.execute(
            "INSERT INTO ct_state(log_url,next_index,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(log_url) DO UPDATE SET next_index=excluded.next_index, updated_at=excluded.updated_at",
            (log_url, idx, db.now()),
        )
        self.conn.commit()

    def poll_log(self, log_url: str) -> int:
        r = self.client.get(f"{log_url}/checkpoint")
        r.raise_for_status()
        size = parse_checkpoint(r.text)
        nxt = self._state(log_url)
        if nxt is None:  # start at the current head, rounded down to a tile
            nxt = (size // TILE_WIDTH) * TILE_WIDTH
            self._save(log_url, nxt)
        processed = 0
        for _ in range(self.cfg["max_tiles_per_poll"]):
            tile = nxt // TILE_WIDTH
            if (tile + 1) * TILE_WIDTH > size:
                break  # wait for the tile to fill
            resp = self.client.get(f"{log_url}/tile/names/{tile_path(tile)}")
            if resp.status_code == 429:
                log.warning("429 from %s; backing off", log_url)
                time.sleep(30)
                break
            resp.raise_for_status()
            self.counters.inc("bytes", len(resp.content))
            entries = parse_names_tile(resp.content)
            for entry in entries[nxt - tile * TILE_WIDTH :]:
                self.handle_entry(entry, log_url)
                processed += 1
            nxt = (tile + 1) * TILE_WIDTH
            self._save(log_url, nxt)
        return processed

    def handle_entry(self, entry: dict, log_url: str) -> None:
        self.counters.inc("entries")
        sans = set(entry.get("DNS") or [])
        cn = (entry.get("Subject") or {}).get("CommonName")
        if cn:
            sans.add(cn)
        by_reg: dict[str, list[str]] = {}
        for san in sans:
            reg = names.registrable(san)
            if reg:
                by_reg.setdefault(reg, []).append(san)
        ct_ts = int(entry.get("Timestamp", 0) / 1000) or None
        for reg, sample in by_reg.items():
            self.counters.inc("names")
            if reg in self.seen:
                continue
            self.seen[reg] = None
            if zlib.crc32(reg.encode()) % self.cfg["background_sample_mod"] == 0:
                self.conn.execute("INSERT OR IGNORE INTO ct_sample(domain,ct_ts) VALUES(?,?)", (reg, ct_ts))
            if len(self.seen) > 500_000:
                for k in list(self.seen)[:100_000]:
                    del self.seen[k]
            ok, matches, model_score = names.passes(reg)
            if not ok:
                continue
            self.counters.inc("filter_pass")
            tags = sorted({(m.group, m.term) for m in matches})
            if model_score is not None:
                tags.append(("model", f"{model_score:.3f}"))
            self.add_candidate(reg, ct_ts, log_url, sorted(sample)[:10], tags)

    def add_candidate(self, reg, ct_ts, log_url, sample, matches) -> bool:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO candidates(domain,first_seen,ct_ts,log_url,names,keywords,priority) VALUES(?,?,?,?,?,?,?)",
            (reg, db.now(), ct_ts, log_url, db.dumps(sample), db.dumps(matches), names.priority(reg, matches)),
        )
        if cur.rowcount:
            first = config.load()["fetch"]["delays_seconds"][0]
            self.conn.execute(
                "INSERT OR IGNORE INTO visits(domain,attempt,due_at) VALUES(?,?,?)",
                (reg, 1, (ct_ts or db.now()) + first),
            )
            self.counters.inc("candidates_new")
        self.conn.commit()
        return bool(cur.rowcount)

    def run(self, once: bool = False) -> None:
        while True:
            t0 = time.time()
            for url in self.cfg["log_urls"]:
                try:
                    n = self.poll_log(url)
                    log.debug("%s +%d", url, n)
                except (httpx.HTTPError, ValueError, sqlite3.OperationalError) as e:
                    self.counters.inc("errors")
                    log.warning("poll %s failed: %s", url, e)
                    self.conn.rollback()
            if once:
                self.counters.flush()
                return
            time.sleep(max(0.0, self.cfg["poll_seconds"] - (time.time() - t0)))


def backfill_sample(conn, log_url: str, tiles: int, client: httpx.Client | None = None) -> int:
    """One-off: read `tiles` older names tiles (below the tailer's start) and store every
    registrable name in ct_sample, as negatives for training the name classifier."""
    client = client or httpx.Client(timeout=30, headers={"User-Agent": UA})
    row = conn.execute("SELECT next_index FROM ct_state WHERE log_url=?", (log_url,)).fetchone()
    top = (row[0] if row else parse_checkpoint(client.get(f"{log_url}/checkpoint").text)) // TILE_WIDTH - 1
    added = 0
    for tile in range(top - 10_000, top - 10_000 - tiles, -1):  # ~2.5M entries back: well before our window
        r = client.get(f"{log_url}/tile/names/{tile_path(tile)}")
        if r.status_code != 200:
            continue
        for entry in parse_names_tile(r.content):
            for san in set(entry.get("DNS") or []):
                reg = names.registrable(san)
                if reg:
                    added += conn.execute(
                        "INSERT OR IGNORE INTO ct_sample(domain,ct_ts) VALUES(?,?)",
                        (reg, int(entry.get("Timestamp", 0) / 1000)),
                    ).rowcount
        conn.commit()
        time.sleep(0.2)
    return added
