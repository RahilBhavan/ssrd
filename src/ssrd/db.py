"""SQLite store. WAL mode so the ingest and fetcher processes can share one file."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS ct_state (
    log_url TEXT PRIMARY KEY,
    next_index INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS candidates (
    domain TEXT PRIMARY KEY,          -- registrable domain (eTLD+1), unicode
    first_seen INTEGER NOT NULL,      -- when we saw it
    ct_ts INTEGER,                    -- CT entry timestamp (seconds)
    log_url TEXT,
    names TEXT,                       -- JSON list of sample SANs
    keywords TEXT,                    -- JSON list of matched keyword groups/terms
    priority INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ct_sample (      -- unfiltered background sample of CT names
    domain TEXT PRIMARY KEY,
    ct_ts INTEGER
);
CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    due_at INTEGER NOT NULL,
    done_at INTEGER,
    outcome TEXT,                     -- content|parked|blank|seized|blocked|error|skipped|expired
    final_url TEXT,
    status INTEGER,
    body_sha256 TEXT,
    evidence TEXT,                    -- JSON evidence record
    UNIQUE(domain, attempt)
);
CREATE INDEX IF NOT EXISTS visits_due ON visits(done_at, due_at);
CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,             -- live|urlscan
    ref TEXT NOT NULL,                -- visit id or urlscan uuid
    domain TEXT NOT NULL,
    observed_at INTEGER,
    page_class TEXT,
    features TEXT NOT NULL,           -- JSON (see fingerprint.py)
    UNIQUE(source, ref)
);
CREATE TABLE IF NOT EXISTS seeds (
    domain TEXT NOT NULL,
    source TEXT NOT NULL,             -- cbr|kcda|dfpi|manual
    listed_at TEXT,
    name TEXT,
    note TEXT,
    PRIMARY KEY(domain, source)
);
CREATE TABLE IF NOT EXISTS kits (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    built_at INTEGER
);
CREATE TABLE IF NOT EXISTS kit_members (
    kit_id INTEGER NOT NULL,
    page_id INTEGER NOT NULL,
    PRIMARY KEY(kit_id, page_id)
);
CREATE TABLE IF NOT EXISTS scores (
    page_id INTEGER NOT NULL,
    kit_id INTEGER NOT NULL,
    score REAL NOT NULL,
    alert INTEGER NOT NULL,
    details TEXT,
    scored_at INTEGER NOT NULL,
    PRIMARY KEY(page_id, kit_id)
);
CREATE TABLE IF NOT EXISTS alert_log (     -- first time a page alerted; survives kit rebuilds
    page_id INTEGER PRIMARY KEY,
    first_alert_at INTEGER NOT NULL,
    kit_name TEXT
);
CREATE TABLE IF NOT EXISTS labels (
    page_id INTEGER NOT NULL,
    reviewer TEXT NOT NULL,
    label TEXT NOT NULL,              -- scam-kit|not-scam|decoy-cloaked|parked|error|unsure
    note TEXT,
    labeled_at INTEGER NOT NULL,
    PRIMARY KEY(page_id, reviewer)
);
CREATE TABLE IF NOT EXISTS urlscan_cache (
    key TEXT PRIMARY KEY,
    body BLOB NOT NULL,
    fetched_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS samples (         -- frozen random samples of alerts for labeling
    name TEXT PRIMARY KEY,
    since INTEGER NOT NULL,
    until INTEGER NOT NULL,
    seed INTEGER NOT NULL,
    population INTEGER NOT NULL,             -- alerts in [since, until) when drawn
    drawn_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sample_members (
    name TEXT NOT NULL,
    page_id INTEGER NOT NULL,
    position INTEGER NOT NULL,               -- random order; the second labeler takes the first 50
    PRIMARY KEY(name, page_id)
);
"""


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or config.load()["paths"]["db"], timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(candidates)")}
    if "priority" not in cols:  # migrate DBs created before the priority column existed
        conn.execute("ALTER TABLE candidates ADD COLUMN priority INTEGER NOT NULL DEFAULT 0")
    if "origin" not in cols:  # 'ct' = from the CT filter; 'seed' = seed refresh visit (never alerts)
        conn.execute("ALTER TABLE candidates ADD COLUMN origin TEXT NOT NULL DEFAULT 'ct'")
    if "status" not in {r[1] for r in conn.execute("PRAGMA table_info(kits)")}:
        conn.execute("ALTER TABLE kits ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
    return conn


log = logging.getLogger("ssrd.db")
SLOW_TX_SECONDS = 2.0


@contextmanager
def tx(conn: sqlite3.Connection, label: str):
    """Short write transaction: BEGIN IMMEDIATE (waits up to busy_timeout), commit, and warn
    if the write lock was held long enough to stall the other processes sharing the file."""
    conn.commit()  # never nest inside an implicit transaction
    conn.execute("BEGIN IMMEDIATE")
    t0 = time.monotonic()
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        held = time.monotonic() - t0
        if held > SLOW_TX_SECONDS:
            log.warning("write lock held %.1fs in %s", held, label)


def write_probe(path: str | None = None, seconds: float = 5.0) -> dict:
    """Try a no-op write every 100 ms; reports how often the database was writable."""
    c = sqlite3.connect(path or config.load()["paths"]["db"], timeout=0.05, isolation_level=None)
    ok = blocked = 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            c.execute("BEGIN IMMEDIATE")
            c.execute("ROLLBACK")
            ok += 1
        except sqlite3.OperationalError:
            blocked += 1
        time.sleep(0.1)
    c.close()
    return {"writable_share": round(ok / max(1, ok + blocked), 3), "samples": ok + blocked}


def now() -> int:
    return int(time.time())


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)
