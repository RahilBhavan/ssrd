"""Delayed, passive fetcher (SPEC R3). Rules are in SAFETY.md and CLAUDE.md; every one is
enforced here, not by convention.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

from . import config, db, fingerprint, safety, score
from .metrics import Counters

log = logging.getLogger("ssrd.fetch")
RETRY_CLASSES = {"parked", "blank", "error"}


class RateLimiter:
    def __init__(self, per_minute: float):
        self.interval = 60.0 / per_minute
        self.next_ok = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            delay = self.next_ok - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.next_ok = max(time.monotonic(), self.next_ok) + self.interval


@dataclass
class FetchResult:
    url: str
    final_url: str | None = None
    status: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    content_type: str = ""
    body: bytes | None = None
    ip: str | None = None
    cert_sha256: str | None = None
    chain: list[dict] = field(default_factory=list)
    error: str | None = None


def tool_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=config.ROOT, timeout=5
        ).stdout.strip() or os.environ.get("SSRD_COMMIT", "unknown")
    except Exception:
        return os.environ.get("SSRD_COMMIT", "unknown")


class SafeFetcher:
    def __init__(self, limiter: RateLimiter | None = None, resolve=safety.resolve_public, transport=None):
        self.cfg = config.load()["fetch"]
        self.limiter = limiter or RateLimiter(self.cfg["requests_per_minute"])
        self.resolve = resolve
        self.allowed_types = tuple(self.cfg["content_types"])
        self.client = httpx.Client(
            verify=False,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(self.cfg["timeout_seconds"], connect=self.cfg["connect_timeout_seconds"]),
            transport=transport,
        )
        self.base_headers = {
            "User-Agent": self.cfg["user_agent"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": self.cfg["accept_language"],
        }

    def get(self, url: str, max_bytes: int | None = None) -> FetchResult:
        max_bytes = max_bytes or self.cfg["max_bytes"]
        res = FetchResult(url=url)
        current = url
        for _hop in range(self.cfg["max_redirects"] + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                res.error = f"scheme_refused:{parts.scheme}"
                return res
            if parts.username or parts.password:
                res.error = "userinfo_refused"
                return res
            port = parts.port or (443 if parts.scheme == "https" else 80)
            if port not in (80, 443):
                res.error = f"port_refused:{port}"
                return res
            try:
                ip = self.resolve(parts.hostname)
            except safety.UnsafeTarget as e:
                res.error = f"unsafe:{e}"
                return res
            pinned = urlunsplit((parts.scheme, ip if ":" not in ip else f"[{ip}]", parts.path or "/", parts.query, ""))
            headers = {**self.base_headers, "Host": parts.hostname}
            ext = {"sni_hostname": parts.hostname} if parts.scheme == "https" else {}
            self.limiter.wait()
            try:
                with self.client.stream("GET", pinned, headers=headers, extensions=ext) as r:
                    hop = {"url": current, "ip": ip, "status": r.status_code}
                    res.chain.append(hop)
                    res.ip, res.status = ip, r.status_code
                    res.headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in r.headers.raw]
                    res.content_type = r.headers.get("content-type", "")
                    if parts.scheme == "https" and res.cert_sha256 is None:
                        res.cert_sha256 = _peer_cert_sha256(r)
                    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                        current = str(httpx.URL(current).join(r.headers["location"]))
                        continue
                    res.final_url = current
                    ctype = res.content_type.split(";")[0].strip().lower()
                    if ctype and not ctype.startswith(self.allowed_types):
                        res.error = f"content_type_refused:{ctype}"
                        hop["content_length"] = r.headers.get("content-length")
                        return res
                    buf = bytearray()
                    deadline = time.monotonic() + self.cfg["total_timeout_seconds"]
                    for chunk in r.iter_bytes():
                        buf += chunk
                        if len(buf) > max_bytes:
                            res.error = "too_large"
                            return res
                        if time.monotonic() > deadline:  # slow-drip (tarpit) responses
                            res.error = "too_slow"
                            return res
                    res.body = bytes(buf)
                    return res
            except httpx.HTTPError as e:
                res.error = f"http:{type(e).__name__}"
                return res
        res.error = "too_many_redirects"
        return res


def _peer_cert_sha256(r: httpx.Response) -> str | None:
    try:
        ssl_obj = r.extensions["network_stream"].get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True)
        return hashlib.sha256(der).hexdigest() if der else None
    except Exception:
        return None


class Visitor:
    """Runs one passive visit per due job, stores evidence, fingerprints and scores it."""

    def __init__(self, conn, fetcher: SafeFetcher | None = None):
        self.conn = conn
        self.cfg = config.load()
        self.fetcher = fetcher or SafeFetcher()
        data = Path(self.cfg["paths"]["data_dir"])
        self.captures = data / "captures"
        self.manifest_dir = data / "manifest"
        self.captures.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.manifest_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lib_re = re.compile(self.cfg["fetch"]["library_asset_pattern"], re.I)
        self.counters = Counters("fetcher")
        self.commit = tool_commit()
        self.workers = self.cfg["fetch"]["concurrency"]
        self.pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="fetch")

    def store(self, body: bytes) -> str:
        digest = fingerprint.sha256(body)
        path = self.captures / f"{digest}.gz"
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(gzip.compress(body))
        return digest

    def manifest(self, record: dict) -> None:
        day = datetime.now(UTC).strftime("%Y-%m-%d")
        with open(self.manifest_dir / f"{day}.jsonl", "a") as f:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    def observe(self, job) -> dict:
        """Network phase (thread-safe, no database access): fetch, fingerprint, enrich."""
        domain = job["domain"]
        t0 = time.monotonic()
        res = self.fetcher.get(f"https://{domain}/")
        if res.error in ("http:ConnectError", "http:SSLError") and res.status is None:  # not on timeouts
            res = self.fetcher.get(f"http://{domain}/")
        features, outcome = None, "error"
        if res.body is not None:
            features = fingerprint.html_features(
                res.body, res.final_url or res.url, res.content_type, res.status, res.headers
            )
            outcome = features["page_class"]
            if (
                self.cfg["fetch"]["mode"] == "passive_visit"
                and outcome == "content"
                and features["invest_terms"] >= self.cfg["fetch"]["asset_min_invest_terms"]
            ):
                self.fetch_assets(features)
        elif res.error and res.error.startswith("unsafe:"):
            outcome = "skipped"
        elif res.status in (401, 403, 406, 429, 451, 503):
            outcome = "blocked"
        asn = safety.asn_for_ip(res.ip) if res.ip else {}
        ns = safety.lookup_ns(domain) if res.ip else []
        return {
            "res": res,
            "features": features,
            "outcome": outcome,
            "asn": asn,
            "ns": ns,
            "fetched_at": datetime.now(UTC).isoformat(),
            "elapsed_s": round(time.monotonic() - t0, 2),
        }

    def visit(self, job, obs: dict | None = None) -> dict:
        """Record phase (database thread): store capture, evidence, page, score, retries."""
        obs = obs or self.observe(job)
        res, features, outcome, asn = obs["res"], obs["features"], obs["outcome"], obs["asn"]
        domain, attempt = job["domain"], job["attempt"]
        self.counters.inc("visits")
        if res.body is not None:
            self.store(res.body)
        evidence = {
            "requested_url": res.url,
            "final_url": res.final_url,
            "redirect_chain": res.chain,
            "fetched_at_utc": obs["fetched_at"],
            "ct_ts": job["ct_ts"],
            "resolved_ip": res.ip,
            "asn": asn.get("asn"),
            "asn_cc": asn.get("cc"),
            "ns": obs["ns"],
            "request_headers": self.fetcher.base_headers,
            "response_status": res.status,
            "response_headers": res.headers,
            "cert_sha256": res.cert_sha256,
            "body_sha256": fingerprint.sha256(res.body) if res.body else None,
            "outcome": outcome,
            "error": res.error,
            "mode": self.cfg["fetch"]["mode"],
            "tool_git_commit": self.commit,
            "domain": domain,
            "attempt": attempt,
            "origin": job["origin"],
            "elapsed_s": obs.get("elapsed_s"),
        }
        self.manifest(evidence)
        self.counters.inc(f"outcome_{outcome}")
        log.info("visit %s #%d -> %s%s", domain, attempt, outcome, f" ({res.error})" if res.error else "")
        self.conn.execute(
            "UPDATE visits SET done_at=?, outcome=?, final_url=?, status=?, body_sha256=?, evidence=? WHERE id=?",
            (db.now(), outcome, res.final_url, res.status, evidence["body_sha256"], db.dumps(evidence), job["id"]),
        )
        page_id = None
        # Seed refresh visits feed the kit library with raw HTML + favicon + assets; never scored.
        source = "seedlive" if job["origin"] == "seed" else "live"
        if features is not None:
            features.update({"asn": asn.get("asn"), "ns": obs["ns"], "cert_sha256": res.cert_sha256})
            cur = self.conn.execute(
                "INSERT OR REPLACE INTO pages(source,ref,domain,observed_at,page_class,features) VALUES(?,?,?,?,?,?)",
                (source, str(job["id"]), domain, db.now(), outcome, db.dumps(features)),
            )
            page_id = cur.lastrowid
        delays = self.cfg["fetch"]["delays_seconds"]
        if outcome in RETRY_CLASSES and attempt < len(delays):
            self.conn.execute(
                "INSERT OR IGNORE INTO visits(domain,attempt,due_at) VALUES(?,?,?)",
                (domain, attempt + 1, (job["ct_ts"] or db.now()) + delays[attempt]),
            )
        self.conn.commit()  # release the write lock before the (CPU-heavy) scoring step
        if page_id is not None and outcome == "content" and source == "live":
            self.counters.inc("alerts", score.score_page(self.conn, page_id))
        return evidence

    def fetch_assets(self, features: dict) -> None:
        """passive_visit mode only: favicon + up to max_assets same-host, non-library JS/CSS."""
        assets = features["assets"]
        host = urlsplit(features["url"]).hostname
        base = f"{urlsplit(features['url']).scheme}://{host}"
        icon = next((u for u in assets["icons"] if urlsplit(u).hostname == host), f"{base}/favicon.ico")
        t0 = time.monotonic()
        budget = self.cfg["fetch"]["asset_budget_seconds"]
        r = self.fetcher.get(icon, max_bytes=200_000)
        if r.body and r.status == 200:
            features["favicon_mmh3"] = fingerprint.favicon_mmh3(r.body)
        picked = [
            u
            for u in assets["scripts"] + assets["styles"]
            if urlsplit(u).hostname == host and not self.lib_re.search(u)
        ][: self.cfg["fetch"]["max_assets"]]
        for u in picked:
            if time.monotonic() - t0 > budget:
                features["asset_budget_exhausted"] = True
                break
            r = self.fetcher.get(u, max_bytes=1_000_000)
            if r.body and r.status == 200:
                features["asset_sha256"][urlsplit(u).path] = fingerprint.sha256(r.body)

    def expire_stale(self) -> int:
        cutoff = db.now() - self.cfg["fetch"]["expire_after_seconds"]
        cur = self.conn.execute(
            "UPDATE visits SET done_at=?, outcome='expired' WHERE done_at IS NULL AND due_at<? "
            "AND domain IN (SELECT domain FROM candidates WHERE origin='ct')",
            (db.now(), cutoff),
        )
        self.conn.commit()
        if cur.rowcount:
            self.counters.inc("outcome_expired", cur.rowcount)
        return cur.rowcount

    def due_jobs(self, limit: int = 20):
        return self.conn.execute(
            "SELECT v.id, v.domain, v.attempt, c.ct_ts, c.origin FROM visits v JOIN candidates c ON c.domain=v.domain "
            "WHERE v.done_at IS NULL AND v.due_at<=? ORDER BY c.priority DESC, v.due_at LIMIT ?",
            (db.now(), limit),
        ).fetchall()

    def run(self, once: bool = False) -> None:
        while True:
            try:
                jobs = self._run_batch()
            except sqlite3.OperationalError as e:  # busy database: back off, never crash the loop
                log.warning("db busy: %s", e)
                self.conn.rollback()
                time.sleep(10)
                continue
            if once:
                self.counters.flush()
                return
            if not jobs:
                time.sleep(15)

    def _run_batch(self):
        self.expire_stale()
        jobs = self.due_jobs(limit=self.workers * 4)
        futures = {self.pool.submit(self.observe, job): job for job in jobs}
        for fut in as_completed(futures):
            job = futures[fut]
            try:
                self.visit(job, fut.result())
            except sqlite3.OperationalError:
                raise  # a busy database is not the site's fault; the job stays pending
            except Exception as e:  # one bad site must not stop the loop
                log.exception("visit %s failed", job["domain"])
                self.conn.execute(
                    "UPDATE visits SET done_at=?, outcome='error', evidence=? WHERE id=?",
                    (db.now(), db.dumps({"error": repr(e)}), job["id"]),
                )
                self.conn.commit()
        return jobs


def daily_manifest_hashes() -> list[str]:
    mdir = Path(config.load()["paths"]["data_dir"]) / "manifest"
    lines = []
    for p in sorted(mdir.glob("*.jsonl")):
        lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}")
    (mdir / "hashes.txt").write_text("\n".join(lines) + "\n")
    return lines
