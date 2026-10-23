"""Wayback Machine harvester: archived pre-seizure pages for seed domains.

Reads archive.org's stored copies (raw `id_` mode, no Wayback rewriting), so the scam
infrastructure itself is never contacted. Pages are stored with source='wayback'.
"""

from __future__ import annotations

import logging
import re
import time

import httpx

from . import db, fingerprint

log = logging.getLogger("ssrd.wayback")
CDX = "https://web.archive.org/cdx/search/cdx"
UA = "ssrd-research/0.1 (student research; contact rbhavanzim@gmail.com)"


class Client:
    def __init__(self, min_interval: float = 1.5):
        self.http = httpx.Client(timeout=60, headers={"User-Agent": UA}, follow_redirects=True)
        self.min_interval = min_interval
        self.last = 0.0

    def _get(self, url: str, params: dict | None = None) -> httpx.Response | None:
        for attempt in range(3):
            wait = self.min_interval - (time.time() - self.last)
            if wait > 0:
                time.sleep(wait)
            self.last = time.time()
            try:
                r = self.http.get(url, params=params)
            except httpx.HTTPError as e:
                log.warning("wayback %s: %s", url, e)
                time.sleep(5 * (attempt + 1))
                continue
            if r.status_code in (429, 503):
                time.sleep(10 * (attempt + 1))
                continue
            return r
        return None

    def snapshots(self, domain: str, before: str) -> list[tuple[str, str]]:
        """[(timestamp, original_url)] of 200 text/html captures of the homepage, newest first."""
        r = self._get(
            CDX,
            {
                "url": domain,
                "output": "json",
                "fl": "timestamp,original,mimetype",
                "filter": ["statuscode:200", "mimetype:text/html"],
                "to": before.replace("-", ""),
                "collapse": "digest",
                "limit": "200",
            },
        )
        if r is None or r.status_code != 200 or not r.text.strip():
            return []
        rows = r.json()[1:]
        return sorted(((ts, orig) for ts, orig, _ in rows), reverse=True)

    def raw(self, ts: str, url: str, conn=None) -> bytes | None:
        """Archived bytes for a snapshot; cached in urlscan_cache (key 'wayback:...') when conn is given."""
        key = f"wayback:{ts}:{url}"
        if conn is not None:
            row = conn.execute("SELECT body FROM urlscan_cache WHERE key=?", (key,)).fetchone()
            if row:
                return row[0]
        r = self._get(f"https://web.archive.org/web/{ts}id_/{url}")
        if r is None or r.status_code != 200 or not r.content:
            return None
        if conn is not None:
            conn.execute(
                "INSERT OR REPLACE INTO urlscan_cache(key,body,fetched_at) VALUES(?,?,?)", (key, r.content, db.now())
            )
            conn.commit()
        return r.content


def harvest_domain(conn, client: Client, domain: str, before: str, per_domain: int = 3) -> int:
    stored = 0
    for ts, orig in client.snapshots(domain, before):
        if stored >= per_domain:
            break
        ref = f"{domain}@{ts}"
        if conn.execute("SELECT 1 FROM pages WHERE source='wayback' AND ref=?", (ref,)).fetchone():
            stored += 1
            continue
        body = client.raw(ts, orig, conn)
        if body is None:
            continue
        url = re.sub(r"^http://", "https://", orig) if orig.startswith("http") else f"https://{domain}/"
        f = fingerprint.html_features(body, url, "text/html", 200, [])
        f["wayback_original"] = orig
        f.update({"asn": None, "ns": [], "body_source": "wayback", "archived_at": ts})
        conn.execute(
            "INSERT OR IGNORE INTO pages(source,ref,domain,observed_at,page_class,features) VALUES(?,?,?,?,?,?)",
            ("wayback", ref, domain, db.now(), f["page_class"], db.dumps(f)),
        )
        conn.commit()
        stored += f["page_class"] == "content"
    return stored


def _looks_like_image(body: bytes) -> bool:
    head = body[:16].lstrip()
    return bool(body) and not head.startswith(b"<") and len(body) < 500_000


def add_favicons(conn, client: Client) -> int:
    """Fill favicon_mmh3 for archived seed pages from archive.org's copy of the icon."""
    import json
    from urllib.parse import urlsplit

    done = 0
    rows = conn.execute("SELECT id, features FROM pages WHERE source='wayback' AND page_class='content'").fetchall()
    for pid, raw in rows:
        f = json.loads(raw)
        if f.get("favicon_mmh3") is not None:
            continue
        orig = f.get("wayback_original") or f["url"]
        parts = urlsplit(orig)
        base = f"{parts.scheme or 'http'}://{parts.netloc or urlsplit(f['url']).netloc}"
        host = urlsplit(f["url"]).hostname
        icons = [u for u in f["assets"]["icons"] if urlsplit(u).hostname == host]
        candidates = [base + urlsplit(u).path for u in icons] + [f"{base}/favicon.ico"]
        for icon in candidates[:2]:
            body = client.raw(f["archived_at"], icon, conn)
            if body and _looks_like_image(body):
                f["favicon_mmh3"] = fingerprint.favicon_mmh3(body)
                conn.execute("UPDATE pages SET features=? WHERE id=?", (db.dumps(f), pid))
                conn.commit()
                done += 1
                break
    return done
