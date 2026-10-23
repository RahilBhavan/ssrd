"""urlscan.io client: SEARCH AND RESULT-FETCH ONLY.

There is deliberately no scan-submission code here: submitting would publish flagged
domains or actively visit them (SAFETY.md). tests/test_safety.py enforces this.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from urllib.parse import urlsplit

import httpx

from . import config, db, fingerprint

log = logging.getLogger("ssrd.urlscan")
WEB = "https://urlscan.io"


class QuotaExceeded(Exception):
    pass


class NeedsApiKey(Exception):
    pass


class Client:
    def __init__(self, conn, api_key: str | None = None):
        self.cfg = config.load()["urlscan"]
        self.conn = conn
        key = api_key or os.environ.get("URLSCAN_API_KEY")
        headers = {"User-Agent": "ssrd-research/0.1 (student research; contact rbhavanzim@gmail.com)"}
        if key:
            headers["API-Key"] = key
        self.has_key = bool(key)
        self.http = httpx.Client(timeout=30, headers=headers)
        self.last = 0.0

    def _get(self, url: str, params: dict | None = None, cache: bool = True, raw: bool = False):
        key = url + ("?" + json.dumps(params, sort_keys=True) if params else "")
        if cache:
            row = self.conn.execute("SELECT body FROM urlscan_cache WHERE key=?", (key,)).fetchone()
            if row:
                if row[0] == b"":  # cached "not available" (404)
                    return None
                return row[0] if raw else json.loads(row[0])
        for attempt in range(5):
            wait = self.cfg["min_interval_seconds"] - (time.time() - self.last)
            if wait > 0:
                time.sleep(wait)
            self.last = time.time()
            r = self.http.get(url, params=params)
            if r.status_code == 429:
                reset = float(r.headers.get("X-Rate-Limit-Reset-After", 2 ** (attempt + 2)))
                if reset > 300:
                    raise QuotaExceeded(r.text[:200])
                log.warning("urlscan 429; sleeping %.0fs", reset)
                time.sleep(reset)
                continue
            if r.status_code == 404:
                if cache:  # remember misses; free accounts get 404 for every /responses/ body
                    self.conn.execute(
                        "INSERT OR REPLACE INTO urlscan_cache(key,body,fetched_at) VALUES(?,?,?)", (key, b"", db.now())
                    )
                    self.conn.commit()
                return None
            if r.status_code >= 500:  # broken stored scan or transient error: retry once, then skip
                if attempt == 0:
                    time.sleep(3)
                    continue
                log.warning("urlscan %s for %s; skipping", r.status_code, url)
                return None
            if r.status_code in (401, 403) and not self.has_key:
                raise NeedsApiKey("urlscan refused anonymous access; put URLSCAN_API_KEY=... in data/.env")
            r.raise_for_status()
            body = r.content
            if cache:
                self.conn.execute(
                    "INSERT OR REPLACE INTO urlscan_cache(key,body,fetched_at) VALUES(?,?,?)", (key, body, db.now())
                )
                self.conn.commit()
            return body if raw else json.loads(body)
        raise QuotaExceeded("repeated 429")

    def quotas(self) -> dict:
        return self._get(f"{WEB}/user/quotas/", cache=False)

    def search(self, q: str, size: int = 100, max_results: int = 1000) -> list[dict]:
        out, search_after = [], None
        while len(out) < max_results:
            params = {"q": q, "size": min(size, max_results - len(out))}
            if search_after:
                params["search_after"] = search_after
            res = self._get(f"{self.cfg['api_base']}/search/", params)
            batch = (res or {}).get("results", [])
            out += batch
            if not batch or not res.get("has_more"):
                break
            search_after = ",".join(str(x) for x in batch[-1]["sort"])
        return out

    def result(self, uuid: str) -> dict | None:
        return self._get(f"{self.cfg['api_base']}/result/{uuid}/")

    def response_body(self, sha256: str) -> bytes | None:
        try:
            return self._get(f"{WEB}/responses/{sha256}/", raw=True)
        except httpx.HTTPStatusError:
            return None

    def dom(self, uuid: str) -> bytes | None:
        try:
            return self._get(f"{WEB}/dom/{uuid}/", raw=True)
        except httpx.HTTPStatusError:
            return None


def features_from_result(client: Client, res: dict, lib_re: re.Pattern) -> dict | None:
    """Build fingerprint features from a stored urlscan result, without touching the site."""
    page = res.get("page", {})
    reqs = res.get("data", {}).get("requests", [])
    page_url = page.get("url") or res.get("task", {}).get("url")
    if not reqs or not page_url:
        return None
    main = reqs[0].get("response", {})
    body, body_src = None, "response"
    if main.get("hash"):
        body = client.response_body(main["hash"])
    if body is None:
        body, body_src = client.dom(res["task"]["uuid"]), "dom"
    if not body:
        return None
    resp = main.get("response", {})
    headers = list((resp.get("headers") or {}).items())
    f = fingerprint.html_features(
        body, page_url, resp.get("mimeType", "text/html"), resp.get("status") or page.get("status"), headers
    )
    host = urlsplit(page_url).hostname
    for rq in reqs[1:]:
        r = rq.get("response", {})
        url = (r.get("response") or {}).get("url") or rq.get("request", {}).get("request", {}).get("url", "")
        mime = (r.get("response") or {}).get("mimeType", "")
        h = r.get("hash")
        if not h or urlsplit(url).hostname != host:
            continue
        path = urlsplit(url).path
        if mime.startswith("image/") and ("favicon" in path or url in f["assets"]["icons"]):
            if f["favicon_mmh3"] is None:
                icon = client.response_body(h)
                if icon:
                    f["favicon_mmh3"] = fingerprint.favicon_mmh3(icon)
        elif ("javascript" in mime or "css" in mime) and not lib_re.search(url):
            f["asset_sha256"][path] = h
    asn = str(page.get("asn") or "").upper().removeprefix("AS")
    f.update(
        {
            "asn": int(asn) if asn.isdigit() else None,
            "ns": [],
            "body_source": body_src,
            "urlscan_uuid": res["task"]["uuid"],
            "scanned_at": res["task"].get("time"),
        }
    )
    return f


def harvest_domain(conn, client: Client, domain: str, per_domain: int = 2, extra_q: str = "") -> int:
    """Store up to `per_domain` content-class historical scans for a seed domain."""
    lib_re = re.compile(config.load()["fetch"]["library_asset_pattern"], re.I)
    hits = client.search(f'page.domain:"{domain}" {extra_q}'.strip(), size=20, max_results=20)
    stored = 0
    for hit in hits:
        if stored >= per_domain:
            break
        uuid = hit["task"]["uuid"]
        if conn.execute("SELECT 1 FROM pages WHERE source='urlscan' AND ref=?", (uuid,)).fetchone():
            stored += 1
            continue
        if (hit.get("page", {}).get("status") or "200") not in ("200", 200):
            continue
        res = client.result(uuid)
        if not res:
            continue
        f = features_from_result(client, res, lib_re)
        if not f:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO pages(source,ref,domain,observed_at,page_class,features) VALUES(?,?,?,?,?,?)",
            ("urlscan", uuid, domain, db.now(), f["page_class"], db.dumps(f)),
        )
        conn.commit()
        if f["page_class"] == "content":
            stored += 1
    return stored


def harvest_background(conn, client: Client, limit: int, query: str) -> int:
    """Random recent public scans stored as source='background' for the common-value denylist."""
    lib_re = re.compile(config.load()["fetch"]["library_asset_pattern"], re.I)
    stored = 0
    for hit in client.search(query, size=100, max_results=limit):
        uuid = hit["task"]["uuid"]
        if conn.execute("SELECT 1 FROM pages WHERE ref=?", (uuid,)).fetchone():
            continue
        res = client.result(uuid)
        f = features_from_result(client, res, lib_re) if res else None
        if not f or f["page_class"] != "content":
            continue
        conn.execute(
            "INSERT OR IGNORE INTO pages(source,ref,domain,observed_at,page_class,features) VALUES(?,?,?,?,?,?)",
            ("background", uuid, hit["page"].get("domain") or "?", db.now(), f["page_class"], db.dumps(f)),
        )
        conn.commit()
        stored += 1
    return stored
