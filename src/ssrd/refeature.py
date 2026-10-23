"""Recompute features for stored pages after fingerprint changes, without re-contacting sites.

urlscan/background pages are rebuilt from the local urlscan cache, live pages from captures;
Wayback pages are re-read from archive.org (cached afterwards). Fields added by the fetcher or
harvesters (favicon, asset hashes, ASN, NS, archive timestamps) are preserved.
"""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

from . import config, db, fingerprint, urlscan, wayback

KEEP = (
    "favicon_mmh3",
    "asset_sha256",
    "asn",
    "ns",
    "cert_sha256",
    "body_source",
    "urlscan_uuid",
    "scanned_at",
    "archived_at",
    "wayback_original",
)


def _merge(old: dict, new: dict) -> dict:
    for k in KEEP:
        if k in old and old[k] not in (None, {}, []):
            new[k] = old[k]
    return new


def run(conn) -> dict:
    counts = {"urlscan": 0, "background": 0, "wayback": 0, "live": 0, "missing": 0}
    us = urlscan.Client(conn)
    wb = wayback.Client()
    lib_re = re.compile(config.load()["fetch"]["library_asset_pattern"], re.I)
    captures = Path(config.load()["paths"]["data_dir"]) / "captures"
    order = "CASE source WHEN 'wayback' THEN 1 ELSE 0 END, id"  # offline sources first, archive.org last
    for row in conn.execute(f"SELECT id, source, ref, domain, features FROM pages ORDER BY {order}").fetchall():
        old = json.loads(row["features"])
        new = None
        if row["source"] in ("urlscan", "background"):
            res = us.result(row["ref"])
            new = urlscan.features_from_result(us, res, lib_re) if res else None
        elif row["source"] == "wayback":
            ts = old.get("archived_at") or row["ref"].split("@")[-1]
            orig = old.get("wayback_original") or old.get("url", "").replace("https://", "http://", 1)
            body = wb.raw(ts, orig, conn)
            if body is not None:
                new = fingerprint.html_features(body, old["url"], "text/html", 200, [])
        elif row["source"] == "live":
            path = captures / f"{old['body_sha256']}.gz"
            if path.exists():
                new = fingerprint.html_features(
                    gzip.decompress(path.read_bytes()),
                    old["url"],
                    "",
                    old.get("status"),
                    [(h, "") for h in old.get("header_order", [])],
                )
        if new is None:
            counts["missing"] += 1
            continue
        new = _merge(old, new)
        conn.execute(
            "UPDATE pages SET features=?, page_class=? WHERE id=?", (db.dumps(new), new["page_class"], row["id"])
        )
        conn.commit()  # short transactions: ingest and fetcher share this database
        counts[row["source"]] += 1
    conn.commit()
    return counts


def _cached_urlscan_body(conn, uuid: str) -> bytes | None:
    """Main-document body from the local urlscan cache (stored response, else DOM); never fetches."""
    get = lambda key: (conn.execute("SELECT body FROM urlscan_cache WHERE key=?", (key,)).fetchone() or [None])[0]  # noqa: E731
    res = get(f"{config.load()['urlscan']['api_base']}/result/{uuid}/")
    if res:
        reqs = json.loads(res).get("data", {}).get("requests", [])
        h = reqs[0].get("response", {}).get("hash") if reqs else None
        if h and (body := get(f"{urlscan.WEB}/responses/{h}/")):
            return body
    return get(f"{urlscan.WEB}/dom/{uuid}/") or None


def reclassify(conn) -> int:
    """Offline pass after PARKED_PATTERNS changes: mark stored content pages parked when their title
    (or, for captured pages, their text) now matches. Never re-contacts a site."""
    captures = Path(config.load()["paths"]["data_dir"]) / "captures"
    changed = 0
    for row in conn.execute("SELECT id, source, ref, features FROM pages WHERE page_class='content'").fetchall():
        f = json.loads(row["features"])
        blob = f.get("title") or ""
        path = captures / f"{f.get('body_sha256', '')}.gz"
        body = None
        if row["source"] in ("live", "seedlive") and path.exists():
            body = gzip.decompress(path.read_bytes())
        elif row["source"] in ("urlscan", "background"):
            body = _cached_urlscan_body(conn, row["ref"])
        elif row["source"] == "wayback" and f.get("archived_at") and f.get("wayback_original"):
            hit = conn.execute(
                "SELECT body FROM urlscan_cache WHERE key=?", (f"wayback:{f['archived_at']}:{f['wayback_original']}",)
            ).fetchone()
            body = hit[0] if hit and hit[0] else None
        if body:
            blob += " " + fingerprint.sanitized_text(body, limit=5000)
        if fingerprint.PARKED_PATTERNS.search(blob):
            f["page_class"] = "parked"
            conn.execute("UPDATE pages SET features=?, page_class='parked' WHERE id=?", (db.dumps(f), row["id"]))
            conn.commit()
            changed += 1
    return changed
