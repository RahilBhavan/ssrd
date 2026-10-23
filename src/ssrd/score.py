"""Pairwise page comparison and the two-family alert rule (SPEC R6).

Families: A content, B assets, C page features, D infrastructure.
Alert = >= 2 strong signals from different families among A/B/C, or one strong family plus >= 2
supporting signals (further strong or medium signals, or header order). Generator tags and D
(infrastructure) signals only add score: WordPress versions and Cloudflare are near-universal.
"""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict

from . import config, db, fingerprint

STRONG, MEDIUM, WEAK = 3, 2, 1
_DENY: dict = {"at": 0.0, "values": set()}


def _hash_values(f: dict) -> list[tuple[str, str]]:
    out = []
    if f.get("favicon_mmh3") is not None:
        out.append(("favicon", str(f["favicon_mmh3"])))
    out += [("asset", h) for h in f.get("asset_sha256", {}).values()]
    out += [("inline", h) for h in f.get("inline_script_sha256", [])]
    out += [("path", p) for p in f.get("assets", {}).get("local_paths", [])]
    if f.get("title_norm"):
        out.append(("title", f["title_norm"]))
    out += [("copy", str(h)) for h in f.get("copy_shingles", [])]
    return out


def common_values(conn, refresh_seconds: int = 600) -> set[tuple[str, str]]:
    """Values seen on more than max(common_min_hosts, common_share * N) background/live hosts get zero weight."""
    if time.time() - _DENY["at"] < refresh_seconds:
        return _DENY["values"]
    cfg, cfg_review = config.load()["score"], config.load()["review"]
    # Only a value that a library page carries can ever become a signal, so count hosts for those
    # alone. Counting every live value (about 4,000 copy shingles per page) outgrew the fetcher's 1 GB limit.
    library: set[tuple[str, str]] = set()
    for (raw,) in conn.execute(
        "SELECT features FROM pages WHERE source IN ('urlscan','wayback','seedlive') "
        "OR (source='live' AND id IN (SELECT page_id FROM labels WHERE label='scam-kit' AND reviewer!=?))",
        (cfg_review["assist_reviewer"],),
    ):
        library.update(_hash_values(json.loads(raw)))
    hosts: dict[tuple[str, str], set[str]] = defaultdict(set)
    all_hosts: set[str] = set()
    # Background (random urlscan scans) and live pages only: counting seed pages would let a
    # large, genuine kit denylist its own shared assets.
    for row in conn.execute("SELECT domain, features FROM pages WHERE source IN ('background','live')"):
        all_hosts.add(row["domain"])
        for v in _hash_values(json.loads(row["features"])):
            if v in library:
                hosts[v].add(row["domain"])
    limit = max(cfg["common_min_hosts"], cfg["common_share"] * len(all_hosts))
    _DENY.update(at=time.time(), values={v for v, h in hosts.items() if len(h) > limit})
    return _DENY["values"]


def compare(a: dict, b: dict, deny: set | frozenset = frozenset()) -> list[dict]:
    cfg = config.load()["score"]
    sig: list[dict] = []

    def add(family, name, strength, value):
        sig.append({"family": family, "signal": name, "strength": strength, "value": value})

    d = fingerprint.tlsh_distance(a.get("tlsh"), b.get("tlsh"))
    if d is not None and d <= cfg["tlsh_max_distance"]:
        add("A", "tlsh", STRONG, d)
    j = fingerprint.jaccard_from_minhash(a.get("minhash"), b.get("minhash"))
    if j is not None and j >= cfg["jaccard_min"]:
        add("A", "tag_jaccard", STRONG, round(j, 3))

    ca, cb = set(a.get("copy_shingles", [])), set(b.get("copy_shingles", []))
    if ca and cb:
        shared = {h for h in ca & cb if ("copy", str(h)) not in deny}
        containment = len(shared) / min(len(ca), len(cb))
        if len(shared) >= cfg["copy_min_shared"] and containment >= cfg["copy_min_containment"]:
            add("A", "copy", STRONG, len(shared))
        elif len(shared) >= cfg["copy_medium_shared"]:
            add("A", "copy", MEDIUM, len(shared))

    fa, fb = a.get("favicon_mmh3"), b.get("favicon_mmh3")
    if fa is not None and fa == fb and ("favicon", str(fa)) not in deny:
        add("B", "favicon_mmh3", STRONG, fa)
    shared_assets = set(a.get("asset_sha256", {}).values()) & set(b.get("asset_sha256", {}).values())
    shared_assets = {h for h in shared_assets if ("asset", h) not in deny}
    if shared_assets:
        add("B", "asset_sha256", STRONG, sorted(shared_assets)[:3])
    shared_inline = set(a.get("inline_script_sha256", [])) & set(b.get("inline_script_sha256", []))
    shared_inline = {h for h in shared_inline if ("inline", h) not in deny}
    if shared_inline:
        add("B", "inline_script", STRONG, sorted(shared_inline)[:3])
    pa = set(a.get("assets", {}).get("local_paths", []))
    pb = set(b.get("assets", {}).get("local_paths", []))
    shared_paths = {p for p in pa & pb if ("path", p) not in deny}
    if len(shared_paths) >= 2 and len(shared_paths) / max(1, len(pa | pb)) >= 0.5:
        add("B", "asset_paths", MEDIUM, sorted(shared_paths)[:5])

    ta, tb = a.get("title_norm"), b.get("title_norm")
    if ta and ta == tb and len(ta) >= cfg["min_title_len"] and ("title", ta) not in deny:
        add("C", "title", MEDIUM, ta)
    for key in ("telegram", "whatsapp", "crypto_addresses"):
        shared = set(a.get(key, [])) & set(b.get(key, []))
        if shared:
            add("C", key, STRONG, sorted(shared)[:3])
    if a.get("header_order") and a.get("header_order") == b.get("header_order"):
        add("C", "header_order", WEAK, len(a["header_order"]))
    if a.get("generator") and a.get("generator") == b.get("generator"):
        add("C", "generator", WEAK, a["generator"])

    if a.get("asn") and a.get("asn") == b.get("asn"):
        add("D", "asn", WEAK, a["asn"])
    if a.get("ns") and a.get("ns") == b.get("ns"):
        add("D", "ns", WEAK, a["ns"][:2])
    return sig


def strong_families(signals: list[dict]) -> set[str]:
    return {s["family"] for s in signals if s["strength"] == STRONG and s["family"] in "ABC"}


NON_SUPPORTING = {"generator"}


def decide(signals: list[dict]) -> tuple[bool, float]:
    strong_fams = strong_families(signals)
    abc = [s for s in signals if s["family"] in "ABC" and s["signal"] not in NON_SUPPORTING]
    # Signals beyond the one that made the family strong: the second strong asset hash, a medium
    # copy match, shared asset paths, title, header order.
    support = len(abc) - 1 if strong_fams else 0
    alert = len(strong_fams) >= 2 or (len(strong_fams) == 1 and support >= 2)
    return alert, float(sum(s["strength"] for s in signals))


def kit_members(conn, exclude_page: int | None = None) -> dict[int, list[tuple[int, str, dict]]]:
    kits: dict[int, list] = defaultdict(list)
    for row in conn.execute(
        "SELECT km.kit_id, p.id, p.domain, p.features FROM kit_members km JOIN pages p ON p.id=km.page_id"
    ):
        if row["id"] != exclude_page:
            kits[row["kit_id"]].append((row["id"], row["domain"], json.loads(row["features"])))
    return kits


def best_match(features: dict, members: list[tuple[int, str, dict]], deny) -> dict | None:
    best = None
    for pid, dom, f in members:
        sig = compare(features, f, deny)
        alert, sc = decide(sig)
        if best is None or (alert, sc) > (best["alert"], best["score"]):
            best = {"alert": alert, "score": sc, "member_page": pid, "member_domain": dom, "signals": sig}
    return best


def score_page(conn, page_id: int) -> int:
    """Compute all kit matches first (read-only), then write them in one short transaction."""
    row = conn.execute("SELECT domain, features FROM pages WHERE id=?", (page_id,)).fetchone()
    features = json.loads(row["features"])
    deny = common_values(conn)
    results = []
    active = {r[0] for r in conn.execute("SELECT id FROM kits WHERE status='active'")}
    for kit_id, members in kit_members(conn, exclude_page=page_id).items():
        if kit_id not in active:
            continue
        members = [m for m in members if m[1] != row["domain"]]
        best = best_match(features, members, deny)
        if best and best["score"] > 0:
            results.append((kit_id, best))
    names = dict(conn.execute("SELECT id, name FROM kits").fetchall())
    alerts = 0
    with db.tx(conn, "score_page"):
        for kit_id, best in results:
            alerts += best["alert"]
            conn.execute(
                "INSERT OR REPLACE INTO scores(page_id,kit_id,score,alert,details,scored_at) VALUES(?,?,?,?,?,?)",
                (page_id, kit_id, best["score"], int(best["alert"]), db.dumps(best), db.now()),
            )
            if best["alert"]:
                conn.execute(
                    "INSERT OR IGNORE INTO alert_log(page_id,first_alert_at,kit_name) VALUES(?,?,?)",
                    (page_id, db.now(), names.get(kit_id)),
                )
    if alerts:
        from . import prelabel

        prelabel.apply(conn, page_id)
    return alerts


def rescore_live(conn) -> Counter:
    c: Counter = Counter()
    for (pid,) in conn.execute("SELECT id FROM pages WHERE source='live' AND page_class='content'").fetchall():
        c["pages"] += 1
        c["alerts"] += score_page(conn, pid)
    return c
