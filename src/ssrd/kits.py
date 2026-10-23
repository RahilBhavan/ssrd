"""Cluster seed pages into named kits (SPEC R5).

Two seed pages are linked when they pass the same two-family rule used for live alerts;
kits are connected components with >= 2 members on distinct registrable domains.
"""

from __future__ import annotations

import json
from collections import Counter

from . import config, db, score

MIN_MEDIAN_INVEST_TERMS = 3  # kits of parking/hosting templates (no investment copy) never alert


class DSU:
    def __init__(self, items):
        self.p = {i: i for i in items}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def seed_pages(conn) -> list[tuple[int, str, dict]]:
    """Library pages: harvested seeds plus live pages a reviewer confirmed as scam-kit."""
    rows = conn.execute(
        "SELECT id, domain, features FROM pages WHERE page_class='content' AND (source IN ('urlscan','wayback','seedlive') "
        "OR (source='live' AND id IN (SELECT page_id FROM labels WHERE label='scam-kit' AND reviewer!=?)))",
        (config.load()["review"]["assist_reviewer"],),
    ).fetchall()
    return [(r["id"], r["domain"], json.loads(r["features"])) for r in rows]


def describe(members: list[tuple[int, str, dict]], links: list[list[dict]]) -> str:
    counts = Counter(s["signal"] for sig in links for s in sig)
    titles = Counter(f.get("title") for _, _, f in members if f.get("title"))
    top_title = titles.most_common(1)[0][0] if titles else "untitled"
    sigs = ", ".join(f"{k}×{v}" for k, v in counts.most_common(4))
    return f"{len(members)} pages on {len({d for _, d, _ in members})} domains; common title '{top_title[:60]}'; links via {sigs}"


def cluster(pages: list[tuple[int, str, dict]], deny) -> tuple[list[list], dict[int, list]]:
    """Connected components under the alert rule; returns groups spanning >= 2 domains."""
    dsu = DSU([p[0] for p in pages])
    edge_sigs: dict[int, list] = {}
    for i, (pa, da, fa) in enumerate(pages):
        for pb, dbm, fb in pages[i + 1 :]:
            if da == dbm:
                continue
            sig = score.compare(fa, fb, deny)
            # Clustering is stricter than alerting: two independent strong families per link,
            # so single-linkage cannot chain unrelated sites through one shared widget.
            if len(score.strong_families(sig)) >= 2:
                dsu.union(pa, pb)
                edge_sigs.setdefault(pa, []).append(sig)
    groups: dict[int, list] = {}
    for p in pages:
        groups.setdefault(dsu.find(p[0]), []).append(p)
    ranked = sorted((g for g in groups.values() if len({d for _, d, _ in g}) >= 2), key=len, reverse=True)
    return ranked, edge_sigs


def build(conn) -> list[dict]:
    pages = seed_pages(conn)
    deny = score.common_values(conn, refresh_seconds=0)
    ranked, edge_sigs = cluster(pages, deny)
    conn.execute("DELETE FROM kit_members")
    conn.execute("DELETE FROM kits")
    conn.execute("DELETE FROM scores")
    out = []
    kcda = {r[0] for r in conn.execute("SELECT domain FROM seeds WHERE source='kcda'")}
    for n, members in enumerate(ranked, 1):
        links = [s for pid, _, _ in members for s in edge_sigs.get(pid, [])]
        desc = describe(members, links)
        name = f"kit-{n:02d}" + ("-KCDA" if any(d in kcda for _, d, _ in members) else "")
        inv = sorted(f.get("invest_terms", 0) for _, _, f in members)
        status = "active" if inv[len(inv) // 2] >= MIN_MEDIAN_INVEST_TERMS else "excluded-non-investment"
        cur = conn.execute(
            "INSERT INTO kits(name,description,built_at,status) VALUES(?,?,?,?)", (name, desc, db.now(), status)
        )
        conn.executemany(
            "INSERT INTO kit_members(kit_id,page_id) VALUES(?,?)", [(cur.lastrowid, pid) for pid, _, _ in members]
        )
        out.append({"kit": name, "members": len(members), "description": desc, "status": status})
    # Reference sites: investment-content seed domains not in any kit. A live match means
    # "matches known listed site X" (lower confidence than a multi-domain kit match).
    in_kits = {d for g in ranked for _, d, _ in g}
    by_domain: dict[str, list] = {}
    for p in pages:
        if p[1] not in in_kits:
            by_domain.setdefault(p[1], []).append(p)
    refs = 0
    for dom, members in sorted(by_domain.items()):
        inv = sorted(f.get("invest_terms", 0) for _, _, f in members)
        if inv[len(inv) // 2] < MIN_MEDIAN_INVEST_TERMS:
            continue
        name = f"ref-{dom}" + ("-KCDA" if dom in kcda else "")
        cur = conn.execute(
            "INSERT INTO kits(name,description,built_at,status) VALUES(?,?,?,?)",
            (name, f"single listed site ({len(members)} pages)", db.now(), "active"),
        )
        conn.executemany(
            "INSERT INTO kit_members(kit_id,page_id) VALUES(?,?)", [(cur.lastrowid, pid) for pid, _, _ in members]
        )
        refs += 1
    conn.commit()
    out.append(
        {
            "kit": f"{refs} reference sites",
            "members": refs,
            "description": "single-domain references",
            "status": "active",
        }
    )
    return out
