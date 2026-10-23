"""Metrics (SPEC R8): precision with Wilson CI, backtest, kappa, time to flag, volume,
decoy share, CBR forward confirmations, and offline keyword-filter recall on CBR seeds.
"""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime

from . import kits, names, score

LABELS = ("scam-kit", "not-scam", "decoy-cloaked", "parked", "error", "unsure")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def group_of(kit_name: str | None) -> str:
    """SPEC R8: KCDA-network results are reported separately from general CBR results."""
    return "kcda" if kit_name and "KCDA" in kit_name else "cbr"


def precision(conn, reviewer: str, group: str | None = None, since: int = 0, sample: str | None = None) -> dict:
    if sample:  # uniform random sample of the window's alerts: an unbiased precision estimate
        rows = conn.execute(
            "SELECT l.label, a.kit_name FROM sample_members m JOIN alert_log a ON a.page_id=m.page_id "
            "JOIN labels l ON l.page_id=m.page_id WHERE m.name=? AND l.reviewer=?",
            (sample, reviewer),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT l.label, a.kit_name FROM alert_log a JOIN labels l ON l.page_id=a.page_id "
            "WHERE l.reviewer=? AND a.first_alert_at>=?",
            (reviewer, since),
        ).fetchall()
    counts = Counter(r[0] for r in rows if group is None or group_of(r[1]) == group)
    n, k = sum(counts.values()), counts["scam-kit"]
    lo, hi = wilson(k, n)
    return {
        "n_labeled_alerts": n,
        "scam_kit": k,
        "precision": k / n if n else None,
        "ci95": [round(lo, 3), round(hi, 3)],
        "label_counts": dict(counts),
        "decoy_share": counts["decoy-cloaked"] / n if n else None,
        "accepted_assistant_suggestion": conn.execute(
            "SELECT COUNT(*) FROM labels WHERE reviewer=? AND note='accepted assistant suggestion'", (reviewer,)
        ).fetchone()[0],
    }


def kappa(conn, r1: str, r2: str, sample: str | None = None) -> dict:
    rows = conn.execute(
        "SELECT a.label, b.label FROM labels a JOIN labels b ON a.page_id=b.page_id "
        "WHERE a.reviewer=? AND b.reviewer=? "
        + ("AND a.page_id IN (SELECT page_id FROM sample_members WHERE name=?)" if sample else ""),
        (r1, r2, sample) if sample else (r1, r2),
    ).fetchall()
    n = len(rows)
    if n == 0:
        return {"n": 0, "kappa": None}
    po = sum(a == b for a, b in rows) / n
    ca, cb = Counter(a for a, _ in rows), Counter(b for _, b in rows)
    pe = sum(ca[x] * cb[x] for x in set(ca) | set(cb)) / (n * n)
    return {"n": n, "observed_agreement": round(po, 3), "kappa": round((po - pe) / (1 - pe), 3) if pe < 1 else 1.0}


RETRO_SECONDS = 300  # an alert this long after the visit came from a later library rebuild, not the live path


def time_to_flag(conn) -> dict:
    """CT entry to alert, for alerts raised when the page was visited. Alerts raised later by a kit
    rebuild (a page re-scored against new references) are counted separately as retroactive."""
    rows = conn.execute(
        "SELECT a.first_alert_at - c.ct_ts, a.first_alert_at - p.observed_at FROM alert_log a "
        "JOIN pages p ON p.id=a.page_id JOIN candidates c ON c.domain=p.domain "
        "WHERE p.source='live' AND c.ct_ts IS NOT NULL"
    ).fetchall()
    live = [r[0] for r in rows if r[0] is not None and r[0] >= 0 and r[1] is not None and r[1] <= RETRO_SECONDS]
    retro = sum(1 for r in rows if r[1] is not None and r[1] > RETRO_SECONDS)
    mins = sorted(x / 60 for x in live)
    if not mins:
        return {"n": 0, "retroactive_alerts": retro}
    p90 = mins[min(len(mins) - 1, int(math.ceil(0.9 * len(mins))) - 1)]
    return {
        "n": len(mins),
        "median_min": round(statistics.median(mins), 1),
        "p90_min": round(p90, 1),
        "retroactive_alerts": retro,
    }


def weekly_volume(conn, reviewer: str) -> dict:
    rows = conn.execute(
        "SELECT a.first_alert_at, a.kit_name FROM alert_log a JOIN labels l ON l.page_id=a.page_id "
        "WHERE l.reviewer=? AND l.label='scam-kit'",
        (reviewer,),
    ).fetchall()
    out: dict = defaultdict(Counter)
    for ts, kit in rows:
        wk = datetime.fromtimestamp(ts, UTC).strftime("%G-W%V")
        out[wk][group_of(kit)] += 1
    return {wk: dict(c) for wk, c in sorted(out.items())}


def cbr_forward(conn) -> dict:
    """Live candidates later added to the CBR list: external confirmation independent of us."""
    rows = conn.execute(
        "SELECT c.domain, c.first_seen, s.listed_at, EXISTS(SELECT 1 FROM alert_log a JOIN pages p ON p.id=a.page_id "
        "WHERE p.domain=c.domain) AS alerted FROM candidates c JOIN seeds s ON s.domain=c.domain AND s.source='cbr'"
    ).fetchall()
    later = [
        r
        for r in rows
        if r["listed_at"] and r["listed_at"] >= datetime.fromtimestamp(r["first_seen"], UTC).strftime("%Y-%m-%d")
    ]
    return {"candidates_later_listed": len(later), "of_which_alerted": sum(r["alerted"] for r in later)}


def filter_recall(conn, since: str = "2026-01-01") -> dict:
    """Share of recent CBR-listed domains our CT keyword filter would have passed."""
    doms = [
        r[0] for r in conn.execute("SELECT DISTINCT domain FROM seeds WHERE source='cbr' AND listed_at>=?", (since,))
    ]
    hits = sum(bool(names.keyword_matches(d)) for d in doms)
    return {"n": len(doms), "passed": hits, "recall": round(hits / len(doms), 3) if doms else None}


def backtest(conn, holdout_mod: int = 5) -> dict:
    """Hold out ~20% of seed pages, re-cluster the rest, check held-out pages match the right kit."""
    pages = kits.seed_pages(conn)
    deny = score.common_values(conn, refresh_seconds=0)
    # Multi-domain kits only: a held-out page of a single-site reference (ref-*) has no other
    # domain left to match, so counting it would only add guaranteed misses.
    full = {
        pid: kid
        for kid, pid in conn.execute(
            "SELECT m.kit_id, m.page_id FROM kit_members m JOIN kits k ON k.id=m.kit_id WHERE k.name LIKE 'kit-%'"
        )
    }
    held = [p for p in pages if p[0] in full and p[0] % holdout_mod == 0]
    train = [p for p in pages if p[0] not in {h[0] for h in held}]
    groups, _ = kits.cluster(train, deny)
    caught = 0
    for pid, dom, f in held:
        best_kit, best = None, None
        for g in groups:
            m = score.best_match(f, [x for x in g if x[1] != dom], deny)
            if m and m["alert"] and (best is None or m["score"] > best["score"]):
                best, best_kit = m, g
        if best_kit is not None:
            majority = Counter(full.get(x[0]) for x in best_kit).most_common(1)[0][0]
            caught += majority == full[pid]
    n = len(held)
    lo, hi = wilson(caught, n)
    return {
        "held_out": n,
        "caught_correct_kit": caught,
        "catch_rate": caught / n if n else None,
        "ci95": [round(lo, 3), round(hi, 3)],
    }


def sweep(conn, reviewer: str, before: int, grid: dict[str, list] | None = None) -> dict:
    """Threshold sweep on labeled live pages observed before `before` (the tuning set).

    Precision for the write-up must come from alerts after the freeze (`report(..., since=before)`),
    so thresholds are never tuned on the evaluation set (CLAUDE.md).
    """
    import itertools

    from . import config

    grid = grid or {
        "tlsh_max_distance": [50, 60, 70, 80, 90],
        "jaccard_min": [0.7, 0.8, 0.9],
        "copy_min_shared": [20, 30, 40],
    }
    rows = conn.execute(
        "SELECT p.id, p.domain, p.features, l.label FROM pages p JOIN labels l ON l.page_id=p.id "
        "WHERE p.source='live' AND p.page_class='content' AND l.reviewer=? AND p.observed_at<? "
        "AND l.label IN ('scam-kit','not-scam','decoy-cloaked')",
        (reviewer, before),
    ).fetchall()
    labeled = [(r["id"], r["domain"], json.loads(r["features"]), r["label"] == "scam-kit") for r in rows]
    positives = sum(y for *_, y in labeled)
    active = {r[0] for r in conn.execute("SELECT id FROM kits WHERE status='active'")}
    kits_m = {k: m for k, m in score.kit_members(conn).items() if k in active}
    deny = score.common_values(conn, refresh_seconds=0)
    cfg = config.load()["score"]
    saved = {k: cfg[k] for k in grid}
    out = []
    try:
        for combo in itertools.product(*grid.values()):
            cfg.update(dict(zip(grid, combo, strict=True)))
            tp = fp = 0
            for pid, dom, f, y in labeled:
                hit = any(
                    (m := score.best_match(f, [x for x in mem if x[0] != pid and x[1] != dom], deny)) and m["alert"]
                    for mem in kits_m.values()
                )
                tp += hit and y
                fp += hit and not y
            n = tp + fp
            lo, hi = wilson(tp, n)
            out.append(
                {
                    **dict(zip(grid, combo, strict=True)),
                    "alerts": n,
                    "tp": tp,
                    "precision": round(tp / n, 3) if n else None,
                    "ci95": [round(lo, 3), round(hi, 3)],
                    "recall_on_labeled": round(tp / positives, 3) if positives else None,
                }
            )
    finally:
        cfg.update(saved)
    return {"tuning_pages": len(labeled), "positives": positives, "current": saved, "grid": out}


def sample_estimate(conn, reviewer: str, sample: str) -> dict:
    """Scale the sample's precision CI to the alert population it was drawn from."""
    from . import sample as sample_mod

    meta = sample_mod.info(conn, sample)
    p = precision(conn, reviewer, sample=sample)
    pop = meta["population"] if meta else 0
    return {
        "sample": sample,
        "population_alerts": pop,
        "sample_size": len(sample_mod.members(conn, sample)),
        "labeled": p["n_labeled_alerts"],
        "estimated_true_alerts": round(p["precision"] * pop) if p["precision"] is not None else None,
        "estimated_true_alerts_ci95": [round(p["ci95"][0] * pop), round(p["ci95"][1] * pop)],
    }


def report(conn, reviewer: str, second: str | None = None, since: int = 0, sample: str | None = None) -> dict:
    out = {
        "precision": precision(conn, reviewer, since=since, sample=sample),
        "precision_kcda": precision(conn, reviewer, "kcda", since=since, sample=sample),
        "precision_cbr": precision(conn, reviewer, "cbr", since=since, sample=sample),
        "time_to_flag": time_to_flag(conn),
        "weekly_volume": weekly_volume(conn, reviewer),
        "cbr_forward": cbr_forward(conn),
        "filter_recall_cbr_2026": filter_recall(conn),
    }
    if sample:
        out["sample"] = sample_estimate(conn, reviewer, sample)
    if second:
        out["kappa"] = kappa(conn, reviewer, second, sample)
    return out


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)
