"""Describe evaluation populations and restrict public aggregate labels."""

from . import config, evaluate


def _annotate_evaluation(conn, data: dict, reviewer: str, sample: str | None) -> None:
    ev = data["evaluation"]
    meta = conn.execute("SELECT population FROM samples WHERE name=?", (sample,)).fetchone() if sample else None
    if sample and meta is None:
        raise ValueError("unknown frozen evaluation sample")
    size = conn.execute("SELECT COUNT(*) FROM sample_members WHERE name=?", (sample,)).fetchone()[0] if sample else 0
    for key in ("precision", "precision_kcda", "precision_cbr"):
        metric = ev[key]
        complete = bool(sample and size and ev["precision"]["n_labeled_alerts"] == size)
        metric.update(
            basis="completed frozen random sample" if complete else "reviewed alert subset",
            representative=complete,
            sample_size=size if sample else None,
            minimum_sample_met=complete and metric["n_labeled_alerts"] >= 50,
        )
    if sample and not ev["precision"]["representative"]:
        ev["sample"]["estimated_true_alerts"] = None
        ev["sample"]["estimated_true_alerts_ci95"] = None
    # Same-day listing has unknown order: it cannot establish a later confirmation.
    later = conn.execute(
        "SELECT DISTINCT c.domain FROM candidates c JOIN seeds s ON s.domain=c.domain "
        "WHERE s.source='cbr' AND s.listed_at > date(c.first_seen, 'unixepoch')"
    ).fetchall()
    alerted = {r[0] for r in conn.execute("SELECT p.domain FROM alert_log a JOIN pages p ON p.id=a.page_id")}
    ev["cbr_forward"] = {
        "candidates_later_listed": len(later),
        "of_which_alerted": sum(r[0] in alerted for r in later),
        "basis": "listing date strictly after first-seen UTC date; same-day order unknown",
    }
    if reviewer == config.load()["review"]["assist_reviewer"]:
        raise ValueError("assistant suggestions cannot be used as human evaluation")


def _counts(values: dict, allowed: set[str]) -> dict:
    out = {}
    for key, count in values.items():
        safe = key if key in allowed else "other"
        out[safe] = out.get(safe, 0) + count
    return out


def _public_labels(data: dict) -> None:
    """DB labels are not trusted publication copy, even when they contain no domain."""
    f, ev = data["funnel"], data["evaluation"]
    f["seeds_by_source"] = _counts(f["seeds_by_source"], {"cbr", "kcda", "dfpi", "manual"})
    f["visits_by_outcome"] = _counts(
        f["visits_by_outcome"], {"content", "parked", "error", "decoy-cloaked", "expired", "blocked", "seized"}
    )
    for key in ("assist_triage", "human_labels"):
        ev[key] = _counts(ev[key], set(evaluate.LABELS))
    for key in ("precision", "precision_kcda", "precision_cbr"):
        ev[key]["label_counts"] = _counts(ev[key]["label_counts"], set(evaluate.LABELS))
    for i, item in enumerate(ev["samples_drawn"], 1):
        item["name"] = f"sample-{i}"
    if "sample" in ev:
        ev["sample"]["sample"] = "selected frozen sample"


def _lead_confidence(conn) -> dict:
    """Count human-reviewed leads without loading private capture features into the export."""
    assist = config.load()["review"]["assist_reviewer"]
    out = {"confirmed": 0, "likely": 0, "speculative": 0}
    rows = conn.execute(
        "SELECT a.page_id, a.first_alert_at, p.domain, "
        "SUM(CASE WHEN l.label='scam-kit' THEN 1 ELSE 0 END) AS yes, "
        "SUM(CASE WHEN l.label IN ('not-scam','parked','error','decoy-cloaked') THEN 1 ELSE 0 END) AS no "
        "FROM alert_log a JOIN pages p ON p.id=a.page_id "
        "LEFT JOIN labels l ON l.page_id=a.page_id AND l.reviewer!=? "
        "WHERE EXISTS(SELECT 1 FROM scores s WHERE s.page_id=a.page_id AND s.alert=1) "
        "GROUP BY a.page_id",
        (assist,),
    ).fetchall()
    later = {
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT c.domain FROM candidates c JOIN seeds s ON s.domain=c.domain "
            "WHERE s.source='cbr' AND s.listed_at > date(c.first_seen, 'unixepoch')"
        )
    }
    for row in rows:
        if row["no"] and not row["yes"]:
            continue
        key = (
            "confirmed"
            if row["yes"] >= 2 or (row["yes"] == 1 and row["domain"] in later)
            else "likely"
            if row["yes"]
            else "speculative"
        )
        out[key] += 1
    return out
