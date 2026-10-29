"""Showcase dashboard: static HTML generator (--public / --private), Rich terminal view, and
loopback-only read-only explorer (127.0.0.1).

Follows CLAUDE.md and SAFETY.md:
- Public mode exports only aggregate telemetry, cluster topology, and synthetic .test walkthroughs,
  verified against seeds/pages domains (including [.] defanged forms) and config/publish-deny.txt.
- Private mode stays in gitignored data/drafts/ (mode 0600) or on 127.0.0.1, defangs every domain,
  and shows sanitized plain text only — raw HTML is never rendered.
- Assistant suggestions (claude-assist) are displayed strictly as uncounted triage hints.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from . import config, evaluate, names, score

TOKEN_RE = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])", re.I)
PUBLIC_ALLOW = {
    "urlscan.io",
    "web.archive.org",
    "archive.org",
    "brooklynda.org",
    "cbr.ru",
    "github.com",
    "cloudflare.com",
    "google.com",
    "googleusercontent.com",
    "x.com",
    "example.com",
    "example.test",
    "dfpi.ca.gov",
    "t.me",
    "wa.me",
    "letsencrypt.org",
    "geomys.org",
}

SIGNAL_FAMILY = {
    "tlsh": "A",
    "tag_jaccard": "A",
    "copy": "A",
    "favicon_mmh3": "B",
    "asset_sha256": "B",
    "inline_script": "B",
    "asset_paths": "B",
    "title": "C",
    "telegram": "C",
    "whatsapp": "C",
    "crypto_addresses": "C",
    "header_order": "C",
    "generator": "C",
    "asn": "D",
    "ns": "D",
}


def connect_ro(path: str | None = None) -> sqlite3.Connection:
    """Open an existing database without creating or migrating private state."""
    target = Path(path or config.load()["paths"]["db"]).resolve()
    conn = sqlite3.connect(target.as_uri() + "?mode=ro", uri=True, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _defang_tokens(text: str) -> str:
    return TOKEN_RE.sub(lambda m: m.group(1) if m.group(1).lower() in PUBLIC_ALLOW else names.defang(m.group(1)), text)


def _private_domains(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT domain FROM seeds UNION SELECT domain FROM pages UNION SELECT domain FROM candidates"
    ).fetchall()
    return {r[0].lower() for r in rows if r[0]} - PUBLIC_ALLOW


def assert_public_safe(text: str, conn: sqlite3.Connection, root: Path | None = None) -> None:
    """Refuse to write public output if any seed/live domain (even defanged) or deny-pattern appears."""
    priv = _private_domains(conn)
    un_defanged = text.replace("[.]", ".")
    hits = sorted(
        {d for t in TOKEN_RE.findall(un_defanged) for d in priv if t.lower() == d or t.lower().endswith("." + d)}
    )
    if hits:
        raise ValueError(f"public privacy check failed: {len(hits)} private domain(s) matched")
    repo_root = root or Path(__file__).resolve().parents[2]
    deny_file = repo_root / "config" / "publish-deny.txt"
    if deny_file.exists():
        for line in deny_file.read_text().splitlines():
            pat = line.strip()
            if pat and not pat.startswith("#") and re.search(pat, un_defanged):
                raise ValueError("public privacy check failed: matched local deny pattern in config/publish-deny.txt")


def _ct_log_label(url: str) -> str:
    host = urlparse(url).netloc or url
    if "sycamore" in host:
        return "LE Sycamore"
    if "willow" in host:
        return "LE Willow"
    if "tuscolo" in host:
        return "Geomys Tuscolo"
    return "Other CT log"


def _collect_funnel_and_series(conn: sqlite3.Connection, metrics_path: Path | None = None) -> tuple[dict, dict, dict]:
    q = lambda sql, *p: conn.execute(sql, p).fetchone()[0]  # noqa: E731
    mpath = metrics_path or (Path(config.load()["paths"]["data_dir"]) / "metrics.jsonl")

    tot: Counter = Counter()
    ingest_buckets: dict[int, Counter] = defaultdict(Counter)
    fetch_buckets: dict[int, Counter] = defaultdict(Counter)
    first_ts: int | None = None
    last_ts: int | None = None

    if mpath.exists():
        for line in mpath.read_text().splitlines(keepends=True):
            if not line.strip():
                continue
            if not line.endswith("\n"):
                continue  # an append in progress is not a completed telemetry record
            m = json.loads(line)
            st, en = int(m.get("start", 0)), int(m.get("end", 0))
            if st:
                first_ts = st if first_ts is None else min(first_ts, st)
            if en:
                last_ts = en if last_ts is None else max(last_ts, en)
            slot = ((en or st) // 21600) * 21600  # 6-hour UTC buckets
            if m.get("component") == "ingest":
                for k in ("entries", "names", "filter_pass", "candidates_new", "bytes", "errors"):
                    tot[k] += int(m.get(k, 0))
                    ingest_buckets[slot][k] += int(m.get(k, 0))
            elif m.get("component") == "fetcher":
                tot["metrics_visits"] += int(m.get("visits", 0))
                fetch_buckets[slot]["visits"] += int(m.get("visits", 0))
                fetch_buckets[slot]["content"] += int(m.get("outcome_content", 0))
                fetch_buckets[slot]["alerts"] += int(m.get("alerts", 0))

    outcomes = dict(
        conn.execute("SELECT outcome, COUNT(*) FROM visits WHERE done_at IS NOT NULL GROUP BY 1").fetchall()
    )
    visits_done = sum(outcomes.values())
    seeds_by_source = dict(conn.execute("SELECT source, COUNT(*) FROM seeds GROUP BY source").fetchall())

    active_rows = conn.execute(
        "SELECT a.first_alert_at, a.kit_name FROM alert_log a "
        "WHERE EXISTS(SELECT 1 FROM scores s WHERE s.page_id=a.page_id AND s.alert=1)"
    ).fetchall()
    alerts_kcda = sum(1 for r in active_rows if evaluate.group_of(r["kit_name"]) == "kcda")
    alerts_cbr = len(active_rows) - alerts_kcda

    daily: dict[str, Counter] = defaultdict(Counter)
    for ts, kit_name in conn.execute("SELECT first_alert_at, kit_name FROM alert_log ORDER BY first_alert_at"):
        day = datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d")
        daily[day]["total"] += 1
        daily[day][evaluate.group_of(kit_name)] += 1

    candidates_ct = q("SELECT COUNT(*) FROM candidates WHERE origin='ct'")
    ct_names = tot["names"] or 0
    filter_pass = tot["filter_pass"]

    funnel = {
        "ct_entries": tot["entries"],
        "ct_names": ct_names,
        "ct_bytes_mb": round(tot["bytes"] / 1e6, 1),
        "filter_pass": filter_pass,
        "pass_rate_pct": round((filter_pass / ct_names) * 100, 3) if ct_names else None,
        "candidates_db": candidates_ct,
        "visits_done": visits_done,
        "visits_pending": q("SELECT COUNT(*) FROM visits WHERE done_at IS NULL"),
        "visits_by_outcome": outcomes,
        "pages_live_content": q("SELECT COUNT(*) FROM pages WHERE source='live' AND page_class='content'"),
        "alerts_total": q("SELECT COUNT(*) FROM alert_log"),
        "alerts_active": len(active_rows),
        "alerts_kcda": alerts_kcda,
        "alerts_cbr": alerts_cbr,
        "seeds_by_source": seeds_by_source,
        "kits_multi_active": q("SELECT COUNT(*) FROM kits WHERE name LIKE 'kit-%' AND status='active'"),
        "kits_multi_excluded": q("SELECT COUNT(*) FROM kits WHERE name LIKE 'kit-%' AND status!='active'"),
        "kits_single_ref": q("SELECT COUNT(*) FROM kits WHERE name LIKE 'ref-%' AND status='active'"),
        "ct_logs": [
            {"label": _ct_log_label(r[0]), "next_index": r[1]}
            for r in conn.execute("SELECT log_url, next_index FROM ct_state ORDER BY log_url")
        ],
    }

    fmt_slot = lambda s: datetime.fromtimestamp(s, UTC).strftime("%Y-%m-%d %H:00")  # noqa: E731
    timeseries = {
        "ingest_6h": [
            {
                "t": fmt_slot(s),
                "names": c["names"],
                "filter_pass": c["filter_pass"],
                "mb": round(c["bytes"] / 1e6, 1),
            }
            for s, c in sorted(ingest_buckets.items())[-48:]
        ],
        "fetch_6h": [
            {"t": fmt_slot(s), "visits": c["visits"], "content": c["content"], "alerts": c["alerts"]}
            for s, c in sorted(fetch_buckets.items())[-48:]
        ],
        "alerts_daily": [
            {"day": d, "total": c["total"], "kcda": c["kcda"], "cbr": c["cbr"]} for d, c in sorted(daily.items())
        ],
    }

    window = {
        "first_utc": datetime.fromtimestamp(first_ts, UTC).strftime("%Y-%m-%d %H:%M UTC") if first_ts else None,
        "last_utc": datetime.fromtimestamp(last_ts, UTC).strftime("%Y-%m-%d %H:%M UTC") if last_ts else None,
        "hours": round((last_ts - first_ts) / 3600, 1) if first_ts and last_ts and last_ts >= first_ts else 0,
    }
    return funnel, timeseries, window


def _ttf_with_buckets(conn: sqlite3.Connection) -> dict:
    rows = conn.execute(
        "SELECT a.first_alert_at - c.ct_ts, a.first_alert_at - p.observed_at FROM alert_log a "
        "JOIN pages p ON p.id=a.page_id JOIN candidates c ON c.domain=p.domain "
        "WHERE p.source='live' AND c.ct_ts IS NOT NULL"
    ).fetchall()
    mins = [
        r[0] / 60
        for r in rows
        if r[0] is not None and r[0] >= 0 and r[1] is not None and 0 <= r[1] <= evaluate.RETRO_SECONDS
    ]
    edges = [
        ("<25m", 0, 25),
        ("25–30m", 25, 30),
        ("30–60m", 30, 60),
        ("1–2h", 60, 120),
        ("2–6h", 120, 360),
        ("6–24h", 360, 1440),
        (">24h", 1440, float("inf")),
    ]
    buckets = [{"label": lbl, "count": sum(1 for m in mins if lo <= m < hi)} for lbl, lo, hi in edges]
    ordered = sorted(mins)
    base = {"n": len(mins), "retroactive_alerts": sum(r[1] is not None and r[1] > evaluate.RETRO_SECONDS for r in rows)}
    if ordered:
        base.update(
            median_min=round(statistics.median(ordered), 1),
            p90_min=round(ordered[math.ceil(0.9 * len(ordered)) - 1], 1),
        )
    return {**base, "buckets": buckets}


def _parse_desc_signals(desc: str | None) -> list[str]:
    if not desc or "links via " not in desc:
        return []
    tail = desc.split("links via ", 1)[1]
    out = []
    for part in tail.split(","):
        sig = part.strip().split("×")[0].strip()
        if sig in SIGNAL_FAMILY:
            out.append(f"{SIGNAL_FAMILY[sig]}:{sig}")
    return out


def _collect_kits(conn: sqlite3.Connection, mode: str) -> dict:
    member_stats: dict[int, list[tuple[str, int]]] = defaultdict(list)
    for kid, dom, feat_raw in conn.execute(
        "SELECT km.kit_id, p.domain, p.features FROM kit_members km JOIN pages p ON p.id=km.page_id"
    ):
        inv = json.loads(feat_raw).get("invest_terms", 0)
        member_stats[kid].append((dom, inv))

    kit_alerts: Counter = Counter()
    kit_live_sigs: dict[int, Counter] = defaultdict(Counter)
    sig_counter: Counter = Counter()
    combo_counter: Counter = Counter()

    seen_pages: set[int] = set()
    for pid, kid, details_raw in conn.execute(
        "SELECT s.page_id, s.kit_id, s.details FROM alert_log a "
        "JOIN scores s ON s.page_id=a.page_id JOIN pages p ON p.id=s.page_id "
        "WHERE s.alert=1 AND p.source='live' ORDER BY s.score DESC"
    ):
        kit_alerts[kid] += 1
        d = json.loads(details_raw)
        sigs = d.get("signals", [])
        for s in sigs:
            if SIGNAL_FAMILY.get(s.get("signal")) != s.get("family"):
                continue
            tag = f"{s['family']}:{s['signal']}"
            kit_live_sigs[kid][tag] += 1
        if pid not in seen_pages:
            seen_pages.add(pid)
            for s in {
                f"{x['family']}:{x['signal']}" for x in sigs if SIGNAL_FAMILY.get(x.get("signal")) == x.get("family")
            }:
                sig_counter[s] += 1
            strong = sorted(
                score.strong_families([x for x in sigs if SIGNAL_FAMILY.get(x.get("signal")) == x.get("family")])
            )
            combo = " + ".join(f"Fam {f}" for f in strong) if len(strong) >= 2 else "1 Strong + ≥2 Support"
            combo_counter[combo] += 1

    multi = []
    for r in conn.execute("SELECT id, name, description, status FROM kits WHERE name LIKE 'kit-%' ORDER BY id"):
        kid = r["id"]
        mems = member_stats.get(kid, [])
        pages_n = len(mems)
        doms_n = len({d for d, _ in mems})
        invs = sorted(inv for _, inv in mems)
        med_inv = invs[len(invs) // 2] if invs else 0
        sigs = _parse_desc_signals(r["description"]) or [k for k, _ in kit_live_sigs[kid].most_common(4)]
        summary = (
            f"{pages_n} seed pages across {doms_n} listed domains · median {med_inv} invest terms"
            if mode == "public"
            else _defang_tokens(r["description"] or f"{pages_n} pages across {doms_n} domains")
        )
        multi.append(
            {
                "name": (f"kit-{kid:02d}" + ("-KCDA" if evaluate.group_of(r["name"]) == "kcda" else ""))
                if mode == "public"
                else r["name"],
                "group": evaluate.group_of(r["name"]),
                "status": "active" if r["status"] == "active" else "excluded",
                "pages": pages_n,
                "domains": doms_n,
                "live_alerts": kit_alerts[kid],
                "median_invest_terms": med_inv,
                "signals": sigs,
                "summary": summary,
            }
        )
    multi.sort(key=lambda x: (x["status"] == "active", x["live_alerts"], x["domains"], x["pages"]), reverse=True)

    ref_rows = conn.execute("SELECT id, name FROM kits WHERE name LIKE 'ref-%' AND status='active'").fetchall()
    ref_kcda = sum(1 for r in ref_rows if evaluate.group_of(r["name"]) == "kcda")
    ref_alerts = sum(kit_alerts[r["id"]] for r in ref_rows)

    return {
        "multi": multi,
        "single_ref_summary": {
            "count": len(ref_rows),
            "kcda_count": ref_kcda,
            "cbr_count": len(ref_rows) - ref_kcda,
            "live_alerts": ref_alerts,
        },
        "signal_matrix": {
            "by_signal": [
                {"family": k.split(":")[0], "signal": k.split(":")[1], "alerts": v}
                for k, v in sig_counter.most_common(12)
            ],
            "by_family_combo": [{"combo": k, "alerts": v} for k, v in combo_counter.most_common()],
        },
    }


def _safe_kit_name(name: str | None, mode: str) -> str:
    if not name:
        return "unknown"
    if name.startswith("ref-"):
        if mode == "public":
            return "ref-site-KCDA" if name.endswith("-KCDA") else "ref-site"
        body = name[4:-5] if name.endswith("-KCDA") else name[4:]
        suffix = "-KCDA" if name.endswith("-KCDA") else ""
        return f"ref-{names.defang(body)}{suffix}"
    return name
