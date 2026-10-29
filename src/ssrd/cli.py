"""`ssrd` command-line entry point."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import config, db

FIREWALL_MARKER = Path("/run/ssrd/firewall-ok")


def _fetch_preflight(allow_host: bool) -> dict:
    """Refuse to fetch unless every safety layer is in place (SAFETY.md)."""
    from . import safety

    cfg = config.load()["fetch"]
    if not cfg["enabled"]:
        sys.exit("fetch.enabled = false in config/ssrd.toml. Read SAFETY.md, then enable it.")
    if not FIREWALL_MARKER.exists() and not allow_host:
        sys.exit(
            "Container egress firewall not detected. Run the fetcher via `docker compose up fetcher` "
            "(or pass --allow-host to accept running without layer 2)."
        )
    info = safety.check_egress()
    print(f"egress ok: {info}", file=sys.stderr)
    return info


def cmd_init(a):
    db.connect()
    print(f"db ready at {config.load()['paths']['db']}")


def cmd_ingest(a):
    from .ct import Tailer

    Tailer(db.connect()).run(once=a.once)


def cmd_fetcher(a):
    from .fetch import Visitor

    _fetch_preflight(a.allow_host)
    Visitor(db.connect()).run(once=a.once)


def cmd_safety_check(a):
    from . import safety

    ok = True
    try:
        info = safety.check_egress()
        print(f"[ok]   egress {info['ip']} AS{info['asn']} ({info.get('cc')}) is allowed")
    except Exception as e:
        ok = False
        print(f"[FAIL] egress: {e}")
    in_container = FIREWALL_MARKER.exists()
    if in_container:
        status = Path("/proc/self/status").read_text()
        cap_eff = next(line.split()[1] for line in status.splitlines() if line.startswith("CapEff"))
        cap_bnd = next(line.split()[1] for line in status.splitlines() if line.startswith("CapBnd"))
        unprivileged = os.getuid() != 0 and int(cap_eff, 16) == 0 and int(cap_bnd, 16) == 0
        ok &= unprivileged
        print(f"[{'ok' if unprivileged else 'FAIL'}]   process uid={os.getuid()} CapEff={cap_eff} CapBnd={cap_bnd}")
    print(
        f"[{'ok' if in_container else 'warn'}]   container firewall marker {'present' if in_container else 'absent (host run)'}"
    )
    for name, blocked in safety.probe_private_blocked().items():
        status = "ok" if blocked else ("FAIL" if in_container else "warn")
        ok &= blocked or not in_container
        print(f"[{status}]   private target {name}: {'blocked' if blocked else 'REACHABLE'}")
    for host in ("localhost", "metadata.google.internal"):
        try:
            safety.resolve_public(host)
            ok = False
            print(f"[FAIL] app guard allowed {host}")
        except safety.UnsafeTarget:
            print(f"[ok]   app guard refuses {host}")
    cfg = config.load()["fetch"]
    print(f"[info] fetch.enabled={cfg['enabled']} mode={cfg['mode']} rate={cfg['requests_per_minute']}/min")
    sys.exit(0 if ok else 1)


def cmd_fetch_one(a):
    from . import fingerprint, safety
    from .fetch import SafeFetcher

    print(f"egress: {safety.check_egress()}", file=sys.stderr)
    res = SafeFetcher().get(a.url)
    out = {
        "url": res.url,
        "final_url": res.final_url,
        "status": res.status,
        "ip": res.ip,
        "error": res.error,
        "chain": res.chain,
        "content_type": res.content_type,
        "bytes": len(res.body or b""),
    }
    if res.body:
        f = fingerprint.html_features(res.body, res.final_url or res.url, res.content_type, res.status, res.headers)
        out["features"] = {k: v for k, v in f.items() if k != "minhash"}
    print(json.dumps(out, indent=2, ensure_ascii=False))


def cmd_seeds(a):
    from . import seeds

    conn = db.connect()
    if a.which == "refresh":
        print(
            f"queued {seeds.enqueue_refresh(conn, a.source, a.limit)} {a.source} seed domains for live refresh visits"
        )
    elif a.which == "cbr":
        path = (
            seeds.download_cbr()
            if a.download
            else Path(config.load()["paths"]["data_dir"]) / "raw" / "cbr_blacklist.json"
        )
        rows = seeds.parse_cbr(path, since=a.since)
        print(f"parsed {len(rows)} CBR seed domains since {a.since}; inserted {seeds.upsert(conn, rows)} new")
    else:
        print(f"inserted {seeds.import_manual(conn, Path(a.file), a.source)} from {a.file}")


def cmd_urlscan(a):
    from . import urlscan

    try:
        _urlscan(a)
    except urlscan.NeedsApiKey as e:
        sys.exit(str(e))


def _urlscan(a):
    from . import urlscan

    conn = db.connect()
    c = urlscan.Client(conn)
    if not c.has_key:
        print("warning: URLSCAN_API_KEY not set; anonymous access may be refused", file=sys.stderr)
    if a.action == "quotas":
        print(json.dumps(c.quotas(), indent=2))
    elif a.action == "search":
        for h in c.search(a.query, max_results=a.limit):
            print(
                h["task"]["time"],
                h["page"].get("domain"),
                h["page"].get("status"),
                (h["page"].get("title") or "")[:80],
                h["task"]["uuid"],
            )
    elif a.action == "kcda":
        from . import names, seeds

        hits = c.search('page.title:"This Website Has Been Seized"', max_results=a.limit)
        kcda_hashes, verdict = set(), {}
        for h in hits:  # keep only Kings County DA banners; the title is shared with FBI/other seizures
            res = c.result(h["task"]["uuid"])
            reqs = (res or {}).get("data", {}).get("requests", [])
            mh = reqs[0].get("response", {}).get("hash") if reqs else None
            if mh and mh not in verdict:
                body = (c.response_body(mh) or c.dom(h["task"]["uuid"]) or b"").upper()
                verdict[mh] = b"KINGS COUNTY DISTRICT ATTORNEY" in body or b"#KCDA" in body
            if mh and verdict[mh]:
                kcda_hashes.add(mh)
        for mh in kcda_hashes:  # expand: every scan serving the same banner document
            hits += c.search(f"hash:{mh}", max_results=a.limit)
        doms = sorted({h["page"]["domain"] for h in hits if h.get("page", {}).get("domain")})
        keep = []
        for h in hits:
            res = c.result(h["task"]["uuid"])
            reqs = (res or {}).get("data", {}).get("requests", [])
            if reqs and reqs[0].get("response", {}).get("hash") in kcda_hashes:
                keep.append(h["page"]["domain"])
        rows = [
            {
                "domain": names.registrable(d) or d,
                "source": "kcda",
                "listed_at": None,
                "name": None,
                "note": "urlscan scan serving KCDA seizure banner",
            }
            for d in sorted(set(keep))
        ]
        conn.execute("DELETE FROM seeds WHERE source='kcda' AND note='urlscan seizure-banner title'")
        print(
            f"{len(doms)} seized domains seen, {len(set(keep))} with the KCDA banner "
            f"({len(kcda_hashes)} banner hashes); inserted {seeds.upsert(conn, rows)} new kcda seeds"
        )
    elif a.action == "background":
        q = a.query or "date:>now-3d AND page.status:200 AND NOT page.title:seized"
        print(f"stored {urlscan.harvest_background(conn, c, a.limit, q)} background pages for query: {q}")
    elif a.action == "harvest":
        q = "SELECT domain FROM seeds WHERE source=? AND domain NOT IN (SELECT domain FROM pages WHERE source='urlscan') ORDER BY listed_at DESC LIMIT ?"
        doms = [r[0] for r in conn.execute(q, (a.source, a.limit))]
        extra = 'AND NOT page.title:"Seized"' if a.source == "kcda" else ""
        total = 0
        for i, d in enumerate(doms, 1):
            try:
                n = urlscan.harvest_domain(conn, c, d, extra_q=extra)
            except urlscan.QuotaExceeded as e:
                print(f"quota exceeded after {i - 1} domains: {e}")
                break
            total += n
            print(f"[{i}/{len(doms)}] {d}: {n} content pages (total {total})", flush=True)


def cmd_wayback(a):
    from . import wayback

    conn = db.connect()
    q = (
        "SELECT DISTINCT domain FROM seeds WHERE source=? AND domain NOT IN "
        "(SELECT domain FROM pages WHERE source='wayback') ORDER BY listed_at DESC LIMIT ?"
    )
    client, total = wayback.Client(), 0
    doms = [r[0] for r in conn.execute(q, (a.source, a.limit))]
    for i, d in enumerate(doms, 1):
        n = wayback.harvest_domain(conn, client, d, before=a.before)
        total += n
        print(f"[{i}/{len(doms)}] {d}: {n} content pages (total {total})", flush=True)
    print(f"favicons added from archive.org: {wayback.add_favicons(conn, client)}")


def cmd_train_names(a):
    from . import name_model

    print(json.dumps(name_model.train(db.connect(), split_date=a.split_date), indent=1))


def cmd_refeature(a):
    from . import refeature

    print(refeature.run(db.connect()))


def cmd_kits(a):
    from . import kits, score

    conn = db.connect()
    for k in kits.build(conn):
        flag = "" if k["status"] == "active" else f"  [{k['status']}]"
        print(f"{k['kit']}: {k['description']}{flag}")
    print(f"rescored live pages: {dict(score.rescore_live(conn))}")


def cmd_review(a):
    from . import review

    review.run(db.connect(), a.reviewer, a.all, a.blind, a.sample, a.limit, a.suggested)


def cmd_evaluate(a):
    from . import evaluate

    conn = db.connect()
    freeze = _ts(a.freeze) if a.freeze else 0
    if a.sweep:
        if not freeze:
            raise SystemExit("--sweep needs --freeze YYYY-MM-DD: tune on pages before it, evaluate after it")
        print(evaluate.dumps(evaluate.sweep(conn, a.reviewer, freeze)))
        return
    rep = evaluate.report(conn, a.reviewer, a.second, since=freeze, sample=a.sample)
    if a.backtest:
        rep["backtest"] = evaluate.backtest(conn)
    print(evaluate.dumps(rep))


def _ts(day: str) -> int:
    from datetime import UTC, datetime

    return int(datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=UTC).timestamp())


def cmd_stats(a):
    conn = db.connect()
    q = lambda s: conn.execute(s).fetchone()[0]  # noqa: E731
    print(
        json.dumps(
            {
                "seeds": dict(conn.execute("SELECT source, COUNT(*) FROM seeds GROUP BY source").fetchall()),
                "pages": dict(
                    conn.execute("SELECT source||':'||page_class, COUNT(*) FROM pages GROUP BY 1").fetchall()
                ),
                "kits": q("SELECT COUNT(*) FROM kits"),
                "candidates": q("SELECT COUNT(*) FROM candidates"),
                "visits_pending": q("SELECT COUNT(*) FROM visits WHERE done_at IS NULL"),
                "visits_by_outcome": dict(
                    conn.execute("SELECT outcome, COUNT(*) FROM visits WHERE done_at IS NOT NULL GROUP BY 1").fetchall()
                ),
                "alerts": q("SELECT COUNT(*) FROM alert_log"),
                "labels": dict(conn.execute("SELECT label, COUNT(*) FROM labels GROUP BY 1").fetchall()),
                "ct_state": {r[0]: r[1] for r in conn.execute("SELECT log_url, next_index FROM ct_state")},
            },
            indent=2,
            ensure_ascii=False,
        )
    )


def health_report(conn) -> dict:
    """Operational snapshot: is the pipeline alive, keeping up, and close to alerting?"""
    from collections import Counter

    from . import names, score

    n = db.now()
    q = lambda sql, *p: conn.execute(sql, p).fetchone()[0]  # noqa: E731
    near = []
    for r in conn.execute(
        "SELECT p.id, p.domain, k.name, s.score, s.details FROM scores s JOIN pages p ON p.id=s.page_id "
        "JOIN kits k ON k.id=s.kit_id WHERE s.alert=0 AND p.source='live' ORDER BY s.score DESC LIMIT 200"
    ):
        sig = json.loads(r["details"])["signals"]
        if score.strong_families(sig):
            near.append(
                {
                    "domain": names.defang(r["domain"]),
                    "kit": r["name"],
                    "score": r["score"],
                    "signals": sorted({f"{x['family']}:{x['signal']}" for x in sig}),
                }
            )
    bytes_24h = 0
    mpath = Path(config.load()["paths"]["data_dir"]) / "metrics.jsonl"
    if mpath.exists():
        for line in mpath.read_text().splitlines()[-500:]:
            m = json.loads(line)
            if m.get("component") == "ingest" and m.get("end", 0) > n - 86400:
                bytes_24h += m.get("bytes", 0)
    return {
        "db_write_probe": db.write_probe(seconds=3),
        "ingest": {
            "seconds_since_ct_state_update": n - (q("SELECT MAX(updated_at) FROM ct_state") or 0),
            "ct_lag_seconds": n - (q("SELECT MAX(ct_ts) FROM candidates WHERE origin='ct'") or n),
            "candidates_last_hour": q("SELECT COUNT(*) FROM candidates WHERE origin='ct' AND first_seen>?", n - 3600),
            "names_tile_mb_last_24h": round(bytes_24h / 1e6, 1),
        },
        "fetch": {
            "visits_last_hour": q(
                "SELECT COUNT(*) FROM visits WHERE done_at>? AND outcome NOT IN ('expired','refiltered')", n - 3600
            ),
            "due_now_ct": q(
                "SELECT COUNT(*) FROM visits v JOIN candidates c USING(domain) WHERE v.done_at IS NULL AND v.due_at<=? AND c.origin='ct'",
                n,
            ),
            "due_now_seed_refresh": q(
                "SELECT COUNT(*) FROM visits v JOIN candidates c USING(domain) WHERE v.done_at IS NULL AND c.origin='seed'"
            ),
            "outcomes_last_24h": dict(
                Counter(r[0] for r in conn.execute("SELECT outcome FROM visits WHERE done_at>?", (n - 86400,)))
            ),
        },
        "kits": {
            "active": q("SELECT COUNT(*) FROM kits WHERE status='active'"),
            "excluded": q("SELECT COUNT(*) FROM kits WHERE status!='active'"),
        },
        "alerts_total": q("SELECT COUNT(*) FROM alert_log"),
        "alerts_last_24h": q("SELECT COUNT(*) FROM alert_log WHERE first_alert_at>?", n - 86400),
        "near_misses": near[:10],
    }


def cmd_health(a):
    rep = health_report(db.connect())
    if a.summary:
        f = rep["fetch"]
        print(
            f"alerts 24h: {rep['alerts_last_24h']} (total {rep['alerts_total']}) · visits/h: {f['visits_last_hour']} "
            f"· CT due: {f['due_now_ct']} · expired 24h: {f['outcomes_last_24h'].get('expired', 0)} "
            f"· db writable: {rep['db_write_probe']['writable_share']}"
        )
        return
    print(json.dumps(rep, indent=2, ensure_ascii=False))


def watch_problems(rep: dict) -> list[str]:
    """Liveness rules for the hourly watchdog (SPEC week 2: alert if certs/s drops to 0)."""
    w = config.load()["watch"]
    i, f = rep["ingest"], rep["fetch"]
    out = []
    if i["seconds_since_ct_state_update"] > w["ct_stale_seconds"]:
        out.append(f"CT ingest stalled for {i['seconds_since_ct_state_update'] // 60} min")
    if i["candidates_last_hour"] == 0:
        out.append("no new CT candidates in the last hour")
    if f["visits_last_hour"] == 0 and f["due_now_ct"] > 0:
        out.append(f"fetcher idle with {f['due_now_ct']} visits due")
    if f["due_now_ct"] > w["max_due_ct"]:
        out.append(f"fetch backlog {f['due_now_ct']} (> {w['max_due_ct']})")
    if rep["db_write_probe"]["writable_share"] < 1.0:
        out.append("database write lock contention")
    return out


def cmd_watch(a):
    problems = watch_problems(health_report(db.connect()))
    if problems:
        print("; ".join(problems))
        raise SystemExit(1)
    print("ok")


def cmd_memo(a):
    from . import memo

    md, csv_path = memo.build(db.connect(), a.reviewer, a.second, _ts(a.freeze) if a.freeze else 0, a.top, a.sample)
    print(f"wrote {md} and {csv_path} (private; review before sending anything)")


def review_keys() -> list[str]:
    from .review import KEYS

    return list(KEYS.values())


def cmd_export(a):
    from . import export

    for path, n in export.write(db.connect(), a.reviewer):
        print(f"{path}: {n} leads")


def cmd_backup(a):
    from . import backup

    out = backup.run(Path(a.out).expanduser(), a.keep)
    print(f"wrote {out} ({out.stat().st_size / 1e6:.0f} MB); passphrase in {backup.key_path()}")


def cmd_sample(a):
    from . import sample

    conn = db.connect()
    if a.action == "draw":
        until = _ts(a.until) if a.until else db.now()
        try:
            print(json.dumps(sample.draw(conn, a.name, a.n, _ts(a.since), until, a.seed)))
        except sample.SampleExists as e:
            raise SystemExit(str(e)) from None
    else:
        meta = sample.info(conn, a.name)
        if meta is None:
            raise SystemExit(f"no sample {a.name!r}")
        labeled = conn.execute(
            "SELECT l.reviewer, COUNT(*) FROM sample_members m JOIN labels l ON l.page_id=m.page_id "
            "WHERE m.name=? GROUP BY 1",
            (a.name,),
        ).fetchall()
        print(json.dumps({**meta, "labeled": dict(labeled)}, indent=2))


def cmd_prelabel(a):
    from . import prelabel

    print(json.dumps(prelabel.run(db.connect())))


def cmd_reclassify(a):
    from .refeature import reclassify

    print(f"marked parked: {reclassify(db.connect())}")


def cmd_manifest_hash(a):
    from .fetch import daily_manifest_hashes

    print("\n".join(daily_manifest_hashes()))


def cmd_dashboard(a):
    from rich.console import Console

    from . import dashboard

    mode = "private" if a.private else "public"
    since = _ts(a.freeze) if a.freeze else 0
    conn = dashboard.connect_ro()
    try:
        payload = dashboard.collect_payload(
            conn,
            mode=mode,
            reviewer=a.reviewer,
            second=a.second,
            since=since,
            sample=a.sample,
            run_backtest=a.backtest,
        )
        if a.terminal:
            dashboard.render_terminal(Console(), payload)
        if a.svg:
            svg_path = dashboard.export_svg(payload, Path(a.svg))
            if mode == "public":
                dashboard.assert_public_safe(svg_path.read_text(), conn)
            print(f"wrote {svg_path}")
        if not a.out and a.terminal and not a.public and not a.private:
            return
        dest = dashboard.write_dashboard(
            conn,
            mode=mode,
            out=Path(a.out) if a.out else None,
            payload=payload,
        )
        note = "public redacted showcase" if mode == "public" else "private 0600 briefing; never publish"
        print(f"wrote {dest} ({note})")
    finally:
        conn.close()


def cmd_serve(a):
    from . import dashboard

    dashboard.serve(
        a.host,
        a.port,
        reviewer=a.reviewer,
        second=a.second,
        since=_ts(a.freeze) if a.freeze else 0,
        sample=a.sample,
    )


def main(argv=None):
    p = argparse.ArgumentParser(prog="ssrd", description="Scam-Site Respawn Detector")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    s = sub.add_parser("ingest", help="tail CT names tiles into candidates")
    s.add_argument("--once", action="store_true")
    s.set_defaults(fn=cmd_ingest)
    s = sub.add_parser("fetcher", help="run due passive visits (guarded)")
    s.add_argument("--once", action="store_true")
    s.add_argument("--allow-host", action="store_true", help="run without the container firewall (not recommended)")
    s.set_defaults(fn=cmd_fetcher)
    sub.add_parser("safety-check").set_defaults(fn=cmd_safety_check)
    s = sub.add_parser("fetch-one", help="guarded single fetch for testing; prints features, stores nothing")
    s.add_argument("url")
    s.set_defaults(fn=cmd_fetch_one)
    s = sub.add_parser("seeds")
    s.add_argument("which", choices=["cbr", "import", "refresh"])
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--download", action="store_true")
    s.add_argument("--since", default="2025-07-01")
    s.add_argument("--file")
    s.add_argument("--source", default="manual")
    s.set_defaults(fn=cmd_seeds)
    s = sub.add_parser("urlscan", help="search/result only; never submits scans")
    s.add_argument("action", choices=["quotas", "search", "kcda", "harvest", "background"])
    s.add_argument("query", nargs="?")
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--source", default="cbr")
    s.set_defaults(fn=cmd_urlscan)
    s = sub.add_parser("wayback", help="archived pre-seizure pages for seeds (archive.org only)")
    s.add_argument("--source", default="kcda")
    s.add_argument("--before", default="2026-10-01", help="only snapshots before this date (YYYY-MM-DD)")
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(fn=cmd_wayback)
    s = sub.add_parser("train-names", help="train the CT name classifier (needs `uv run --group train`)")
    s.add_argument("--split-date", default="2026-07-01")
    s.set_defaults(fn=cmd_train_names)
    sub.add_parser("refeature", help="recompute stored page features (no site contact)").set_defaults(fn=cmd_refeature)
    sub.add_parser("kits", help="cluster seed pages into kits and rescore").set_defaults(fn=cmd_kits)
    s = sub.add_parser("review")
    s.add_argument("--reviewer", default=os.environ.get("SSRD_REVIEWER", "rahil"))
    s.add_argument("--all", action="store_true", help="include non-alerting live pages")
    s.add_argument("--blind", action="store_true", help="hide assistant suggestions (use for the second labeler)")
    s.add_argument("--sample", help="label a frozen random sample (see `ssrd sample draw`)")
    s.add_argument("--limit", type=int, help="with --sample: only the first N positions (second labeler: 50)")
    s.add_argument(
        "--suggested", choices=sorted(set(review_keys())), help="only alerts the assistant suggested this label for"
    )
    s.set_defaults(fn=cmd_review)
    s = sub.add_parser("evaluate")
    s.add_argument("--reviewer", default=os.environ.get("SSRD_REVIEWER", "rahil"))
    s.add_argument("--second")
    s.add_argument("--backtest", action="store_true")
    s.add_argument("--freeze", help="threshold freeze date: precision counts alerts on/after it")
    s.add_argument("--sweep", action="store_true", help="threshold sweep on labeled pages before --freeze")
    s.add_argument("--sample", help="estimate precision from this frozen random sample")
    s.set_defaults(fn=cmd_evaluate)
    sub.add_parser("stats").set_defaults(fn=cmd_stats)
    s = sub.add_parser("health", help="liveness, throughput, lock probe, alerts and near-misses")
    s.add_argument("--summary", action="store_true", help="one line (used by the daily timer)")
    s.set_defaults(fn=cmd_health)
    sub.add_parser("manifest-hash").set_defaults(fn=cmd_manifest_hash)
    s = sub.add_parser("sample", help="frozen random sample of alerts for labeling (precision estimate)")
    s.add_argument("action", choices=["draw", "show"])
    s.add_argument("name")
    s.add_argument("--n", type=int, default=100)
    s.add_argument("--since", default="2026-11-09", help="window start YYYY-MM-DD (alerts on/after)")
    s.add_argument("--until", help="window end YYYY-MM-DD (exclusive; default now)")
    s.add_argument("--seed", type=int, default=20261116)
    s.set_defaults(fn=cmd_sample)
    sub.add_parser("prelabel", help="rule-based assistant suggestions for unsuggested alerts").set_defaults(
        fn=cmd_prelabel
    )
    sub.add_parser("reclassify", help="offline: re-apply parked patterns to stored pages").set_defaults(
        fn=cmd_reclassify
    )
    sub.add_parser("watch", help="exit 1 and print problems if ingest/fetch look stalled").set_defaults(fn=cmd_watch)
    s = sub.add_parser("memo", help="write the private VCU memo draft and leads CSV to data/drafts/")
    s.add_argument("--reviewer", default=os.environ.get("SSRD_REVIEWER", "rahil"))
    s.add_argument("--second")
    s.add_argument("--freeze", help="threshold freeze date; precision counts alerts on/after it")
    s.add_argument("--top", type=int, default=25)
    s.add_argument("--sample")
    s.set_defaults(fn=cmd_memo)
    s = sub.add_parser("export", help="per-recipient CSVs of leads a human labeled scam-kit (data/drafts/reports/)")
    s.add_argument("--reviewer", default=os.environ.get("SSRD_REVIEWER", "rahil"))
    s.set_defaults(fn=cmd_export)
    s = sub.add_parser("backup", help="gpg-encrypted snapshot of data/ (SPEC R9)")
    s.add_argument("--out", default="~/ssrd-backups")
    s.add_argument("--keep", type=int, default=4)
    s.set_defaults(fn=cmd_backup)
    s = sub.add_parser("dashboard", help="build static showcase HTML (--public or --private) or terminal view")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--public", action="store_true", help="redacted showcase for docs/ (default)")
    g.add_argument("--private", action="store_true", help="private defanged briefing in data/drafts/ (mode 0600)")
    s.add_argument("--out", help="override output HTML path")
    s.add_argument("--terminal", action="store_true", help="print Rich multi-panel terminal dashboard")
    s.add_argument("--svg", help="export Rich terminal dashboard as SVG")
    s.add_argument("--reviewer", default=os.environ.get("SSRD_REVIEWER", "rahil"))
    s.add_argument("--second")
    s.add_argument("--freeze", help="threshold freeze date; precision counts alerts on/after it")
    s.add_argument("--sample")
    s.add_argument("--backtest", action="store_true", help="compute fresh 20%% hold-out backtest")
    s.set_defaults(fn=cmd_dashboard)
    s = sub.add_parser("serve", help="run read-only local explorer on 127.0.0.1")
    s.add_argument("--host", default="127.0.0.1", help="loopback address only (127.0.0.1 or ::1)")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--reviewer", default=os.environ.get("SSRD_REVIEWER", "rahil"))
    s.add_argument("--second")
    s.add_argument("--freeze")
    s.add_argument("--sample")
    s.set_defaults(fn=cmd_serve)
    a = p.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    a.fn(a)


if __name__ == "__main__":
    main()
