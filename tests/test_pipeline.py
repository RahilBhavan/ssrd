import gzip
import json
from pathlib import Path

import httpx

from ssrd import config, db, evaluate, kits, safety
from ssrd import fingerprint as fp
from ssrd.fetch import RateLimiter, SafeFetcher, Visitor
from tests.conftest import FIX

KIT2_EXTRA = '<div class="ticker">{x}</div>' * 1


def add_page(conn, source, domain, body, ref=None):
    f = fp.html_features(body, f"https://{domain}/", "text/html", 200, [])
    cur = conn.execute(
        "INSERT INTO pages(source,ref,domain,observed_at,page_class,features) VALUES(?,?,?,?,?,?)",
        (source, ref or domain, domain, db.now(), f["page_class"], db.dumps(f)),
    )
    return cur.lastrowid


def other_kit(brand):
    return f"""<html lang="en"><head><title>{brand} | Mining Pool</title><script src="/assets/pool/core.js"></script>
<script src="/assets/pool/ui.js"></script></head><body><nav><a href="/">Home</a><a href="/plans">Plans</a><a href="/faq">FAQ</a></nav>
<div class="card"><h2>Cloud mining contracts</h2><p>Hashrate packages with daily payouts in USDT. Join {brand} today.</p></div>
<div class="card"><h2>Referral</h2><p>Earn 10% from every friend you invite to {brand}.</p></div>
<p>Contact: https://t.me/pool_helpdesk_bot</p>
<script>var POOL={{"api":"/rpc","coins":["BTC","LTC","DOGE"],"payout":"daily","theme":"light","version":"4.2.1","chat":"none","ref":true}};
function boot(){{console.log('pool ready')}};boot();</script></body></html>""".encode()


def seed_two_kits(conn, kit_html):
    for i in range(6):
        add_page(conn, "urlscan", f"brand{i}-invest.com", kit_html(f"Brand{i} Invest", wallet="0x" + f"{i:02d}" * 20))
        add_page(conn, "urlscan", f"pool{i}-mining.net", other_kit(f"Pool{i}"))
    add_page(conn, "urlscan", "garden.example", (FIX / "benign.html").read_bytes())
    conn.commit()


def test_kits_and_backtest(conn, kit_html):
    seed_two_kits(conn, kit_html)
    built = kits.build(conn)
    assert [k["members"] for k in built if k["kit"].startswith("kit-")] == [6, 6]
    bt = evaluate.backtest(conn)
    assert bt["held_out"] >= 2 and bt["catch_rate"] == 1.0


def test_wilson_and_kappa(conn):
    lo, hi = evaluate.wilson(7, 10)
    assert 0.39 < lo < 0.40 and 0.89 < hi < 0.90
    for pid, (a, b) in enumerate(
        [
            ("scam-kit", "scam-kit"),
            ("not-scam", "not-scam"),
            ("scam-kit", "not-scam"),
            ("decoy-cloaked", "decoy-cloaked"),
        ]
    ):
        conn.execute("INSERT INTO labels VALUES(?,?,?,?,?)", (pid, "r1", a, None, 0))
        conn.execute("INSERT INTO labels VALUES(?,?,?,?,?)", (pid, "r2", b, None, 0))
    k = evaluate.kappa(conn, "r1", "r2")
    assert k["n"] == 4 and k["observed_agreement"] == 0.75 and 0 < k["kappa"] < 1


def test_visit_end_to_end(conn, kit_html, monkeypatch):
    seed_two_kits(conn, kit_html)
    kits.build(conn)
    monkeypatch.setattr(safety, "asn_for_ip", lambda ip: {"asn": 64500, "cc": "US"})
    monkeypatch.setattr(safety, "lookup_ns", lambda d: ["ns1.example"])
    pages = {
        "fresh-invest-hub.com": kit_html("Fresh Hub", wallet="0x" + "ef" * 20),
        "parked-capital.com": b"<html><body>This domain is parked free, courtesy of a registrar.</body></html>",
    }

    def handler(req):
        return httpx.Response(200, headers={"content-type": "text/html"}, content=pages[req.headers["host"]])

    fetcher = SafeFetcher(
        limiter=RateLimiter(10_000), resolve=lambda h: "93.184.216.34", transport=httpx.MockTransport(handler)
    )
    v = Visitor(conn, fetcher=fetcher)
    for d in pages:
        conn.execute(
            "INSERT INTO candidates(domain,first_seen,ct_ts,log_url,names,keywords) VALUES(?,?,?,?,?,?)",
            (d, db.now(), db.now() - 1500, "l", "[]", "[]"),
        )
        conn.execute("INSERT INTO visits(domain,attempt,due_at) VALUES(?,1,0)", (d,))
    conn.commit()
    for job in v.due_jobs():
        v.visit(job)
    out = dict(conn.execute("SELECT domain, outcome FROM visits WHERE attempt=1").fetchall())
    assert out == {"fresh-invest-hub.com": "content", "parked-capital.com": "parked"}
    retry = conn.execute("SELECT domain, attempt FROM visits WHERE done_at IS NULL").fetchall()
    assert [tuple(r) for r in retry] == [("parked-capital.com", 2)]
    alerted = conn.execute("SELECT p.domain, a.kit_name FROM alert_log a JOIN pages p ON p.id=a.page_id").fetchall()
    assert [tuple(r) for r in alerted] == [("fresh-invest-hub.com", "kit-01")]
    data = Path(config.load()["paths"]["data_dir"])
    sha = fp.sha256(pages["fresh-invest-hub.com"])
    cap = data / "captures" / f"{sha}.gz"
    assert gzip.decompress(cap.read_bytes()) == pages["fresh-invest-hub.com"]
    assert oct(cap.stat().st_mode & 0o777) == "0o600"
    manifest = [json.loads(line) for p in (data / "manifest").glob("*.jsonl") for line in p.read_text().splitlines()]
    rec = next(m for m in manifest if m["domain"] == "fresh-invest-hub.com")
    assert rec["body_sha256"] == sha and rec["resolved_ip"] == "93.184.216.34" and rec["mode"] == "strict"
    ttf = evaluate.time_to_flag(conn)
    assert ttf["n"] == 1 and 24 < ttf["median_min"] < 27


def test_expiry_and_priority_order(conn):
    from ssrd.fetch import Visitor

    v = Visitor(
        conn,
        fetcher=SafeFetcher(
            limiter=RateLimiter(10_000),
            resolve=lambda h: "93.184.216.34",
            transport=httpx.MockTransport(lambda r: httpx.Response(500)),
        ),
    )
    now = db.now()
    for dom, prio, due in [("old.com", 5, now - 90_000), ("low.com", 0, now - 60), ("high.com", 3, now - 30)]:
        conn.execute(
            "INSERT INTO candidates(domain,first_seen,ct_ts,log_url,names,keywords,priority) VALUES(?,?,?,?,?,?,?)",
            (dom, now, now, "l", "[]", "[]", prio),
        )
        conn.execute("INSERT INTO visits(domain,attempt,due_at) VALUES(?,1,?)", (dom, due))
    assert v.expire_stale() == 1
    assert [j["domain"] for j in v.due_jobs()] == ["high.com", "low.com"]


def test_seed_refresh_visits_feed_library_not_alerts(conn, kit_html, monkeypatch):
    from ssrd import seeds

    seed_two_kits(conn, kit_html)
    kits.build(conn)
    monkeypatch.setattr(safety, "asn_for_ip", lambda ip: {})
    monkeypatch.setattr(safety, "lookup_ns", lambda d: [])
    conn.execute("INSERT INTO seeds VALUES('listed-invest.com','cbr','2026-10-01',NULL,NULL)")
    assert seeds.enqueue_refresh(conn, "cbr", 10) == 1
    conn.execute("UPDATE visits SET due_at=0")  # far past due: seed visits must not expire
    conn.commit()
    fetcher = SafeFetcher(
        limiter=RateLimiter(10_000),
        resolve=lambda h: "93.184.216.34",
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, headers={"content-type": "text/html"}, content=kit_html("Listed Invest"))
        ),
    )
    v = Visitor(conn, fetcher=fetcher)
    assert v.expire_stale() == 0
    for job in v.due_jobs():
        v.visit(job)
    assert conn.execute("SELECT source FROM pages WHERE domain='listed-invest.com'").fetchone()[0] == "seedlive"
    assert conn.execute("SELECT COUNT(*) FROM alert_log").fetchone()[0] == 0
