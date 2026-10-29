import gzip
import os
import stat
import threading
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from ssrd import cli, config, dashboard, db, kits, score
from ssrd import fingerprint as fp
from tests.conftest import FIX


def _add_captured_page(conn, data_dir: Path, source: str, domain: str, body: bytes) -> int:
    feat = fp.html_features(body, f"https://{domain}/", "text/html", 200, [("server", "cloudflare")])
    cap_dir = data_dir / "captures"
    cap_dir.mkdir(parents=True, exist_ok=True)
    (cap_dir / f"{feat['body_sha256']}.gz").write_bytes(gzip.compress(body))
    cur = conn.execute(
        "INSERT INTO pages(source,ref,domain,observed_at,page_class,features) VALUES(?,?,?,?,?,?)",
        (source, domain, domain, db.now(), feat["page_class"], db.dumps(feat)),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_fixture_db(conn, tmp_path: Path, kit_html):
    conn.execute(
        "INSERT INTO seeds(domain,source,listed_at) VALUES"
        "('secret-seed1.org','cbr','2026-08-01'),"
        "('secret-seed2.org','cbr','2026-08-02'),"
        "('kcda-seized1.net','kcda',NULL),"
        "('single-ref-scam.biz','cbr','2026-09-01')"
    )
    wallet = "0x" + "de" * 20
    extra = "<script>window.stealSecret()</script><p>Contact https://t.me/secret_scam_ops for VIP profit.</p>"
    _add_captured_page(
        conn, tmp_path, "urlscan", "secret-seed1.org", kit_html("secret-seed1.org", wallet=wallet, extra=extra)
    )
    _add_captured_page(
        conn, tmp_path, "urlscan", "secret-seed2.org", kit_html("SeedTwo", wallet="0x" + "ab" * 20, extra=extra)
    )
    _add_captured_page(conn, tmp_path, "wayback", "kcda-seized1.net", kit_html("KCDASeized", wallet="0x" + "cd" * 20))
    _add_captured_page(conn, tmp_path, "urlscan", "single-ref-scam.biz", kit_html("SingleRef", wallet="0x" + "ef" * 20))
    kits.build(conn)

    now = db.now()
    conn.execute(
        "INSERT INTO candidates(domain,first_seen,ct_ts,origin) VALUES('flagged-respawn.xyz',?,?,'ct')",
        (now - 1500, now - 1500),
    )
    conn.execute(
        "INSERT INTO visits(domain,attempt,due_at,done_at,outcome,status) VALUES('flagged-respawn.xyz',1,?,?,'content',200)",
        (now - 300, now - 60),
    )
    live_body = kit_html("flagged-respawn.xyz", wallet="0x" + "99" * 20, extra=extra + "<!-- </script> -->")
    hit = _add_captured_page(conn, tmp_path, "live", "flagged-respawn.xyz", live_body)
    score.score_page(conn, hit)
    _add_captured_page(conn, tmp_path, "live", "benign-garden.org", (FIX / "benign.html").read_bytes())
    return hit


def test_public_dashboard_redacts_all_private_data(conn, tmp_path, monkeypatch, kit_html):
    monkeypatch.setitem(config.load()["paths"], "data_dir", str(tmp_path))
    _seed_fixture_db(conn, tmp_path, kit_html)

    out = dashboard.write_dashboard(conn, mode="public", out=tmp_path / "public.html", run_backtest=True)
    html = out.read_text()

    assert "default-src 'none'" in html
    assert "PUBLIC REDACTED SHOWCASE" in html
    for secret in (
        "secret-seed1",
        "secret-seed2",
        "kcda-seized1",
        "single-ref-scam",
        "flagged-respawn",
        "benign-garden",
        "secret_scam_ops",
        "0x" + "de" * 20,
        "0x" + "99" * 20,
        "stealSecret",
    ):
        assert secret not in html

    with pytest.raises(ValueError, match="private domain"):
        dashboard.assert_public_safe("leaked flagged-respawn.xyz here", conn)
    with pytest.raises(ValueError, match="private domain"):
        dashboard.assert_public_safe("even defanged flagged-respawn[.]xyz fails", conn)

    fake_root = tmp_path / "repo"
    (fake_root / "config").mkdir(parents=True)
    (fake_root / "config" / "publish-deny.txt").write_text("AS64512-HOME-NET\n")
    with pytest.raises(ValueError, match="publish-deny"):
        dashboard.assert_public_safe("trace from AS64512-HOME-NET", conn, root=fake_root)


def test_private_dashboard_permissions_sanitization_and_assist_separation(conn, tmp_path, monkeypatch, kit_html):
    monkeypatch.setitem(config.load()["paths"], "data_dir", str(tmp_path))
    hit = _seed_fixture_db(conn, tmp_path, kit_html)

    assist = config.load()["review"]["assist_reviewer"]
    conn.execute(
        "INSERT OR REPLACE INTO labels(page_id,reviewer,label,note,labeled_at) VALUES(?,?,?,?,?)",
        (hit, assist, "scam-kit", "rule: synthetic test", db.now()),
    )
    conn.commit()

    payload_unreviewed = dashboard.collect_payload(conn, mode="private", reviewer="rahil")
    assert payload_unreviewed["evaluation"]["precision"]["n_labeled_alerts"] == 0
    assert payload_unreviewed["evaluation"]["lead_confidence"]["speculative"] == 1
    assert payload_unreviewed["evaluation"]["assist_triage"]["scam-kit"] == 1

    conn.execute(
        "INSERT INTO labels(page_id,reviewer,label,labeled_at) VALUES(?,?,?,?)",
        (hit, "rahil", "scam-kit", db.now()),
    )
    conn.commit()

    out = dashboard.write_dashboard(conn, mode="private", reviewer="rahil")
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    html = out.read_text()

    assert "flagged-respawn[.]xyz" in html
    assert "flagged-respawn.xyz" not in html
    assert "stealSecret" not in html
    assert "</script> -->" not in html  # JSON HTML-breakout characters are unicode-escaped
    assert "operated by" not in html.lower()
    assert "belongs to" not in html.lower()


def test_terminal_dashboard_and_svg_export(conn, tmp_path, monkeypatch, kit_html):
    monkeypatch.setitem(config.load()["paths"], "data_dir", str(tmp_path))
    _seed_fixture_db(conn, tmp_path, kit_html)
    payload = dashboard.collect_payload(conn, mode="public")

    buf_console = Console(record=True, width=116, force_terminal=True)
    dashboard.render_terminal(buf_console, payload)
    text = buf_console.export_text()
    assert "CT-to-Alert Funnel" in text
    assert "Honesty Scorecard" in text
    assert "flagged-respawn" not in text

    svg = tmp_path / "dash.svg"
    dashboard.export_svg(payload, svg)
    svg_text = svg.read_text()
    assert svg_text.lstrip().startswith("<svg")
    dashboard.assert_public_safe(svg_text, conn)


def test_local_server_enforces_loopback_and_serves_sanitized_data(conn, tmp_path, monkeypatch, kit_html):
    db_file = tmp_path / "srv.sqlite"
    monkeypatch.setitem(config.load()["paths"], "data_dir", str(tmp_path))
    monkeypatch.setitem(config.load()["paths"], "db", str(db_file))
    srv_conn = db.connect(str(db_file))
    hit = _seed_fixture_db(srv_conn, tmp_path, kit_html)
    srv_conn.close()

    for bad_host in ("0.0.0.0", "192.168.1.50", "example.com"):
        with pytest.raises(ValueError, match="non-loopback"):
            dashboard.make_server(bad_host, 0, db_path=str(db_file))

    srv = dashboard.make_server("127.0.0.1", 0, db_path=str(db_file), reviewer="rahil")
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        r_health = httpx.get(f"{base}/healthz", timeout=5)
        assert r_health.status_code == 200 and r_health.json() == {"status": "ok"}

        r_root = httpx.get(f"{base}/", timeout=5)
        assert r_root.status_code == 200
        assert "connect-src 'self'" in r_root.headers["Content-Security-Policy"]
        assert r_root.headers["X-Content-Type-Options"] == "nosniff"
        assert "flagged-respawn[.]xyz" in r_root.text
        assert "flagged-respawn.xyz" not in r_root.text

        for path in ("/", "/api/snapshot", f"/api/page/{hit}"):
            hostile = httpx.get(
                f"{base}{path}",
                headers={"Host": f"attacker.example:{port}", "Origin": f"http://attacker.example:{port}"},
                timeout=5,
            )
            assert hostile.status_code == 403 and "flagged-respawn" not in hostile.text
            assert (
                httpx.get(f"{base}{path}", headers={"Origin": "https://attacker.example"}, timeout=5).status_code == 403
            )
        assert (
            httpx.get(
                f"{base}/healthz",
                headers={"Host": f"localhost:{port}", "Origin": f"http://localhost:{port}"},
                timeout=5,
            ).status_code
            == 200
        )

        r_snap = httpx.get(f"{base}/api/snapshot", timeout=5)
        assert r_snap.status_code == 200 and r_snap.json()["mode"] == "private"

        r_page = httpx.get(f"{base}/api/page/{hit}", timeout=5)
        assert r_page.status_code == 200
        pdata = r_page.json()
        assert pdata["domain"] == "flagged-respawn[.]xyz"
        assert "stealSecret" not in pdata["sanitized_text"]

        assert httpx.get(f"{base}/api/page/999999", timeout=5).status_code == 404
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_dashboard_entrypoint(tmp_path, monkeypatch, kit_html):
    db_file = tmp_path / "cli.sqlite"
    monkeypatch.setitem(config.load()["paths"], "data_dir", str(tmp_path))
    monkeypatch.setitem(config.load()["paths"], "db", str(db_file))
    c = db.connect(str(db_file))
    _seed_fixture_db(c, tmp_path, kit_html)
    c.close()

    pub_out = tmp_path / "out_pub.html"
    cli.main(["dashboard", "--public", "--out", str(pub_out)])
    assert pub_out.exists() and "flagged-respawn" not in pub_out.read_text()

    cli.main(["dashboard", "--terminal"])
