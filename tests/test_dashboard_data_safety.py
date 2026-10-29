"""Observable privacy, snapshot, and refresh behavior for the public exporter."""

import json
import sqlite3
import stat

import pytest

from ssrd import config, dashboard, db, score
from tests.test_dashboard import _seed_fixture_db


def test_missing_database_is_never_created(tmp_path):
    missing = tmp_path / "missing.sqlite"
    with pytest.raises(sqlite3.OperationalError):
        dashboard.connect_ro(str(missing))
    assert not missing.exists()


def test_existing_connection_is_read_only(tmp_path):
    path = tmp_path / "existing.sqlite"
    db.connect(str(path)).close()
    conn = dashboard.connect_ro(str(path))
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("INSERT INTO seeds(domain,source) VALUES('test.test','cbr')")
    finally:
        conn.close()


def test_collection_uses_one_snapshot_and_preserves_caller_transaction(tmp_path, monkeypatch):
    path = tmp_path / "snapshot.sqlite"
    writer = db.connect(str(path))
    reader = dashboard.connect_ro(str(path))
    seen = []

    def collect(conn, **kwargs):
        seen.append(conn.execute("SELECT COUNT(*) FROM seeds").fetchone()[0])
        writer.execute("INSERT INTO seeds(domain,source) VALUES('new.test','cbr')")
        writer.commit()
        seen.append(conn.execute("SELECT COUNT(*) FROM seeds").fetchone()[0])
        return {"mode": "private"}

    monkeypatch.setattr(dashboard, "_collect_payload", collect)
    monkeypatch.setattr(dashboard, "_annotate_evaluation", lambda *args: None)
    try:
        dashboard.collect_payload(reader, mode="private")
        assert seen == [0, 0]
        assert not reader.in_transaction
        assert reader.execute("SELECT COUNT(*) FROM seeds").fetchone()[0] == 1
        writer.execute("INSERT INTO seeds(domain,source) VALUES('pending.test','cbr')")
        monkeypatch.setattr(dashboard, "_collect_payload", lambda *args, **kwargs: {"mode": "private"})
        dashboard.collect_payload(writer, mode="private")
        assert writer.in_transaction
        writer.rollback()
    finally:
        reader.close()
        writer.close()


def test_failed_refresh_keeps_previous_and_private_replacement_is_restrictive(conn, tmp_path, monkeypatch):
    out = tmp_path / "dashboard.html"
    out.write_text("previous checked publication")
    monkeypatch.setattr(dashboard, "render_html", lambda *args, **kwargs: "replacement")
    monkeypatch.setattr(dashboard, "assert_public_safe", lambda *args: None)
    replace = dashboard.os.replace
    monkeypatch.setattr(dashboard.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("disk failure")))
    with pytest.raises(OSError, match="disk failure"):
        dashboard.write_dashboard(conn, out=out, payload={"mode": "public"})
    assert out.read_text() == "previous checked publication"
    assert list(tmp_path.glob(".dashboard.html.*")) == []
    monkeypatch.setattr(dashboard.os, "replace", replace)
    dashboard.write_dashboard(conn, mode="private", out=out, payload={"mode": "private"})
    assert out.read_text() == "replacement"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    with pytest.raises(ValueError, match="mode"):
        dashboard.write_dashboard(conn, mode="public", out=out, payload={"mode": "private"})
    assert out.read_text() == "replacement"


def test_public_payload_omits_arbitrary_database_text(conn, tmp_path, monkeypatch, kit_html):
    monkeypatch.setitem(config.load()["paths"], "data_dir", str(tmp_path))
    hit = _seed_fixture_db(conn, tmp_path, kit_html)
    marker = "PRIVATE_UNSANITIZED_OPERATOR_NOTE"
    conn.execute("UPDATE kits SET name='kit-' || ?, status=?", (marker, marker))
    conn.execute("INSERT INTO seeds(domain,source) VALUES('another.test',?)", (marker,))
    conn.execute("UPDATE visits SET outcome=?", (marker,))
    conn.execute(
        "INSERT INTO labels(page_id,reviewer,label,labeled_at) VALUES(?,?,?,?)", (hit, "rahil", marker, db.now())
    )
    conn.execute("INSERT INTO samples(name,since,until,seed,population,drawn_at) VALUES(?,0,1,1,0,1)", (marker,))
    conn.execute(
        "INSERT INTO ct_state(log_url,next_index,updated_at) VALUES(?,1,1)", ("https://" + marker + "/secret",)
    )
    conn.commit()
    data = dashboard.collect_payload(conn, mode="public")
    assert marker not in json.dumps(data)
    assert data["evaluation"]["precision"]["representative"] is False
    assert data["evaluation"]["model_benchmark"]["ngram_recall"] is None
    assert data["evaluation"]["recorded_backtest"] is None


def test_filter_recall_updates_for_equal_count_replacement(conn):
    conn.execute("INSERT INTO seeds(domain,source,listed_at) VALUES('investment.test','cbr','2026-08-01')")
    first = dashboard._cached_filter_recall(conn)
    conn.execute("UPDATE seeds SET listed_at='2025-01-01'")
    second = dashboard._cached_filter_recall(conn)
    assert first["n"] == 1
    assert second["n"] == 0


def test_partial_sample_has_no_population_estimate(conn, tmp_path, monkeypatch, kit_html):
    monkeypatch.setitem(config.load()["paths"], "data_dir", str(tmp_path))
    hit = _seed_fixture_db(conn, tmp_path, kit_html)
    conn.execute(
        "INSERT INTO samples(name,since,until,seed,population,drawn_at) VALUES('private-name',0,9999999999,1,1,1)"
    )
    conn.execute("INSERT INTO sample_members(name,page_id,position) VALUES('private-name',?,0)", (hit,))
    conn.commit()
    data = dashboard.collect_payload(conn, sample="private-name")
    assert data["evaluation"]["sample"]["estimated_true_alerts"] is None
    assert data["evaluation"]["sample"]["estimated_true_alerts_ci95"] is None
    conn.execute("INSERT INTO labels(page_id,reviewer,label,labeled_at) VALUES(?,'rahil','scam-kit',1)", (hit,))
    data = dashboard.collect_payload(conn, sample="private-name")
    assert data["evaluation"]["precision"]["representative"] is True
    assert data["evaluation"]["precision"]["minimum_sample_met"] is False
    assert data["evaluation"]["sample"]["estimated_true_alerts"] == 1


def test_synthetic_and_backtest_do_not_change_private_scorer_cache(conn):
    saved = score._DENY.copy()
    sentinel = {("private", "sentinel")}
    try:
        score._DENY.update(at=123, values=sentinel)
        dashboard.synthetic_walkthrough()
        assert score._DENY == {"at": 123, "values": sentinel}
        dashboard._snapshot_backtest(conn)
        assert score._DENY == {"at": 123, "values": sentinel}
    finally:
        score._DENY.clear()
        score._DENY.update(saved)


def test_partial_metrics_line_cannot_inflate_pass_rate(conn, tmp_path):
    metrics = tmp_path / "metrics.jsonl"
    metrics.write_text(
        json.dumps({"component": "ingest", "names": 100, "filter_pass": 10, "start": 1, "end": 2})
        + "\n"
        + '{"component":'
    )
    payload = dashboard.collect_payload(conn, metrics_path=metrics)
    assert payload["funnel"]["pass_rate_pct"] == 10
    metrics.write_text(json.dumps({"component": "ingest", "names": 100, "start": 1, "end": 2}) + "\n")
    conn.execute("INSERT INTO candidates(domain,first_seen,origin) VALUES('test.test',1,'ct')")
    assert dashboard.collect_payload(conn, metrics_path=metrics)["funnel"]["pass_rate_pct"] == 0


def test_same_day_cbr_listing_does_not_confirm_lead(conn, tmp_path, monkeypatch, kit_html):
    monkeypatch.setitem(config.load()["paths"], "data_dir", str(tmp_path))
    hit = _seed_fixture_db(conn, tmp_path, kit_html)
    conn.execute("UPDATE candidates SET first_seen=1000 WHERE domain='flagged-respawn.xyz'")
    conn.execute("INSERT INTO seeds(domain,source,listed_at) VALUES('flagged-respawn.xyz','cbr','1970-01-01')")
    conn.execute("INSERT INTO labels(page_id,reviewer,label,labeled_at) VALUES(?,'rahil','scam-kit',1)", (hit,))
    data = dashboard.collect_payload(conn)
    assert data["evaluation"]["lead_confidence"]["likely"] == 1
    assert data["evaluation"]["cbr_forward"]["candidates_later_listed"] == 0
    conn.execute("UPDATE seeds SET listed_at='1970-01-02' WHERE domain='flagged-respawn.xyz'")
    data = dashboard.collect_payload(conn)
    assert data["evaluation"]["lead_confidence"]["confirmed"] == 1
    assert data["evaluation"]["cbr_forward"]["candidates_later_listed"] == 1
