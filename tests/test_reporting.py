import os
import shutil
import stat
import subprocess
import tarfile

import pytest

from ssrd import backup, db, evaluate, kits, memo, score
from ssrd.cli import watch_problems
from tests.conftest import FIX
from tests.test_pipeline import add_page, seed_two_kits


def _live(conn, kit_html):
    seed_two_kits(conn, kit_html)
    kits.build(conn)
    hit = add_page(conn, "live", "newbrand-invest.com", kit_html("Newbrand Invest", wallet="0x" + "77" * 20))
    miss = add_page(conn, "live", "garden2.example", (FIX / "benign.html").read_bytes())
    conn.commit()
    for pid in (hit, miss):
        score.score_page(conn, pid)
    return hit, miss


def _label(conn, pid, reviewer, label):
    conn.execute(
        "INSERT INTO labels(page_id,reviewer,label,labeled_at) VALUES(?,?,?,?)", (pid, reviewer, label, db.now())
    )
    conn.commit()


def test_sweep_uses_tuning_set_and_restores_config(conn, kit_html):
    from ssrd import config

    hit, miss = _live(conn, kit_html)
    _label(conn, hit, "r", "scam-kit")
    _label(conn, miss, "r", "not-scam")
    before = dict(config.load()["score"])
    res = evaluate.sweep(conn, "r", before=db.now() + 10, grid={"tlsh_max_distance": [10, 70], "jaccard_min": [0.8]})
    assert res["tuning_pages"] == 2 and res["positives"] == 1
    assert all(row["tp"] <= 1 for row in res["grid"]) and any(row["precision"] == 1.0 for row in res["grid"])
    assert config.load()["score"] == before
    assert evaluate.sweep(conn, "r", before=0)["tuning_pages"] == 0  # nothing before the freeze


def test_precision_split_and_freeze(conn, kit_html):
    hit, _ = _live(conn, kit_html)
    _label(conn, hit, "r", "scam-kit")
    assert evaluate.precision(conn, "r")["scam_kit"] == 1
    assert evaluate.precision(conn, "r", "kcda")["n_labeled_alerts"] == 0
    assert evaluate.precision(conn, "r", since=db.now() + 3600)["n_labeled_alerts"] == 0
    assert evaluate.group_of("kit-01-KCDA") == "kcda" and evaluate.group_of("ref-x.com") == "cbr"


def test_memo_confidence_and_privacy(conn, kit_html):
    hit, _ = _live(conn, kit_html)
    assert [x["confidence"] for x in memo.leads(conn)] == ["speculative"]
    _label(conn, hit, "r", "scam-kit")
    assert memo.leads(conn)[0]["confidence"] == "likely"
    _label(conn, hit, "r2", "scam-kit")
    lead = memo.leads(conn)[0]
    assert lead["confidence"] == "confirmed" and "[.]" in lead["domain"]
    md, csv_path = memo.build(conn, "r", "r2", since=0)
    text = md.read_text()
    assert "newbrand-invest[.]com" in text and "newbrand-invest.com" not in text
    assert "operated by" not in text.lower()
    assert "KCDA-seized sites: 0; from CBR-listed sites: 1." in text
    for p in (md, csv_path):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_memo_drops_rejected_leads(conn, kit_html):
    hit, _ = _live(conn, kit_html)
    _label(conn, hit, "r", "not-scam")
    assert memo.leads(conn) == []


def test_watch_problems():
    ok = {
        "db_write_probe": {"writable_share": 1.0},
        "ingest": {"seconds_since_ct_state_update": 30, "candidates_last_hour": 300},
        "fetch": {"visits_last_hour": 250, "due_now_ct": 40},
    }
    assert watch_problems(ok) == []
    bad = {
        "db_write_probe": {"writable_share": 0.5},
        "ingest": {"seconds_since_ct_state_update": 3600, "candidates_last_hour": 0},
        "fetch": {"visits_last_hour": 0, "due_now_ct": 5000},
    }
    assert len(watch_problems(bad)) == 5


@pytest.mark.skipif(not shutil.which("gpg"), reason="gpg not installed")
def test_backup_roundtrip(conn, tmp_path, monkeypatch):
    from ssrd import config

    monkeypatch.setitem(config.load()["paths"], "db", str(tmp_path / "t.sqlite"))
    monkeypatch.setenv("GNUPGHOME", str(tmp_path / "gnupg"))
    (tmp_path / "gnupg").mkdir(mode=0o700)
    out = backup.run(tmp_path / "bk", keep=1)
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    plain = tmp_path / "plain.tgz"
    subprocess.run(
        [
            "gpg",
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(backup.key_path()),
            "-o",
            str(plain),
            "-d",
            str(out),
        ],
        check=True,
        capture_output=True,
    )
    names = tarfile.open(plain).getnames()
    assert "data/ssrd.sqlite" in names and not any(n.endswith(".env") for n in names)


def test_assistant_suggestions_never_count(conn, kit_html):
    from ssrd import config, review

    assist = config.load()["review"]["assist_reviewer"]
    hit, _ = _live(conn, kit_html)
    _label(conn, hit, assist, "scam-kit")
    assert memo.leads(conn)[0]["confidence"] == "speculative"
    assert evaluate.precision(conn, "r")["n_labeled_alerts"] == 0
    assert hit not in {p[0] for p in kits.seed_pages(conn)}
    assert review.suggestion(conn, hit) == ("scam-kit", None)
    assert [r["id"] for r in review.queue(conn, "r")] == [hit]  # still in the human queue


def test_time_to_flag_separates_retroactive_alerts(conn, kit_html):
    hit, _ = _live(conn, kit_html)
    conn.execute(
        "INSERT INTO candidates(domain,first_seen,ct_ts) VALUES('newbrand-invest.com',?,?)",
        (db.now() - 1500, db.now() - 1500),
    )
    conn.commit()
    t = evaluate.time_to_flag(conn)
    assert t["n"] == 1 and t["retroactive_alerts"] == 0 and 20 <= t["median_min"] <= 30
    conn.execute("UPDATE pages SET observed_at=observed_at-86400 WHERE id=?", (hit,))
    conn.commit()
    assert evaluate.time_to_flag(conn) == {"n": 0, "retroactive_alerts": 1}
