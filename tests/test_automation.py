import pytest

from ssrd import config, db, evaluate, prelabel, review, sample, score
from ssrd import fingerprint as fp
from tests.test_pipeline import add_page
from tests.test_reporting import _label, _live


def sig(family, name, strength):
    return {"family": family, "signal": name, "strength": strength, "value": None}


def test_generic_script_plus_wordpress_and_cloudflare_no_longer_alerts():
    s = [sig("B", "inline_script", 3), sig("C", "generator", 1), sig("D", "asn", 1), sig("D", "ns", 1)]
    assert score.decide(s)[0] is False


def test_one_family_with_independent_support_still_alerts():
    s = [sig("B", "asset_sha256", 3), sig("B", "inline_script", 3), sig("B", "asset_paths", 2)]
    assert score.decide(s)[0] is True
    assert score.decide([sig("A", "tlsh", 3), sig("B", "inline_script", 3)])[0] is True


@pytest.mark.parametrize(
    "text",
    [
        "Your domain is expired. Renew the domain to activate the website",
        "example.com Something amazing will be constructed here... upload your website into the public_html directory",
    ],
)
def test_registrar_and_hosting_placeholders_are_parked(text):
    assert fp.classify(text * 3, "", 200) == "parked"


def test_reclassify_marks_stored_placeholder_pages(conn):
    from ssrd.refeature import reclassify

    pid = add_page(
        conn,
        "urlscan",
        "old.example",
        b"<html><title>Your domain is expired</title><body>" + b"x " * 100 + b"</body></html>",
    )
    conn.execute("UPDATE pages SET page_class='content' WHERE id=?", (pid,))
    conn.commit()
    assert reclassify(conn) == 1
    assert conn.execute("SELECT page_class FROM pages WHERE id=?", (pid,)).fetchone()[0] == "parked"


def test_prelabel_rule_fires_on_alert_and_never_overrides(conn, kit_html, monkeypatch):
    rule = {"label": "scam-kit", "title": __import__("re").compile("Newbrand"), "note": "rule: test"}
    monkeypatch.setattr(prelabel, "_rules", lambda: [rule])
    hit, _ = _live(conn, kit_html)  # score_page runs prelabel.apply on alert
    assist = config.load()["review"]["assist_reviewer"]
    assert review.suggestion(conn, hit) == ("scam-kit", "rule: test")
    conn.execute("UPDATE labels SET label='unsure' WHERE page_id=? AND reviewer=?", (hit, assist))
    conn.commit()
    assert prelabel.apply(conn, hit) is None  # an existing suggestion is kept
    assert conn.execute("SELECT COUNT(*) FROM labels WHERE page_id=? AND reviewer!=?", (hit, assist)).fetchone()[0] == 0


def test_sample_is_frozen_and_drives_review_and_precision(conn, kit_html):
    hit, _ = _live(conn, kit_html)
    res = sample.draw(conn, "final", 100, 0, db.now() + 10, seed=1)
    assert res == {"name": "final", "population": 1, "drawn": 1}
    with pytest.raises(sample.SampleExists):
        sample.draw(conn, "final", 100, 0, db.now() + 10, seed=2)
    assert [r["id"] for r in review.queue(conn, "r", sample="final")] == [hit]
    assert review.queue(conn, "r", sample="final", limit=0) == []
    _label(conn, hit, "r", "scam-kit")
    _label(conn, hit, "r2", "scam-kit")
    p = evaluate.precision(conn, "r", sample="final")
    assert p["n_labeled_alerts"] == 1 and p["precision"] == 1.0
    est = evaluate.sample_estimate(conn, "r", "final")
    assert est["population_alerts"] == 1 and est["estimated_true_alerts"] == 1
    assert evaluate.kappa(conn, "r", "r2", "final")["n"] == 1


def test_sample_draw_is_uniform_without_replacement(conn):
    for i in range(50):
        conn.execute("INSERT INTO alert_log(page_id,first_alert_at,kit_name) VALUES(?,?,?)", (i, 100 + i, "k"))
    conn.commit()
    res = sample.draw(conn, "s", 10, 110, 140, seed=7)
    got = sample.members(conn, "s")
    assert res["population"] == 30 and len(got) == len(set(got)) == 10
    assert all(10 <= pid < 40 for pid in got)


def test_export_only_human_scam_labels_and_routes_by_language(conn, kit_html):
    import json as _json

    from ssrd import export

    hit, _ = _live(conn, kit_html)
    assist = config.load()["review"]["assist_reviewer"]
    _label(conn, hit, assist, "scam-kit")
    assert export.reports(conn, "r") == {}  # a suggestion alone is never exported
    with pytest.raises(ValueError):
        export.reports(conn, assist)
    f = _json.loads(conn.execute("SELECT features FROM pages WHERE id=?", (hit,)).fetchone()[0])
    f["lang"] = "it-IT"
    conn.execute("UPDATE pages SET features=? WHERE id=?", (_json.dumps(f), hit))
    _label(conn, hit, "r", "scam-kit")
    got = export.reports(conn, "r")
    assert set(got) == {"cbr", "consob"}
    assert got["consob"][0]["domain"] == "newbrand-invest[.]com"
    assert [r["id"] for r in review.queue(conn, "r2", suggested="scam-kit")] == [hit]
    assert review.queue(conn, "r2", suggested="not-scam") == []
