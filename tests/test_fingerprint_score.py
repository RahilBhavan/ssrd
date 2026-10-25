import base64

from ssrd import fingerprint as fp
from ssrd import score
from tests.conftest import FIX


def feats(body, url="https://a.example/"):
    return fp.html_features(
        body, url, "text/html; charset=utf-8", 200, [("Server", "nginx"), ("Content-Type", "text/html")]
    )


def test_favicon_recipe_uses_newline_base64():
    data = bytes(range(256)) * 2
    assert b"\n" in base64.encodebytes(data)
    assert fp.favicon_mmh3(data) == fp.mmh3.hash(base64.encodebytes(data))


def test_classify():
    assert fp.classify("This Website Has Been Seized By Law Enforcement ... #KCDA", "", 200) == "seized"
    assert fp.classify("This domain is parked free, courtesy of ...", "", 200) == "parked"
    assert fp.classify("ok", "", 200) == "blank"
    assert fp.classify("x" * 500, "", 403) == "blocked"
    assert fp.classify("x" * 500, "", 200) == "content"


def test_features_extract_kit_traits(kit_html):
    f = feats(kit_html("NovaTrade"))
    assert f["lang"] == "ru" and f["cyrillic_ratio"] > 0.5
    assert f["telegram"] == ["support_invest_desk"]
    assert f["crypto_addresses"] == ["0x" + "ab" * 20]
    assert "/static/css/app.min.css" in f["assets"]["local_paths"]
    assert {"bitlicense", "nydfs"} <= set(f["bait_terms"])
    assert f["inline_script_sha256"] and f["page_class"] == "content"


def test_same_kit_alerts_benign_does_not(kit_html):
    a = feats(kit_html("NovaTrade"), "https://novatrade-invest.com/")
    b = feats(kit_html("Quantix Capital", wallet="0x" + "cd" * 20), "https://quantix-capital.net/")
    benign = feats((FIX / "benign.html").read_bytes(), "https://garden.example/")
    alert, sc = score.decide(score.compare(a, b))
    fams = {s["family"] for s in score.compare(a, b)}
    assert alert and {"A", "B", "C"} <= fams
    assert not score.decide(score.compare(a, benign))[0]


def test_infrastructure_alone_never_alerts():
    a = {"asn": 13335, "ns": ["a.ns", "b.ns"], "header_order": ["server"], "generator": "WP"}
    sig = score.compare(a, dict(a))
    assert {s["family"] for s in sig} == {"C", "D"}
    assert not score.decide(sig)[0]


def test_denylist_zeroes_common_favicon():
    a = {"favicon_mmh3": 123, "telegram": ["x_support"]}
    assert len(score.compare(a, dict(a))) == 2
    assert [s["signal"] for s in score.compare(a, dict(a), {("favicon", "123")})] == ["telegram"]


def test_seed_pages_never_feed_the_denylist(conn):
    import json

    from ssrd import db

    f = {"favicon_mmh3": 7, "title_norm": "x"}
    for i in range(30):  # a big genuine kit: 30 seed domains sharing a favicon
        conn.execute(
            "INSERT INTO pages(source,ref,domain,features) VALUES('urlscan',?,?,?)",
            (str(i), f"s{i}.com", json.dumps(f)),
        )
    score._DENY["at"] = 0
    assert ("favicon", "7") not in score.common_values(conn, refresh_seconds=0)
    for i in range(30):  # the same favicon on 30 random background sites -> generic
        conn.execute(
            "INSERT INTO pages(source,ref,domain,features) VALUES('background',?,?,?)",
            (f"b{i}", f"b{i}.com", json.dumps(f)),
        )
    assert ("favicon", "7") in score.common_values(conn, refresh_seconds=0)
    score._DENY["at"] = 0
    db.now()


def test_common_limit_is_capped_as_the_crawl_grows(conn, monkeypatch):
    import json

    from ssrd import config

    cfg = config.load()
    monkeypatch.setitem(cfg["score"], "common_max_hosts", 5)
    monkeypatch.setattr(config, "load", lambda *a, **k: cfg)
    builder = {"asset_sha256": {"/app.js": "b" * 64}}
    conn.execute(
        "INSERT INTO pages(source,ref,domain,features) VALUES('urlscan','r','ref.com',?)", (json.dumps(builder),)
    )
    rows = [(f"l{i}", f"l{i}.com", json.dumps(builder if i < 6 else {})) for i in range(1000)]
    conn.executemany("INSERT INTO pages(source,ref,domain,features) VALUES('live',?,?,?)", rows)
    score._DENY["at"] = 0
    # 6 of 1,000 hosts is under the 2% share (20) but over the cap (5): generic.
    assert ("asset", "b" * 64) in score.common_values(conn, refresh_seconds=0)
    score._DENY["at"] = 0
