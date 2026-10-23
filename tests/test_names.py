from ssrd import names, seeds


def test_registrable_and_idn():
    assert names.registrable("*.Login.Example.co.uk.") == "example.co.uk"
    assert names.registrable("foo.vercel.app") == "foo.vercel.app"  # private PSL suffix
    assert names.registrable("1.2.3.4") is None
    assert names.to_unicode("xn--80aswg.xn--p1ai") == "сайт.рф"


def test_keyword_matches_groups():
    groups = {m.group for m in names.keyword_matches("quantum-invest-capital.com")}
    assert "investment" in groups
    assert {m.term for m in names.keyword_matches("xn--b1aghcaa4a8aj5b.com")}  # инвест... in punycode
    assert any(m.group == "recovery" for m in names.keyword_matches("crypto-refund-desk.net"))
    assert any(m.group == "bait" for m in names.keyword_matches("gazprom-dohod.online"))


def test_short_tokens_need_boundaries():
    assert not any(m.term == "fx" for m in names.keyword_matches("firefoxhelp.com"))
    assert names.keyword_matches("geelong-commercial.com") == []  # elon is a boundary term
    assert names.keyword_matches("assets.zoozags.com") == []  # subdomains are not matched
    assert any(m.term == "fx" for m in names.keyword_matches("pro-fx.com"))


def test_skip_suffixes():
    assert names.keyword_matches("invest.s3.amazonaws.com") == []
    assert names.keyword_matches("cryptoinvest.amazonaws.com") == []


def test_defang():
    assert names.defang("https://a.b") == "hxxps://a[.]b"


def test_cbr_site_splitting():
    raw = "t.me/Demo_Bot, https://demo-robo-synthetic.com/ru, mail.alphafin-synthetic.com; vk.com/club1 sub.zeta-demo.top"
    assert seeds.split_sites(raw) == ["alphafin-synthetic.com", "demo-robo-synthetic.com", "zeta-demo.top"]


def test_model_filter_and_priority(monkeypatch):
    import json

    from ssrd import config, name_model

    w = {k: 5.0 for k in name_model.features(name_model.label_of("quantix-capital.com"))}
    path = name_model.model_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"b": -3.0, "w": {str(k): v for k, v in w.items()}}))
    name_model._load.cache_clear()
    monkeypatch.setitem(config.load()["filter"], "mode", "model")
    ok, matches, score = names.passes("quantix-capital.com")
    assert ok and score > 0.93 and any(m.term == "capital" for m in matches)
    ok, _, score = names.passes("garden-club.org")
    assert not ok and score < 0.93
    assert names.passes("quantix-capital.amazonaws.com")[0] is False  # skip list still applies
    assert names.priority("x.top", [("model", "0.990"), ("investment", "capital")]) == 9 + 1 + 1
    path.unlink()
    name_model._load.cache_clear()
