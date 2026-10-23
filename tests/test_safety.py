import re
from pathlib import Path

import httpx
import pytest

from ssrd import cli, safety
from ssrd.fetch import RateLimiter, SafeFetcher

SRC = Path(__file__).resolve().parents[1] / "src" / "ssrd"


@pytest.mark.parametrize(
    "ip,ok",
    [
        ("8.8.8.8", True),
        ("10.136.27.254", False),
        ("172.17.0.1", False),
        ("192.168.1.1", False),
        ("100.100.100.100", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),
        ("0.0.0.0", False),
        ("::1", False),
        ("fe80::1", False),
        ("fd7a:115c:a1e0::1", False),
        ("::ffff:10.0.0.1", False),
    ],
)
def test_is_public(ip, ok):
    assert safety.is_public(ip) is ok


def test_resolve_refuses_literal_ip():
    with pytest.raises(safety.UnsafeTarget):
        safety.resolve_public("10.0.0.1")


def test_resolve_refuses_any_private_answer(monkeypatch):
    class R:
        def resolve(self, host, rtype):
            class A:
                def __init__(self, t):
                    self.t = t

                def to_text(self):
                    return self.t

            return [A("93.184.216.34"), A("10.136.27.5")]  # rebinding-style mixed answer

    monkeypatch.setattr(safety, "_resolver", lambda: R())
    with pytest.raises(safety.UnsafeTarget, match="non-public"):
        safety.resolve_public("evil.example")


def _fetcher(handler, mapping):
    def resolve(host):
        ip = mapping.get(host)
        if ip is None or not safety.is_public(ip):
            raise safety.UnsafeTarget(f"blocked {host}")
        return ip

    return SafeFetcher(limiter=RateLimiter(10_000), resolve=resolve, transport=httpx.MockTransport(handler))


def test_pins_ip_and_sets_host_and_sni():
    seen = {}

    def handler(req):
        seen.update(host=req.url.host, header=req.headers["host"], sni=req.extensions.get("sni_hostname"))
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<html>hi</html>")

    r = _fetcher(handler, {"site.example": "93.184.216.34"}).get("https://site.example/")
    assert r.body == b"<html>hi</html>" and r.error is None
    assert seen == {"host": "93.184.216.34", "header": "site.example", "sni": "site.example"}


def test_redirect_to_private_is_refused():
    def handler(req):
        return httpx.Response(302, headers={"location": "http://router.lan/admin"})

    r = _fetcher(handler, {"site.example": "93.184.216.34", "router.lan": "10.136.27.254"}).get("https://site.example/")
    assert r.body is None and r.error.startswith("unsafe:")


@pytest.mark.parametrize(
    "url,err",
    [
        ("file:///etc/passwd", "scheme_refused"),
        ("ftp://site.example/", "scheme_refused"),
        ("https://site.example:8443/", "port_refused"),
        ("https://user:pw@site.example/", "userinfo_refused"),
    ],
)
def test_refused_urls(url, err):
    r = _fetcher(lambda req: httpx.Response(200), {"site.example": "93.184.216.34"}).get(url)
    assert r.error.startswith(err)


def test_binary_not_downloaded_and_size_cap():
    def handler(req):
        if req.url.path == "/app.apk":
            return httpx.Response(
                200, headers={"content-type": "application/vnd.android.package-archive"}, content=b"PK"
            )
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"x" * 3_000_000)

    f = _fetcher(handler, {"site.example": "93.184.216.34"})
    r = f.get("https://site.example/app.apk")
    assert r.body is None and r.error.startswith("content_type_refused")
    r = f.get("https://site.example/")
    assert r.body is None and r.error == "too_large"


def test_redirect_cap():
    f = _fetcher(lambda req: httpx.Response(302, headers={"location": "/again"}), {"site.example": "93.184.216.34"})
    assert f.get("https://site.example/").error == "too_many_redirects"


def test_urlscan_client_cannot_submit_scans():
    src = (SRC / "urlscan.py").read_text()
    assert not re.search(r"\.post\(|/scan/|\"visibility\"", src)
    for path in SRC.glob("*.py"):
        assert "urlscan.io/api/v1/scan" not in path.read_text(), path


def test_only_get_requests_in_fetcher():
    src = (SRC / "fetch.py").read_text()
    assert re.findall(r'stream\("(\w+)"', src) == ["GET"]
    assert ".post(" not in src


def test_fetcher_preflight_refuses_when_disabled():
    with pytest.raises(SystemExit, match="fetch.enabled = false"):
        cli._fetch_preflight(allow_host=False)


def test_slow_drip_response_is_cut_off(monkeypatch):
    import time as _t

    class Slow(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(1000):
                yield b"x"

    clock = iter(range(0, 10_000, 5))
    monkeypatch.setattr("ssrd.fetch.time.monotonic", lambda: next(clock))
    f = _fetcher(
        lambda req: httpx.Response(200, headers={"content-type": "text/html"}, stream=Slow()),
        {"site.example": "93.184.216.34"},
    )
    assert f.get("https://site.example/").error == "too_slow"
    assert _t  # keep import used
