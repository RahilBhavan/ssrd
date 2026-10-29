"""Offline deployment boundary checks: only synthetic public HTML crosses the network."""

import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest

spec = importlib.util.spec_from_file_location("deploy_website", Path(__file__).parents[1] / "scripts/deploy_website.py")
website = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = website
spec.loader.exec_module(website)


@pytest.fixture
def stage(tmp_path):
    folder = tmp_path / "stage"
    folder.mkdir()
    (folder / "index.html").write_text("<html><head>" + website.MARKER + "</head><body>synthetic</body></html>")
    return folder


def api_client(handler):
    cfg = website.Settings(
        "prj_test", "ssrd-test", "ssrd.example.test", Path("/unused"), approved_source_sha256=website.source_digest()
    )
    return website.Vercel(httpx.Client(transport=httpx.MockTransport(handler)), cfg, "never-log-this-token")


def test_upload_refuses_extra_files_and_symlinks(stage):
    (stage / "private.sqlite").write_text("secret")
    with pytest.raises(website.PublishError, match="only regular"):
        website.upload_files(stage)
    (stage / "private.sqlite").unlink()
    target = stage.parent / "outside.html"
    (stage / "index.html").rename(target)
    (stage / "index.html").symlink_to(target)
    with pytest.raises(website.PublishError, match="only regular"):
        website.upload_files(stage)


def test_ready_uploads_only_index_and_verifies_without_auth(stage):
    uploaded = []
    aliases = iter(["dpl_old", "dpl_new"])

    def handler(request):
        assert request.url.host == "api.vercel.com"
        if request.url.path.startswith("/v4/aliases"):
            return httpx.Response(200, json={"deploymentId": next(aliases)})
        payload = json.loads(request.content)
        uploaded.extend(payload["files"])
        assert payload["target"] == "production"
        return httpx.Response(200, json={"id": "dpl_new", "readyState": "READY"})

    def public(request):
        assert "authorization" not in request.headers
        return httpx.Response(200, content=(stage / "index.html").read_bytes())

    result = website.deploy(api_client(handler), httpx.Client(transport=httpx.MockTransport(public)), stage)
    assert result == "dpl_new"
    assert [f["file"] for f in uploaded] == ["index.html"]
    assert uploaded[0]["encoding"] == "base64"


def test_failed_build_does_not_change_alias(stage):
    paths = []

    def handler(request):
        paths.append((request.method, request.url.path))
        if request.method == "GET":
            return httpx.Response(200, json={"deploymentId": "dpl_old"})
        return httpx.Response(200, json={"id": "dpl_new", "readyState": "ERROR"})

    def public(request):
        pytest.fail("failed build must not trigger website request")

    with pytest.raises(website.PublishError, match="before readiness"):
        website.deploy(api_client(handler), httpx.Client(transport=httpx.MockTransport(public)), stage)
    assert all("/v2/" not in path for _, path in paths)


def test_wrong_public_hash_restores_previous_alias(stage):
    requests = []

    def handler(request):
        requests.append((request.method, request.url.path))
        if request.url.path.startswith("/v4/"):
            return httpx.Response(200, json={"deploymentId": "dpl_old" if len(requests) == 1 else "dpl_new"})
        return httpx.Response(200, json={"id": "dpl_new", "readyState": "READY"})

    public = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=website.MARKER + "old")))
    with pytest.raises(website.PublishError, match="freshness/hash"):
        website.deploy(api_client(handler), public, stage)
    assert requests[-1] == ("POST", "/v2/deployments/dpl_old/aliases")


def test_timeout_cancels_deployment_without_reposting(stage):
    requests = []

    def handler(request):
        requests.append((request.method, request.url.path))
        if request.url.path.startswith("/v4/"):
            return httpx.Response(200, json={"deploymentId": "dpl_old"})
        return httpx.Response(200, json={"id": "dpl_new", "readyState": "BUILDING"})

    with pytest.raises(website.PublishError, match="timed out"):
        website.deploy(api_client(handler), httpx.Client(), stage, timeout=0)
    assert ("PATCH", "/v12/deployments/dpl_new/cancel") in requests
    assert requests.count(("POST", "/v13/deployments")) == 1


def test_api_errors_withhold_response_body():
    def handler(request):
        return httpx.Response(403, text="secret remote error content")

    with pytest.raises(website.PublishError) as error:
        api_client(handler).request("GET", "/v4/aliases/test")
    assert "secret" not in str(error.value)


def test_build_refuses_missing_deny_config(tmp_path, monkeypatch):
    monkeypatch.setattr(website, "ROOT", tmp_path)
    with pytest.raises(website.PublishError, match="deny configuration"):
        website.build(tmp_path)


def test_build_refuses_private_payload_before_writing(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "config").mkdir(parents=True)
    (root / "config/publish-deny.txt").write_text("blocked-local-pattern")
    monkeypatch.setattr(website, "ROOT", root)

    class Connection:
        def close(self):
            pass

    monkeypatch.setattr(website.dashboard, "connect_ro", lambda path: Connection())
    monkeypatch.setattr(website.dashboard, "collect_payload", lambda conn, **kw: {"mode": "private"})
    with pytest.raises(website.PublishError, match="nonpublic"):
        website.build(tmp_path)
    assert not (tmp_path / "index.html").exists()


def test_source_mismatch_refuses_before_any_network(stage):
    api = api_client(lambda request: pytest.fail("source drift must not make any network request"))
    api.cfg = website.Settings(
        "prj_test", "ssrd-test", "ssrd.example.test", Path("/unused"), approved_source_sha256="0" * 64
    )
    with pytest.raises(website.PublishError, match="source approval mismatch"):
        website.deploy(api, httpx.Client(), stage)


def test_source_digest_covers_source_paths_assets_and_ignores_live_data(tmp_path):
    (tmp_path / "src/ssrd/dashboard_assets").mkdir(parents=True)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "tests/fixtures").mkdir(parents=True)
    for name in ("kit_template.html", "benign.html"):
        (tmp_path / "tests/fixtures" / name).write_text("reviewed synthetic fixture")
    (tmp_path / "src/ssrd/export.py").write_text("reviewed exporter")
    (tmp_path / "src/ssrd/dashboard_assets/page.html").write_text("reviewed UI")
    (tmp_path / "scripts/deploy_website.py").write_text("reviewed publisher")
    initial = website.source_digest(tmp_path)
    (tmp_path / "data/live.sqlite").write_text("new live aggregates")
    assert website.source_digest(tmp_path) == initial
    (tmp_path / "src/ssrd/dashboard_assets/page.html").write_text("unreviewed UI")
    changed = website.source_digest(tmp_path)
    assert changed != initial
    (tmp_path / "src/ssrd/dashboard_assets/page.html").rename(tmp_path / "src/ssrd/dashboard_assets/new.html")
    assert website.source_digest(tmp_path) != changed

    for name in ("kit_template.html", "benign.html"):
        before = website.source_digest(tmp_path)
        (tmp_path / "tests/fixtures" / name).write_text("unreviewed fixture content")
        assert website.source_digest(tmp_path) != before
