#!/usr/bin/env python3
"""Publish one checked public HTML file; never upload a directory or private state."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import re
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx

from ssrd import dashboard

ROOT = Path(__file__).resolve().parents[1]
API = "https://api.vercel.com"
MARKER = '<meta name="ssrd-public-export" content="1">'


class PublishError(Exception):
    """Safe-to-log failure: never contains response bodies or private input."""


@dataclass(frozen=True)
class Settings:
    project: str
    name: str
    domain: str
    token_file: Path
    team: str | None = None
    approved_source_sha256: str = ""


def settings(path: Path) -> Settings:
    if path.resolve().is_relative_to(ROOT):
        raise PublishError("website credentials must live outside the repository")
    if path.stat().st_mode & 0o077:
        raise PublishError("website config must have mode 0600")
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise PublishError("invalid website configuration")
    project = raw.get("project_id") or raw.get("project_name")
    name = raw.get("project_name", "ssrd")
    domain = raw.get("domain")
    if not isinstance(project, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", project):
        raise PublishError("invalid project identifier")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9-]{1,100}", name):
        raise PublishError("invalid project name")
    if not isinstance(domain, str) or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", domain):
        raise PublishError("invalid public domain")
    token = Path(raw["token_file"]).expanduser().resolve()
    if token.is_relative_to(ROOT):
        raise PublishError("token must live outside the repository")
    team = raw.get("team_id")
    if team is not None and (not isinstance(team, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", team)):
        raise PublishError("invalid team identifier")
    approved = raw.get("approved_source_sha256")
    if not isinstance(approved, str) or not re.fullmatch(r"[a-f0-9]{64}", approved):
        raise PublishError("required approved_source_sha256 must be a SHA-256 digest")
    return Settings(project, name, domain, token, team, approved)


def source_digest(root: Path | None = None) -> str:
    """Hash source identity and content with length framing, excluding all live data."""
    root = root or ROOT
    paths = list((root / "src/ssrd").glob("*.py"))
    paths += [p for p in (root / "src/ssrd/dashboard_assets").rglob("*") if p.is_file() or p.is_symlink()]
    paths.append(root / "scripts/deploy_website.py")
    paths += [root / "tests/fixtures" / name for name in ("kit_template.html", "benign.html")]
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda p: p.relative_to(root).as_posix()):
        if path.is_symlink() or not path.is_file():
            raise PublishError("approved source must contain only regular files")
        name, content = path.relative_to(root).as_posix().encode(), path.read_bytes()
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(len(content).to_bytes(8, "big") + content)
    return digest.hexdigest()


def require_approved_source(cfg: Settings) -> None:
    if cfg.approved_source_sha256 != source_digest():
        raise PublishError("source approval mismatch; review changes and approve the new source digest")


def build(stage: Path, *, db_path: str | None = None) -> bytes:
    deny = ROOT / "config" / "publish-deny.txt"
    if not deny.is_file() or not any(
        line.strip() and not line.startswith("#") for line in deny.read_text().splitlines()
    ):
        raise PublishError("nonempty local publish deny configuration required")
    with closing(dashboard.connect_ro(db_path)) as conn:
        payload = dashboard.collect_payload(conn, mode="public")
        if payload.get("mode") != "public":
            raise PublishError("refusing nonpublic export")
        dest = dashboard.write_dashboard(conn, mode="public", out=stage / "index.html", payload=payload)
        html = dest.read_text()
        if "</head>" not in html:
            raise PublishError("public HTML is missing its head")
        html = html.replace("</head>", MARKER + "\n</head>", 1)
        dashboard.assert_public_safe(html, conn)
        dest.write_text(html)
    return html.encode()


def upload_files(stage: Path) -> list[dict]:
    entries = list(stage.iterdir())
    if len(entries) != 1 or entries[0].name != "index.html" or entries[0].is_symlink() or not entries[0].is_file():
        raise PublishError("staging must contain only regular index.html")
    data = entries[0].read_bytes()
    if MARKER.encode() not in data or len(data) > 5_000_000:
        raise PublishError("invalid public HTML artifact")
    return [{"file": "index.html", "data": base64.b64encode(data).decode(), "encoding": "base64"}]


class Vercel:
    def __init__(self, client: httpx.Client, cfg: Settings, token: str):
        self.client, self.cfg, self.token = client, cfg, token

    def request(self, method: str, path: str, *, body: dict | None = None, missing: bool = False) -> dict:
        response = self.client.request(
            method,
            API + path,
            params={"teamId": self.cfg.team} if self.cfg.team else {},
            headers={"Authorization": f"Bearer {self.token}"},
            json=body,
        )
        if missing and response.status_code == 404:
            return {}
        if not response.is_success:
            raise PublishError(f"Vercel {method} failed (HTTP {response.status_code})")
        try:
            data = response.json()
        except ValueError:
            raise PublishError("invalid Vercel response") from None
        if not isinstance(data, dict):
            raise PublishError("invalid Vercel response")
        return data

    def alias(self) -> str | None:
        data = self.request("GET", "/v4/aliases/" + quote(self.cfg.domain, safe=""), missing=True)
        deployment = data.get("deployment") or {}
        if not isinstance(deployment, dict):
            raise PublishError("invalid alias response")
        ident = data.get("deploymentId") or deployment.get("id")
        if ident is not None and (not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", ident)):
            raise PublishError("invalid alias deployment identifier")
        return ident

    def restore(self, previous: str | None, current: str) -> None:
        # Do not overwrite an alias another publisher changed after our deployment.
        if self.alias() != current:
            return
        if previous:
            self.request("POST", f"/v2/deployments/{previous}/aliases", body={"alias": self.cfg.domain})
        else:
            self.request("DELETE", "/v2/aliases/" + quote(self.cfg.domain, safe=""))


def verify(client: httpx.Client, domain: str, expected: bytes) -> None:
    # Separate unauthenticated client: the Vercel bearer token never reaches a website.
    response = client.get(f"https://{domain}/", headers={"Cache-Control": "no-cache"})
    if not response.is_success or MARKER.encode() not in response.content:
        raise PublishError("public website marker verification failed")
    if hashlib.sha256(response.content).digest() != hashlib.sha256(expected).digest():
        raise PublishError("public website freshness/hash verification failed")


def deploy(api: Vercel, public: httpx.Client, stage: Path, *, timeout: float = 240, interval: float = 5) -> str:
    require_approved_source(api.cfg)
    files = upload_files(stage)
    expected = (stage / "index.html").read_bytes()
    previous = api.alias()
    created = api.request(
        "POST",
        "/v13/deployments",
        body={
            "name": api.cfg.name,
            "project": api.cfg.project,
            "target": "production",
            "files": files,
            "alias": [api.cfg.domain],
            "projectSettings": {"framework": None, "buildCommand": "", "installCommand": "", "outputDirectory": "."},
            "meta": {"ssrdPublicSha256": hashlib.sha256(expected).hexdigest()},
        },
    )
    ident = created.get("id")
    if not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", ident):
        raise PublishError("invalid deployment identifier")
    deadline = time.monotonic() + timeout
    try:
        state = created
        while state.get("readyState") != "READY":
            if state.get("readyState") in {"ERROR", "CANCELED"}:
                raise PublishError("deployment failed before readiness")
            if time.monotonic() >= deadline:
                # Stop a queued deployment from silently replacing the site after timeout.
                api.request("PATCH", f"/v12/deployments/{ident}/cancel")
                raise PublishError("deployment readiness timed out; cancellation requested")
            time.sleep(interval)
            state = api.request("GET", f"/v13/deployments/{ident}")
        if state.get("aliasError"):
            raise PublishError("production alias assignment failed")
        if api.alias() != ident:
            raise PublishError("production alias does not point to new deployment")
        verify(public, api.cfg.domain, expected)
    except (PublishError, httpx.HTTPError):
        try:
            api.restore(previous, ident)
        except (PublishError, httpx.HTTPError):
            raise PublishError("deployment verification failed; automatic alias restoration also failed") from None
        raise
    return ident


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path.home() / ".config/ssrd/website.json")
    parser.add_argument("--db")
    parser.add_argument("--check", "--build-only", action="store_true", help="export and privacy-check without network")
    args = parser.parse_args()
    state_dir = ROOT / "data" / "website"
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with (state_dir / "publish.lock").open("w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PublishError("another website publisher is running") from None
            with tempfile.TemporaryDirectory(prefix="stage-", dir=state_dir) as temp:
                stage = Path(temp)
                artifact = build(stage, db_path=args.db)
                upload_files(stage)
                if args.check:
                    print("public website build/privacy check passed; sha256=" + hashlib.sha256(artifact).hexdigest())
                    print("approved_source_sha256=" + source_digest())
                    return 0
                cfg = settings(args.config)
                require_approved_source(cfg)
                if cfg.token_file.stat().st_mode & 0o077:
                    raise PublishError("token file must have mode 0600")
                token = cfg.token_file.read_text().strip()
                if not token or any(c.isspace() for c in token):
                    raise PublishError("invalid token file")
                with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as client:
                    with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as public:
                        ident = deploy(Vercel(client, cfg, token), public, stage)
                receipt = {
                    "deployment_id": ident,
                    "sha256": hashlib.sha256(artifact).hexdigest(),
                    "verified_at": int(time.time()),
                    "approved_source_sha256": cfg.approved_source_sha256,
                }
                dashboard._atomic_write(state_dir / "last-success.json", json.dumps(receipt), private=True)
                print("public website deployment verified")
        return 0
    except PublishError as exc:
        print(f"website publication stopped: {exc}", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, httpx.HTTPError):
        print(
            "website publication stopped: local configuration, export or network error (details withheld)",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
