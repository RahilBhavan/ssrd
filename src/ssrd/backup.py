"""Encrypted backup of the private data/ directory (SPEC R9).

Snapshots SQLite with the online backup API (readers never block the running containers),
tars it with captures, manifests, seeds, models, drafts and logs, and encrypts the archive
with gpg (AES-256, symmetric). The passphrase lives in data/.backup_key (0600); keep a copy
in a password manager, because the backup is useless without it. data/.env is never included.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import config

INCLUDE = ["captures", "manifest", "seeds", "raw", "models", "drafts", "logs", "metrics.jsonl"]


def key_path() -> Path:
    path = Path(config.load()["paths"]["data_dir"]) / ".backup_key"
    if not path.exists():
        path.write_text(secrets.token_urlsafe(32) + "\n")
        os.chmod(path, 0o600)
    return path


def run(out_dir: Path, keep: int = 4) -> Path:
    cfg = config.load()["paths"]
    data = Path(cfg["data_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    out = out_dir / f"ssrd-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.tar.gz.gpg"
    with tempfile.TemporaryDirectory(dir=out_dir) as tmp:
        snap = Path(tmp) / "ssrd.sqlite"
        src, dst = sqlite3.connect(cfg["db"]), sqlite3.connect(snap)
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
        tar = Path(tmp) / "data.tar.gz"
        with tarfile.open(tar, "w:gz") as t:
            t.add(snap, arcname="data/ssrd.sqlite")
            for name in INCLUDE:
                if (data / name).exists():
                    t.add(data / name, arcname=f"data/{name}")
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-file",
                str(key_path()),
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "--output",
                str(out),
                str(tar),
            ],
            check=True,
        )
    os.chmod(out, 0o600)
    for old in sorted(out_dir.glob("ssrd-*.tar.gz.gpg"))[:-keep]:
        old.unlink()
    return out
