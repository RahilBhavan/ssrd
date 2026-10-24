"""Load config/ssrd.toml into a plain dict, with paths resolved against the repo root.

An optional git-ignored config/ssrd.local.toml next to it overrides values per key, one section deep.
"""

from __future__ import annotations

import os
import tomllib
from functools import cache
from pathlib import Path

ROOT = Path(os.environ.get("SSRD_ROOT", Path(__file__).resolve().parents[2]))


@cache
def load(path: str | None = None) -> dict:
    cfg_path = Path(path or os.environ.get("SSRD_CONFIG", ROOT / "config" / "ssrd.toml"))
    with open(cfg_path, "rb") as f:
        cfg = tomllib.load(f)
    local = cfg_path.with_name(cfg_path.stem + ".local.toml")
    if local.exists():
        with open(local, "rb") as f:
            for section, values in tomllib.load(f).items():
                cfg.setdefault(section, {}).update(values)
    for key, rel in cfg["paths"].items():
        cfg["paths"][key] = str(ROOT / rel) if not os.path.isabs(rel) else rel
    Path(cfg["paths"]["data_dir"]).mkdir(parents=True, exist_ok=True)
    _load_env(Path(cfg["paths"]["data_dir"]) / ".env")
    return cfg


def _load_env(path: Path) -> None:
    """Read KEY=VALUE secrets (e.g. URLSCAN_API_KEY) from the private data/.env; env vars win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key and not key.startswith("#"):
            os.environ.setdefault(key.strip(), value.strip().strip('"'))
