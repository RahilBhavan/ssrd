import os
import re
import tempfile
from pathlib import Path

import pytest

# Isolate every test run from the real data/ directory.
_TMP = tempfile.mkdtemp(prefix="ssrd-test-")
_cfg = (Path(__file__).resolve().parents[1] / "config" / "ssrd.toml").read_text()
_cfg = _cfg.replace('data_dir = "data"', f'data_dir = "{_TMP}"').replace(
    'db = "data/ssrd.sqlite"', f'db = "{_TMP}/t.sqlite"'
)
# Tests always run with fetching disabled and strict mode, whatever the live config says.
_cfg = re.sub(r"(?m)^enabled = .*$", "enabled = false", _cfg)
_cfg = re.sub(r'(?m)^mode = "passive_visit".*$', 'mode = "strict"', _cfg)
_cfg = re.sub(r'(?m)^mode = "model"$', 'mode = "keyword"', _cfg)  # unit tests exercise the keyword filter
(Path(_TMP) / "ssrd.toml").write_text(_cfg)
os.environ["SSRD_CONFIG"] = str(Path(_TMP) / "ssrd.toml")

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def conn(tmp_path):
    from ssrd import db

    return db.connect(str(tmp_path / "t.sqlite"))


@pytest.fixture
def kit_html():
    """Synthetic 'fake investment platform' template, parameterized by brand name."""

    def make(brand: str, wallet: str = "0x" + "ab" * 20, extra: str = "") -> bytes:
        return (
            (FIX / "kit_template.html")
            .read_text()
            .replace("{BRAND}", brand)
            .replace("{WALLET}", wallet)
            .replace("{EXTRA}", extra)
            .encode()
        )

    return make
