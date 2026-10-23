import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import privacy_check as pc  # noqa: E402


def test_token_finds_domains_but_not_emails_or_code():
    text = "matches seized-site.com and sub.bad-kit.net; mail a@b.org; call fn.method(x)"
    assert {"seized-site.com", "sub.bad-kit.net"} <= {t.lower() for t in pc.TOKEN.findall(text)}
    assert "b.org" not in {t.lower() for t in pc.TOKEN.findall(text)}


def test_public_infrastructure_is_allowed():
    assert {"urlscan.io", "brooklynda.org", "x.com"} <= pc.ALLOW
