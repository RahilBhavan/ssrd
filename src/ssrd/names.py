"""Domain-name normalization and the cheap keyword filter (SPEC R2)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache

import idna
import tldextract

from . import config

# Bundled PSL snapshot (pinned by the tldextract version); private suffixes such as
# vercel.app count as public so each customer subdomain is its own registrable domain.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def to_unicode(label_or_name: str) -> str:
    """Decode punycode labels (xn--...) for keyword matching; leave others untouched."""
    out = []
    for label in label_or_name.split("."):
        if label.startswith("xn--"):
            try:
                label = idna.decode(label)
            except idna.IDNAError:
                pass
        out.append(label)
    return ".".join(out)


def clean_name(name: str) -> str | None:
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name or " " in name or "." not in name or "@" in name:
        return None
    return name


def registrable(name: str) -> str | None:
    """eTLD+1 in ASCII form, or None for IPs / bare suffixes."""
    name = clean_name(name)
    if not name:
        return None
    ext = _EXTRACT(name)
    if not ext.suffix or not ext.domain:
        return None
    return f"{ext.domain}.{ext.suffix}"


@dataclass(frozen=True)
class Match:
    group: str
    term: str


@cache
def _compiled() -> tuple[list[tuple[str, str, re.Pattern]], tuple[str, ...]]:
    cfg = config.load()["filter"]
    boundary = set(cfg.get("boundary_terms", []))
    terms = []
    for group in ("investment", "russian_translit", "recovery", "bait"):
        for term in cfg[group]:
            if len(term) >= 4 and term not in boundary:
                pat = re.compile(re.escape(term))
            else:  # short tokens must stand alone between separators/digits
                pat = re.compile(rf"(?:^|[.\-_0-9]){re.escape(term)}(?:$|[.\-_0-9])")
            terms.append((group, term, pat))
    return terms, tuple(cfg["skip_suffixes"])


def keyword_matches(name: str) -> list[Match]:
    """Match keywords against the unicode form of the registrable label (no subdomains, no suffix)."""
    name = clean_name(name)
    if not name:
        return []
    terms, skip = _compiled()
    reg = registrable(name)
    if reg is None or reg.endswith(skip) or any(reg == s for s in skip):
        return []
    haystack = to_unicode(_EXTRACT(name).domain)
    return [Match(g, t) for g, t, pat in terms if pat.search(haystack)]


def priority(reg: str, matches) -> int:
    """Fetch order: model score (0-10 above 0.9), keyword groups, bait terms, scam-common TLDs."""
    cfg = config.load()["filter"]
    groups = {m[0] if isinstance(m, tuple) else m.group for m in matches}
    model = next((float(m[1]) for m in matches if isinstance(m, tuple) and m[0] == "model"), None)
    p = len(groups - {"model"}) + 2 * ("bait" in groups)
    if model is not None:
        p += max(0, round((model - 0.9) * 100))
    return p + (reg.rsplit(".", 1)[-1] in cfg.get("priority_tlds", []))


def defang(text: str) -> str:
    """Make domains/URLs non-clickable for display: hxxps://example[.]com"""
    return text.replace("http", "hxxp").replace(".", "[.]")


def passes(reg: str) -> tuple[bool, list, float | None]:
    """Filter decision for a registrable domain: (passes, keyword matches, model score)."""
    from . import name_model

    cfg = config.load()["filter"]
    matches = keyword_matches(reg)
    if not matches and (reg.endswith(_compiled()[1])):
        return False, [], None
    score = name_model.score(reg) if cfg.get("mode") == "model" else None
    if score is None:
        return bool(matches), matches, None
    return score >= cfg["model_threshold"], matches, score
