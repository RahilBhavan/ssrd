"""Pure feature extraction: bytes in, features out (SPEC R4).

The same functions run on live captures and on urlscan history so features are comparable.
"""

from __future__ import annotations

import base64
import hashlib
import re
from urllib.parse import urljoin, urlsplit

import mmh3
import tlsh
from datasketch import MinHash
from selectolax.lexbor import LexborHTMLParser

from . import config

PARKED_PATTERNS = re.compile(
    r"(domain (is|may be) for sale|buy this domain|this domain is parked|parked free|parking page|sedo|"
    r"dan\.com|afternic|hugedomains|coming soon|under construction|welcome to nginx|"
    r"apache2 (ubuntu|debian) default page|it works!|index of /|default web site page|"
    r"account suspended|this site can.t be reached|website is under maintenance|"
    r"your domain (is|has) expired|domain has expired|renew the domain|"
    r"something amazing will be constructed here|upload your website into the public_html|"
    r"домен продается|сайт в разработке)",
    re.I,
)
SEIZED_PATTERNS = re.compile(r"(this website has been seized|#kcda|seized by (the )?(fbi|law enforcement))", re.I)
INVEST_TERMS = re.compile(
    r"(invest|trading|crypto|bitcoin|profit|deposit|withdraw|portfolio|dividend|forex|"
    r"инвест|крипт|депозит|прибыл|доход|вывод средств|трейд|бирж)",
    re.I,
)
BAIT_TERMS = re.compile(r"(bitlicense|nydfs|\bsec\b|finra|elon musk|tesla|gazprom|газпром|сбер|центробанк)", re.I)
TELEGRAM = re.compile(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_+]{4,})", re.I)
WHATSAPP = re.compile(r"(?:wa\.me|api\.whatsapp\.com/send\?phone=)/?\+?(\d{7,15})", re.I)
CRYPTO_ADDR = re.compile(
    r"\b(0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|T[1-9A-HJ-NP-Za-km-z]{33})\b"
)
_NORM_SUBS = [
    (re.compile(r"[a-f0-9]{16,}", re.I), "H"),  # hashes, tokens, nonces
    (re.compile(r"[A-Za-z0-9+/=_-]{40,}"), "B"),  # base64 blobs
    (re.compile(r"\d+"), "0"),  # numbers, dates, prices
    (re.compile(r"\s+"), " "),
]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def favicon_mmh3(data: bytes) -> int:
    """Shodan-style favicon hash: mmh3 32-bit signed of base64 with newlines every 76 chars."""
    return mmh3.hash(base64.encodebytes(data))


def normalize_html(html: str) -> str:
    s = html.lower()
    for pat, rep in _NORM_SUBS:
        s = pat.sub(rep, s)
    return s


def tlsh_hash(text: str) -> str | None:
    b = text.encode("utf-8", "ignore")
    if len(b) < 50:
        return None
    h = tlsh.hash(b)
    return None if h in ("TNULL", "") else h


def tlsh_distance(a: str | None, b: str | None) -> int | None:
    if not a or not b:
        return None
    return tlsh.diff(a, b)


def tag_shingles(tree: LexborHTMLParser, k: int) -> set[str]:
    tags = [n.tag for n in tree.root.traverse() if n.tag and not n.tag.startswith("-")]
    return {" ".join(tags[i : i + k]) for i in range(max(0, len(tags) - k + 1))}


def minhash(shingles: set[str], num_perm: int) -> list[int]:
    m = MinHash(num_perm=num_perm, seed=1)
    for s in shingles:
        m.update(s.encode())
    return [int(x) for x in m.hashvalues]


def jaccard_from_minhash(a: list[int] | None, b: list[int] | None) -> float | None:
    if not a or not b or len(a) != len(b):
        return None
    return sum(x == y for x, y in zip(a, b, strict=True)) / len(a)


def decode_html(body: bytes, content_type: str = "") -> str:
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    for enc in ([m.group(1)] if m else []) + ["utf-8", "cp1251", "latin-1"]:
        try:
            return body.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", "replace")


def visible_text(tree: LexborHTMLParser) -> str:
    t = LexborHTMLParser(tree.html or "")
    for n in t.css("script, style, noscript, template, svg"):
        n.decompose()
    body = t.body or t.root
    return re.sub(r"\s+", " ", body.text(separator=" ") if body else "").strip()


def cyrillic_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum("Ѐ" <= c <= "ӿ" for c in letters) / len(letters)


def asset_refs(tree: LexborHTMLParser, base_url: str) -> dict:
    """Script/stylesheet/icon references, split into same-host and external."""
    host = urlsplit(base_url).hostname or ""
    scripts, styles, icons = [], [], []
    for n in tree.css("script[src]"):
        scripts.append(urljoin(base_url, n.attributes.get("src") or ""))
    for n in tree.css("link[href]"):
        rel = (n.attributes.get("rel") or "").lower()
        href = urljoin(base_url, n.attributes.get("href") or "")
        if "stylesheet" in rel:
            styles.append(href)
        elif "icon" in rel:
            icons.append(href)
    same = lambda u: (urlsplit(u).hostname or "") == host  # noqa: E731
    paths = sorted({urlsplit(u).path for u in scripts + styles if same(u) and urlsplit(u).path})
    return {
        "scripts": scripts,
        "styles": styles,
        "icons": icons,
        "local_paths": paths,
        "external_hosts": sorted(
            {urlsplit(u).hostname for u in scripts + styles if not same(u) and urlsplit(u).hostname}
        ),
    }


WORD = re.compile(r"[a-zа-яё]{2,}")


def copy_shingles(text: str, host: str, k: int = 5, cap: int = 4000) -> list[int]:
    """Bottom-k sample of hashed word k-grams of the page copy, with brand tokens removed.

    Kits are re-skinned per domain, so tokens taken from the domain label are dropped; the
    bottom-k sample is consistent across pages, so overlaps between samples estimate overlap.
    """
    label = (host or "").split(".")[-2] if host and host.count(".") >= 1 else ""
    brand = {p for p in re.split(r"[-_0-9]+", label.lower()) if len(p) >= 4}
    toks = [t for t in WORD.findall(text.lower()) if t not in brand and not any(t in b or b in t for b in brand)]
    grams = {mmh3.hash(" ".join(toks[i : i + k])) for i in range(max(0, len(toks) - k + 1))}
    return sorted(grams)[:cap]


def classify(text: str, title: str, status: int | None) -> str:
    blob = f"{title} {text[:5000]}"
    if SEIZED_PATTERNS.search(blob):
        return "seized"
    if status is not None and status in (401, 403, 406, 429, 451, 503):
        return "blocked"
    if status is not None and status >= 400:
        return "error"
    if PARKED_PATTERNS.search(blob):
        return "parked"
    if len(text) < 80:
        return "blank"
    return "content"


def html_features(
    body: bytes,
    url: str,
    content_type: str = "",
    status: int | None = 200,
    headers: list[tuple[str, str]] | None = None,
) -> dict:
    cfg = config.load()["score"]
    html = decode_html(body, content_type)
    tree = LexborHTMLParser(html)
    title_node = tree.css_first("title")
    title = re.sub(r"\s+", " ", title_node.text()).strip() if title_node else ""
    html_node = tree.css_first("html")
    text = visible_text(tree)
    inline = [n.text() for n in tree.css("script:not([src])") if n.text() and len(n.text()) > 200]
    gen = tree.css_first('meta[name="generator"]')
    raw = html
    return {
        "url": url,
        "status": status,
        "body_sha256": sha256(body),
        "size": len(body),
        "title": title,
        "title_norm": normalize_html(title).strip(),
        "lang": (html_node.attributes.get("lang") or "").lower() if html_node else "",
        "cyrillic_ratio": round(cyrillic_ratio(text), 3),
        "text_len": len(text),
        "invest_terms": len(INVEST_TERMS.findall(text)),
        "bait_terms": sorted({m.lower() for m in BAIT_TERMS.findall(text)}),
        "tlsh": tlsh_hash(normalize_html(html)),
        "minhash": minhash(tag_shingles(tree, cfg["shingle_k"]), cfg["minhash_perm"]),
        "assets": asset_refs(tree, url),
        # Whitespace-only normalization: account/widget IDs inside snippets must survive, or every
        # site using the same chat widget collapses to one hash (seen: kit-01 chaining, Oct 17).
        "inline_script_sha256": sorted({sha256(re.sub(r"\s+", " ", s).strip().encode()) for s in inline}),
        "generator": gen.attributes.get("content") if gen else None,
        "telegram": sorted({m.lower() for m in TELEGRAM.findall(raw)}),
        "whatsapp": sorted(set(WHATSAPP.findall(raw))),
        "crypto_addresses": sorted(set(CRYPTO_ADDR.findall(text))),
        "header_order": [k.lower() for k, _ in headers] if headers else [],
        "server": next((v for k, v in (headers or []) if k.lower() == "server"), None),
        "page_class": classify(text, title, status),
        "copy_shingles": copy_shingles(text, urlsplit(url).hostname or ""),
        "favicon_mmh3": None,
        "asset_sha256": {},  # path -> sha256, filled by the fetcher / urlscan harvester
    }


def sanitized_text(body: bytes, content_type: str = "", limit: int = 2000) -> str:
    """Text-only, script-free rendering for the review queue."""
    tree = LexborHTMLParser(decode_html(body, content_type))
    return visible_text(tree)[:limit]
