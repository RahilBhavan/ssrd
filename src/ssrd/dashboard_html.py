"""Self-contained offline HTML/SVG/JS renderer for the SSRD showcase dashboard.

Enforces a strict Content-Security-Policy so opening a generated file in a browser can never
make external network requests, execute captured scripts, or contact flagged domains.
"""

from __future__ import annotations

import base64
import json
from html import escape
from pathlib import Path

_ASSETS = Path(__file__).with_name("dashboard_assets")


def safe_json_for_html(data: dict) -> str:
    """Serialize JSON with HTML-sensitive characters escaped so </script> can never break out."""
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return raw.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def render_html(payload: dict, *, live_server: bool = False, embed: bool = False) -> str:
    csp = (
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; font-src data:; connect-src 'self'"
        if live_server
        else "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:"
    )
    mode = payload.get("mode", "public")
    title = (
        "SSRD — Scam-Site Respawn Detector (Public Telemetry Showcase)"
        if mode == "public"
        else "SSRD — Private Investigative Dashboard (Defanged & Sanitized)"
    )
    embedded = safe_json_for_html(payload)
    live_flag = "true" if live_server else "false"
    embed_flag = "true" if embed else "false"
    body_cls = "embed" if embed else "standalone"
    fonts = "".join(
        f"@font-face{{font-family:'{family}';src:url(data:font/ttf;base64,{base64.b64encode((_ASSETS / filename).read_bytes()).decode()}) format('truetype');font-weight:{weight};font-display:swap;}}"
        for family, filename, weight in (
            ("Rahil Display", "Archivo-VF.ttf", "100 900"),
            ("Rahil Mono", "IBMPlexMono-Regular.ttf", "400"),
        )
    )
    template = (_ASSETS / "page.html").read_text()
    template = template.replace("__STYLES__", fonts + (_ASSETS / "style.css").read_text())
    template = template.replace(
        "__SCRIPTS__", "\n".join((_ASSETS / name).read_text() for name in ("charts.js", "review.js"))
    )
    funnel = payload.get("funnel", {})
    snapshot = escape(str(payload.get("generated_at_utc", "unavailable")))
    fallback = f'<p class="freshness">Snapshot generated: {snapshot}. Counts are observations at this time, not a live feed.</p>'
    fallback += '<noscript><section class="card"><h2>Snapshot summary</h2><p>Interactive charts need JavaScript. The metric guide and these recorded counts remain available.</p><dl class="glossary">'
    for label, key in (
        ("CT names in metrics window", "ct_names"),
        ("Candidates in database", "candidates_db"),
        ("Completed visits", "visits_done"),
        ("Active kit alerts", "alerts_active"),
    ):
        value = escape(str(funnel.get(key, "Unavailable")))
        fallback += f"<div><dt>{label}</dt><dd>{value}</dd></div>"
    fallback += "</dl></section></noscript>"
    return (
        template.replace("__FALLBACK__", fallback)
        .replace("__CSP__", csp)
        .replace("__TITLE__", title)
        .replace("__DATA__", embedded)
        .replace("__LIVE_SERVER__", live_flag)
        .replace("__EMBED__", embed_flag)
        .replace("__BODY_CLASS__", body_cls)
    )
