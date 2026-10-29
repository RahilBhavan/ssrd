"""Showcase dashboard: static HTML generator (--public / --private), Rich terminal view, and
loopback-only read-only explorer (127.0.0.1).

Follows CLAUDE.md and SAFETY.md:
- Public mode exports only aggregate telemetry, cluster topology, and synthetic .test walkthroughs,
  verified against seeds/pages domains (including [.] defanged forms) and config/publish-deny.txt.
- Private mode stays in gitignored data/drafts/ (mode 0600) or on 127.0.0.1, defangs every domain,
  and shows sanitized plain text only — raw HTML is never rendered.
- Assistant suggestions (claude-assist) are displayed strictly as uncounted triage hints.
"""

from __future__ import annotations

import gzip
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
from collections import defaultdict
from copy import deepcopy
from functools import lru_cache
from pathlib import Path

from . import config, db, evaluate, kits, memo, names, prelabel, review, score
from . import fingerprint as fp
from .dashboard_data import _safe_kit_name


def _build_synthetic_walkthrough() -> dict:
    """Build deterministic walkthrough cards from synthetic fixtures through the real SSRD pipeline."""
    fix_dir = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
    tpl = (fix_dir / "kit_template.html").read_text()

    def make_cbr_page(brand: str, extra: str = "") -> bytes:
        html = tpl.replace("{BRAND}", brand).replace("{WALLET}", "0x" + "00" * 20).replace("{EXTRA}", extra)
        html = html.replace(
            "— Инвестиционная платформа нового поколения",
            "| AI Trading Platform | Official Website",
        )
        return html.encode()

    def make_kcda_page(brand: str) -> bytes:
        return (
            f"<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
            f"<title>{brand} — Возврат средств и крипто компенсация</title>"
            f"<link rel='stylesheet' href='/assets/recovery-bundle.css'>"
            f"<link rel='stylesheet' href='/assets/cabinet-grid.css'></head><body>"
            f"<main class='recovery'><article><h1>{brand}: возврат инвестиций, брокер капитал и прибыль</h1>"
            f"<p>Юридическая компенсация депозита от $500 на крипто бирже. Доход и вывод за 48 часов через фонд трейд актив.</p>"
            f"<section class='steps'><div>Шаг 1: Проверка транзакции BTC ETH USDT</div>"
            f"<div>Шаг 2: Возврат средств на ваш крипто портфель</div></section>"
            f"<p>Связь: <a href='https://t.me/synthetic_recovery_demo'>Telegram Desk</a></p></article>"
            f"<script>window.__RECOVERY_PORTAL__={{version:'4.2',desk:'claim-intake',minClaim:500,asset:'USDT'}};</script>"
            f"</main></body></html>"
        ).encode()

    with tempfile.TemporaryDirectory(prefix="ssrd-walk-") as tmp:
        mem = db.connect(str(Path(tmp) / "walk.sqlite"))
        mem.execute("INSERT INTO seeds(domain,source) VALUES('kcda-seed01.test','kcda'),('kcda-seed02.test','kcda')")

        def insert_page(src: str, dom: str, body: bytes) -> tuple[int, dict]:
            feat = fp.html_features(
                body,
                f"https://{dom}/",
                "text/html",
                200,
                [("server", "cloudflare"), ("content-type", "text/html")],
            )
            feat["asn"] = 13335
            cur = mem.execute(
                "INSERT INTO pages(source,ref,domain,observed_at,page_class,features) VALUES(?,?,?,?,?,?)",
                (src, dom, dom, db.now(), feat["page_class"], db.dumps(feat)),
            )
            return int(cur.lastrowid), feat

        insert_page("urlscan", "seed-alpha.test", make_cbr_page("Alpha Yield"))
        insert_page("urlscan", "seed-beta.test", make_cbr_page("Beta Yield"))
        insert_page("wayback", "kcda-seed01.test", make_kcda_page("Vozvrat Group"))
        insert_page("wayback", "kcda-seed02.test", make_kcda_page("Kompensac Desk"))
        mem.commit()
        kits.build(mem)

        live_cases = [
            ("newbrand-capital.test", make_cbr_page("Newbrand Capital"), 21.4),
            ("vozvrat-kapital.test", make_kcda_page("Vozvrat Kapital"), 23.8),
            (
                "gate-check-invest.test",
                make_cbr_page(
                    "GateInvest",
                    "<p>Confirming you are human. You will be redirected to portal.example.test in 5 seconds.</p>",
                ),
                26.1,
            ),
        ]

        cards = []
        for dom, body, mins in live_cases:
            pid, feat = insert_page("live", dom, body)
            mem.commit()
            score.score_page(mem, pid)
            prelabel.apply(mem, pid)
            srow = mem.execute(
                "SELECT k.name, s.score, s.alert, s.details FROM scores s JOIN kits k ON k.id=s.kit_id "
                "WHERE s.page_id=? ORDER BY s.alert DESC, s.score DESC LIMIT 1",
                (pid,),
            ).fetchone()
            det = json.loads(srow["details"])
            sug = review.suggestion(mem, pid)
            cards.append(
                {
                    "page_id": 0,
                    "domain": names.defang(dom),
                    "kit": srow["name"],
                    "group": evaluate.group_of(srow["name"]),
                    "score": srow["score"],
                    "alert": bool(srow["alert"]),
                    "confidence": "synthetic-demo",
                    "nearest_member": names.defang(det["member_domain"]),
                    "page_class": feat["page_class"],
                    "lang": feat.get("lang"),
                    "cyrillic_ratio": feat.get("cyrillic_ratio"),
                    "invest_terms": feat.get("invest_terms", 0),
                    "signals": [
                        {"family": s["family"], "signal": s["signal"], "strength": s["strength"]}
                        for s in det["signals"]
                    ],
                    "assist_hint": {"label": sug[0], "note": sug[1]} if sug else None,
                    "human_labels": [],
                    "ct_to_alert_min": mins,
                    "sanitized_text": names.defang(fp.sanitized_text(body))[:1800],
                }
            )

        benign_body = (fix_dir / "benign.html").read_bytes()
        b_feat = fp.html_features(
            benign_body, "https://garden-notes.test/", "text/html", 200, [("server", "cloudflare")]
        )
        cards.append(
            {
                "page_id": 0,
                "domain": "garden-notes[.]test",
                "kit": "kit-01",
                "group": "cbr",
                "score": 2.0,
                "alert": False,
                "confidence": "near-miss-demo",
                "nearest_member": "seed-alpha[.]test",
                "page_class": b_feat["page_class"],
                "lang": b_feat.get("lang"),
                "cyrillic_ratio": b_feat.get("cyrillic_ratio"),
                "invest_terms": b_feat.get("invest_terms", 0),
                "signals": [
                    {"family": "C", "signal": "header_order", "strength": 1},
                    {"family": "D", "signal": "asn", "strength": 1},
                ],
                "assist_hint": None,
                "human_labels": [],
                "ct_to_alert_min": None,
                "sanitized_text": names.defang(fp.sanitized_text(benign_body))[:1800],
            }
        )
        mem.close()

    return {
        "is_synthetic": True,
        "note": "Rendered from synthetic .test fixtures through fingerprint.py → kits.py → score.py → prelabel.py (real domains stay in private data/).",
        "cards": cards,
    }


def _sanitized_body_preview(features: dict, max_chars: int = 2400) -> str:
    sha = features.get("body_sha256")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        return "(no capture body recorded)"
    cap = Path(config.load()["paths"]["data_dir"]) / "captures" / f"{sha}.gz"
    if not cap.exists():
        return "(capture file not present on disk)"
    return names.defang(fp.sanitized_text(gzip.decompress(cap.read_bytes())))[:max_chars]


def private_walkthrough(conn: sqlite3.Connection, limit: int = 40) -> dict:
    assist = config.load()["review"]["assist_reviewer"]
    human_by_page: dict[int, list[str]] = defaultdict(list)
    assist_by_page: dict[int, tuple[str, str | None]] = {}
    for pid, rev, lab, note in conn.execute("SELECT page_id, reviewer, label, note FROM labels"):
        if rev == assist:
            assist_by_page[pid] = (lab, note)
        else:
            human_by_page[pid].append(lab)

    cbr_domains = {r[0] for r in conn.execute("SELECT domain FROM seeds WHERE source='cbr'")}
    rows = conn.execute(
        "SELECT a.page_id, a.first_alert_at, a.kit_name, p.domain, p.page_class, p.features, "
        "(SELECT MIN(ct_ts) FROM candidates c WHERE c.domain=p.domain) AS ct_ts "
        "FROM alert_log a JOIN pages p ON p.id=a.page_id "
        "WHERE EXISTS(SELECT 1 FROM scores s WHERE s.page_id=p.id AND s.alert=1) "
        "ORDER BY a.first_alert_at DESC LIMIT ?",
        (limit,),
    ).fetchall()

    cards = []
    conf_rank = {"confirmed": 3, "likely": 2, "speculative": 1}
    for r in rows:
        pid = r["page_id"]
        hlabs = human_by_page.get(pid, [])
        yes = hlabs.count("scam-kit")
        if yes >= 2 or (yes == 1 and r["domain"] in cbr_domains):
            conf = "confirmed"
        elif yes == 1:
            conf = "likely"
        elif any(x in memo.EXCLUDE for x in hlabs):
            conf = "rejected"
        else:
            conf = "speculative"

        srow = conn.execute(
            "SELECT k.name, s.score, s.alert, s.details FROM scores s JOIN kits k ON k.id=s.kit_id "
            "WHERE s.page_id=? AND s.alert=1 ORDER BY k.name=? DESC, s.score DESC LIMIT 1",
            (pid, r["kit_name"]),
        ).fetchone()
        if not srow:
            continue
        det = json.loads(srow["details"])
        feat = json.loads(r["features"])
        sug = assist_by_page.get(pid)
        ttf = (
            round((r["first_alert_at"] - r["ct_ts"]) / 60, 1)
            if r["ct_ts"] and r["first_alert_at"] >= r["ct_ts"]
            else None
        )
        cards.append(
            {
                "page_id": pid,
                "domain": names.defang(r["domain"]),
                "kit": _safe_kit_name(srow["name"], "private"),
                "group": evaluate.group_of(srow["name"]),
                "score": srow["score"],
                "alert": True,
                "confidence": conf,
                "nearest_member": names.defang(det.get("member_domain", "")),
                "page_class": r["page_class"] or "content",
                "lang": feat.get("lang"),
                "cyrillic_ratio": feat.get("cyrillic_ratio"),
                "invest_terms": feat.get("invest_terms", 0),
                "signals": [
                    {"family": s["family"], "signal": s["signal"], "strength": s["strength"]}
                    for s in det.get("signals", [])
                ],
                "assist_hint": {"label": sug[0], "note": sug[1]} if sug else None,
                "human_labels": hlabs,
                "ct_to_alert_min": ttf,
                "sanitized_text": _sanitized_body_preview(feat, max_chars=2000),
            }
        )

    cards.sort(key=lambda c: (conf_rank.get(c["confidence"], 0), c["group"] == "kcda", c["score"]), reverse=True)
    return {
        "is_synthetic": False,
        "note": f"Showing {len(cards)} active live alerts (domains defanged, scripts stripped via fingerprint.sanitized_text).",
        "cards": cards,
    }


def page_detail(conn: sqlite3.Connection, page_id: int) -> dict | None:
    """Read-only sanitized page inspection for the local 127.0.0.1 explorer."""
    row = conn.execute("SELECT id, domain, page_class, features FROM pages WHERE id=?", (page_id,)).fetchone()
    if not row:
        return None
    feat = json.loads(row["features"])
    return {
        "page_id": row["id"],
        "domain": names.defang(row["domain"]),
        "page_class": row["page_class"],
        "sanitized_text": _sanitized_body_preview(feat, max_chars=8000),
    }


@lru_cache(maxsize=1)
def _synthetic_json() -> str:
    # The scorer owns a process-global deny cache. Synthetic scoring must never populate
    # or consume a cache belonging to the real private database.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json; from ssrd.dashboard_walkthrough import _build_synthetic_walkthrough; print(json.dumps(_build_synthetic_walkthrough()))",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.stdout


def synthetic_walkthrough() -> dict:
    return deepcopy(json.loads(_synthetic_json()))
