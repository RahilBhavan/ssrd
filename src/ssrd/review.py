"""CLI review queue (SPEC R7). Shows sanitized, defanged text only; never renders HTML."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import config, db, fingerprint, names

KEYS = {"s": "scam-kit", "n": "not-scam", "d": "decoy-cloaked", "p": "parked", "e": "error", "u": "unsure"}


def queue(
    conn,
    reviewer: str,
    include_below: bool = False,
    sample: str | None = None,
    limit: int | None = None,
    suggested: str | None = None,
):
    if sample:  # a frozen random sample, in its stored random order; limit = first N positions
        return conn.execute(
            "SELECT p.id, p.domain, p.features, p.page_class FROM sample_members m JOIN pages p ON p.id=m.page_id "
            "WHERE m.name=? AND m.position<? "
            "AND NOT EXISTS(SELECT 1 FROM labels l WHERE l.page_id=p.id AND l.reviewer=?) ORDER BY m.position",
            (sample, limit if limit is not None else 1 << 30, reviewer),
        ).fetchall()
    where = "1=1" if include_below else "EXISTS(SELECT 1 FROM alert_log a WHERE a.page_id=p.id)"
    args: list = [reviewer]
    if suggested:  # only alerts the assistant suggested this label for, e.g. to confirm leads before reporting
        where += " AND EXISTS(SELECT 1 FROM labels g WHERE g.page_id=p.id AND g.reviewer=? AND g.label=?)"
        args = [config.load()["review"]["assist_reviewer"], suggested, reviewer]
    return conn.execute(
        f"SELECT p.id, p.domain, p.features, p.page_class, "
        f"(SELECT MAX(score) FROM scores s WHERE s.page_id=p.id) AS best "
        f"FROM pages p WHERE p.source='live' AND {where} "
        f"AND NOT EXISTS(SELECT 1 FROM labels l WHERE l.page_id=p.id AND l.reviewer=?) "
        f"ORDER BY best DESC NULLS LAST, p.id",
        args,
    ).fetchall()


def body_text(features: dict) -> str:
    path = Path(config.load()["paths"]["data_dir"]) / "captures" / f"{features['body_sha256']}.gz"
    if not path.exists():
        return "(capture missing)"
    return names.defang(fingerprint.sanitized_text(gzip.decompress(path.read_bytes())))


def show(console: Console, conn, row, hints: bool = True) -> None:
    f = json.loads(row["features"])
    console.rule(f"page {row['id']} · {names.defang(row['domain'])} · class={row['page_class']}")
    meta = Table.grid(padding=(0, 2))
    meta.add_row("title", f.get("title", "")[:120])
    meta.add_row("lang / cyr", f"{f.get('lang')} / {f.get('cyrillic_ratio')}")
    meta.add_row("invest terms", str(f.get("invest_terms")))
    meta.add_row("bait", ", ".join(f.get("bait_terms", [])))
    meta.add_row("asn / server", f"{f.get('asn')} / {f.get('server')}")
    console.print(meta)
    for s in conn.execute(
        "SELECT k.name, s.score, s.alert, s.details FROM scores s JOIN kits k ON k.id=s.kit_id "
        "WHERE s.page_id=? ORDER BY s.score DESC LIMIT 3",
        (row["id"],),
    ):
        d = json.loads(s["details"])
        sigs = "; ".join(f"{x['family']}:{x['signal']}" for x in d["signals"])
        console.print(
            f"[bold]{s['name']}[/] score={s['score']} alert={bool(s['alert'])} "
            f"nearest={names.defang(d['member_domain'])} · {sigs}"
        )
    console.print(Panel(body_text(f), title="sanitized text (scripts stripped, links defanged)", height=24))
    sug = suggestion(conn, row["id"]) if hints else None
    if sug:
        console.print(
            f"[dim]assistant suggests[/] [bold]{sug[0]}[/] [dim]({sug[1] or 'no note'}); press enter to accept, "
            "or another key to override. Only your label counts.[/]"
        )


def suggestion(conn, page_id: int) -> tuple[str, str | None] | None:
    r = conn.execute(
        "SELECT label, note FROM labels WHERE page_id=? AND reviewer=?",
        (page_id, config.load()["review"]["assist_reviewer"]),
    ).fetchone()
    return (r[0], r[1]) if r else None


def run(
    conn,
    reviewer: str,
    include_below: bool = False,
    blind: bool = False,
    sample: str | None = None,
    limit: int | None = None,
    suggested: str | None = None,
) -> None:
    console = Console()
    rows = queue(conn, reviewer, include_below, sample, limit, suggested)
    console.print(
        f"{len(rows)} pages to review as [bold]{reviewer}[/]. Keys: "
        + ", ".join(f"{k}={v}" for k, v in KEYS.items())
        + ", q=quit, enter=skip"
    )
    for row in rows:
        show(console, conn, row, hints=not blind)
        key = console.input("label> ").strip().lower()
        if key == "q":
            break
        sug = None if blind else suggestion(conn, row["id"])
        if key == "" and sug and reviewer != config.load()["review"]["assist_reviewer"]:
            key = next(k for k, v in KEYS.items() if v == sug[0])
            note = "accepted assistant suggestion"
        elif key not in KEYS:
            continue
        else:
            note = console.input("note (optional)> ").strip() or None
        conn.execute(
            "INSERT OR REPLACE INTO labels(page_id,reviewer,label,note,labeled_at) VALUES(?,?,?,?,?)",
            (row["id"], reviewer, KEYS[key], note, db.now()),
        )
        conn.commit()
