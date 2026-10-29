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

import ipaddress
import json
import os
import sqlite3
import tempfile
import threading
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import config, evaluate, memo, score
from .dashboard_data import _collect_funnel_and_series, _collect_kits, _ttf_with_buckets, assert_public_safe, connect_ro
from .dashboard_evaluation import _annotate_evaluation, _lead_confidence, _public_labels
from .dashboard_html import render_html
from .dashboard_walkthrough import page_detail, private_walkthrough, synthetic_walkthrough

_BACKTEST_LOCK = threading.Lock()


def _snapshot_backtest(conn):
    with _BACKTEST_LOCK:
        saved = score._DENY.copy()
        try:
            return evaluate.backtest(conn)
        finally:
            score._DENY.clear()
            score._DENY.update(saved)


def _cached_filter_recall(conn: sqlite3.Connection) -> dict:
    # Seed count is not an identity or revision: equal-sized databases may differ.
    return evaluate.filter_recall(conn)


def _collect_payload(
    conn: sqlite3.Connection,
    *,
    mode: str = "public",
    reviewer: str = "rahil",
    second: str | None = None,
    since: int = 0,
    sample: str | None = None,
    run_backtest: bool = False,
    metrics_path: Path | None = None,
) -> dict:
    if mode not in ("public", "private"):
        raise ValueError(f"mode must be 'public' or 'private', got {mode!r}")

    funnel, timeseries, window = _collect_funnel_and_series(conn, metrics_path=metrics_path)
    ev: dict = {
        "precision": evaluate.precision(conn, reviewer, since=since, sample=sample),
        "precision_kcda": evaluate.precision(conn, reviewer, "kcda", since=since, sample=sample),
        "precision_cbr": evaluate.precision(conn, reviewer, "cbr", since=since, sample=sample),
        "time_to_flag": _ttf_with_buckets(conn),
        "weekly_volume": evaluate.weekly_volume(conn, reviewer),
        "cbr_forward": evaluate.cbr_forward(conn),
        "filter_recall_cbr_2026": _cached_filter_recall(conn),
    }
    if sample:
        ev["sample"] = evaluate.sample_estimate(conn, reviewer, sample)
    if second:
        ev["kappa"] = evaluate.kappa(conn, reviewer, second, sample)

    ev["model_benchmark"] = {
        "split_date": None,
        "ngram_recall": None,
        "ngram_pass_rate_pct": None,
        "keyword_recall": None,
        "keyword_pass_rate_pct": None,
        "confidence": "unverified",
    }
    ev["backtest"] = _snapshot_backtest(conn) if run_backtest else None
    ev["recorded_backtest"] = None

    assist = config.load()["review"]["assist_reviewer"]
    ev["assist_triage"] = dict(
        conn.execute(
            "SELECT l.label, COUNT(*) FROM labels l JOIN alert_log a ON a.page_id=l.page_id "
            "WHERE l.reviewer=? AND EXISTS(SELECT 1 FROM scores s WHERE s.page_id=a.page_id AND s.alert=1) GROUP BY 1",
            (assist,),
        ).fetchall()
    )
    ev["human_labels"] = dict(
        conn.execute("SELECT label, COUNT(*) FROM labels WHERE reviewer=? GROUP BY 1", (reviewer,)).fetchall()
    )
    ev["lead_confidence"] = _lead_confidence(conn)
    ev["samples_drawn"] = [
        dict(r) for r in conn.execute("SELECT name, since, until, population, drawn_at FROM samples ORDER BY drawn_at")
    ]

    return {
        "mode": mode,
        "generated_at_utc": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "window": window,
        "funnel": funnel,
        "timeseries": timeseries,
        "evaluation": ev,
        "kits": _collect_kits(conn, mode=mode),
        "walkthrough": synthetic_walkthrough() if mode == "public" else private_walkthrough(conn),
        "limitations": [
            "Name filtering misses domains without recognizable investment patterns; current classifier recall is not verified in this snapshot."
            if line.startswith("Name-filter recall:")
            else line
            for line in memo.LIMITATIONS
        ],
    }


def collect_payload(conn: sqlite3.Connection, **kwargs) -> dict:
    """Collect all database aggregates in one read snapshot, without committing caller work."""
    owned = not conn.in_transaction
    if owned:
        conn.execute("BEGIN")
    try:
        data = _collect_payload(conn, **kwargs)
        _annotate_evaluation(conn, data, kwargs.get("reviewer", "rahil"), kwargs.get("sample"))
        if data["mode"] == "public":
            _public_labels(data)
        return data
    finally:
        if owned:
            conn.rollback()


def _atomic_write(dest: Path, text: str, private: bool = False) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{dest.name}.", dir=dest.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600 if private else 0o644)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, dest)
    finally:
        Path(name).unlink(missing_ok=True)
    return dest


def write_dashboard(
    conn: sqlite3.Connection,
    *,
    mode: str = "public",
    out: Path | None = None,
    reviewer: str = "rahil",
    second: str | None = None,
    since: int = 0,
    sample: str | None = None,
    run_backtest: bool = False,
    metrics_path: Path | None = None,
    payload: dict | None = None,
) -> Path:
    if mode not in ("public", "private"):
        raise ValueError("invalid dashboard mode")
    if payload is not None and payload.get("mode") != mode:
        raise ValueError("payload mode does not match export mode")
    data = (
        payload
        if payload is not None
        else collect_payload(
            conn,
            mode=mode,
            reviewer=reviewer,
            second=second,
            since=since,
            sample=sample,
            run_backtest=run_backtest,
            metrics_path=metrics_path,
        )
    )
    html = render_html(data, live_server=False)
    if mode == "public":
        assert_public_safe(html, conn)
        dest = out or (Path(__file__).resolve().parents[2] / "docs" / "dashboard.html")
        return _atomic_write(dest, html)

    dest = out or (Path(config.load()["paths"]["data_dir"]) / "drafts" / "dashboard.html")
    return _atomic_write(dest, html, private=True)


def _bar(val: float, max_val: float, width: int = 16) -> str:
    if max_val <= 0 or val <= 0:
        return "·" * width
    filled = max(1, min(width, round((val / max_val) * width)))
    return "█" * filled + "░" * (width - filled)


def render_terminal(console: Console, payload: dict) -> None:
    """Render a concise multi-panel Rich terminal dashboard."""
    f = payload["funnel"]
    ev = payload["evaluation"]
    ttf = ev["time_to_flag"]
    prec = ev["precision"]
    bt = ev.get("backtest") or ev.get("recorded_backtest")
    mode_tag = "[green]PUBLIC REDACTED[/]" if payload["mode"] == "public" else "[yellow]PRIVATE LOCAL[/]"

    console.rule(f"[bold #ea580c]SSRD Showcase Dashboard[/] · {mode_tag} · {payload['generated_at_utc']}")

    funnel_tbl = Table(box=None, pad_edge=False, expand=True)
    funnel_tbl.add_column("Stage", style="bold")
    funnel_tbl.add_column("Volume", justify="right", style="cyan")
    funnel_tbl.add_column("Notes", style="dim")
    funnel_tbl.add_row(
        "CT Names",
        f"{f['ct_names']:,}",
        f"{f['ct_bytes_mb']:,} MB ({payload['window']['hours']}h)",
    )
    pass_note = f"{f['pass_rate_pct']:.2f}% pass" if f["pass_rate_pct"] is not None else "classifier"
    funnel_tbl.add_row("Candidates", f"{f['candidates_db']:,}", f"{pass_note} · {f['visits_pending']:,} due")
    funnel_tbl.add_row("Passive Visits", f"{f['visits_done']:,}", f"{f['pages_live_content']:,} content HTML")
    funnel_tbl.add_row(
        "Kit Library",
        f"{f['kits_multi_active']} kits",
        f"+ {f['kits_single_ref']} refs ({sum(f['seeds_by_source'].values()):,} seeds)",
    )
    funnel_tbl.add_row(
        "Active Alerts",
        f"[bold red]{f['alerts_active']:,}[/]",
        f"{f['alerts_total']:,} total (KCDA={f['alerts_kcda']}, CBR={f['alerts_cbr']})",
    )

    eval_tbl = Table(box=None, pad_edge=False, expand=True)
    eval_tbl.add_column("Metric", style="bold")
    eval_tbl.add_column("Value", style="green")
    eval_tbl.add_column("Conf.", style="yellow")
    if prec["n_labeled_alerts"]:
        p_str = f"{prec['precision']:.0%} ({prec['ci95'][0]:.0%}–{prec['ci95'][1]:.0%}, n={prec['n_labeled_alerts']})"
        eval_tbl.add_row("Reviewed alert share", p_str, prec["basis"])
    else:
        eval_tbl.add_row("Precision", "pending sample", "none yet")
    if bt and bt.get("catch_rate") is not None:
        eval_tbl.add_row(
            "Hold-Out Backtest",
            f"{bt['catch_rate']:.0%} ({bt['caught_correct_kit']}/{bt['held_out']})",
            "confirmed",
        )
    eval_tbl.add_row(
        "Time to Flag",
        f"med {ttf.get('median_min', '—')}m · p90 {ttf.get('p90_min', '—')}m",
        "likely" if ttf["n"] else "pending",
    )
    mb = ev["model_benchmark"]
    eval_tbl.add_row("Name Classifier", "benchmark not verified in this snapshot", mb["confidence"])
    fwd = ev["cbr_forward"]
    eval_tbl.add_row(
        "CBR Forward", f"{fwd['candidates_later_listed']} listed ({fwd['of_which_alerted']} alert)", "confirmed"
    )

    top_row = Table.grid(expand=True, padding=(0, 1))
    top_row.add_column(ratio=1)
    top_row.add_column(ratio=1)
    top_row.add_row(
        Panel(funnel_tbl, title="1. CT-to-Alert Funnel"),
        Panel(eval_tbl, title="2. Honesty Scorecard"),
    )
    console.print(top_row)

    kits_tbl = Table(box=None, pad_edge=False, expand=True)
    kits_tbl.add_column("Kit", style="bold")
    kits_tbl.add_column("Grp")
    kits_tbl.add_column("Seeds", justify="right")
    kits_tbl.add_column("Alerts", justify="right", style="bold red")
    kits_tbl.add_column("Signals", style="cyan")
    kits_tbl.add_column("Summary", style="dim")
    for k in payload["kits"]["multi"][:6]:
        kits_tbl.add_row(
            k["name"],
            k["group"].upper(),
            f"{k['pages']}p/{k['domains']}d",
            str(k["live_alerts"]),
            ", ".join(k["signals"][:3]),
            k["summary"],
        )
    console.print(Panel(kits_tbl, title="3. Top Multi-Domain Scam Kits & Signal Families"))

    out_counts = f["visits_by_outcome"]
    max_o = max(out_counts.values(), default=1)
    out_lines = [
        f"{k:<10} {_bar(v, max_o, 16)} {v:>7,}"
        for k, v in sorted(out_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]
    combos = payload["kits"]["signal_matrix"]["by_family_combo"]
    max_c = max((c["alerts"] for c in combos), default=1)
    combo_lines = [f"{c['combo']:<22} {_bar(c['alerts'], max_c, 14)} {c['alerts']:>4}" for c in combos[:5]]
    bot_row = Table.grid(expand=True, padding=(0, 1))
    bot_row.add_column(ratio=1)
    bot_row.add_column(ratio=1)
    bot_row.add_row(
        Panel("\n".join(out_lines) or "(no visits yet)", title="4. Passive Visit Outcomes"),
        Panel("\n".join(combo_lines) or "(no active alerts)", title="5. Two-Family Rule Triggers"),
    )
    console.print(bot_row)


def export_svg(payload: dict, out: Path) -> Path:
    console = Console(record=True, width=124, force_terminal=True)
    render_terminal(console, payload)
    out.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(out), title="ssrd dashboard")
    return out


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    db_path: str | None = None,
    reviewer: str = "rahil",
    second: str | None = None,
    since: int = 0,
    sample: str | None = None,
) -> ThreadingHTTPServer:
    if not _is_loopback_host(host):
        raise ValueError(f"Refusing to bind private SSRD explorer to non-loopback host {host!r}; use 127.0.0.1 or ::1.")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; font-src data:; connect-src 'self'",
            )
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            actual_port = self.server.server_address[1]
            authority = f"[{host}]:{actual_port}" if ":" in host else f"{host}:{actual_port}"
            allowed = {authority, f"localhost:{actual_port}"}
            hosts = self.headers.get_all("Host", [])
            origins = self.headers.get_all("Origin", [])
            if (
                len(hosts) != 1
                or hosts[0].lower() not in allowed
                or (origins and (len(origins) != 1 or origins[0] != f"http://{hosts[0]}"))
            ):
                self._send(HTTPStatus.FORBIDDEN, b"unexpected request origin", "text/plain; charset=utf-8")
                return
            parsed = urlparse(self.path)
            path = parsed.path
            conn = connect_ro(db_path)
            try:
                if path == "/healthz":
                    self._send(HTTPStatus.OK, b'{"status":"ok"}', "application/json; charset=utf-8")
                    return
                if path == "/api/snapshot":
                    payload = collect_payload(
                        conn, mode="private", reviewer=reviewer, second=second, since=since, sample=sample
                    )
                    self._send(
                        HTTPStatus.OK,
                        json.dumps(payload, ensure_ascii=False).encode(),
                        "application/json; charset=utf-8",
                    )
                    return
                if path.startswith("/api/page/"):
                    pid_str = path.removeprefix("/api/page/")
                    if not pid_str.isdigit():
                        self._send(
                            HTTPStatus.BAD_REQUEST, b'{"error":"invalid page id"}', "application/json; charset=utf-8"
                        )
                        return
                    detail = page_detail(conn, int(pid_str))
                    if detail is None:
                        self._send(HTTPStatus.NOT_FOUND, b'{"error":"not found"}', "application/json; charset=utf-8")
                        return
                    self._send(
                        HTTPStatus.OK,
                        json.dumps(detail, ensure_ascii=False).encode(),
                        "application/json; charset=utf-8",
                    )
                    return
                if path in ("/", "/index.html"):
                    payload = collect_payload(
                        conn, mode="private", reviewer=reviewer, second=second, since=since, sample=sample
                    )
                    html = render_html(payload, live_server=True).encode()
                    self._send(HTTPStatus.OK, html, "text/html; charset=utf-8")
                    return
                self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain; charset=utf-8")
            finally:
                conn.close()

        def log_message(self, fmt: str, *args) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    db_path: str | None = None,
    reviewer: str = "rahil",
    second: str | None = None,
    since: int = 0,
    sample: str | None = None,
) -> None:
    srv = make_server(host, port, db_path=db_path, reviewer=reviewer, second=second, since=since, sample=sample)
    actual_host, actual_port = srv.server_address[:2]
    print(f"SSRD local read-only explorer listening on http://{actual_host}:{actual_port} (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
