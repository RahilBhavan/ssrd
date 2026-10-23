"""Private VCU memo draft (SPEC "VCU memo"). Writes data/drafts/ only; never sends anything.

Every lead carries a confidence label:
  confirmed   - labeled scam-kit by >= 2 human reviewers, or by one reviewer and later listed by CBR
  likely      - labeled scam-kit by one reviewer
  speculative - alerted, not yet reviewed
Assistant suggestions ([review] assist_reviewer) are ignored. Leads labeled not-scam / parked / error / decoy-cloaked are left out of the lead list.
"""

from __future__ import annotations

import csv
import json
import os
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from . import config, evaluate, names

EXCLUDE = {"not-scam", "parked", "error", "decoy-cloaked"}
LIMITATIONS = [
    "Cloaking: these kits often show decoy pages to non-target visitors; a decoy visit cannot match a kit, so counts are a lower bound.",
    "Name-filter recall: the CT name classifier passes about 55% of recently listed CBR domain names (measured on a temporal hold-out); sites with unremarkable names are missed.",
    "Wildcard certificates: sites served under a wildcard cert never show their hostname in CT.",
    "CT-only view: the victim funnel starts with social-media ads and messaging apps that this monitor cannot see.",
    'A match means shared site software and copy ("matches kit X"), not common operators. These are investigative leads, not attribution.',
]


def _utc(ts: int | None) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M") if ts else "-"


def leads(conn) -> list[dict]:
    labels: dict[int, list[str]] = defaultdict(list)
    assist = config.load()["review"]["assist_reviewer"]
    for pid, lab in conn.execute("SELECT page_id, label FROM labels WHERE reviewer!=?", (assist,)):
        labels[pid].append(lab)
    cbr = {r[0]: r[1] for r in conn.execute("SELECT domain, listed_at FROM seeds WHERE source='cbr'")}
    out = []
    for r in conn.execute(
        "SELECT a.page_id, a.first_alert_at, a.kit_name, p.domain, p.features, "
        "(SELECT MIN(ct_ts) FROM candidates c WHERE c.domain=p.domain) AS ct_ts, "
        "(SELECT details FROM scores s JOIN kits k ON k.id=s.kit_id WHERE s.page_id=p.id AND s.alert=1 "
        "ORDER BY k.name=a.kit_name DESC, s.score DESC LIMIT 1) AS details "
        "FROM alert_log a JOIN pages p ON p.id=a.page_id "
        "WHERE EXISTS(SELECT 1 FROM scores s WHERE s.page_id=p.id AND s.alert=1) "  # still alerting today
        "ORDER BY a.first_alert_at"
    ):
        labs = labels.get(r["page_id"], [])
        if any(lab in EXCLUDE for lab in labs) and "scam-kit" not in labs:
            continue
        yes = labs.count("scam-kit")
        if yes >= 2 or (yes == 1 and r["domain"] in cbr):
            conf = "confirmed"
        elif yes == 1:
            conf = "likely"
        else:
            conf = "speculative"
        d = json.loads(r["details"]) if r["details"] else {"signals": [], "member_domain": ""}
        f = json.loads(r["features"])
        out.append(
            {
                "domain": names.defang(r["domain"]),
                "kit": r["kit_name"],
                "group": evaluate.group_of(r["kit_name"]),
                "nearest_member": names.defang(d.get("member_domain", "")),
                "signals": "; ".join(sorted({f"{s['family']}:{s['signal']}" for s in d["signals"]})),
                "ct_seen_utc": _utc(r["ct_ts"]),
                "alert_utc": _utc(r["first_alert_at"]),
                "minutes_to_flag": round((r["first_alert_at"] - r["ct_ts"]) / 60) if r["ct_ts"] else None,
                "labels": ",".join(labs) or "unreviewed",
                "cbr_listed": cbr.get(r["domain"], ""),
                "confidence": conf,
                "title": (f.get("title") or "")[:80],
                "telegram": ",".join(f.get("telegram", [])[:3]),
                "crypto_addresses": len(f.get("crypto_addresses", [])),
            }
        )
    return out


def _metrics_totals() -> dict:
    path = Path(config.load()["paths"]["data_dir"]) / "metrics.jsonl"
    tot: Counter = Counter()
    first = last = None
    if path.exists():
        for line in path.read_text().splitlines():
            m = json.loads(line)
            if m.get("component") == "ingest":
                tot["names"] += m.get("names", 0)
                tot["filter_pass"] += m.get("filter_pass", 0)
                first = first or m["start"]
                last = m["end"]
            elif m.get("component") == "fetcher":
                tot["visits"] += m.get("visits", 0)
    return {**tot, "first": first, "last": last}


def _fmt_precision(p: dict) -> str:
    if not p["n_labeled_alerts"]:
        return "not yet measured (0 labeled alerts)"
    return f"{p['precision']:.0%} (95% CI {p['ci95'][0]:.0%}-{p['ci95'][1]:.0%}, n={p['n_labeled_alerts']})"


def build(
    conn, reviewer: str, second: str | None, since: int, top: int = 25, sample: str | None = None
) -> tuple[Path, Path]:
    drafts = Path(config.load()["paths"]["data_dir"]) / "drafts"
    drafts.mkdir(exist_ok=True)
    rep = evaluate.report(conn, reviewer, second, since=since, sample=sample)
    ls = leads(conn)
    mt = _metrics_totals()
    conf = Counter(x["confidence"] for x in ls)
    kit_rows = conn.execute(
        "SELECT k.name, k.description, COUNT(km.page_id) FROM kits k JOIN kit_members km ON km.kit_id=k.id "
        "WHERE k.status='active' GROUP BY k.id"
    ).fetchall()
    alert_kits = Counter(x["kit"] for x in ls)
    ttf = rep["time_to_flag"]

    md = [
        "# Investigative leads: new domains matching crypto-investment scam kits",
        "",
        f"PRIVATE DRAFT, generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC. For the Brooklyn DA Virtual Currency Unit only.",
        "Not reviewed or approved for sending until Rahil Bhavan says so. Domains are defanged (`[.]`).",
        "",
        "## Summary",
        "",
        f"- Monitoring window: {_utc(mt['first'])} to {_utc(mt['last'])} UTC (confirmed: from local logs).",
        f"- Certificate names read from CT logs: {mt.get('names', 0):,}; passed the name filter: {mt.get('filter_pass', 0):,}; "
        f"passive homepage visits: {mt.get('visits', 0):,} (confirmed).",
        f"- Alerts (two independent signal families matched a known kit): {len(ls)} leads listed below "
        f"({conf['confirmed']} confirmed, {conf['likely']} likely, {conf['speculative']} speculative). "
        f"Leads matching kits built from KCDA-seized sites: {sum(x['group'] == 'kcda' for x in ls)}; "
        f"from CBR-listed sites: {sum(x['group'] != 'kcda' for x in ls)}.",
        f"- Precision of reviewed alerts: {_fmt_precision(rep['precision'])}. "
        f"KCDA-network kits: {_fmt_precision(rep['precision_kcda'])}. CBR kits: {_fmt_precision(rep['precision_cbr'])}."
        + (
            f" Estimated from a uniform random sample of {rep['sample']['sample_size']} of "
            f"{rep['sample']['population_alerts']} alerts; that is about {rep['sample']['estimated_true_alerts']} "
            f"true kit matches (95% CI {rep['sample']['estimated_true_alerts_ci95'][0]}-"
            f"{rep['sample']['estimated_true_alerts_ci95'][1]})."
            if sample and rep["sample"]["labeled"]
            else ""
        ),
        "- Time from certificate to alert: "
        + (
            f"median {ttf['median_min']} min, p90 {ttf['p90_min']} min (n={ttf['n']} alerts raised at the first visit; "
            f"the first visit is deliberately delayed 20 min). Another {ttf['retroactive_alerts']} pages alerted later, "
            "when the weekly library rebuild added new reference sites."
            if ttf.get("n")
            else "not yet measured."
        ),
        f"- Later listed by the Bank of Russia after we first saw them: {rep['cbr_forward']['candidates_later_listed']} "
        f"candidates, {rep['cbr_forward']['of_which_alerted']} of which we had alerted on (independent confirmation).",
    ]
    if "kappa" in rep and rep["kappa"]["n"]:
        md.append(
            f"- Agreement between two independent reviewers: Cohen's kappa {rep['kappa']['kappa']} (n={rep['kappa']['n']})."
        )
    md += [
        "",
        "## What the kits share",
        "",
        "A kit is a reusable scam-site template. Kits were built from sites listed by the Bank of Russia (CBR) "
        "and from pre-seizure copies of sites seized by the KCDA (urlscan and archive.org history only).",
        "",
        "| Kit | Library pages | Leads | What members share |",
        "|---|---|---|---|",
    ]
    for name, desc, n in sorted(kit_rows, key=lambda r: (-alert_kits[r[0]], r[0])):
        if alert_kits[name] or "KCDA" in name:
            md.append(f"| {names.defang(name)} | {n} | {alert_kits[name]} | {desc} |")
    md += [
        "",
        f"## Leads (top {min(top, len(ls))} of {len(ls)}; full list in the attached CSV)",
        "",
        "| Domain | Matches kit | Signals | CT seen (UTC) | Min to flag | Confidence |",
        "|---|---|---|---|---|---|",
    ]
    order = {"confirmed": 0, "likely": 1, "speculative": 2}
    for x in sorted(ls, key=lambda x: (order[x["confidence"]], x["alert_utc"]))[:top]:
        md.append(
            f"| {x['domain']} | {names.defang(x['kit'] or '')} | {x['signals']} | {x['ct_seen_utc']} | "
            f"{x['minutes_to_flag'] if x['minutes_to_flag'] is not None else '-'} | {x['confidence']} |"
        )
    md += [
        "",
        "Signal families: A = page content (TLSH, tag structure, shared copy), B = assets (favicon, scripts), "
        "C = page features (title, chat IDs, wallet patterns). An alert needs two different strong families.",
        "",
        "## Method",
        "",
        "1. Read new certificate names from three public Certificate Transparency logs (Let's Encrypt, Geomys).",
        "2. Score each name with a character n-gram classifier trained on earlier CBR-listed names.",
        "3. 20 minutes later, make one passive visit (homepage, favicon, up to 5 scripts; no forms, no logins, no JS) "
        "from a firewalled container. Captures are SHA-256-named; an append-only evidence manifest is hashed daily.",
        "4. Fingerprint the page and compare it with every kit. Alert only when two independent signal families match.",
        "5. A person reviews each alert from a sanitized text view and labels it.",
        "",
        "No site was submitted to any public scanner, and no address, handle or operator was contacted.",
        "",
        "## Limitations",
        "",
    ]
    md += [f"- {x}" for x in LIMITATIONS]
    md += ["", "Contact: Rahil Bhavan. Evidence captures, manifests and hashes are available on request."]

    memo = drafts / "vcu_memo.md"
    memo.write_text("\n".join(md) + "\n")
    csv_path = drafts / "vcu_leads.csv"
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(ls[0]) if ls else ["domain"])
        w.writeheader()
        w.writerows(ls)
    for p in (memo, csv_path):
        os.chmod(p, 0o600)
    return memo, csv_path
