# Architecture

```
LIVE (local box, docker compose; see SAFETY.md)
 static-CT logs ──tile/names (JSONL)──▶ ct.py ──▶ names.py ──▶ visits queue (+20m/+2h/+24h)
   (LE Sycamore/Willow,                (eTLD+1,   (keywords,       │
    Geomys Tuscolo)                     seen-set)  IDN decode)     ▼  [fetcher container: nft egress
                                                                   │   firewall, no caps, ASN check]
                                                                    fetch.py ──▶ captures/ (gz, sha256)
                                                                       │        manifest.jsonl
                                                                       ▼
                                                              fingerprint.py ──▶ score.py ──▶ alerts
                                                                                    ▲            │
BUILT ONCE (week 1, re-seedable)                                                    │            ▼
 CBR JSON ─┐                                                                        │     review.py (CLI)
 KCDA set ─┼─▶ seeds.py ──▶ urlscan search/result ──▶ fingerprint.py ──▶ kits.py ───┘            │
 DFPI ─────┘   (clean)      (cache JSON locally)                         (cluster, name)          ▼
                                                                                         labels ──▶ evaluate.py
 CBR daily additions ─────────────────────────────────────────────────────────────────────────────▶ (forward check)
```

## Modules (`src/ssrd/`)

| Module | Responsibility |
|---|---|
| `config.py` | Loads `config/ssrd.toml` (keyword lists, logs, thresholds, fetch rules, safety allowlists). |
| `ct.py` | Static-CT names-tile tailer: full tiles only, per-log position in SQLite, resumes after sleep, never backfills past its start. |
| `names.py` | IDNA decode, eTLD+1 (bundled PSL), keyword filter with group labels, skip list, defang. |
| `safety.py` | Public-resolver DNS, non-global IP refusal (rebinding-safe), egress ASN check, private-range probes. |
| `fetch.py` | `SafeFetcher` (pinned-IP GETs, SNI/Host preserved, redirect/size/type caps, rate limit) and `Visitor` (delayed queue, captures, manifest, retries, scoring). |
| `fingerprint.py` | Pure features: normalized-HTML TLSH, tag-shingle MinHash, favicon mmh3, assets, inline-script hashes, contacts, page class. |
| `seeds.py` | CBR blacklist download/clean, manual/DFPI/KCDA imports. |
| `urlscan.py` | Search + result fetch only, cached; builds features from stored scans (raw response body, else DOM). |
| `kits.py` | Clusters seed pages into kits with the alert rule (union-find). |
| `score.py` | Pairwise signals, two-family rule, common-value denylist, `alert_log`. |
| `review.py` | Rich CLI queue with sanitized, defanged text; `--sample` walks a frozen random sample in its stored order. |
| `prelabel.py` | Rule-based assistant suggestions (config `[[prelabel.rules]]`) written when a page alerts: placeholder pages → parked, "human verification" gates → decoy-cloaked, known template titles → scam-kit. Hints only; never counted. |
| `sample.py` | Frozen uniform random samples of alerts (`samples`, `sample_members`): drawn once with a seed, never redrawn; precision and kappa are computed on them. |
| `evaluate.py` | Precision + Wilson CI (overall, KCDA, CBR; `--freeze` counts only post-freeze alerts), kappa, backtest (re-cluster without hold-outs), time to flag, weekly volume, CBR forward check, filter recall on CBR, threshold sweep on pre-freeze labels. |
| `memo.py` | Private VCU memo draft + leads CSV in `data/drafts/` (0600). Confidence per lead: confirmed (2 reviewers, or 1 + later CBR-listed) / likely (1 reviewer) / speculative (unreviewed). Sends nothing. |
| `backup.py` | SQLite online-backup snapshot + captures/manifests/seeds/models/drafts → tar.gz → gpg AES-256 (passphrase `data/.backup_key`); never includes `data/.env`. |
| `cli.py` | `ssrd` entry point; the fetcher refuses to run unless enabled, firewalled and on an allowed ASN. |

## Storage

SQLite (WAL) file `data/ssrd.sqlite`, shared by the ingest and fetcher containers. Tables: `ct_state`, `candidates`, `visits`, `pages` (live + urlscan features), `seeds`, `kits`, `kit_members`, `scores`, `alert_log`, `labels`, `urlscan_cache`. Hourly counters go to `data/metrics.jsonl`.
Raw bytes go in `data/captures/<sha256>.gz`. The append-only `data/manifest/YYYY-MM-DD.jsonl` gets a daily SHA-256 in `data/manifest/hashes.txt`.
All of `data/` (mode 700) is gitignored and lives on the box's LUKS-encrypted disk. `ssrd backup` (weekly) writes gpg-encrypted archives to `~/ssrd-backups`; only those encrypted files may leave the box.

## Evidence record (one per capture)

`requested_url, final_url, redirect_chain[], fetched_at_utc, ct_seen_at_utc, resolved_ip, asn, request_headers, response_status, response_headers, cert_sha256, ct_log/crt.sh id, body_sha256, outcome, tool_git_commit`

## Signal families

| Family | Signals | Strength |
|---|---|---|
| A Content | TLSH distance on normalized HTML; tag-shingle MinHash Jaccard | strong |
| B Assets | Favicon mmh3; SHA-256 of non-library JS/CSS; kit asset paths | strong |
| C Page features | Title regex, chat or Telegram IDs, header order, regulator or brand bait strings | strong or medium |
| D Infrastructure | ASN, registrar, NS, cert issuer pattern | weak only |

Alert = ≥ 2 strong signals from **different** families among A/B/C.
Thresholds are set by sweeps on labeled data (TLSH 30-150, Jaccard 0.6-0.95).

## Runtime (local box)

`compose.yaml` runs `ingest` (always) and `fetcher` (profile `fetch`, off by default) from one image. Both use a read-only root filesystem, `cap_drop: ALL` and `no-new-privileges`, with memory, CPU and pids limits, a dedicated bridge network, public DNS, and `./data` as the only mount. The entrypoint installs `docker/egress.nft` in the container's own network namespace, which drops private, CGNAT, link-local and loopback ranges and IPv6, and allows only 80/443 out plus DNS to the resolvers. It then drops every capability and runs as UID 1000. `ssrd safety-check` verifies all of this from inside the container.
