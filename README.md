<img src="assets/icon.svg" width="64" height="64" alt="">

# SSRD: Scam-site respawn detector for certificate-transparency logs

![Review queue rendered from synthetic fixtures: each alert shows the matched kit, the signals and sanitized, defanged page text](docs/review-demo.svg)

SSRD watches Certificate Transparency (CT) logs for newly certified domains and checks each one against fingerprints of known fake crypto-investment kits. The aim is to measure whether, and how fast, the operation behind the Brooklyn DA Virtual Currency Unit's Oct 2026 takedown rebuilds. A kit match means "same software", not "same people". The flagged-domain list and seed data are never published.

The figure above is rendered from synthetic fixtures by `scripts/demo_review.py`.

## Results

Status on Oct 23 2026, reported by the author from a private run. The run data lives in `data/`, which is not in this repository, so a fresh clone cannot reproduce these numbers. Thresholds are frozen before precision is counted, and precision counts only alerts after the freeze date.

| Metric | Value | Confidence |
|---|---|---|
| Precision at the frozen threshold | pending (uniform random sample of 100 post-freeze alerts, after Nov 16) | none yet |
| Backtest catch rate (20% hold-out, multi-domain kits) | 69% (38/55, 95% CI 56-80%), 54 kits, measured Oct 21 | confirmed |
| Time to flag, CT entry to alert | median 21 min, p90 368 min (n=306 alerts raised at a visit; the first visit is delayed 20 min by design; 72 later retroactive alerts excluded) | likely: alerts are unreviewed |
| Name filter, CBR names listed from 2026-07-01 | n-gram classifier recall 0.55 at 0.71% pass rate; keyword list 0.44 at 1.19% (`docs/research.md`) | confirmed |
| Live alerts since Oct 17 | 378 raised; 257 still alert under the Oct 21 rule. Only 2 matched KCDA kits and both look like false positives, so no visible respawn of the seized network on new certificates so far | unreviewed |
| Weekly confirmed volume (KCDA vs CBR), decoy share, Cohen's kappa, CBR forward confirmations | pending labels | none yet |

KCDA is the Kings County DA seized-domain set. CBR is the Bank of Russia blacklist.

## What it does

- Ingests CT names tiles from static-CT logs (Let's Encrypt and Geomys).
- Seeds from the Bank of Russia blacklist (52,966 domains at last refresh) and 13 KCDA domains, with pre-seizure pages from the Wayback Machine.
- Builds a kit library: 54 multi-domain kits and 306 single-site references.
- Fetches flagged sites passively from a firewalled container (about 450-720 visits/h since Oct 17). See [SAFETY.md](SAFETY.md).
- Runs a labeling queue, then computes precision with a Wilson CI, kappa, backtest and time to flag, and drafts a private memo.
- Runs on systemd user timers: hourly watchdog, daily CBR and seed refresh, weekly kit rebuild and encrypted backup, monthly classifier retrain (`ops/`).

Seed counts, kit counts and live-run figures come from the same private run as the Results table.

## How it works

1. **Ingest:** `ct.py` tails JSONL names tiles from Let's Encrypt and Geomys static-CT logs.
2. **Filter:** `names.py` and `name_model.py` keep registrable domains that a character n-gram classifier (trained on earlier CBR-listed names) scores at 0.93 or higher. Keyword groups set fetch priority.
3. **Fetch:** `fetch.py` makes a delayed, guarded visit from a container with an egress firewall. It uses pinned public IPs only, no JS, size and type caps, and an evidence manifest.
4. **Fingerprint:** `fingerprint.py` computes normalized-HTML TLSH, tag-shingle MinHash, favicon mmh3, asset and inline-script hashes, contact IDs and page class.
5. **Score:** `score.py` alerts only on strong signals from two different families (content, assets, page features). Infrastructure is supporting evidence only.
6. **Review and evaluate:** `review.py` and `evaluate.py` give a CLI labeling queue, then precision, kappa, backtest, time to flag, CBR forward confirmations and a threshold sweep on a separate tuning set.
7. **Report:** `memo.py` drafts the private VCU memo with a confidence label on every lead. `backup.py` writes encrypted off-box backups.

## Run it

Prerequisites: Python 3.12 or newer and [uv](https://docs.astral.sh/uv/). Docker is needed only for the live pipeline.

Offline path. This needs no network and no keys. The CT and fetch tests use recorded fixtures and mock HTTP transports, so nothing contacts a CT log or a scam site:

```sh
uv sync --frozen
uv run pytest -q          # 67 tests pass (checked Oct 24 2026)
uv run ruff check .
uv run python scripts/demo_review.py   # re-renders docs/review-demo.svg from synthetic data
```

Live pipeline. This contacts the public CT logs, the Bank of Russia list, urlscan.io and archive.org, and it fetches scam sites. Read [SAFETY.md](SAFETY.md) first. urlscan needs `URLSCAN_API_KEY` in `data/.env`.

```sh
uv sync && uv run pytest                          # install + tests
uv run ssrd init                                  # create data/ssrd.sqlite
uv run ssrd seeds cbr --download                  # Bank of Russia blacklist → seeds
echo 'URLSCAN_API_KEY=...' >> data/.env && chmod 600 data/.env
uv run ssrd urlscan kcda                          # KCDA seized domains (banner-verified)
uv run ssrd wayback --source kcda                 # pre-seizure pages from archive.org
uv run ssrd urlscan background --limit 300        # benign sample for the common-value denylist
uv run ssrd urlscan harvest --source cbr --limit 300
uv run ssrd kits                                  # cluster into kits, rescore live pages

docker compose build
docker compose up -d ingest                       # CT tailer
docker compose --profile check run --rm check     # safety check (must be all [ok])
# after reading SAFETY.md, listing your network's ASN in config/ssrd.local.toml
# (git-ignored, see SAFETY.md) and setting fetch.enabled = true:
docker compose --profile fetch up -d fetcher

uv run ssrd stats
uv run ssrd health                                # liveness, throughput, lock probe, near-misses
uv run ssrd sample draw final --since 2026-11-09 --until 2026-11-16   # frozen random sample of 100 alerts
uv run ssrd review --reviewer rahil --sample final                     # enter accepts the assistant hint
uv run ssrd review --reviewer <classmate> --sample final --limit 50 --blind   # independent second labeler
uv run ssrd evaluate --sweep --freeze 2026-11-09  # tune thresholds on the pre-freeze "tune" sample
uv run ssrd evaluate --reviewer rahil --second <classmate> --sample final --freeze 2026-11-09 --backtest
uv run ssrd memo --second <classmate> --sample final --freeze 2026-11-09   # private VCU memo draft → data/drafts/
uv run ssrd backup                                # gpg-encrypted snapshot → ~/ssrd-backups
uv run ssrd watch                                 # exit 1 if ingest/fetch stalled (hourly timer)
```

## Repository layout

- `src/ssrd/`: the pipeline modules, one per stage.
- `tests/`: unit and pipeline tests with synthetic fixtures in `tests/fixtures/`.
- `config/ssrd.toml`: thresholds, keyword lists and CT log URLs. An optional git-ignored `config/ssrd.local.toml` overrides it, for example the allowed egress ASN.
- `docker/`, `compose.yaml`: hardened ingest and fetcher containers with an nftables egress allowlist.
- `ops/`: systemd user timers and the job wrapper.
- `scripts/`: privacy check, publish script and the review demo renderer.
- `docs/`: architecture, labeling guide, research log and the demo figure.
- `CLAUDE.md`: agent workflow file for the author's coding agent; not needed to use the code.

## Documentation

- [SPEC.md](SPEC.md): requirements, milestones and metrics.
- [SAFETY.md](SAFETY.md): the threat model and controls for running on a home machine.
- [docs/architecture.md](docs/architecture.md): pipeline, modules and storage.
- [docs/labeling-guide.md](docs/labeling-guide.md): what each label means; read before labeling.
- [docs/research.md](docs/research.md): sourced research and a dated log of findings.

## Sources

- Bank of Russia blacklist of illegal financial-activity sites, refreshed daily.
- Kings County DA seized domains, found through the seizure banner on urlscan.io, plus pre-seizure pages from the Wayback Machine.
- Takedown facts: the Brooklyn DA [release of Oct 14 2026](https://www.brooklynda.org/2026/10/14/brooklyn-das-virtual-currency-unit-dismantles-infrastructure-of-multinational-crypto-investment-scam-that-targeted-russian-speakers/).
- CT names tiles from the Let's Encrypt and Geomys static-CT logs listed in `config/ssrd.toml`.

Seed domains, captures and labels stay private and are not in this repository.

## Scope and limits

- Independent student project. It is not affiliated with the Brooklyn DA or any other agency. Findings go privately to the VCU.
- Precision and kappa are not measured yet. Until the labeled samples exist, no accuracy claim applies to live alerts.
- The Results numbers come from private data and are not reproducible from this repository. The tests cover the code on synthetic fixtures only.
- The backtest covers multi-domain kits only. A single-site reference can never match its own held-out page.
- A fingerprint match shows shared software, not shared operators. Seeds are "listed by CBR", which is an indicator, not a court finding.
- The KCDA seed set is thin (13 domains), and the recoverable pages are generic WordPress and Elementor, which limits kit detection for that network (`docs/research.md`).
- It does not trace funds, attribute operators or publish dashboards, and it never submits urlscan scans, logs in or interacts with scam sites.
- CI exists in `.github/workflows/ci.yml` but had not run on GitHub when this was written. Live behaviour of the container pipeline was not re-run for this documentation pass.

## License

[MIT](LICENSE). The license covers this project's code only; third-party lists, logs and fetched pages keep their own terms.

Part of [Rahil Bhavan's projects](https://github.com/RahilBhavan).
