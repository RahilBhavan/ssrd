# SSRD: Scam-Site Respawn Detector

Watches Certificate Transparency logs and flags newly certified domains matching fingerprints
of known fake crypto investment kits. Findings go privately to the Brooklyn DA Virtual
Currency Unit. Read `SPEC.md` (requirements, milestones), `SAFETY.md` (local-box threat model)
and `docs/architecture.md` first; `docs/research.md` holds sourced facts. Don't restate those here.
Runs on Rahil's local box (no VPS): Docker containers, data in `./data`.

## Stack
- Python 3.12, managed with `uv`. Package in `src/ssrd/`, tests in `tests/`.
- httpx, selectolax (lexbor backend), py-tlsh (pinned), mmh3, datasketch, tldextract (bundled
  PSL snapshot), idna, dnspython, rich. Storage: SQLite in WAL mode (`data/ssrd.sqlite`).
- CT ingest: own static-CT names-tile tailer (`ct.py`), not certstream-server-go.
- Runtime: `docker compose` (`compose.yaml`, `docker/`), hardened containers with an nftables
  egress firewall. The fetcher only runs inside that container.
- Config in `config/*.toml`. No magic numbers in code; thresholds and keyword lists live in config.

## Commands
- `uv sync`: install
- `uv run pytest`: tests
- `uv run ruff check . && uv run ruff format .`: lint/format
- `uv run ssrd --help`: CLI (init, ingest, fetcher, safety-check, seeds, urlscan, wayback, kits, review, evaluate, memo, backup, health, watch)
- `docker compose up -d ingest` · `docker compose --profile check run --rm check` (safety check)
- `docker compose --profile fetch up -d fetcher`: only after `fetch.enabled = true` (see SAFETY.md)

## Hard rules (safety and legal; never relax without Rahil's explicit say-so)
1. **Passive visit only:** GET `/`, the favicon, and at most 5 same-origin JS/CSS files referenced
   by the HTML. No POST, no forms, no logins, no cookies persisted, no JS execution, no browsers.
   (Chosen 2026-10-17: passive_visit; assets only for investment-looking homepages.)
2. Fetch limits: 5 s connect, 10 s read, 20 s total per body, ≤ 3 redirects (http/https only), abort > 2 MB,
   Content-Type allowlist (html, css, js, image icons). Never save or run binaries; log hash+size.
3. Rate: global 20 requests/min, concurrency ≤ 2, one fixed UA. **Never** use proxies,
   rotate IPs, or retry from another IP to get past blocks. A block is recorded as `decoy-cloaked`/`error`.
4. **urlscan: search and result-fetch only.** Never write code that submits scans in any
   visibility. Respect quotas, back off on 429, cache every response locally.
5. Never interact with crypto addresses, Telegram/WhatsApp handles, operators or victims.
6. Never port-scan. Outbound traffic: HTTP(S), DNS, RDAP/WHOIS only.
7. Only the hardened fetcher container fetches scam sites; never fetch from the host or a browser.
   Never render raw captured HTML in a browser; the review queue shows sanitized text.
8. Never weaken `docker/egress.nft`, the container hardening in `compose.yaml`, the egress ASN
   allowlist, or `safety.resolve_public` without Rahil's explicit say-so; tests/test_safety.py must pass.

## Data handling
- Everything under `data/` is private and gitignored: seeds, flagged domains, captures,
  labels, manifests, extracted contacts/addresses. Never commit, paste into issues, or log
  flagged domains to any third-party service.
- Exception (Rahil, 2026-10-23): leads a human labeled scam-kit may go to the regulators and
  law-enforcement intake channels in `[export]` via `ssrd export`. Never send assistant-only
  suggestions. Blocklists (Netcraft, Google Safe Browsing, APWG) only after the VCU confirms
  that reporting won't interfere with an investigation.
- Tests use synthetic fixtures in `tests/fixtures/`. Never commit real scam HTML.
- `scripts/privacy_check.py` runs as the git pre-commit and pre-push hook (install: see the script).
  Commit `95356d0` still names 5 seed domains: never push this branch's history; publish via a
  fresh orphan/squash commit that passes `privacy_check.py --range`. Public repo:
  github.com/RahilBhavan/ssrd (published 2026-10-23); update it only with `scripts/publish.sh "msg"`.
- Evidence manifest is append-only JSONL; never rewrite past entries.

## Language in code, docs, and output
- Say "matches kit X", never "operated by"/"belongs to". A kit is software, not people.
- Seeds are "listed by CBR/DFPI" (indicators, not adjudications).
- Every claim in memo/README carries confirmed / likely / speculative.
- Report metrics honestly with n and 95% CI; never tune thresholds on the evaluation set.

## Conventions
- `fingerprint.py` functions are pure (bytes in, features out) and shared by live and seed paths.
- Type hints everywhere; small modules; no frameworks beyond the stack above.
- Every pipeline stage logs counters hourly to `data/metrics.jsonl`.
- SQLite is shared by host commands and both containers: keep write transactions short (commit per row/item).
- Commit messages: imperative, scoped (`fetch: add +24h retry`).

## Don't
- Don't add features outside SPEC.md scope (on-chain tracing, attribution, public dashboards).
- Don't replace the two-family alert rule with a single-signal shortcut.
- Don't use residential proxies, headless browsers, or ad-click parameters to defeat cloaking.
