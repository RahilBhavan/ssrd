# SPEC: Scam-Site Respawn Detector (SSRD)

Owner: Rahil Bhavan · Window: Oct 19 to Nov 15 2026 · About 10 h/week · Budget < $50 (runs on the local box: $0; see SAFETY.md)
Evidence and sources: [docs/research.md](docs/research.md) · Design: [docs/architecture.md](docs/architecture.md)

## Goal

Flag newly certified domains that match fingerprints of known fake crypto investment kits. The two target sets are the network the Brooklyn DA VCU disrupted on Oct 14 2026 and the wider set of investment-scam sites on the Bank of Russia (CBR) blacklist. Report four honest numbers.

Pitch: "I built a monitor that watches certificate transparency logs and flags new domains matching known scam-kit fingerprints. Over N days it flagged X sites at Y% precision (95% CI a-b)."

## Changes from the Oct 17 scope (from research)

| Scope said | Now | Why |
|---|---|---|
| One plain GET of the homepage | **One passive visit**: GET `/`, plus the favicon, plus at most 5 same-origin JS/CSS files the HTML references. Plain GETs only, no cookies, no JS, size-capped. | Favicon hashing and asset hashing need these extra requests. **Rahil must confirm this change.** If he declines, run strict mode: homepage only, inline assets, asset paths as features. |
| Fetch on sight | First fetch at **+20 min** after the CT entry. Retry at +2 h and +24 h **only** if parked or error. | Precerts reach CT before the site is serving anything. |
| Labels: scam / not / unsure | **scam-kit / not-scam / decoy-cloaked / parked / error / unsure** | Cloaking is the default for these kits. Report the decoy share. |
| Russian-language priority, keyword filter on Cyrillic transliterations | Target **Russian-speaker victims**. The filter adds English investment terms, recovery-scam terms and IDN decoding. Detect language from the page, not the domain. | CBR seeds are mostly English-named .com sites. The VCU network also ran recovery scams. |
| urlscan for history and scanning | urlscan for **search and result fetch only**. Never submit scans. | Submitting a scan publishes the domain or actively visits it. |
| Chainabuse as a main seed, CFTC list | CBR JSON + KCDA seized set + DFPI. Chainabuse for spot checks. CFTC dropped. | Free Chainabuse is 10 calls/month. The CFTC RED list has no URLs. |
| Precision of 100 labels | Precision at the chosen threshold, with a **95% Wilson CI**, n ≥ 50 above threshold. A second labeler double-labels 50 items and we report **Cohen's kappa**. | One person labeling their own alerts is circular. |
| Time to flag < 30 min | Report the **median and p90** from CT entry to alert. Target is < 30 min for sites that are live at the first fetch. | The fetch delay is deliberate. |

## Requirements

**R1 Ingest.** A Python static-CT names-tile tailer (`ct.py`) in a hardened container on the local box reads Let's Encrypt Sycamore/Willow and Geomys Tuscolo. It reads full tiles only, saves its position per log and keeps a 1/1000 unfiltered background sample. It logs entries, names, filter passes and bytes every hour. (This replaces certstream-server-go, which is too much bandwidth for home Wi-Fi.)

**R2 Filter.** Normalize each name: lowercase, IDNA-decode, eTLD+1 using the PSL, dedupe against a persistent seen-set. Match keyword lists (investment EN, transliterated RU, recovery, regulator or brand bait) against the **registrable label only**. Give each candidate a priority for fetch order. Skip known infra suffixes. Every keyword list lives in versioned config. **Done Oct 17:** a character n-gram classifier (`ssrd train-names`) trained on CBR names listed before 2026-07-01 (positives) against 37k CT background names (negatives). On CBR names listed after the split, the keyword list gets recall 0.44 at a 1.19% pass rate. The model at ≥ 0.93 (now the live filter) gets **recall 0.55 at a 0.71% pass rate**. Retrain monthly, and report the table in the README.

**R3 Fetch.** A delayed, priority-ordered queue (+20 min, +2 h, +24 h). Jobs still unrun 24 h after they were due are marked `expired` and counted, never dropped silently. Fetch rules are in SAFETY.md and CLAUDE.md. Fetching happens only inside the firewalled container, after `ssrd safety-check` passes. Store the raw bytes gzipped and named by SHA-256. Append one evidence record per capture to the JSONL manifest (fields in architecture.md). Hash the manifest daily.

**R4 Fingerprint.** Normalized-HTML TLSH, tag-shingle MinHash, favicon mmh3 (Shodan recipe), SHA-256 of non-library JS/CSS, title, `lang`, redirect chain, header order, chat or Telegram IDs and crypto-address patterns (kept private), plus ASN, registrar and issuer. Hashes on the common-hash denylist get zero weight.

**R5 Library.** Seeds come from the CBR JSON (filtered to 2025-07 or later, internet projects), the KCDA seized set (pre-seizure scans) and DFPI. Pull urlscan history, compute fingerprints, cluster into named kits. Each kit has a one-sentence description of what its members share. Seized and sinkholed pages are excluded from fingerprints.

**R6 Score.** Score each candidate against each kit. Alert only on ≥ 2 strong signals from different families (A content / B assets / C page features). Infrastructure (D) only adds weight. Thresholds come from sweeps on labeled data, not from the literature.

**R7 Review.** A CLI review queue that shows a sanitized text render, the signals that matched and the nearest kit member. It writes labels to the DB along with the reviewer's ID. No raw HTML is ever opened in a browser.

**R8 Evaluate.** (a) Precision at the threshold with a Wilson CI. (b) Backtest: hold out 20% of the seeds per kit and report the catch rate to the correct kit. (c) **CBR forward check**: any CT detection that CBR lists later counts as externally confirmed. (d) Median and p90 time to flag. (e) Weekly confirmed volume. (f) Decoy share. (g) Kappa. Report the KCDA-network results separately from the general CBR results.

**R9 Privacy.** Flagged domains, seeds, captures, labels and contact or wallet artifacts never go in the public repo. They stay in `data/` (gitignored) and in an encrypted backup.

## Milestones

Do not start a week until the previous week's definition of done is met. The labeling step is never cut.

### Week 0 (Oct 17-18, about 2 h): setup
- [x] Rahil confirms the fetch-rule change: passive_visit (Oct 17).
- [x] Get a urlscan API key and run `GET /user/quotas/`. Tested: search and result work; free accounts get 404 on `/responses/` (DOM used instead).
- [ ] Email urlscan (research use; draft in `data/drafts/urlscan_email.txt`, Rahil sends). Chainabuse dropped to spot checks.
- [x] ~~Pick a VPS~~ → runs on the local box. Hardened containers are built and `ssrd safety-check` passes (Oct 17).
- [x] Put `URLSCAN_API_KEY=...` in `data/.env` (anonymous result fetches return 403).
- [x] Read SAFETY.md and pick `strict` or `passive_visit`, then set `fetch.enabled = true` (Oct 17).

### Week 1 (Oct 19-25): seed set, library, ingest smoke test
- [ ] Learning evenings: CT and static CT, favicon mmh3, TLSH, urlscan syntax, precision and base rates, Phillips & Wilder.
- [x] Download the CBR JSON. Clean the Site field down to eTLD+1 plus a Telegram flag.
- [x] Build the KCDA seized set from the banner title, `#KCDA` and the banner hash in urlscan, plus Shadowserver NS checks. Pull pre-seizure scans.
- [x] Pull urlscan history for the seeds, drop parked pages, compute fingerprints, build the common-hash denylist, cluster into kits.
- [x] CT ingest running in the container since Oct 17. Check `data/metrics.jsonl` bytes/day by day 3.
- **Done when:** ≥ 50 seed pages fingerprinted and grouped into named kits, each with a one-sentence description, including ≥ 1 kit from the KCDA set or a written note that none could be recovered. Ingest has run for ≥ 24 h and bandwidth is measured.

### Week 2 (Oct 26 to Nov 1): live pipeline
- [x] Name filter with IDN decoding, PSL dedupe and versioned keyword lists.
- [x] Delayed fetch queue with the evidence manifest and the outcome classifier (scam-looking / decoy / parked / error).
- [x] Fingerprints computed on every capture.
- [x] systemd units with restart-on-fail, an hourly counters log and an alert if certs/s drops to 0 (`ssrd watch`, hourly timer; containers `restart: unless-stopped`).
- **Done when:** the pipeline runs 48 h untouched and logs certs seen, filter passes, fetches and outcome counts.

### Week 3 (Nov 2-8): scoring, review, backtest
- [x] Scoring with the two-family rule. Sweep built (`ssrd evaluate --sweep --freeze DATE`); run it once ≥ 50 labels exist.
- [x] CLI review queue (sanitized render, matched signals, nearest kit member).
- [x] 20% hold-out backtest (68%, 13/19). CBR forward check runs on every `evaluate`; the daily timer refreshes the CBR list.
- [ ] Label the frozen `tune` sample (60 random alerts, Oct 21-Nov 1) for the threshold sweep. A second labeler double-labels 50 items of the `final` sample (`ssrd review --reviewer <name> --sample final --limit 50 --blind`). Assistant hints (reviewer `claude-assist`) speed up Rahil's queue but never count; `evaluate` reports how many labels accepted a hint.
- **Done when:** the samples are hand-labeled (precision comes from a uniform random sample of alerts, so the labeling load stays fixed however many alerts arrive), precision with CI is computed at a chosen threshold, the backtest catch rate is recorded and kappa is computed. Adjust the starting targets here.

### Week 4 (Nov 9-15): run, measure, write up
- [ ] 7-day run at the chosen threshold (3 days if behind schedule), labeling daily.
- [ ] README with the architecture diagram, the four metrics with CIs, the decoy share, limitations and a review-queue recording made with synthetic or redacted data.
- [ ] Private 2-page memo for the VCU (spec below). Generator built: `ssrd memo` (weekly draft in `data/drafts/`); Rahil edits and approves.
- [ ] Look up the intake channel via the DA's office. Send the email to Alona Katz and Paul Stenzel only after Rahil approves the final text.
- **Done when:** the repo, the README with numbers and the memo are finished, and the email is sent.

## Operations (automated, `ops/`)

- **Daily 07:30:** refresh the CBR list (forward-check ground truth), queue 100 seed refresh visits, hash manifests, desktop summary (`ssrd health --summary`).
- **Weekly Sunday 09:00:** new KCDA seizures, urlscan history for new CBR listings, Wayback, kit rebuild.
- **Monthly on the 1st:** retrain the name classifier (table saved to `data/logs/`) and restart ingest.

## Success metrics (starting targets; revise after week 3)

| Metric | Definition | Target |
|---|---|---|
| Precision | Of alerts above the threshold, the share labeled scam-kit, estimated from a frozen uniform random sample of 100 post-freeze alerts. Report the Wilson 95% CI, n and the population size. Decoys count as not confirmed. | ≥ 70% |
| Backtest catch rate | Held-out seeds matched to the correct kit | ≥ 60% |
| Time to flag | CT entry to alert, median and p90 | < 30 min for sites live at the first fetch |
| Weekly volume | New confirmed kit matches per week in the final run, split KCDA vs CBR | Report as found |
| Also reported | Decoy share, kappa, CBR forward confirmations, filter pass rate | — |

## VCU memo (2 pages, private)

What the kits share. How many new matches appeared and how fast after Oct ~7. Method. A confidence label on every claim (confirmed / likely / speculative). Signals matched per lead. Limitations: cloaking, keyword-filter recall, wildcard certs, the CT-only view of a funnel that starts with Facebook ads. Wording: "matches kit X" and "investigative leads, not attribution". No operator names.

## Risks and fallbacks

| Risk | Signal | Fallback |
|---|---|---|
| Too few seeds | < 50 pages by Oct 25 | Widen to all CBR investment sites and DFPI. Very unlikely per research. |
| Home bandwidth / box downtime | `bytes` in metrics too high; gaps in ct_state updates | Drop Tuscolo; report uptime with time-to-flag |
| Filter recall (33%) | Most CBR scam names are made-up brand names | n-gram name classifier (R2). Report filter recall as a limitation. |
| Fetch capacity | `expired` count grows | Raise priority cutoffs, tune `requests_per_minute`, improve the filter |
| Fetcher can't keep up | Queue grows hour over hour | Tighten keywords, add more big-host suffixes to the skip list |
| Cloaking | High decoy share | Report it. Fingerprint the decoys too. Lean on cert, DNS and hosting signals. **Never** use proxies or IP rotation. |
| Widely sold kits | Look-alike legitimate sites | Two-family rule plus the common-hash denylist |
| Few respawns | < 10 alerts/week | Still a result. Lean on the backtest and the CBR forward check, and report the base rate. |
| Stale library after the takedown | Seeds match nothing live | Reseed from the first confirmed new sites. Weight 2026 snapshots. |
| Behind schedule | Week 2 slips | Cut the run to 3 days. Never cut labeling. |
