# SSRD website design

Design owner: **Rahil Bhavan Research 4.0.1**, because this is Rahil's public research project. User authorization for a public aggregate website supersedes the original no-public-dashboard scope. Private investigative details remain private.

The reader is a visitor assessing what SSRD does and what its counts establish. The primary task is to understand the mechanism and distinguish recorded pipeline activity from a measured detection result. The self-authored brief uses the established light web identity: Archivo, IBM Plex Mono, warm white `#F5F5EF`, charcoal `#111214`, yellow `#FFE500`. No photographs, invented testimonials, external font requests or checked/approval stamps are used. The existing identity overrides Web Designer Pro's alternate palette/type exploration defaults.

The page opens with the question, mechanism and limits, then a quiet operational ledger. Next are pipeline activity, evaluation, latency, the reference library, synthetic review and definitions. Yellow belongs to selection; quantitative context uses token greys. Funnel stages are a count ledger rather than the former logarithmically sized bars, because these counts mix metrics-window and cumulative database populations. The page explicitly explains this basis. Time-series bars retain zero baselines and provide exact bucket values in a keyboard-operable disclosure table. Latency has directly written bucket counts. Empty and pending measurements remain visible.

Every metric group has a plain-language definition: names/candidates/pass rate; completed/queued visits and outcome denominators; kits/reference pages/source groups; active/cumulative alerts; overlapping signals/scores; reviewed-subset precision, sample bias and Wilson intervals; held-out backtest; median/p90 and retrospective alerts; recall; forward listings; reviewer agreement. The population precision headline remains pending until the backend reports an eligible complete sample. A reviewed subset is separately labeled as potentially biased.

`src/ssrd/dashboard_html.py` embeds packaged `dashboard_assets` into one generated HTML artifact. Both font binaries and their OFL licenses ship in that directory; no font CDN is used. CSP permits `data:` fonts and inline application code/styles, retaining `default-src 'none'` for static exports. Captured content continues through text nodes, never HTML. A no-JavaScript snapshot count summary, static timestamp, explanatory content and definitions remain readable. Live-server refresh failures retain the prior snapshot and explain the failure. Static publication/reload behavior is described without claiming browser polling.

## Checks and remaining review

- `uv run pytest tests/test_dashboard.py -q`: 5 passed, including public redaction, private sanitization and payload escaping.
- `uv run ruff check src/ssrd/dashboard_html.py`: passed.
- Combined `charts.js` + `review.js`, `node --check`: passed.
- Full staged diff check flags upstream font-license line endings and blank JavaScript whitespace; these have no behavior effect and the reviewed bytes were retained.
- Synthetic empty-database artifact opened in Chromium headless shell at 390 and 1440 CSS px: no page errors, no document horizontal overflow, embedded Archivo font loaded, null benchmark displayed as unavailable. Browser checked only generated trusted HTML, never captured pages or flagged sites.
- Initial screenshot capture timed out in both system Chromium and cached Chromium/headless shell after fonts loaded. DOM checks succeeded, but screenshots were not obtained. Exact live-data desktop/phone visual inspection, keyboard walkthrough, contrast/tool validation, other browser engines and independent design review remain with the parent delivery task. **Design review pending** until those exact-artifact checks are complete; this document is not an approval stamp.

Scratch evidence for initial checks: `/home/rahil/scratch/ssrd/website-design/` (synthetic fixture database, generated HTML and browser check script). Keep only for delivery review, then remove this exact task folder.

## Integration lint repair

The initial identity lint found inherited markup, font aliases, small labels and transparency. These were corrected before independent review: removed the unused orange SVG logo; use `--font-display` / `--font-figure`; web labels and SVG labels are at least 14 CSS px; token radii only; disabled controls use a dashed border instead of opacity; chart marks have solid token colors. Chart width/left padding increased and date tick density reduced to accommodate larger labels.

After repair, `design_check.py lint` on all five UI sources exits 0 with no findings. `design_check.py system` reports Rahil Design 4.0.1, 19 contrast pairs, five pairs across three CVD simulations, zero errors. The scoped `check_palette.py` on the generated synthetic HTML passes with no errors (artifact SHA-256 `85f9f1ffa2e314c9771ed19d2c8da77e5bae36dee366f34bd602fba666194c93`). This checks literal palette and declared role contrast, not arbitrary rendered CSS combinations or complete accessibility. The repeated 390/1440 browser DOM checks show no overflow/errors and fonts loaded; dashboard tests remain 5/5. Exact live artifact visual and independent review remain pending.

Firefox 1555 subsequently captured full-page synthetic-empty screenshots successfully at 390 and 1440 CSS px (`firefox-390.png`, `firefox-1440.png` in the scratch evidence folder). Both were visually inspected. No clipping or document overflow was observed; larger labels remain readable, library/evaluation tables scroll locally on phones. Inspection prompted two small corrections: prevent confidence badges splitting within words and show an empty latency explanation instead of an all-zero histogram when no observations exist. Parent retains the exact live-data review gate.


## Final website artifact review — October 28, 2026

Named independent reviewer `design_recheck` (gpt-6.1-sol) passed the exact HTML
SHA-256 `21ca528e1386f11f36279444345d5d998efa0bed8ff73131a12d4ad267ccf42a`
under Rahil Bhavan Research 4.0.1. This supersedes the initial pending record above.

Firefox rendered the exact public aggregate snapshot at 320, 390 and 1440 CSS pixels,
with no script errors, external requests or page overflow. Embedded fonts loaded.
The reviewer inspected desktop, phone, chart-detail and dark-theme screenshots.
Parent interaction checks exercised keyboard expansion/collapse of the eight-row library,
filter/no-results/reset, synthetic card focus, appearance switching and no-JavaScript content.
Two visit series have distinct greys plus wide/narrow bars; labels stay at least 14 CSS px
using scrollable intrinsic chart widths, and exact values have a text table.

Present Data's figure checker passed; documented warnings accept live-web 14px labels,
22px section headings and exploratory questions rather than social-image constraints.
Palette and source design lint passed. A human comprehension test was not conducted.
The public page and metric definitions agree with its embedded aggregate snapshot; there is
no accompanying social post. This approval does not approve the inherited terminal SVG.

Evidence is retained locally in ignored `data/website/review-20261028/`: exact HTML,
screenshots, hashes, interaction results, figure briefs and validation output.
Hourly publication pins reviewed source bytes including runtime synthetic fixtures; changes
to that source require review and a new approval digest. This permits aggregate refreshes
through the reviewed template, not unattended redesign. Deployment and timer proof remain
separate and must be recorded after external HTTPS verification.
