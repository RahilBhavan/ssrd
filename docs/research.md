# Research notes and teardown (2026-10-17)

These notes come from a 7-agent research pass: six topic researchers and one skeptic, who spot-checked the most important claims.
Labels: **confirmed** = seen in the source; **likely** = indirect or a small sample; **unverified** = not yet checked.

## Verdict

**Build, reshaped.** The premise holds up. The way it gets measured needs three changes:

1. The "one plain GET" rule doesn't work with favicon hashing or JS/CSS hashing, because both need extra requests. Define one passive visit instead.
2. Cloaking is the default for this kind of scam, not an edge case. "Decoy page" has to be its own outcome, reported next to precision.
3. The VCU took down the backend servers, so live respawns during Oct 19 to Nov 15 may be rare. Build a backtest on new Bank of Russia (CBR) blacklist additions so a precision number exists even if few new sites appear.

## Strongest objections

| Objection (who raises it) | Answer in the plan |
|---|---|
| A threat-intel analyst: "10 alerts with 6 confirmed isn't a precision number." | Widen the funnel: English investment terms, recovery-scam terms, IDN decoding. Require n ≥ 50 reviewed alerts with a 95% Wilson CI. Add the CBR-addition backtest. |
| An analyst: "You labeled your own alerts, so the result is circular." | A second labeler double-labels 50 items and you report Cohen's kappa. CBR's later additions serve as an independent confirmation stream. |
| An analyst: "Your library is CBR forex sites, not the KCDA network." | Build the seized-domain set first (KCDA banner, Shadowserver NS) and fingerprint its **pre-seizure** urlscan scans. Report results separately for the KCDA network and the general CBR ecosystem. |
| A hiring manager: "phishing_catcher plus dnstwist already do this." | Don't claim a new method. The contribution is a respawn metric measured against a dated takedown, plus an open, auditable precision number for one network that law enforcement cares about. |

## Prior art (claim what's new, nothing more)

- CT keyword triage: [phishing_catcher](https://github.com/x0rz/phishing_catcher)
- Fuzzy HTML comparison: [dnstwist `--lsh tlsh`](https://github.com/elceef/dnstwist)
- Crypto-scam content clustering: [Phillips & Wilder 2020, arXiv 2005.14440](https://arxiv.org/abs/2005.14440) (TF-IDF + DBSCAN on urlscan snapshots, with HTML normalized first). Use it as the published baseline.
- Structure and favicon pivots: urlscan Pro "Similar Pages" (from $1,250/mo), Validin, DomainTools, Silent Push
- Template reuse in fake trading apps: [Sophos CryptoRom](https://www.sophos.com/en-gb/press/press-releases/2022/03/crypto-trading-scam-demands-thousands-of-dollars-in-fake-profit-tax-to-unlock-victims-accounts)
- Cloaking at scale: [Infoblox/Confiant on Keitaro cloaking](https://www.infoblox.com/blog/?p=13063) (about 15.5k investment-scam domains serving "white pages")
- CNAME-based scam infrastructure: [Savvy Seahorse](https://www.bleepingcomputer.com/news/security/savvy-seahorse-gang-uses-dns-cname-records-to-power-investor-scams/)

What's likely new: time from seizure to the first matching new domain, measured for a dated takedown. Also using the CBR blacklist as a near-daily ground-truth stream for CT detections; we found no published use of it (unverified).

## The VCU case (all confirmed, [release](https://www.brooklynda.org/2026/10/14/brooklyn-das-virtual-currency-unit-dismantles-infrastructure-of-multinational-crypto-investment-scam-that-targeted-russian-speakers/))

- Oct 14 2026: 241 domains and 112 **cloud-based** servers disrupted with the FBI, on top of about 400 domains seized earlier. The action happened "last week", around Oct 5-9. About $300k seized.
- Hosting: "Eastern European **and American** companies", with infrastructure in Ukraine. ASN priors are weak.
- Exact quote: "new scam websites popped up quickly." Quote the release, not Decrypt's paraphrase.
- Funnel: Russian-language Facebook ads, then a phone "advisor", then a fake platform, then withdrawal "fees", then a **recovery scam**. The sites referenced US agencies and Elon Musk.
- Partners: FBI, Shadowserver, Coeus, UltaHost, KCDA Digital Evidence Lab.
- Contacts: **Alona Katz**, ADA, Chief of the VCU. **Paul Stenzel**, Senior Virtual Currency Analyst.
- Earlier rounds: Apr 2024 (21 domains), Jun 2024 (70, Russian speakers), Dec 2024 (40 NFT sites; 70 more plus a webmail server; one named investment domain), Jun 2025 (100+ with NYAG/NYDFS; one named site with a fake BitLicense).
- Seizure banner (fetched live from `virtusw-inc.net`): title `This Website Has Been Seized`, text includes `#KCDA`, English only, about 2.7 MB with inline base64 images. **NS records are TD1/TD2.SHADOWSERVER.ORG.** These are pivots for finding the seized set.

## CT ingestion

- **certstream-server-go ≥ v1.10.1** (confirmed). It has read Static CT / tiled logs since v1.9.0 (2026-04-03). Let's Encrypt now runs **only** Sunlight tiled logs, so the Calidog public endpoint and any reader without tiled-log support miss all LE certificates.
- Bandwidth is the limit on a cheap VPS. The README's 14.5 Mbit/s works out to roughly 4.7 TB/month (likely, not measured). Fix: `disable_default_logs: true` and a short list of logs. Measure with vnstat by day 3.
- Known issues: #113 replay storm (keep `recovery` off), HTTP 429s from some logs, #133 (bind to localhost). PR #135 (names tiles, about 25x smaller) is worth enabling if it merges.
- Fallback: a small Python names-tile tailer for the LE Sycamore/Willow logs only. That covers about half of all issuance at less than 1/20 of the bandwidth.
- Precerts reach CT seconds after issuance, often **before** the site is serving anything, so fetch with a delay. Dedupe by eTLD+1 (Public Suffix List). Decode punycode (`xn--`, `.рф` = `xn--p1ai`) before keyword matching.
- crt.sh and Cert Spotter (100 queries/h free) are for offline backfill only. Merkle Town is retired.

## urlscan.io

- Free tier: 1,000 searches, 10,000 result fetches and 5,000 public / 1,000 unlisted / 50 private scans per day. Search sees public scans only. Check real limits with `GET /user/quotas/` on day 1.
- Available on Free: `page.domain`, `page.title`, `page.asn`, `ip`, `hash:` (SHA-256 of response bodies). Regex needs a signed-in account. **Pro only:** similar-page search, `text.content`, `dom.hash`, `content.globalNames`.
- urlscan has **no mmh3 favicon hash and no TLSH**. Compute those from our own fetches. For historical pages, pivot with `hash:<sha256>`.
- **Never submit candidates in any visibility mode.** Public or unlisted scans publish the domain. A private scan is an active browser visit, which goes beyond our fetch rule.
- The ToS say personal and non-commercial use and ban "systematic retrieval" without permission. Email urlscan describing the research use before bulk pulls, and cache every result locally.

## Seed sources

| Source | Use | Notes |
|---|---|---|
| **CBR blacklist JSON** ([export](https://www.cbr.ru/inside/warning-list/black-list-json)) | Main seed **and** ground-truth stream | 27,474 entries, 24,665 with a site, newest dated 2026-10-16, about 270-470 new entries/month. Mostly English-named .com forex and investment sites. Only 102 of the 2,601 from 2026 are .ru. The Site field needs cleaning (Telegram links, comma-separated lists, `mail.*`). About 50% had urlscan scans in a sample of 20. |
| **KCDA seized set** | The network we actually care about | Pivot on the banner title, `#KCDA` and the Shadowserver NS, then pull pre-seizure scans. Keep these out of live scoring. |
| **DFPI Crypto Scam Tracker** | Small US pig-butchering set | Manual collection, no export. |
| Chainabuse | Spot checks only | Free tier allows 10 calls/month (about 500 reports). Ask for researcher access. |
| ~~CFTC "RELIEF"~~ | Drop | It doesn't exist. The RED list has no URLs. |
| ~~CryptoScamDB, ScamSniffer, MetaMask~~ | Drop | CryptoScamDB is stale or down. The other two cover drainer phishing, not investment sites. |

Getting ≥ 50 seed pages you can fingerprint in week 1 looks **very realistic** (about a day of work). Filter out parked and suspended pages so parking-page hashes don't pollute the library.

## Fingerprinting

- Favicon: Shodan style, base64 with newlines then mmh3 32-bit signed. Zero weight for default and CDN icons.
- TLSH: input must be ≥ 50 bytes. Published distance cutoffs come from executables, so **sweep 30-150 on our own labeled set**. Normalize HTML first (strip numbers, dates, addresses, CSRF tokens and nonces).
- Add tag-sequence shingles (k=5) with Jaccard similarity or MinHash (`datasketch`), starting at 0.8 and tuning from there.
- JS/CSS: SHA-256 of files that aren't common libraries. Build a "common hash" denylist from our own crawl (any hash seen on more than about 20 unrelated hosts).
- Signal families: **A** content, **B** assets, **C** page features (title regex, chat widget or Telegram IDs, header order), **D** infrastructure (ASN, registrar, issuer). An alert needs **2 strong signals from different families among A/B/C**. D is never strong on its own.
- Capture the redirect chain and response headers every time. They cost nothing and stay useful as fingerprints.

## Legal and operational

- Legal risk is low for unauthenticated GETs of public pages (Van Buren, hiQ, DOJ 2022 policy). The risk rises if you **get around** blocks: no proxies, no IP rotation, no retries from other IPs.
- **Government-agent risk:** once the VCU directs the work, your collection may count as state action, and you may become a witness. Build and run the tool independently, don't take collection instructions, and keep append-only logs.
- VPS: there's no "research-tolerant" product category. Open a ticket in advance, put an explanatory page on the VPS IP and reverse DNS, use HTTP(S) only, and never port-scan.
- RDAP: use `whoisit` with the IANA bootstrap and don't route volume through rdap.org. ccTLDs like .ru may lack RDAP, so fall back to port 43. ASN: IPinfo Lite MMDB (CC BY-SA) or GeoLite2-ASN. Use Team Cymru as a fallback.
- VCU package: a methods note plus leads with confidence labels and the matching features listed, marked "investigative leads, not attribution". Send it through the channel the office specifies. Look up the intake channel via the DA's main line; don't guess email addresses.
- Optional and cheap: a 30-minute check with UMich OGC or a faculty advisor before launch.

## Measured on the box (Oct 17)

- LE Sycamore grows about 25 entries/s, and names tiles are about 76 KB per 256 entries (about 6× smaller than data tiles). Google ParcelYard and IPng don't serve names tiles; Geomys Tuscolo does.
- Keyword-filter recall on CBR-listed 2026 domains: **33%** (1,650 of 5,020). Matching only the registrable label passes about 14 candidates/min. A 6 requests/min fetcher can't visit them all, hence the priority order, expiry and the n-gram classifier plan.
- urlscan: anonymous **search** works; anonymous **result** fetches return 403, so a free API key is required.
- The seizure-banner title search returns many non-KCDA seizures (FBI, toll-scam sites). KCDA banners are confirmed by main-document hash plus "KINGS COUNTY DISTRICT ATTORNEY" in the body.

- **KCDA seed set is thin.** urlscan has seen about 11 KCDA-banner domains, all on sinkhole IP 103.41.71.252, each scanned only *after* seizure. The Wayback Machine has pre-seizure copies for 7 of them, plus one domain named in a 2025 release (the other named domain's archive shows only older owners and parking pages).
- **The KCDA-network pages we could recover are generic WordPress + Elementor (Hello theme) behind Cloudflare** (3 seized domains; names in `data/` only). Their shared paths and inline scripts also appear on ordinary Elementor sites, so after adding an Elementor background sample they correctly **do not** form a kit. Detecting this network will need content-level features (copy, section structure, title patterns), not asset hashes. This is a key limitation for the memo.
- **Denylist design fix:** common values are now computed from background and live pages only, never seeds. The cutoff is proportional: max(3, 2% of hosts). Background = 142 random recent urlscan scans + 90 Elementor sites.
- **First library (Oct 17):** 212 seed pages on 128 domains → 12 kits with 72 member pages. The largest is 30 pages on 16 domains (an oil/real-estate/agriculture "sustainable wealth" template). Backtest: **14/17 held-out pages matched to the correct kit (82%, 95% CI 59-94%)**. These kits are general CBR-listed investment kits, not the KCDA network.

- **Free urlscan accounts get 404 on `/responses/<sha256>/`**, so raw bodies aren't available. Seed fingerprints use the rendered DOM, and seed favicon mmh3 can't come from urlscan. Asset SHA-256s from result JSON still work.
- **The copy fingerprint separates the KCDA network.** Brand-stripped word 5-grams: KCDA WordPress pairs share 71-99 shingles (containment 0.11-0.23). Seed-vs-background maximum: p99 = 5, max = 15. With it, **kit-03-KCDA forms (the same 3 seized domains)**. Library: 20 kits. Backtest: **27/31 (87%, 95% CI 71-95%)**.
- **Name classifier vs keywords** (temporal split, CBR names listed ≥ 2026-07-01, n = 1,217 positives, 7,423 background names): keyword recall 0.44 at 1.19% pass rate; model ≥ 0.90 gets 0.61 at 1.17%; model ≥ 0.93 gets 0.55 at 0.71% (chosen to fit fetch capacity).
- **Fetch throughput** at 20 requests/min with 2 workers is about 8 visits/min. Many brand-new domains don't resolve or time out on the first attempt.

- **Cluster chaining (fixed Oct 17).** One 87-page "kit" turned out to be single-linkage chaining: 4.8% pair density, linked by one inline-script hash. The cause was the normalizer erasing widget/account IDs before hashing inline scripts. Fixes: whitespace-only inline hashing; clustering needs 2 strong families; kits whose pages have no investment copy are excluded. The honest backtest is **13/19 (68%, CI 46-85%)**. The earlier 87% was inflated.
- **Reference sites:** unclustered investment-content seed domains become `ref-<domain>` entries, so a live page can match a single known listed site. That's lower confidence than a kit match, and it's labeled separately.
- **First live alerts (Oct 17):** 2 domains match a CBR-listed "AI Trading Platform | Official Website" lander: same assets, inline scripts, ASN 62370, TLSH 47. Pending review.
- **Fetch capacity:** median visit 15 s, p90 48 s, about 250 visits/h at concurrency 2 and 20 requests/min, against about 325 model-filter candidates/h. The overflow is handled by the priority queue (highest model score first) with counted expiry.

- **Alert volume after the first weekly rebuild (Oct 18-21).** The library grew to 54 kits + 306 references and alerts jumped to ~100/day. The assistant's suggestions (development check only, not evaluation labels) showed about half were ordinary sites. Causes: (1) a stock WordPress inline script and a Hostinger site-builder script counted as a strong asset match, with the `generator` tag and Cloudflare ASN supplying the two weak "other" signals; (2) registrar "domain expired" and hosting default pages were not classed as parked, so placeholder snapshots entered the library. Fix (Oct 21): generator and infrastructure signals no longer lift a single strong family to an alert; placeholder patterns added and 46 stored pages reclassified offline. On the 265 alerts so far this dropped 82 of 102 suggested not-scam and 23 of 25 parked, and lost 1 of 103 suggested scam-kit (a single asset hash + header order).
- **Remaining false-positive source:** ordinary sites that pass the two-family rule via TLSH ≤ 70 plus a generic inline script. Left for the Nov 9 threshold sweep on labeled data rather than hand-tuned.
- **Fetcher OOM (Oct 19-20).** The common-value denylist tallied hosts for every value on every live page (~4,000 copy shingles each); at ~20k live pages it peaked at 2.2 GB and the 1 GB container was killed every ~73 s for ~13 h (472 restarts, 4,000-visit backlog, 281 visits later expired). Counting only values carried by library pages gives the same deny set for scoring at ~180 MB. The hourly watchdog caught it as a backlog.
- **Backtest (Oct 21):** 38/55 held-out pages of multi-domain kits matched to the correct kit (69%, 95% CI 56-80%). An unrestricted run gave 26% because held-out pages of single-site references can never match (no other domain remains); the backtest now covers kits only, as SPEC R8b defines.
- **Labeling load:** precision is now estimated from frozen uniform random samples (60 for tuning, 100 final) instead of labeling every alert; rule-based suggestions cover ~40% of alerts (102 of 265, 0 disagreements with hand suggestions).

## Still unverified (check in week 1)

VPS bandwidth caps, real urlscan free quotas, whether free accounts can download response bodies (favicon and JS files), RDAP coverage for .ru/.рф, and actual CT volume on our log subset.
