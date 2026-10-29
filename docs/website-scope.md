# SSRD public website — completion scope

Owner: Rahil Bhavan Research 4.0.1. User instructions of October 27–28, 2026
supersede the earlier prohibition on a public dashboard; private source data remains private.

Reader: a recruiter or researcher assessing what this student project does, what is measured,
and which results still require validation. The website explains the mechanism before metrics.

Acceptance:
1. `ssrd.rahilbhavan.com` serves the public showcase over HTTPS, with no private database API.
2. An hourly local publisher refreshes aggregate data. A failed export/privacy check cannot
   overwrite the last successful page. Snapshot time and stale state remain visible.
3. Every displayed metric has a definition and a time/population basis. Human precision remains
   pending until a complete frozen random sample is labeled. Assistant hints never count.
4. Only aggregate values and explicitly synthetic walkthrough cards may leave the host.
5. The page works at desktop and narrow phone widths, with keyboard controls, readable empty
   and pending states, and a useful no-JavaScript fallback. Fonts are bundled and licensed.
6. Exact generated HTML passes privacy, data-integrity, layout and independent design review.
7. Changes are reviewed and merged through a public-history PR; local private history is never pushed.

Not included: changes to collection, live fetch safety, scorer thresholds, human labels,
regulator outreach, or publication of real leads. No claim that a kit match proves an operator.

Verification: fixture tests, live aggregate export, repeat/failure behavior, real browser
rendering and interaction at 320/390/1440 pixels, privacy scan, external HTTPS readback,
and installed timer state. A completed build alone is not deployment evidence.
