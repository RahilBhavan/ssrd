# SSRD website verification — October 28, 2026

Scope: finish the inherited static showcase, private explorer and public aggregate publisher.
Local baseline: `ecf7b47b68afafe07f22b64ce48c842bccc71f17`.

- Full Python suite: **96 passed**. Ruff lint and formatting pass.
- Behavior includes public privacy, private sanitization, read-only missing-database refusal,
  consistent SQLite snapshots, concurrent WAL update, unchanged caller transaction, atomic
  failed output replacement, private file permissions and incomplete telemetry append.
- Publisher tests include only-index upload, nonpublic refusal, absent local deny config,
  failure/timeout behavior, alias restoration, secret-safe errors, and no-network source drift
  rejection. Both runtime synthetic fixture changes invalidate approval.
- Private explorer rejects unexpected Host/Origin before reading data; legitimate loopback
  access succeeds. The existing fetcher and its safety controls were not changed.
- Installed-wheel inspection confirms packaged templates, scripts, fonts and licenses.
- Exact desktop/phone design receipt is in [website-design.md](website-design.md).

Independent initial review requested changes on two Standards and two Spec/design findings:

| ID | Finding | Disposition |
|---|---|---|
| STD-1 | Private explorer accepted unexpected Host | Rejected before DB read; hostile and legitimate route tests pass |
| STD-2 | Approval digest omitted synthetic fixtures | Both runtime fixtures included; mutation tests pass |
| SPEC-01 | Visit/content series indistinguishable | Distinct greys and bar widths, explicit legend and text values |
| SPEC-02 | Entire library dominated phone page | Initial eight rows, accessible expansion and filter resets |

One shared repair cycle was used. Fresh independent `standards_recheck` approved both code
findings after two targeted tests. `design_recheck` approved the exact rendered artifact.
No open material review finding remains. No social images were approved by this task.

Deployment status at code review: Vercel HTTPS returned deployment-not-found; no usable local
Vercel credential was found. The private credential request timed out. No production deploy
or hourly timer was claimed or enabled. Follow [run-website.md](run-website.md) once account
access is supplied; record first real HTTPS/hash readback before enabling the timer.

Higher-impact code to inspect: `scripts/deploy_website.py` (publication, source-approval pin,
privacy checks and alias recovery) and `scripts/publish.sh` (privacy-preserving public-history
PR export). No local private Git history is pushed. The initial HTML and terminal-demo files
in the working directory remain local artifacts; source releases generate fresh exports.
