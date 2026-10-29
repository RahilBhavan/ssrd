# Public aggregate website

The local box generates a self-contained public HTML page from a read-only SQLite snapshot.
Only `index.html` is uploaded; database files, captures, payload JSON, real domains and
repository history are never uploaded by this command. The public page is a static export,
not a remotely accessible review queue. Its generated timestamp tells readers when the
snapshot was made; pipeline timestamps describe underlying collection freshness separately.

## Local check

From the SSRD checkout:

```sh
uv run python scripts/deploy_website.py --check
```

This requires the existing database and nonempty, gitignored `config/publish-deny.txt`.
It runs public export privacy checks against private database domains and local deny patterns.
It does not need credentials or make deployment requests. Temporary staging is created under
`data/website/` and removed after the run. Never replace the deny patterns with public examples.

## Hosting setup

Create a dedicated Vercel project with framework Other, no install/build command and output
`.`. Add the chosen public subdomain to that project, verify its DNS and TLS using Vercel's
project-domain settings, and disable deployment protection for this deliberately public site.
Do not attach unrelated domains or a repository containing private history to this project.
The publisher does not create projects or modify DNS.

Keep configuration outside the repository, at `~/.config/ssrd/website.json`, mode 0600:

```json
{
  "project_id": "prj_REPLACE",
  "project_name": "ssrd",
  "domain": "ssrd.rahilbhavan.com",
  "token_file": "/home/YOUR_USER/.config/ssrd/vercel-token",
  "approved_source_sha256": "REPLACE_WITH_REVIEWED_SOURCE_DIGEST",
  "team_id": "team_REPLACE_IF_NEEDED"
}
```

The required `approved_source_sha256` pins the exact reviewed code and UI. `--check` prints
the current digest after its local export/privacy check; copy that digest into this private
configuration only after code and design review approve the current version. It covers sorted
relative paths and bytes for every `src/ssrd/*.py`, every file under
`src/ssrd/dashboard_assets/`, `scripts/deploy_website.py`, and the two runtime synthetic fixtures
`tests/fixtures/kit_template.html` and `tests/fixtures/benign.html`. Live data, docs and output are
excluded. Any source drift stops before network publication; hourly updates may refresh data
but cannot silently publish later UI or code edits. After a reviewed change, rerun `--check`
and deliberately update the approval digest. A digest is an integrity pin, not itself proof
that a review occurred. The success receipt records the approved source digest as well.

Omit `team_id` for a personal resource. `project_name` can substitute for `project_id`.
Store the Vercel access token in the separate mode-0600 token file; keep its parent directory
mode 0700. Do not put tokens in shell arguments, Git, unit files or logs. Grant only the
account/team access needed for this project. Rotate/revoke through Vercel if exposed.

After the local check and design review, run `uv run python scripts/deploy_website.py`.
The API origin is fixed to `https://api.vercel.com`; redirects and environment proxies are
not followed. Website verification uses a separate client without the bearer token.

## Automatic updates

Rahil authorized hourly aggregate updates for this website. The templates are not installed
automatically. Replace `@SSRD_ROOT@` and `@UV@` in `ops/ssrd-website.service` with the absolute
checkout and `command -v uv` result, install both files in `~/.config/systemd/user/`, then:

```sh
systemctl --user daemon-reload
systemctl --user start ssrd-website.service
systemctl --user enable --now ssrd-website.timer
systemctl --user status ssrd-website.service ssrd-website.timer
journalctl --user -u ssrd-website.service -n 20
```

Read back the first real deployment and confirm the intended custom domain before enabling
the timer. `Persistent=true` catches a missed run after restart; flock prevents overlap.
Stop future updates with `systemctl --user disable --now ssrd-website.timer`.
This does not stop an already active publication; inspect its service status separately.

## Failure and evidence

Privacy/export failure makes no deployment request. There is one deployment POST per run,
with no mutation retry loop; a network timeout is not proof that Vercel rejected that POST.
Readiness polling is bounded to four minutes, then requests cancellation. A failed build
keeps the existing domain. Vercel assigns production domains only after READY; the publisher
checks the alias and exact public HTML SHA-256, including its export marker. If verification
fails, it restores the prior alias if that alias still points to this run's deployment.
With no previous alias it removes the failed new alias. An alias changed by another publisher
is left alone. Cancellation or restoration failure requires inspection in Vercel; the command
reports failure without printing remote bodies. No claim is made that network failures can
provide a distributed atomic transaction.

A successful run records deployment ID, artifact SHA-256 and verification time in private
`data/website/last-success.json`. Failed runs leave this receipt unchanged. The previous
snapshot may remain online while publishing is down; its timestamp remains old rather than
pretending new collection happened. Inspect service failures and the public freshness display.

API implementation references: [create deployment](https://vercel.com/docs/rest-api/deployments/create-a-new-deployment),
[get alias](https://vercel.com/docs/rest-api/aliases/get-an-alias),
[assign alias](https://vercel.com/docs/rest-api/aliases/assign-an-alias).
Public source releases remain separate: use `scripts/publish.sh` with a task-specific
`SSRD_PUBLIC_DIR`; never push the local private history.
