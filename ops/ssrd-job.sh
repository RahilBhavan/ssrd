#!/usr/bin/env bash
# Scheduled SSRD maintenance, run by the systemd user timers in ops/systemd/.
#   daily:   refresh CBR blacklist (forward-check ground truth), queue seed refresh visits,
#            hash evidence manifests, desktop summary
#   hourly:  watchdog (`ssrd watch`): desktop alert if ingest/fetch stall or the DB is locked
#   weekly:  new KCDA seizures, urlscan history for new CBR listings, Wayback, rebuild kits,
#            refresh the private memo draft, encrypted backup to ~/ssrd-backups
#   monthly: retrain the CT name classifier and restart ingest so it loads the new model
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
mkdir -p data/logs
log="data/logs/$1-$(date +%Y%m%d).log"
exec >>"$log" 2>&1
echo "== $(date -Is) $1"

notify() { command -v notify-send >/dev/null && notify-send -a SSRD "SSRD $1" "$2" || true; }

case "$1" in
  hourly)
    if ! out=$(uv run ssrd watch); then echo "$out"; notify "needs attention" "$out"; fi
    ;;
  daily)
    uv run ssrd seeds cbr --download --since 2025-07-01
    uv run ssrd seeds refresh --source cbr --limit 100
    uv run ssrd manifest-hash >/dev/null
    summary=$(uv run ssrd health --summary)
    echo "$summary"; notify daily "$summary"
    ;;
  weekly)
    uv run ssrd urlscan kcda --limit 300
    uv run ssrd urlscan harvest --source cbr --limit 200
    uv run ssrd wayback --source kcda
    uv run ssrd reclassify
    uv run ssrd kits
    uv run ssrd memo
    uv run ssrd backup --out ~/ssrd-backups
    notify weekly "kit library rebuilt — see $log"
    ;;
  monthly)
    uv run --group train ssrd train-names | tee "data/logs/train-names-$(date +%Y%m).json"
    docker compose restart ingest
    notify monthly "name classifier retrained; check data/logs/train-names-$(date +%Y%m).json before relying on the threshold"
    ;;
  *) echo "usage: $0 hourly|daily|weekly|monthly"; exit 2 ;;
esac
echo "== done $(date -Is)"
