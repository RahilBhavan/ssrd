#!/bin/sh
# Install the egress firewall in this container's network namespace, verify it, then drop
# every capability and run ssrd as the unprivileged user.
set -eu
nft -f /usr/local/lib/ssrd/egress.nft
nft list chain inet ssrd output | grep -q "policy drop" || { echo "firewall not active" >&2; exit 1; }
mkdir -p /run/ssrd && touch /run/ssrd/firewall-ok && chmod 0444 /run/ssrd/firewall-ok
exec setpriv --reuid="${SSRD_UID:-10001}" --regid="${SSRD_GID:-10001}" --clear-groups --no-new-privs \
     --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
     ssrd "$@"
