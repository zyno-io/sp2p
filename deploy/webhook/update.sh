#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

if [ "$#" -ne 2 ] || ! printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' \
    || ! printf '%s\n' "$2" | grep -Eq '^[1-9][0-9]{9,10}$'; then
    echo 'Expected a release version and signed request timestamp' >&2
    exit 1
fi
case "$1:$2" in
    *[!0-9A-Za-z.:-]*) echo 'Invalid deployment argument' >&2; exit 1 ;;
esac
version=$1
age=$(($(date +%s) - $2))
if [ "$age" -lt -30 ] || [ "$age" -gt 300 ]; then
    echo 'Deployment request timestamp is outside the allowed window' >&2
    exit 1
fi
cd "${SP2P_DEPLOY_DIR:-/opt/sp2p}"
exec 9>/run/sp2p-deploy.lock
if ! flock -n 9; then
    echo 'A deployment is already running' >&2
    exit 75
fi

# Only the image changes; preserve the production service's ports, volumes,
# environment, and project. Request data never selects a command or repository.
override=$(mktemp /run/sp2p-deploy-override.XXXXXX)
trap 'rm -f "$override"' EXIT
printf '{"services":{"sp2p":{"image":"ghcr.io/zyno-io/sp2p-server:%s"}}}\n' "$version" > "$override"
timeout -k 10 600 docker compose --project-directory "$PWD" \
    --file "${SP2P_DEPLOY_COMPOSE_FILE:-docker-compose.yml}" --file "$override" \
    up --detach --no-deps --no-build --pull always sp2p
