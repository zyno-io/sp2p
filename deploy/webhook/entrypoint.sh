#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

SP2P_DEPLOY_SECRET=$(cat /run/secrets/deploy_secret)
if [ "${#SP2P_DEPLOY_SECRET}" -lt 32 ]; then
    echo 'Deployment secret must contain at least 32 characters' >&2
    exit 1
fi
export SP2P_DEPLOY_SECRET
export SP2P_DEPLOY_DIR="${SP2P_DEPLOY_DIR:-/opt/sp2p}"
export SP2P_DEPLOY_COMPOSE_FILE="${SP2P_DEPLOY_COMPOSE_FILE:-docker-compose.yml}"
cd "$SP2P_DEPLOY_DIR"
exec webhook -hooks /etc/sp2p-deploy/hooks.json.tmpl -template -ip 0.0.0.0 -port 9000 -http-methods POST
