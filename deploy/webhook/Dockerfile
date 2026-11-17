# SPDX-License-Identifier: MIT
FROM docker:29-cli@sha256:34507eb5069d8be82c95dd3b6987d4250fd5fee49b82e2509b7d7a7030740d6d
RUN apk add --no-cache webhook util-linux-misc
COPY hooks.json.tmpl /etc/sp2p-deploy/hooks.json.tmpl
COPY --chmod=755 entrypoint.sh /usr/local/bin/sp2p-deploy-entrypoint
COPY --chmod=755 update.sh /usr/local/bin/sp2p-deploy
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/sp2p-deploy-entrypoint"]
