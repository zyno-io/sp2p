# SPDX-License-Identifier: MIT
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS gate-build
WORKDIR /src
COPY gate/main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /sp2p-deploy-gate main.go

# The internet-facing listener: no shell, no Docker socket, no secret.
FROM scratch AS gate
COPY --from=gate-build /sp2p-deploy-gate /sp2p-deploy-gate
USER 65534:65534
EXPOSE 9000
ENTRYPOINT ["/sp2p-deploy-gate"]

# Default target: webhook and the fixed deployment command.
FROM docker:29-cli@sha256:34507eb5069d8be82c95dd3b6987d4250fd5fee49b82e2509b7d7a7030740d6d AS hook
RUN apk add --no-cache webhook util-linux-misc
COPY hooks.json.tmpl /etc/sp2p-deploy/hooks.json.tmpl
COPY --chmod=755 entrypoint.sh /usr/local/bin/sp2p-deploy-entrypoint
COPY --chmod=755 update.sh /usr/local/bin/sp2p-deploy
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/sp2p-deploy-entrypoint"]
