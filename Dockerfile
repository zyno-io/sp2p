FROM node:26-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ .
RUN npm run build

FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS go-builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /app/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.defaultBaseURL=https://sp2p.io" -o /sp2p-server ./cmd/sp2p-server

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates
RUN addgroup -g 65532 sp2p && adduser -D -u 65532 -G sp2p sp2p && mkdir /config && chown sp2p:sp2p /config
COPY --from=go-builder /sp2p-server /usr/local/bin/sp2p-server
USER 65532:65532
ENV SP2P_CONFIG_DIR=/config
EXPOSE 8080 443 80
ENTRYPOINT ["sp2p-server"]
CMD ["-addr", ":8080"]
