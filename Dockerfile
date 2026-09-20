FROM node:24-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e AS web-builder
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

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates
RUN addgroup -g 65532 sp2p && adduser -D -u 65532 -G sp2p sp2p && mkdir /config && chown sp2p:sp2p /config
COPY --from=go-builder /sp2p-server /usr/local/bin/sp2p-server
USER 65532:65532
ENV SP2P_CONFIG_DIR=/config
EXPOSE 8080 443 80
ENTRYPOINT ["sp2p-server"]
CMD ["-addr", ":8080"]
