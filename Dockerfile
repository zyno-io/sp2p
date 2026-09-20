FROM node:25-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ .
RUN npm run build

FROM golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS go-builder
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
