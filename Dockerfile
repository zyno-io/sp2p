FROM node:26-alpine AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ .
RUN npm run build

FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS go-builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /app/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.defaultBaseURL=https://sp2p.io" -o /sp2p-server ./cmd/sp2p-server

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates
RUN addgroup -g 65532 sp2p && adduser -D -u 65532 -G sp2p sp2p && mkdir /config && chown sp2p:sp2p /config
COPY --from=go-builder /sp2p-server /usr/local/bin/sp2p-server
USER 65532:65532
ENV SP2P_CONFIG_DIR=/config
EXPOSE 8080 443 80
ENTRYPOINT ["sp2p-server"]
CMD ["-addr", ":8080"]
