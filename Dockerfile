FROM node:22-slim AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ .
RUN npm run build

FROM golang:1.25-alpine AS go-builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /app/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.defaultBaseURL=https://sp2p.io" -o /sp2p-server ./cmd/sp2p-server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=go-builder /sp2p-server /usr/local/bin/sp2p-server
EXPOSE 8080 443 80
ENTRYPOINT ["sp2p-server"]
CMD ["-addr", ":8080"]
