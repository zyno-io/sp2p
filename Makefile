.PHONY: build build-cli build-server build-web clean test dev

VERSION ?= dev
RELEASE_URL ?=
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.defaultBaseURL=$(RELEASE_URL)"

build: build-web build-cli build-server

build-cli:
	go build $(LDFLAGS) -o bin/sp2p ./cmd/sp2p

build-server: build-web
	go build $(LDFLAGS) -o bin/sp2p-server ./cmd/sp2p-server

build-web:
	cd web && npm run build

clean:
	rm -rf bin/ web/dist/

test:
	go test ./...

dev:
	go run ./cmd/sp2p-server
