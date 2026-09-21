# Repository Guidelines

## Project Structure & Module Organization

- `cmd/sp2p/` and `cmd/sp2p-server/` contain CLI and signaling-server entrypoints.
- `internal/` holds flat Go packages: `flow` orchestrates transfers, `conn` manages transports, and `crypto`, `transfer`, `archive`, and `server` implement core behavior.
- `web/src/` contains vanilla TypeScript; HTML/CSS assets live in `web/`. Generated `web/dist/` assets are embedded in the server.
- Go tests accompany packages; integration tests live in `internal/`, Playwright tests in `web/tests/`, and documentation in `docs/` and `man/`.

## Build, Test, and Development Commands

Use the Go version in `go.mod` and Node.js 24. Install frontend dependencies with `npm --prefix web ci`.

- `make build`: build web assets plus `bin/sp2p` and `bin/sp2p-server`.
- `make build-cli`: build only the CLI.
- `make build-server`: build web assets and the server.
- `make build-web`: rebuild frontend assets.
- `make dev`: run the server on port 8080; build web assets first.
- `make test`: run `go test ./...`.
- From `web/`, run `npm run watch` for frontend development, `npx tsc --noEmit` for type checking, and `npm test` for Playwright.

## Coding Style & Naming Conventions

Format Go with `gofmt` and check it with `go vet ./...`. Follow existing TypeScript style: two-space indentation, semicolons, and vanilla DOM APIs. Start source files with `// SPDX-License-Identifier: MIT`. Pass contexts explicitly and wrap errors with `fmt.Errorf("context: %w", err)`. Assign awaited results to named locals before further operations.

## Testing Guidelines

Use Go's `testing` package: `*_test.go` files and `TestXxx` functions. Name browser tests `*.spec.ts`; install Chromium with `npx playwright install chromium` from `web/`. Keep Playwright serial because tests share port 18090. Cover regressions, failure paths, and protocol compatibility. Run focused tests with `go test ./internal/transfer -run TestName`; CI also checks races and cross-release compatibility.

## Commit & Pull Request Guidelines

Use short, descriptive imperative subjects; history includes optional prefixes such as `ci:`. Work on a feature branch; describe behavior changes, link relevant issues, and report validation in PRs. Update the changelog, README, man pages, and CLI help when applicable.

## Security & Agent Instructions

Never log transfer codes or commit credentials. Follow [SECURITY.md](SECURITY.md) for vulnerability reports. Preserve negotiated v2 compatibility and v3 authentication guarantees.

During code review, do not run tests unless you previously wrote code needing verification. Validate documentation non-visually; use a browser or visual inspection only when explicitly requested.
