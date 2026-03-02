# Contributing to SP2P

Thanks for your interest in contributing!

## Development Setup

**Requirements:** Go 1.25+, Node.js 20+

```bash
git clone https://github.com/zyno-io/sp2p.git
cd sp2p
make build   # Build web UI + CLI + server
make test    # Run Go tests
make dev     # Run the server locally on :8080
```

## Making Changes

1. Fork the repo and create a feature branch.
2. Make your changes. Follow the existing code style.
3. Add or update tests as needed.
4. Run `make test` and ensure all tests pass.
5. Open a pull request with a clear description of the change.

## Code Style

- Go: standard `gofmt` formatting.
- TypeScript: no framework, vanilla DOM. Keep it simple.
- Error messages should be user-friendly in the CLI/UI, developer-friendly in logs.

## Testing

- Unit tests live alongside the code they test (`_test.go`).
- E2E tests are in `internal/e2e_test.go`.
- Web tests use Playwright (`web/tests/`).

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md).
