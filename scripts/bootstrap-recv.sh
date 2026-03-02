#!/bin/sh
# SP2P bootstrap script — downloads the CLI and runs receive.
# Usage: curl <BASE_URL>/r | sh -s <CODE>
main() {
    set -e

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    case "$OS" in
        linux|darwin) ;;
        *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
    esac

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    echo "Downloading sp2p..." >&2
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "{{BASE_URL}}/dl/${OS}/${ARCH}" -o "$TMPDIR/sp2p.tar.gz"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$TMPDIR/sp2p.tar.gz" "{{BASE_URL}}/dl/${OS}/${ARCH}"
    else
        echo "Error: curl or wget is required" >&2; exit 1
    fi
    tar xz -C "$TMPDIR" -f "$TMPDIR/sp2p.tar.gz"
    chmod +x "$TMPDIR/sp2p"

    SP2P_SERVER="{{WS_URL}}" SP2P_URL="{{BASE_URL}}" "$TMPDIR/sp2p" receive -allow-relay "$@"
}
main "$@"
