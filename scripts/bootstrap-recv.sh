#!/bin/sh
# SPDX-License-Identifier: MIT
# SP2P bootstrap — downloads the CLI and runs receive.
main() {
    set -e

    SP2P_SKIP_CHECKSUM=0
    if [ "${1-}" = "--insecure-skip-checksum" ]; then
        SP2P_SKIP_CHECKSUM=1
        shift
        echo "WARNING: --insecure-skip-checksum disables archive integrity verification; downloaded code will run unchecked." >&2
    fi

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

    if [ "$SP2P_SKIP_CHECKSUM" = 0 ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            hash_file() { sha256sum "$1"; }
        elif command -v shasum >/dev/null 2>&1; then
            hash_file() { shasum -a 256 "$1"; }
        elif command -v openssl >/dev/null 2>&1; then
            hash_file() { openssl dgst -sha256 -r "$1"; }
        else
            echo "Error: sha256sum, shasum, or openssl is required (or explicitly opt out with --insecure-skip-checksum as the first bootstrap argument)" >&2; exit 1
        fi
    fi
    if command -v curl >/dev/null 2>&1; then
        download() { curl -fsSL --connect-timeout 10 --max-time 120 "$1" -o "$2"; }
    elif command -v wget >/dev/null 2>&1; then
        download() { wget -q --timeout=30 --tries=2 -O "$2" "$1"; }
    else
        echo "Error: curl or wget is required" >&2; exit 1
    fi

    SP2P_TMP=$(mktemp -d)
    trap 'rm -rf "$SP2P_TMP"' EXIT
    ASSET="sp2p_${OS}_${ARCH}.tar.gz"
    download "{{BASE_URL}}/dl/${OS}/${ARCH}?resolve=1" "$SP2P_TMP/release-url"
    DOWNLOAD_URL=$(cat "$SP2P_TMP/release-url")
    PREFIX=https://github.com/zyno-io/sp2p/releases/download/
    case "$DOWNLOAD_URL" in
        "$PREFIX"*/"$ASSET") ;;
        *) echo "Invalid SP2P release URL" >&2; exit 1 ;;
    esac
    RELEASE_URL=${DOWNLOAD_URL%/*}
    TAG=${RELEASE_URL#"$PREFIX"}
    case "$TAG" in
        ''|.|..|*[!a-zA-Z0-9._-]*) echo "Invalid SP2P release tag" >&2; exit 1 ;;
    esac

    echo "Downloading sp2p..." >&2
    if [ "$SP2P_SKIP_CHECKSUM" = 0 ]; then
        download "$RELEASE_URL/checksums.txt" "$SP2P_TMP/checksums.txt"
        EXPECTED=$(awk -v asset="$ASSET" '
            { sub(/\r$/, "") }
            $2 == asset || $2 == "./" asset || $2 == "*" asset || $2 == "*./" asset {
                count++; digest = $1
                if (NF != 2 || length(digest) != 64 || digest ~ /[^0-9a-fA-F]/) bad = 1
            }
            END { if (count != 1 || bad) exit 1; print tolower(digest) }
        ' "$SP2P_TMP/checksums.txt") || { echo "Missing or invalid SP2P checksum" >&2; exit 1; }
    fi
    download "$DOWNLOAD_URL" "$SP2P_TMP/sp2p.tar.gz"
    if [ "$SP2P_SKIP_CHECKSUM" = 0 ]; then
        HASH_OUTPUT=$(hash_file "$SP2P_TMP/sp2p.tar.gz")
        ACTUAL=${HASH_OUTPUT%% *}
        if [ "$ACTUAL" != "$EXPECTED" ]; then
            echo "SP2P checksum verification failed; refusing to extract or execute" >&2; exit 1
        fi
    fi
    tar xz -C "$SP2P_TMP" -f "$SP2P_TMP/sp2p.tar.gz"
    chmod +x "$SP2P_TMP/sp2p"

    SP2P_SERVER="{{WS_URL}}" SP2P_URL="{{BASE_URL}}" "$SP2P_TMP/sp2p" receive -allow-relay "$@"
}
main "$@"
