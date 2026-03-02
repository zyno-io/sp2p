// SPDX-License-Identifier: MIT

package sp2p

import "embed"

// WebFS holds the embedded web UI files built from web/src/ into web/dist/.
// Run `make build-web` before building the server to populate this.
//
//go:embed web/dist/*
var WebFS embed.FS
