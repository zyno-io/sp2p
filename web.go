// SPDX-License-Identifier: MIT

package sp2p

import "embed"

// WebFS holds the embedded web UI files built from web/src/ into web/dist/.
// Run `make build-web` before building the server to populate this.
//
//go:embed web/dist/*
var WebFS embed.FS

// AgentSkill is the Agent Skill (SKILL.md) served for `npx skills add <server>`
// discovery. The signaling server substitutes its own base URL for the
// canonical https://sp2p.io before serving it.
//
//go:embed skills/sp2p/SKILL.md
var AgentSkill []byte
