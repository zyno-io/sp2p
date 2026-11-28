# sp2p plugin

This plugin adds one skill, `sp2p`. It tells the agent when to use [sp2p](https://sp2p.io) and how to use it safely. sp2p is an open-source, end-to-end encrypted peer-to-peer transfer tool for files, folders, and streams. It can also run incremental rsync and one-shot TCP, Unix-socket, or stdio tunnels.

The agent uses it to move data between this machine, remote hosts, containers, and Kubernetes pods. It is meant for cases where `scp`, `kubectl cp`, or `kubectl exec ... tar` are slow, flaky, or can't connect.

## Install

```text
/plugin marketplace add zyno-io/sp2p
/plugin install sp2p@sp2p
```

For other agents (Codex, Cursor, OpenCode, GitHub Copilot, and more), run `npx skills add https://sp2p.io` or `npx skills add zyno-io/sp2p`.

## What it runs, sends, and fetches

The plugin contains only instructions: no code, hooks, MCP servers, or binaries. When you ask for a transfer, the skill tells the agent to do the following, using the agent's normal command permissions:

- **Run the `sp2p` CLI** if it is installed.
- **Or use the one-shot bootstrap.** It downloads a pinned sp2p release from GitHub Releases through `https://sp2p.io`, checks its SHA-256 against the release checksums, runs one transfer, and deletes the binary.
- **Contact the signaling server** (`https://sp2p.io` by default, or a self-hosted server you name). It only introduces the two peers.
- **Send the data directly to the other peer**, end-to-end encrypted. If a direct connection fails, data may go through a TURN relay, but only with your consent. The relay sees only ciphertext and connection metadata.
- **Fetch `https://sp2p.io/llm`**, the full agent reference, when it needs a mode the skill doesn't cover.

The skill treats the transfer code as a secret. It keeps the code out of chat and logs, and never turns off checksum verification unless you ask.

## Privacy and terms

The public sp2p.io service is covered by the [Privacy Policy](https://github.com/zyno-io/sp2p/blob/main/PRIVACY.md) and [Terms of Service](https://github.com/zyno-io/sp2p/blob/main/TERMS.md).

## License

MIT. See the [repository](https://github.com/zyno-io/sp2p).
