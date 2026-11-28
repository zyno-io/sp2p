---
name: sp2p
description: Move files, folders, or byte streams between machines, containers, Kubernetes pods, and remote hosts with sp2p (end-to-end encrypted peer-to-peer transfer). Use instead of scp, `kubectl cp`, or `kubectl exec ... tar | tar` when data is more than a few MB, the exec or SSH stream is flaky, or the two ends can't reach each other directly. Also covers incremental rsync over sp2p and one-shot TCP, Unix-socket, or stdio tunnels.
license: MIT
compatibility: Needs outbound HTTPS to the signaling server on both peers. Uses the sp2p CLI, or for plain file transfers a one-shot bootstrap that needs curl or wget plus sha256sum, shasum, or openssl. Rsync mode needs rsync on both ends (macOS/Linux, or WSL).
metadata:
  homepage: https://sp2p.io
  source: https://github.com/zyno-io/sp2p
---

# sp2p

sp2p moves data between two peers over an end-to-end encrypted connection. One side creates a
session and gets a secret **code**; the other side joins with that code. A public signaling server
(`https://sp2p.io` by default, or a self-hosted one) only introduces the peers.

The full agent reference, with every mode and the complete JSON event contract, is at
**https://sp2p.io/llm** (or `<server>/llm` for a self-hosted server). Fetch it for anything this
skill doesn't cover.

## When to use it

- Copying more than a few MB into or out of a container or Kubernetes pod. Large
  `kubectl exec ... tar` streams tend to drop (`websocket: close 1006`); sp2p moves the data outside
  the exec session.
- Host-to-host copies where scp/rsync over SSH is unavailable, blocked, or slow, including across
  NATs and firewalls.
- Piping one finite stream, such as a database dump, to another machine.
- Incremental directory sync (`sp2p rsync`) or a single forwarded TCP/Unix/stdio connection
  (`sp2p tunnel`) between machines that can't otherwise reach each other.

## Rules

- **The code is a secret.** It appears in the creator's `session` event as `code`, and inside
  `share_url`. Never print it to chat, logs, tickets, commits, or public output. Write it straight
  to a private (mode 0600) file and pass it to the joining peer from there. Redact it from any
  diagnostics you show.
- **Use JSON mode.** Pass `-format json` on both peers and parse the JSON Lines events rather than
  scraping human output.
- **Same server on both peers.** Pass the same `-server URL` to both sides. Use `https://sp2p.io`
  unless the user names a self-hosted server.
- **Wait for `result`.** Each peer emits exactly one terminal `result` event with `outcome` set to
  `completed` or `failed`. `error`, connection, and `ready` events are not terminal. A run that
  died before `result` is not complete: start a new session (new code) and retry.
- **Relay needs consent.** Direct P2P is tried first. If JSON mode emits `relay_required`, the
  relay is still end-to-end encrypted but sees connection metadata. Write `allow` or `deny` to the
  event's `response_file` according to the user's policy; for sensitive data, ask first unless
  already authorized. Don't pass `-allow-relay` by default.
- **Never pass `--insecure-skip-checksum`** to the bootstrap unless the user explicitly asks for
  it. Never add it after a checksum failure or because a hash tool is missing.
- **Don't install sp2p permanently** on a shared host or inside a pod the user didn't ask you to
  change. Use the one-shot bootstrap there (it verifies, runs, and deletes the binary).
- **Versions:** peers negotiate the protocol automatically; don't force one. If two ends
  disagree (e.g. an old packaged `sp2p`), use the bootstrap on both so they run the same release,
  or upgrade only with the user's OK.

## Getting the CLI

- Prefer an installed `sp2p` (`sp2p version`). Install options: https://github.com/zyno-io/sp2p#install.
- Otherwise, for **plain file send/receive only**, use the one-shot bootstrap. It downloads a
  pinned release, checks its SHA-256 against the release checksums, runs once, and removes itself:

  ```bash
  curl -fsS https://sp2p.io   | sh -s -- -format json -server https://sp2p.io ./path   # send
  curl -fsS https://sp2p.io/r | sh -s -- -format json -server https://sp2p.io "$CODE"  # receive
  ```

  Use `wget -qO-` in place of `curl -fsS` if needed. PowerShell: `irm https://sp2p.io/ps` and
  `irm https://sp2p.io/ps/r` (see the reference).
- Rsync and tunnels need the real CLI on both ends.

## Send and receive

Below, `sp2p ...` can be replaced by the bootstrap pipeline above. `$WORK` is a private working
directory (`umask 077; mkdir -p "$WORK"`).

```bash
# Sender: keep it running. It prints JSON events, starting with the session code.
sp2p send -format json -server https://sp2p.io ./report.pdf ./photos > "$WORK/send.jsonl" 2> "$WORK/send.err" &

# Wait for the session event, then save ONLY the code to a private file. Never echo it.
until grep -q '"event":"session"' "$WORK/send.jsonl" 2>/dev/null; do sleep 1; done
python3 -I -c '
import json, sys
for line in open(sys.argv[1]):
    try: e = json.loads(line)
    except ValueError: continue
    if e.get("event") == "session": print(e["code"]); break' "$WORK/send.jsonl" > "$WORK/code"
# (or: jq -r 'select(.event=="session") | .code' "$WORK/send.jsonl" | head -n1 > "$WORK/code")

# Receiver (on the other machine): pass the code, not session_id.
sp2p receive -format json -server https://sp2p.io -output "$DEST" "$(cat "$WORK/code")" > "$WORK/recv.jsonl"
```

- Several paths are sent as one archive. A single folder keeps its name. The receiver writes under
  `-output` (default: current directory) and fails rather than overwrite or merge into an existing
  file or folder of the same name.
- The receiver's `metadata` event has `metadata.size` and `metadata.fileCount`; its `result` has
  `saved_path`.
  Compare against the source after completion.
- Progress: read the latest `progress` event (`bytes_transferred` / `total_bytes`), or add
  `-status-file PATH` for an atomically updated snapshot. The sender's events and status file
  contain the code, so filter them and never dump them raw.
- The code is a command-line argument to `receive`, so other users on a shared host can see it in
  the process list. Avoid running the receiver on hosts with untrusted local users.

## Remote host, container, or pod as one end

The peer on the remote side must outlive the `ssh` / `kubectl exec` call that starts it. Run it
under `nohup` with its events in a file, then read the file back.

```bash
REMOTE='kubectl --context CTX -n NS exec deploy/APP --'   # or: ssh user@host
# Sender inside the remote. cd to the parent so the archive is named after the folder.
$REMOTE sh -c 'umask 077; mkdir -p /tmp/sp2pjob && cd /data && \
  nohup sh -c "curl -fsS https://sp2p.io | sh -s -- -format json -server https://sp2p.io FOLDER" \
  > /tmp/sp2pjob/events.jsonl 2> /tmp/sp2pjob/err.log < /dev/null & echo started'

# Read the code back into a private local file (extract the same way as above).
$REMOTE cat /tmp/sp2pjob/events.jsonl | jq -r 'select(.event=="session") | .code' | head -n1 > "$WORK/code"

# Receive locally, then clean up the remote job directory.
sp2p receive -format json -server https://sp2p.io -output "$DEST" "$(cat "$WORK/code")" > "$WORK/recv.jsonl"
$REMOTE sh -c 'cd /tmp/sp2pjob && rm -f events.jsonl err.log code && cd / && rmdir /tmp/sp2pjob'
```

- Local → remote is the reverse: sender locally, receiver under `nohup` remotely. Pass the code in
  over stdin (`$REMOTE sh -c 'cat > /tmp/sp2pjob/code' < "$WORK/code"`), not as a visible argument.
- If the pod or host restarts mid-transfer, the remote peer dies. Start over with a new code.
- To stop a stuck remote peer, kill its process, then run the same cleanup command. It removes only the
  files this job created, and `rmdir` refuses to delete the folder if anything else is in it.

## Streams

```bash
# Sender: one finite stream with a filename
pg_dump mydb | sp2p send -format json -server https://sp2p.io -name mydb.sql - > "$WORK/send.jsonl"
# Receiver: JSON events to stderr so stdout carries only the data
sp2p receive -format json -event-output stderr -stdout -server https://sp2p.io "$(cat "$WORK/code")" \
  > mydb.sql 2> "$WORK/recv.jsonl"
```

`send -` is a one-way verified file transfer. For a live bidirectional byte stream, use a stdio
tunnel instead.

## Rsync and tunnels (CLI on both ends)

Each run uses a new code created by the first command. Put sp2p flags before `--`; everything after
`--` goes to rsync unchanged.

```bash
# Incremental sync. Source creates the code; destination exposes a write-only directory.
sp2p rsync send -format json -server https://sp2p.io -- -av --partial ./photos/ sp2p::share/
sp2p rsync recv -format json -server https://sp2p.io CODE ./backup     # add --allow-delete for --delete

# One TCP connection. The side that can reach the target creates the code.
sp2p tunnel serve   -format json -server https://sp2p.io --to tcp://127.0.0.1:5432
sp2p tunnel connect -format json -server https://sp2p.io --listen tcp://127.0.0.1:15432 CODE
```

- rsync must be installed on both peers; many container images lack it, so check `command -v rsync`.
- A tunnel accepts exactly one connection, then exits. Wait for the `ready` event before connecting
  a client. Bind listeners to loopback unless the user asks otherwise.
- Stdio tunnels (`--stdio`) and Unix sockets (`unix:///path`) are in the reference.
