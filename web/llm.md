# SP2P agent guide

> Use SP2P for end-to-end encrypted file transfer, incremental rsync, and one-use bidirectional TCP, Unix-socket, or stdio streams. Keep both peers running until each exits successfully or, in JSON mode, emits a terminal `result` event.

The transfer code is a secret capability. Give it only to the intended peer, do not put it in public issue trackers or chat logs, and redact it from diagnostic output. The `send` side creates the code for file and rsync workflows; `tunnel serve` creates it for tunnels.

This guide belongs to the signaling server at `{{SP2P_SERVER_URL}}`. Pass that exact URL with `--server` on both peers so a self-hosted creator and joiner use the same server. SP2P accepts HTTP(S) URLs and derives the signaling WebSocket endpoint.

## Choose a workflow

| Need | Creator | Joining peer | Important limit |
| --- | --- | --- | --- |
| One file or folder | `sp2p send` | `sp2p receive CODE` or browser link | One-way, one transfer per code |
| Several files or folders | `sp2p send PATH...` | `sp2p receive CODE` | Sent as one archive; receive does not merge into an existing directory |
| A piped file | `command \| sp2p send -` | `sp2p receive -stdout CODE` | One-way framed file, not a duplex terminal stream |
| Incremental directory update | `sp2p rsync send` | `sp2p rsync recv CODE` | CLI-only; macOS/Linux, or both tools in WSL |
| Fixed TCP or Unix endpoint | `sp2p tunnel serve` | `sp2p tunnel connect CODE` | CLI-only; one accepted connection per code |
| Bidirectional stdin/stdout | `sp2p tunnel serve --stdio` | `sp2p tunnel connect --stdio CODE` | CLI-only; stdout is payload, not status |

## Get SP2P

Prefer an independently trusted installation of `sp2p`. The browser and bootstrap host can replace executable code; end-to-end encryption does not defend against that host compromise. Install the CLI on both machines for rsync and tunnels. The [latest GitHub release](https://github.com/zyno-io/sp2p/releases/latest), [latest-release JSON](https://api.github.com/repos/zyno-io/sp2p/releases/latest), and [README installation options](https://github.com/zyno-io/sp2p#install) provide permanent installations.

If you trust this server and GitHub's HTTPS release channel, the one-shot bootstrap can send or receive an ordinary file without a permanent install. Shell needs curl or wget and one of `sha256sum`, `shasum`, or `openssl`; PowerShell uses built-in commands. The bootstrap downloads a fixed release into a temporary directory, verifies its SHA-256 checksum by default, configures this server, runs the file transfer, and removes the binary.

Missing, duplicate, malformed, or mismatched checksums fail closed, as do unavailable pinned releases and local development archives. This does not independently verify signer identity or release freshness. See [artifact verification and endpoint trust](https://github.com/zyno-io/sp2p/blob/main/SECURITY.md#artifact-verification-and-endpoint-trust).

If the user explicitly accepts unchecked downloaded code, pass `--insecure-skip-checksum` as the first bootstrap argument. It skips manifest/hash checks and warns on stderr; it does not bypass TLS validation. Never enable it automatically after a verification failure or because verification tools are missing.

### Send without installing

```bash
curl -f "{{SP2P_SERVER_URL}}" | sh -s -- -format json "./report.pdf"
```

```bash
wget -O- "{{SP2P_SERVER_URL}}" | sh -s -- -format json "./report.pdf"
```

```powershell
& ([scriptblock]::Create((irm "{{SP2P_SERVER_URL}}/ps"))) -format json "C:\path\to\report.pdf"
```

### Receive without installing

```bash
curl -f "{{SP2P_SERVER_URL}}/r" | sh -s -- -format json "CODE"
```

```bash
wget -O- "{{SP2P_SERVER_URL}}/r" | sh -s -- -format json "CODE"
```

```powershell
& ([scriptblock]::Create((irm "{{SP2P_SERVER_URL}}/ps/r"))) -format json "CODE"
```

## Files, folders, and pipes

### Send one or more paths

Run the sender and keep it running. It creates the code:

```bash
sp2p send -format json -server "{{SP2P_SERVER_URL}}" ./report.pdf
sp2p send -format json -server "{{SP2P_SERVER_URL}}" ./photos
sp2p send -format json -server "{{SP2P_SERVER_URL}}" ./report.pdf ./photos ./notes.txt
```

Multiple roots are sent as one archive. The sender's `session` event includes the complete secret code and a browser receive URL:

```json
{"schema_version":1,"sequence":2,"event":"session","at":"2026-01-02T03:04:05Z","role":"send","session_id":"SESSION_ID","code":"CODE","share_url":"{{SP2P_SERVER_URL}}/r#CODE"}
```

Pass `code`, not `session_id`, to the receiver:

```bash
sp2p receive -format json -server "{{SP2P_SERVER_URL}}" "CODE"
```

The receiver writes to the current directory unless `-output DIR` is given. A completed `result` includes `saved_path`. Files are verified and finalized without replacement before acknowledgement. A single-root folder retains its root; multiple roots publish under one new wrapper. An existing archive destination fails instead of merging. A lost acknowledgement can leave valid saved output while the sender reports failure; completion is not a power-loss durability guarantee.

### Pipe a file

Use file-transfer stdin when one process produces a finite file:

```bash
tar czf - src/ | sp2p send -server "{{SP2P_SERVER_URL}}" -name src.tar.gz -
sp2p receive -server "{{SP2P_SERVER_URL}}" -stdout "CODE" > src.tar.gz
```

For raw bytes on stdout in JSON mode, route events to stderr:

```bash
sp2p receive -format json -event-output stderr -stdout -server "{{SP2P_SERVER_URL}}" "CODE" > received.bin
```

`send -` is still a one-way file transfer with metadata, verification, and a final size. Use [duplex stdio](#duplex-stdio) when both processes must read and write during one session.

### File-transfer compatibility and limits

Two updated CLI/browser peers use file-transfer protocol v3; mixed 0.4.0/0.5.0 peers use v2 through either server version. Selection is automatic. Do not add a version flag or retry a failed v3 connection at v2. New rsync and tunnel streams require authenticated v3 peers and never fall back to file-transfer or v2 mode.

All v3 peers authenticate connection candidates and sender selection before key confirmation. Legacy file mode warns without prompting, disables parallel TCP, and lacks v3 candidate authentication, receive credits, and robust idle/backpressure behavior. Updated peers retain local limits and output protections but cannot repair an old peer.

Decoded receive and expanded archive output each default to 1 TiB. `-max-receive-bytes` and `-max-extract-bytes` accept larger positive finite byte counts for trusted transfers; zero selects the default, never unlimited output. Browser memory downloads are limited to 256 MiB and browser disk receives to 1 TiB. Stdout cannot roll back bytes already accepted.

## Rsync synchronization

SP2P transports one installed rsync invocation through an authenticated stream. It supports macOS and Linux, including Apple's built-in openrsync and the historical macOS rsync 2.6.9; no Homebrew replacement is required. On Windows, run both SP2P and rsync inside WSL because the native Windows adapter remains unsupported. Use `--rsync-binary PATH` before `--` when rsync is not on `PATH` or a specific installation is required. Available options, metadata behavior, cross-version interoperability, and rsync security fixes depend on the implementations installed on both peers; this compatibility is not a guarantee for every historical patch level or option combination.

SP2P configures the child transport automatically. Upstream rsync uses `RSYNC_CONNECT_PROG`; Apple openrsync lacks that hook, so SP2P injects a fixed local `-e` helper instead. Neither path invokes SSH or permits a peer-selected remote command. User-provided remote-shell and `-e` options are rejected; do not export `RSYNC_CONNECT_PROG` or call SP2P's hidden helper yourself.

Rsync remains one-way per invocation even though its protocol needs a bidirectional stream. Each invocation uses one new sender-created code. Reusing the same directories in a later invocation gives rsync the existing data for its incremental comparison, but requires a new code.

### Sender-selected rsync options

On the source machine, `send` creates the code and runs the rsync client:

```bash
sp2p rsync send --server "{{SP2P_SERVER_URL}}" -- -av --partial ./photos/ sp2p::share/
```

On the destination machine, create the module directory first, then replace `CODE` with that code:

```bash
mkdir -p ./backup
sp2p rsync recv --server "{{SP2P_SERVER_URL}}" CODE ./backup
```

The receiver exposes `./backup` as a one-use write-only rsync module. Everything after the required `--` boundary is passed to the installed rsync as separate arguments, preserving order and quoting. `sp2p` is a placeholder host and `share` is the fixed module name.

The destination does not authorize deletion by default. If the sender's forwarded rsync arguments request deletion, the receiver must explicitly add `--allow-delete` before `CODE`:

```bash
sp2p rsync recv --server "{{SP2P_SERVER_URL}}" --allow-delete CODE ./backup
```

Write-only mode prevents downloading destination files, but it is not a metadata-confidentiality boundary: rsync's delta protocol necessarily exchanges information about existing destination files.

### Receiver-selected rsync options

The source can instead expose a read-only directory while still creating the code:

```bash
sp2p rsync send --server "{{SP2P_SERVER_URL}}" ./photos
```

The receiver supplies the client options and destination after `--`:

```bash
sp2p rsync recv --server "{{SP2P_SERVER_URL}}" CODE -- -av --partial sp2p::share/ ./photos/
```

In this form, the receiver's own rsync arguments authorize updates and deletion in its local destination. The sender's exported directory remains read-only.

### Rsync behavior and completion

- `send` always identifies the file source and creates the code; only `recv` accepts a code.
- `--` separates SP2P flags from exact rsync arguments. Put `--server`, `--allow-relay`, `--rsync-binary`, and other SP2P flags before it.
- Rsync controls file selection, metadata, compression, partial files, update rules, and incremental deltas. Ordinary SP2P receive limits and no-replace publication do not govern rsync destinations.
- A directory-serving receiver requires `--allow-delete` before it accepts sender-requested deletion. A receiver running the rsync client controls deletion through its own forwarded arguments.
- Before serving, SP2P rejects an existing symlink in the module tree if it resolves to a directory. Ordinary file and dangling symlinks can remain links under `-a`, and the daemon munges their targets. It refuses peer-requested `copy-links`, `copy-unsafe-links`, `copy-dirlinks`, and `keep-dirlinks` behavior. This preflight and module policy are defense in depth, not an operating-system sandbox, and do not make a concurrently mutated untrusted tree safe; control who can modify a served tree and review paths and options.
- A daemon module path is rejected if its absolute form contains leading or trailing whitespace, NUL, CR/LF, `%`, or a backslash because those values have special meaning in `rsyncd.conf`.
- `--partial` can preserve rsync partials for a later run. A disconnected run is not complete; create a new code and wait for both new commands to emit `result` with `outcome:"completed"`.

## Socket forwarding

Tunnels are CLI-only. `tunnel serve` creates the code on the machine that can reach a fixed target. `tunnel connect` joins it and exposes either one local listener or stdio. The connecting peer cannot choose or replace the provider's target. SP2P does not connect to that target until the peer is authenticated and requests the stream.

The initial listener accepts exactly one local connection, closes the listener, and exits when that connection finishes. It does not reconnect or replay after failure. Directional EOF is preserved where the local endpoint supports half-close, so one side can finish sending and continue receiving. Cancellation closes the peer stream and owned local endpoints. Wait for terminal results on both peers.

### TCP to TCP

On the machine that can reach PostgreSQL, create the code:

```bash
sp2p tunnel serve --server "{{SP2P_SERVER_URL}}" --to tcp://127.0.0.1:5432
```

On the other machine, create a loopback listener:

```bash
sp2p tunnel connect --server "{{SP2P_SERVER_URL}}" --listen tcp://127.0.0.1:15432 CODE
```

Wait for `Ready: tcp://127.0.0.1:15432` in human mode or a `ready` event before starting the local client. TCP listeners require an explicit address; prefer loopback unless the user deliberately authorizes wider exposure.

### Unix to Unix

The `--to` Unix path must identify an existing service socket. The `--listen` Unix path must not already exist; SP2P creates that private listener and removes only the socket it created.

```bash
sp2p tunnel serve --server "{{SP2P_SERVER_URL}}" --to unix:///run/example/service.sock
sp2p tunnel connect --server "{{SP2P_SERVER_URL}}" --listen unix:///tmp/sp2p-example.sock CODE
```

### Mixed TCP and Unix endpoints

Endpoint types are independent. For example, expose a Unix service through a loopback TCP listener:

```bash
sp2p tunnel serve --server "{{SP2P_SERVER_URL}}" --to unix:///run/example/service.sock
sp2p tunnel connect --server "{{SP2P_SERVER_URL}}" --listen tcp://127.0.0.1:15432 CODE
```

The reverse combination, a TCP target with a Unix listener, works the same way.

### Duplex stdio

Use `--stdio` instead of `--to` or `--listen` to attach the authenticated stream directly to stdin/stdout:

```bash
sp2p tunnel serve --server "{{SP2P_SERVER_URL}}" --stdio
sp2p tunnel connect --server "{{SP2P_SERVER_URL}}" --stdio CODE
```

In human mode, stdout contains only payload and status goes to stderr. In JSON mode, `--event-output stderr` is mandatory so JSON cannot corrupt the payload:

```bash
producer | sp2p tunnel connect --format json --event-output stderr --server "{{SP2P_SERVER_URL}}" --stdio CODE > response.bin 2> events.jsonl
```

Closing local stdin sends directional EOF while SP2P continues copying the peer's response to stdout. This is a raw full-duplex byte stream: it has no file metadata, archive extraction, or automatic command execution.

## Automation events and status

JSON mode writes one schema-version-1 object per line. Every event includes `schema_version`, `sequence`, `event`, `at`, and `role`. Stream-service records also include `service` and `mode`. Tunnel role/mode values are `serve` or `connect`. Rsync role is `send` or `recv`; mode is `send-client`, `send-daemon`, `recv-client`, or `recv-daemon`. Read until exactly one terminal `result`; an earlier `error`, peer connection, `ready`, or subprocess exit is not the terminal contract.

Rsync and tunnel help follows the same machine-output boundary. With `--format json`, `--help` emits exactly one `result` with `outcome:"completed"`, `mode:"help"`, and usage/default text in `message` on the selected event stream. It does not contact the signaling server or emit `session`.

| Event | File transfer | Rsync and tunnel streams |
| --- | --- | --- |
| `phase` | Lifecycle such as preparation, connection, transfer, and completion | Stream setup and lifecycle |
| `session` | Creator only; includes `code` and browser `share_url` | Creator only (`rsync send` or `tunnel serve`); includes `code`, never a browser URL |
| `metadata` | File/folder/stream metadata | Not used |
| `ready` | Not used | Local readiness; `endpoint` identifies a socket listener or rsync daemon directory and can be absent in stdio/client modes |
| `progress` | `bytes_transferred` and `total_bytes` | Cumulative `bytes_sent` and `bytes_received`, at most once per second |
| `subprocess_output` | Not used | Rsync JSON mode only; client stdout/stderr and daemon stderr, with `output_stream` set to `stdout` or `stderr` and exact bytes base64-encoded in `output_data` |
| `connection`, `connection_reset`, `protocol`, `verification` | Connection and authentication state | Connection and authenticated v3 state |
| `relay_required`, `relay_response`, `relay_response_invalid`, `relay_prompt_canceled` | Relay decision lifecycle | Same response-file contract |
| `error` | Nonterminal diagnostic; continue reading | Nonterminal diagnostic when emitted; setup and subprocess failures are always present in terminal `result.error` |
| `result` | Exactly one terminal outcome and optional `saved_path` | Exactly one terminal outcome plus final `bytes_sent` and `bytes_received` |

In human rsync client modes, the child uses normal stdin/stdout/stderr and SP2P preserves its numeric exit status. In daemon modes, child stdin/stdout carry the rsync protocol over the authenticated stream, while daemon diagnostics use stderr. JSON mode captures client stdout/stderr and daemon stderr as `subprocess_output` records so unstructured text never corrupts JSON. Base64-decode `output_data` to recover the exact bytes before presenting them. SP2P diagnostics remain structured events, and a subprocess failure is reported in the terminal `result.error`.

Example creator event for a CLI-only service:

```json
{"schema_version":1,"sequence":2,"event":"session","at":"2026-01-02T03:04:05Z","role":"serve","service":"tunnel","mode":"serve","session_id":"SESSION_ID","code":"CODE"}
```

Example listener readiness and terminal result:

```json
{"schema_version":1,"sequence":8,"event":"ready","protocol":3,"at":"2026-01-02T03:04:08Z","role":"connect","service":"tunnel","mode":"connect","endpoint":"tcp://127.0.0.1:15432"}
{"schema_version":1,"sequence":12,"event":"result","protocol":3,"at":"2026-01-02T03:05:00Z","role":"connect","service":"tunnel","mode":"connect","bytes_sent":128,"bytes_received":4096,"outcome":"completed"}
```

Add `--status-file` with JSON mode when another process must poll the latest owner-only snapshot:

```bash
sp2p send -format json -server "{{SP2P_SERVER_URL}}" -status-file /secure/sp2p-file.json ./report.pdf
sp2p rsync send --format json --status-file /secure/sp2p-rsync.json --server "{{SP2P_SERVER_URL}}" -- -av --partial ./photos/ sp2p::share/
sp2p tunnel connect --format json --status-file /secure/sp2p-tunnel.json --server "{{SP2P_SERVER_URL}}" --listen tcp://127.0.0.1:15432 CODE
sp2p tunnel connect --format json --event-output stderr --status-file /secure/sp2p-stdio.json --server "{{SP2P_SERVER_URL}}" --stdio CODE
```

Status files are replaced atomically with owner-only permissions. Creator snapshots contain the secret code, so keep them private. The signaling server cannot report encrypted peer progress or completion; there is intentionally no remote `status CODE` endpoint.

## Respond when relay is required

SP2P attempts direct peer connections first. If they fail and a TURN relay is available, JSON mode creates a temporary owner-only response file:

```json
{"schema_version":1,"sequence":9,"event":"relay_required","at":"2026-01-02T03:04:10Z","role":"recv","service":"rsync","mode":"recv-daemon","response_file":"/tmp/sp2p-relay-response-example","allowed_responses":["allow","deny"]}
```

Write `allow` or `deny` to that exact file:

```bash
printf 'allow\n' > /tmp/sp2p-relay-response-example
```

SP2P emits `relay_response` and removes the file. If the peer or signaling connection ends first, it emits `relay_prompt_canceled` and removes the file; never reuse the path. Relay traffic remains end-to-end encrypted, but the relay observes connection metadata. Use `--allow-relay` only when policy authorizes relay without a per-session decision. Unattended human mode cannot use the response-file mechanism and should fail unless `--allow-relay` is already authorized.

## Agent handoff prompts

Replace bracketed values before acting. The creator must communicate the secret code privately, and both agents must wait for `result` rather than treating connection as completion.

```text
Please send [file or folder] using {{SP2P_SERVER_URL}}/llm
```

```text
Please receive file session [CODE] into [destination directory] using {{SP2P_SERVER_URL}}/llm
```

```text
Please synchronize [source directory] to [destination directory] with rsync using {{SP2P_SERVER_URL}}/llm. The source agent must create the code and the destination agent must join it.
```

```text
Please receive rsync session [CODE] into [destination directory] using {{SP2P_SERVER_URL}}/llm. Wait for the terminal result before reporting completion.
```

```text
Please expose [TCP or Unix target endpoint] to [TCP or Unix local listener endpoint] using {{SP2P_SERVER_URL}}/llm. The target-side agent must create the code.
```

```text
Please join tunnel session [CODE] and listen at [TCP or Unix local endpoint] using {{SP2P_SERVER_URL}}/llm
```

```text
Please connect [local program using stdin/stdout] to [remote program or service] through a duplex SP2P stdio tunnel using {{SP2P_SERVER_URL}}/llm. The serving agent must create the code.
```

For an ordinary file, human-facing sender output also provides a receiving prompt with the actual code and browser-capable guide URL. Rsync and tunnel sessions do not produce browser receive links.
