# SP2P agent guide

> Use SP2P to transfer files directly between peers with end-to-end encryption. Run the CLI in JSON mode, use the `session` event to obtain the transfer code, and wait for the terminal `result` event.

The transfer code is a secret capability. Give it only to the intended receiving agent, do not put it in public issue trackers or chat logs, and redact it from diagnostic output.

This guide belongs to the signaling server at `{{SP2P_SERVER_URL}}`. Pass that
exact URL with `-server` in both commands below so a self-hosted sender and
receiver join the same server. The CLI converts its HTTP(S) URL to the required
WebSocket endpoint automatically.

## Get SP2P

If `sp2p` is not installed, use a one-shot bootstrap command from this server.
It downloads the right binary to a temporary directory, runs it, configures
this server automatically, and then removes the binary. Add `-format json` as
shown when an agent needs lifecycle events.

### Send without installing

macOS or Linux with curl:

```bash
curl -f "{{SP2P_SERVER_URL}}" | sh -s -- -format json "./report.pdf"
```

macOS or Linux with wget:

```bash
wget -O- "{{SP2P_SERVER_URL}}" | sh -s -- -format json "./report.pdf"
```

Windows PowerShell:

```powershell
& ([scriptblock]::Create((irm "{{SP2P_SERVER_URL}}/ps"))) -format json "C:\path\to\report.pdf"
```

### Receive without installing

macOS or Linux with curl:

```bash
curl -f "{{SP2P_SERVER_URL}}/r" | sh -s -- -format json "abc12345-TRANSFER_SECRET"
```

macOS or Linux with wget:

```bash
wget -O- "{{SP2P_SERVER_URL}}/r" | sh -s -- -format json "abc12345-TRANSFER_SECRET"
```

Windows PowerShell:

```powershell
& ([scriptblock]::Create((irm "{{SP2P_SERVER_URL}}/ps/r"))) -format json "abc12345-TRANSFER_SECRET"
```

For a permanent installation, use the [latest GitHub release page](https://github.com/zyno-io/sp2p/releases/latest),
or let an agent inspect the [latest-release JSON](https://api.github.com/repos/zyno-io/sp2p/releases/latest)
and choose a matching `assets[].browser_download_url`. Package-manager options
are also listed in the [SP2P README](https://github.com/zyno-io/sp2p#install).

## Send a file

Run the sender and keep it running until a terminal result is emitted:

```bash
sp2p send -format json -server "{{SP2P_SERVER_URL}}" ./report.pdf
```

The sender emits a `session` event once it has registered with the signaling server:

```json
{"schema_version":1,"sequence":2,"event":"session","at":"2026-01-02T03:04:05Z","role":"send","session_id":"abc12345","code":"abc12345-TRANSFER_SECRET","share_url":"{{SP2P_SERVER_URL}}/r#abc12345-TRANSFER_SECRET"}
```

Pass the `code` value to the receiving agent. Do not use the session ID on its own; it is not the transfer credential.

## Receive a file

Use the complete transfer code:

```bash
sp2p receive -format json -server "{{SP2P_SERVER_URL}}" "abc12345-TRANSFER_SECRET"
```

The receiver writes files to the current directory by default. A successful terminal result includes `saved_path` when SP2P created a file or directory.

For raw file bytes on stdout, route events to stderr so JSON never mixes with the file data:

```bash
sp2p receive -format json -event-output stderr -stdout -server "{{SP2P_SERVER_URL}}" "abc12345-TRANSFER_SECRET" > received.bin
```

## Read status and completion

JSON mode writes one JSON object per line. Every record includes `schema_version`, `sequence`, `event`, `at`, and `role`.

| Event | Meaning |
| --- | --- |
| `phase` | Lifecycle change such as `preparing`, `registered`, `p2p_connecting`, `transferring`, or `done`. |
| `session` | Sender-only handoff event with the transfer code and share URL. |
| `metadata` | File name, byte size, folder/stream mode, and file count once known. |
| `connection` | A TCP or WebRTC connection-method update. |
| `connection_reset` | Connection-method updates were cleared before a relay retry. |
| `progress` | Bytes transferred, emitted at most once per second. |
| `verification` | Short code for a person to compare at both peers. |
| `parallel_streams` | Number of parallel TCP streams in use. |
| `update_available` | A newer SP2P server version is available. |
| `log` | Verbose diagnostic message, emitted only with `-v`; secret transfer codes are excluded. |
| `relay_required` | Direct connection failed and an agent decision is required. |
| `relay_response` | SP2P read the agent's `allow` or `deny` response. |
| `relay_response_invalid` | The response file contains a value other than `allow` or `deny`; SP2P keeps waiting. |
| `relay_prompt_canceled` | The peer or signaling connection ended while relay consent was pending. |
| `status_file_error` | SP2P could not update the optional `-status-file`; the primary event stream remains usable. |
| `error` | A diagnostic failure notice. Continue reading until the terminal `result`. |
| `result` | Exactly one terminal outcome: `completed` or `failed`. |

To let another process poll the latest state, add `-status-file`:

```bash
sp2p send -format json -server "{{SP2P_SERVER_URL}}" -status-file /secure/path/sp2p-status.json ./report.pdf
```

SP2P atomically updates this owner-only JSON file. It includes the transfer code after registration, so keep it in a private location.

## Respond when relay is required

Direct peer-to-peer connections are attempted first. If they fail and a TURN relay is available, JSON mode creates a temporary owner-only response file and emits its path:

```json
{"schema_version":1,"sequence":9,"event":"relay_required","at":"2026-01-02T03:04:10Z","role":"receive","response_file":"/tmp/sp2p-relay-response-example","allowed_responses":["allow","deny"]}
```

The agent must write either `allow` or `deny` into that exact file. For example:

```bash
printf 'allow\n' > /tmp/sp2p-relay-response-example
```

SP2P reads the response, emits `relay_response`, and removes the temporary file. If the peer or signaling connection ends first, it emits `relay_prompt_canceled` and removes the file; do not reuse that path. Allowing a relay does not give the relay server access to file contents: the file transfer remains end-to-end encrypted. Use `-allow-relay` when the agent's policy permits relay automatically and no decision is needed.

## Human handoff prompt

When a person asks an agent to send a file, they can paste this prompt:

```text
Please send [file] using {{SP2P_SERVER_URL}}/llm
```

When a sender is ready, its human-facing output also provides this receiving handoff prompt with the actual transfer token:

```text
AI Agent: Please receive file session [token] using {{SP2P_SERVER_URL}}/llm
```

## Limits of status

The signaling server can coordinate peers but cannot inspect encrypted peer-to-peer transfer progress or completion. Follow the running command's event stream or status file; there is intentionally no remote `status CODE` endpoint.
