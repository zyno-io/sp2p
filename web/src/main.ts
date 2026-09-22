// SPDX-License-Identifier: MIT

// SP2P Web UI — entry point.
// Detects whether this is the send or receive page and initializes accordingly.

import { SignalClient, PROTOCOL_VERSION, Envelope } from "./signal";
import { establishWebRTC, ICEServerConfig, splitIceServers } from "./webrtc";
import { monitorTransfer } from "./diagnostics";
import { confirmDataChannel } from "./handshake";
import {
  generateKeyPair,
  exportTransferPublicKey,
  transferProtocol,
  importPublicKey,
  deriveKeys,
  generateSeed,
  decodeSeed,
  parseCode,
  EncryptedChannel,
  encryptFileInfo,
  decryptFileInfo,
  bytesToBase64,
  base64ToBytes,
} from "./crypto";
import {
  DataChannelTransport,
  sendFile,
  sendFiles,
  receiveFile,
} from "./transfer";
import {
  $,
  show,
  hide,
  setStepStatus,
  updateProgress,
  formatBytes,
  setupDragDrop,
  downloadBlob,
  showError,
} from "./ui";
import { log } from "./log";
import { createTar, type TarArchive } from "./tar";
import { showQRModal, closeQRModal } from "./qr";

const MULTI_FILE_ARCHIVE_NAME = "sp2p-received-folder.tar";

// Wait for a message type, but also race against server error messages
// and peer disconnection so rejections are surfaced immediately instead
// of degrading to timeouts. Uses a single set of handlers with shared
// cleanup to avoid leaking listeners when one event wins the race.
function waitForWithErrors(
  sigClient: SignalClient,
  type: string,
  timeoutMs = 30000
): Promise<Envelope> {
  if (sigClient.closed) {
    return Promise.reject(new Error(`Connection closed while waiting for ${type}`));
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sigClient.removeHandler(type, onMain);
      sigClient.removeHandler("error", onError);
      sigClient.removeHandler("peer-left", onPeerLeft);
      sigClient.removeHandler("_closed", onClose);
      sigClient.removeHandler("_error", onClose);
    };
    const onMain = (env: Envelope) => { cleanup(); resolve(env); };
    const onError = (env: Envelope) => {
      cleanup();
      reject(new Error(env.payload?.message || env.payload?.code || "Server error"));
    };
    const onPeerLeft = () => { cleanup(); reject(new Error("Peer disconnected")); };
    const onClose = () => { cleanup(); reject(new Error(`Connection closed while waiting for ${type}`)); };
    const timer = setTimeout(() => { cleanup(); reject(new Error(`Timeout waiting for ${type}`)); }, timeoutMs);
    sigClient.on(type, onMain);
    sigClient.on("error", onError);
    sigClient.on("peer-left", onPeerLeft);
    sigClient.on("_closed", onClose);
    sigClient.on("_error", onClose);
  });
}

// Determine WebSocket URL from page location.
function getWsUrl(): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}/ws`;
}

// Establish a WebRTC connection with TURN relay fallback.
// 1. First attempt: STUN only (no TURN relay)
// 2. Relay retry: requests TURN credentials from server (last resort, requires explicit user consent)
async function establishP2PWithRetry(
  sigClient: SignalClient,
  isSender: boolean,
  iceServers: ICEServerConfig[] | undefined,
  turnAvailable: boolean,
  confirmRelay: () => Promise<boolean>,
  onStage: (detail: string) => void,
): Promise<{ dc: RTCDataChannel; pc: RTCPeerConnection }> {
  const { stun } = splitIceServers(iceServers);

  // Pre-subscribe to relay-retry signal BEFORE the first attempt,
  // so we don't miss the peer's signal if their attempt fails faster than ours.
  const relayRetryPromise = sigClient.waitFor("relay-retry", 120000);
  relayRetryPromise.catch(() => {});

  // Watch for peer disconnection during P2P establishment.
  let peerLeft = false;
  const peerLeftPromise = sigClient.waitFor("peer-left", 300000);
  peerLeftPromise.then(() => { peerLeft = true; }).catch(() => {});

  // Attempt 1: STUN only.
  log(`P2P attempt 1: STUN only (${stun.length} servers, isSender=${isSender})`);
  try {
    return await establishWebRTC(sigClient, isSender, (_method, _state, detail) => { if (detail) onStage(detail); }, undefined, 15000, stun);
  } catch (err) {
    log(`P2P attempt 1 failed: ${(err as Error).message}`);
    if (peerLeft || sigClient.closed) {
      throw new Error("Peer disconnected");
    }
    // Fall through to relay retry if TURN available.
  }

  // Attempt 2: Relay retry with TURN (last resort, requires consent).
  log(`P2P: direct connection failed, TURN available: ${turnAvailable}`);
  if (!turnAvailable) {
    throw new Error("Could not establish P2P connection (no TURN relay available)");
  }

  // Subscribe to turn-credentials BEFORE sending relay-retry so we don't miss
  // the server's response.
  const turnCredsPromise = sigClient.waitFor("turn-credentials", 30000);
  turnCredsPromise.catch(() => {});

  // Signal relay-retry BEFORE prompting the user. This notifies the peer
  // immediately so they can show their own relay prompt in parallel with ours,
  // rather than waiting for us to click OK first.
  log("P2P: requesting TURN relay credentials");
  onStage("Direct connection failed; requesting relay access");
  sigClient.send("relay-retry", {});

  // Ask user for consent while the peer is being notified in parallel.
  const allowed = await confirmRelay();
  if (!allowed) {
    sigClient.send("relay-denied", {});
    throw new Error("P2P connection failed and relay was declined");
  }

  // Wait for TURN credentials from the server.
  const turnCredsEnv = await turnCredsPromise;
  const turnServers: RTCIceServer[] = (turnCredsEnv.payload?.iceServers || []).map(
    (s: ICEServerConfig) => ({
      urls: s.urls,
      username: s.username,
      credential: s.credential,
    })
  );
  if (turnServers.length === 0) {
    throw new Error("Server returned empty TURN credentials");
  }
  log(`P2P: received ${turnServers.length} TURN servers`);

  log("P2P: waiting for peer to agree to relay retry");
  onStage("Waiting for peer to allow the relay");
  const relayDeniedPromise = sigClient.waitFor("relay-denied", 120000);
  relayDeniedPromise.catch(() => {});
  const peerResult = await Promise.race([
    relayRetryPromise.then(() => "agreed" as const),
    relayDeniedPromise.then(() => "denied" as const),
  ]);
  if (peerResult === "denied") {
    throw new Error("Receiver denied relay connection");
  }
  await new Promise((r) => setTimeout(r, 500));

  log("P2P attempt 2: TURN relay");
  return await establishWebRTC(sigClient, isSender, (_method, _state, detail) => { if (detail) onStage(`Relay attempt: ${detail}`); }, undefined, 15000, [...stun, ...turnServers]);
}

// ─── PLATFORM DETECTION ──────────────────────────────────────

function detectPlatform(): { os: string; arch: string; label: string } {
  const ua = navigator.userAgent;
  const uaData = (navigator as any).userAgentData;

  let os = "linux";
  let osLabel = "Linux";
  let arch = "amd64";

  // Detect OS.
  if (uaData?.platform) {
    const p = uaData.platform.toLowerCase();
    if (p === "macos") { os = "darwin"; osLabel = "macOS"; }
    else if (p === "windows") { os = "windows"; osLabel = "Windows"; }
  } else {
    if (/Mac|iPhone|iPad/.test(ua)) { os = "darwin"; osLabel = "macOS"; }
    else if (/Windows/.test(ua)) { os = "windows"; osLabel = "Windows"; }
  }

  // Detect architecture.
  if (uaData?.architecture === "arm") {
    arch = "arm64";
  } else if (/aarch64|arm64/.test(ua)) {
    arch = "arm64";
  } else if (os === "darwin") {
    // Most modern Macs are ARM64; UA is unreliable for detection.
    arch = "arm64";
  }

  return { os, arch, label: `${osLabel} (${arch})` };
}

function initZeroInstallSection(): void {
  const section = document.querySelector<HTMLElement>(".zero-install-section");
  if (!section) return;
  const origin = location.origin;
  const curlEl = section.querySelector<HTMLElement>(".send-curl");
  const wgetEl = section.querySelector<HTMLElement>(".send-wget");
  const psEl = section.querySelector<HTMLElement>(".send-powershell");
  if (curlEl) {
    curlEl.textContent = `curl -f ${origin} | sh -s <file>`;
    curlEl.dataset.copyText = `curl -f ${origin} | sh -s `;
  }
  if (wgetEl) {
    wgetEl.textContent = `wget -O- ${origin} | sh -s <file>`;
    wgetEl.dataset.copyText = `wget -O- ${origin} | sh -s `;
  }
  if (psEl) {
    psEl.textContent = `& ([scriptblock]::Create((irm ${origin}/ps))) '<file>'`;
    psEl.dataset.copyText = `& ([scriptblock]::Create((irm ${origin}/ps))) '`;
  }
}

function initUsageSection(): void {
  const section = document.querySelector<HTMLElement>(".usage-section");
  if (!section) return;
  const origin = location.origin;

  const setCommand = (selector: string, value: string, copyText = value): void => {
    const element = section.querySelector<HTMLElement>(selector);
    if (!element) return;
    element.textContent = value;
    element.dataset.copyText = copyText;
  };

  setCommand(".agent-send-prompt", `Please send [file] using ${origin}/llm`);
  setCommand(".agent-rsync-prompt", `Please sync [source directory] to [destination directory] with rsync using ${origin}/llm`);
  setCommand(".agent-tunnel-prompt", `Please forward [TCP or Unix target endpoint] to [TCP or Unix local listener endpoint] using ${origin}/llm`);

  setCommand(".rsync-send-command", `sp2p rsync send --server ${origin} -- -av --partial ./photos/ sp2p::share/`);
  setCommand(".rsync-recv-command", `sp2p rsync recv --server ${origin} CODE ./backup`);
  setCommand(".rsync-serve-command", `sp2p rsync send --server ${origin} ./photos`);
  setCommand(".rsync-download-command", `sp2p rsync recv --server ${origin} CODE -- -av --partial sp2p::share/ ./photos/`);
  setCommand(".tunnel-serve-tcp-command", `sp2p tunnel serve --server ${origin} --to tcp://127.0.0.1:5432`);
  setCommand(".tunnel-connect-tcp-command", `sp2p tunnel connect --server ${origin} --listen tcp://127.0.0.1:15432 CODE`);
  setCommand(".tunnel-serve-unix-command", `sp2p tunnel serve --server ${origin} --to unix:///run/example/service.sock`);
  setCommand(".tunnel-connect-unix-command", `sp2p tunnel connect --server ${origin} --listen unix:///tmp/sp2p-example.sock CODE`);
  setCommand(".tunnel-serve-stdio-command", `sp2p tunnel serve --server ${origin} --stdio`);
  setCommand(".tunnel-connect-stdio-command", `sp2p tunnel connect --server ${origin} --stdio CODE`);
  setCommand(".cli-send-command", `sp2p send -server ${origin} <file>`, `sp2p send -server ${origin} `);
  setCommand(".cli-recv-command", `sp2p receive -server ${origin} CODE`);

  const { os, arch, label } = detectPlatform();
  const downloadBtn = section.querySelector<HTMLAnchorElement>(".download-btn");
  const platformLabel = section.querySelector(".download-platform");
  if (downloadBtn) downloadBtn.href = `/dl/${os}/${arch}`;
  if (platformLabel) platformLabel.textContent = `for ${label}`;

  const tabs = Array.from(section.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
  const selectTab = (selectedTab: HTMLButtonElement, moveFocus: boolean): void => {
    for (const tab of tabs) {
      const isSelected = tab === selectedTab;
      tab.setAttribute("aria-selected", String(isSelected));
      tab.tabIndex = isSelected ? 0 : -1;
      const panelId = tab.getAttribute("aria-controls");
      const panel = panelId ? document.getElementById(panelId) : null;
      if (panel) panel.hidden = !isSelected;
    }
    if (moveFocus) selectedTab.focus();
  };

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectTab(tab, false));
    tab.addEventListener("keydown", (event) => {
      let nextIndex: number | null = null;
      if (event.key === "ArrowRight" || event.key === "ArrowDown") {
        nextIndex = (index + 1) % tabs.length;
      } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
        nextIndex = (index - 1 + tabs.length) % tabs.length;
      } else if (event.key === "Home") {
        nextIndex = 0;
      } else if (event.key === "End") {
        nextIndex = tabs.length - 1;
      }
      if (nextIndex === null) return;
      event.preventDefault();
      selectTab(tabs[nextIndex], true);
    });
  });
}

// ─── SEND PAGE ───────────────────────────────────────────────

// Only show a negotiated protocol after successful transcript confirmation.
function showProtocol(protocol: 2 | 3): void {
  log(`authenticated transfer protocol v${protocol}`);
  if (protocol === 2) show($(".legacy-warning"));
}

async function initSend(): Promise<void> {
  initZeroInstallSection();
  initUsageSection();

  const dropZone = $(".drop-zone");
  const zeroInstallSection = $(".zero-install-section");
  const usageSection = $(".usage-section");
  const fileInput = $(".file-input") as HTMLInputElement;
  const shareDisplay = $(".share-display");
  const shareUrl = $(".share-url");
  const shareCurl = $(".share-curl");
  const shareWget = $(".share-wget");
  const sharePowershell = $(".share-powershell");
  const shareCli = $(".share-cli");
  const shareAgent = $(".share-agent");

  // Click-to-copy on share boxes.
  for (const box of document.querySelectorAll<HTMLElement>(".copy-box")) {
    const copy = async (): Promise<void> => {
      const code = box.querySelector("code") as HTMLElement | null;
      if (!code) return;
      const text = code.dataset.copyText || code.textContent;
      if (!text) return;
      await navigator.clipboard.writeText(text);
      const hint = box.querySelector(".copy-hint");
      if (hint) {
        hint.textContent = "copied!";
        box.classList.add("copied");
        setTimeout(() => {
          hint.textContent = "click to copy";
          box.classList.remove("copied");
        }, 2000);
      }
    };
    box.addEventListener("click", () => { void copy(); });
    if (!(box instanceof HTMLButtonElement)) {
      box.tabIndex = 0;
      box.setAttribute("role", "button");
      box.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        event.preventDefault();
        void copy();
      });
    }
  }
  const stepsContainer = $(".steps");
  const progressContainer = $(".progress-container");
  const progressBar = $(".progress-bar-fill");
  const progressInfo = $(".progress-info");
  const statusText = $(".status-text");
  const completeContainer = $(".complete");

  // File selection.
  let selectedFiles: File[] = [];

  setupDragDrop(dropZone, (files) => {
    selectedFiles = files;
    startSend(selectedFiles);
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files?.length) {
      selectedFiles = Array.from(fileInput.files);
      startSend(selectedFiles);
    }
  });

  dropZone.addEventListener("click", () => fileInput.click());

  async function startSend(files: File[]): Promise<void> {
    const isSingleFile = files.length === 1;
    const file = files[0]; // used for single-file path
    const transferName = isSingleFile ? file.name : MULTI_FILE_ARCHIVE_NAME;
    let transferSize = file.size;
    let preparedArchive: TarArchive | undefined;
    hide(dropZone);
    hide(zeroInstallSection);
    hide(usageSection);
    show(stepsContainer);

    let sigClient: SignalClient | null = null;
    let pc: RTCPeerConnection | null = null;

    try {
      if (!isSingleFile) {
        // Validate paths and retain the exact TAR size before publishing a code.
        preparedArchive = createTar(files);
        transferSize = preparedArchive.totalSize;
      }
      // Step 1: Generate seed.
      log("generating encryption seed");
      const { encoded: seedEncoded, raw: seedRaw } = generateSeed();

      // Step 2: Connect to signaling server.
      setStepStatus($(".step-connect"), "active");
      sigClient = await SignalClient.connect(getWsUrl());
      setStepStatus($(".step-connect"), "done");

      // Step 3: Register session.
      sigClient.send("hello", { version: PROTOCOL_VERSION, clientType: "browser" });
      const welcome = await waitForWithErrors(sigClient, "welcome");
      const sessionId = welcome.payload.sessionId;
      const serverIceServers: ICEServerConfig[] | undefined =
        welcome.payload.iceServers;
      const serverTurnAvailable: boolean = !!welcome.payload.turnAvailable;
      log(`session ${sessionId}: ${serverIceServers?.length ?? 0} ICE servers, TURN available: ${serverTurnAvailable}`);

      // Encrypt and send file-info for receiver preview (best-effort).
      try {
        const fileInfoMeta = {
          name: transferName,
          size: transferSize,
          isFolder: !isSingleFile,
          fileCount: isSingleFile ? 0 : files.length,
        };
        const metaJSON = new TextEncoder().encode(JSON.stringify(fileInfoMeta));
        const encBlob = await encryptFileInfo(seedRaw, metaJSON);
        const b64 = bytesToBase64(encBlob);
        sigClient.send("file-info", { data: b64 });
      } catch {}

      // Show share links.
      const code = `${sessionId}-${seedEncoded}`;
      const origin = location.origin;
      shareUrl.textContent = `${origin}/r#${code}`;
      shareCurl.textContent = `curl -f ${origin}/r | sh -s ${code}`;
      shareWget.textContent = `wget -O- ${origin}/r | sh -s ${code}`;
      sharePowershell.textContent = `& ([scriptblock]::Create((irm ${origin}/ps/r))) '${code}'`;
      shareCli.textContent = `sp2p receive -server ${origin} ${code}`;
      shareAgent.textContent = `AI Agent: Please receive file session ${code} using ${origin}/llm`;
      show(shareDisplay);

      // Wire up QR button.
      const shareUrlText = `${origin}/r#${code}`;
      const qrBtn = shareDisplay.querySelector(".qr-btn");
      if (qrBtn) {
        qrBtn.addEventListener("click", () => showQRModal(shareUrlText));
      }

      // Step 4: Wait for receiver.
      setStepStatus($(".step-wait"), "active");
      statusText.textContent = "Waiting for receiver...";
      await sigClient.waitFor("peer-joined", 300000);
      statusText.textContent = "Exchanging encryption keys...";
      closeQRModal();
      setStepStatus($(".step-wait"), "done");

      // Step 5: Key exchange.
      // Pre-subscribe to "crypto" BEFORE generating keys so we don't miss
      // the receiver's message if it arrives during key generation.
      setStepStatus($(".step-crypto"), "active");
      const cryptoPromise = waitForWithErrors(sigClient, "crypto");
      log("generating X25519 key pair");
      const kp = await generateKeyPair();
      const myPub = await exportTransferPublicKey(kp.publicKey);
      sigClient.send("crypto", { publicKey: bytesToBase64(myPub) });

      const cryptoMsg = await cryptoPromise;
      const peerPub = base64ToBytes(cryptoMsg.payload.publicKey);
      const protocol = transferProtocol(myPub, peerPub);
      const peerKey = await importPublicKey(peerPub);

      log("public keys exchanged, deriving session keys");
      const keys = await deriveKeys(
        kp.privateKey,
        peerKey,
        seedRaw,
        sessionId,
        myPub,
        peerPub
      );
      setStepStatus($(".step-crypto"), "done");

      // Show verification code so both sides can confirm the connection.
      const verifyEl = $(".verify-code");
      verifyEl.innerHTML = `Verify: <code>${keys.verifyCode}</code>`;
      show(verifyEl);

      // Step 6: Establish WebRTC (with automatic retry on failure).
      statusText.textContent = "";
      setStepStatus($(".step-p2p"), "active");
      const { dc, pc: peerConn } = await establishP2PWithRetry(
        sigClient,
        true,
        serverIceServers,
        serverTurnAvailable,
        () => Promise.resolve(confirm(
          "Direct P2P connection failed. Allow relaying encrypted data through the server?\n\n" +
          "Your data remains end-to-end encrypted, but the relay server will see connection metadata."
        )),
        detail => { $(".step-p2p").textContent = `Establishing P2P connection — ${detail}`; },
      );
      pc = peerConn;
      $(".step-p2p").textContent = "Establishing P2P connection — Authenticating peer";

      // Step 7: All v3 peers authenticate the candidate before key confirmation.
      log("authenticating and confirming data channel");
      const extraBuffered = await confirmDataChannel(dc, keys, myPub, peerPub, true, protocol);
      log("key confirmation successful");
      showProtocol(protocol);
      $(".step-p2p").textContent = "P2P connected via WebRTC";
      setStepStatus($(".step-p2p"), "done");

      // Step 8: Transfer file(s).
      log("establishing encrypted stream");
      setStepStatus($(".step-transfer"), "active");
      show(progressContainer);
      statusText.textContent = "Sending file...";
      shareDisplay.remove();

      const enc = new EncryptedChannel(
        keys.senderToReceiver,
        keys.receiverToSender
      );
      const transport = new DataChannelTransport(
        dc,
        enc,
        extraBuffered,
        pc.sctp?.maxMessageSize,
        protocol
      );

      // Close signaling — no longer needed after P2P + key confirmation.
      log("closing signaling connection (P2P established)");
      sigClient.close();

      // Start heartbeat for peer liveness detection over P2P.
      transport.startHeartbeat(() => pc?.close());
      const stopDiagnostics = monitorTransfer(pc, transport, relay => {
        $(".step-p2p").textContent = relay ? "Connected via WebRTC (TURN relay)" : "P2P connected via WebRTC (direct)";
      });

      // Best-effort cancel on tab close.
      const onBeforeUnload = () => { transport.sendCancel(); };
      window.addEventListener("beforeunload", onBeforeUnload);

      const startTime = Date.now();
      let sentBytes: number;

      log(`starting transfer: ${transferName} (${formatBytes(transferSize)})`);
      try {
        if (isSingleFile) {
          await sendFile(transport, file, (bytesSent) => {
            updateProgress(progressBar, progressInfo, bytesSent, file.size, startTime);
            if (bytesSent === file.size) statusText.textContent = "Waiting for receiver to verify...";
          });
          sentBytes = file.size;
        } else {
          sentBytes = await sendFiles(
            transport,
            files,
            MULTI_FILE_ARCHIVE_NAME,
            (bytesSent) => {
              updateProgress(progressBar, progressInfo, bytesSent, transferSize, startTime);
              if (bytesSent === transferSize) statusText.textContent = "Waiting for receiver to verify...";
            },
            preparedArchive
          );
        }
      } finally {
        stopDiagnostics();
        transport.stopHeartbeat();
        window.removeEventListener("beforeunload", onBeforeUnload);
      }

      setStepStatus($(".step-transfer"), "done");
      hide(progressContainer);
      log(`transfer complete: ${formatBytes(sentBytes)} sent`);

      // Done.
      hide(stepsContainer);
      closeQRModal();
      hide(shareDisplay);
      statusText.textContent = "";
      const elapsed = (Date.now() - startTime) / 1000;
      const speed = sentBytes / elapsed;
      const desc = isSingleFile ? file.name : `${files.length} files`;
      showComplete(completeContainer, "Sent", desc, sentBytes, elapsed, speed);
      show(completeContainer);
    } catch (err) {
      statusText.textContent = "";
      showError(stepsContainer, (err as Error).message);
    } finally {
      pc?.close();
      sigClient?.close();
    }
  }
}

// ─── RECEIVE PAGE ────────────────────────────────────────────

// Fetch encrypted file-info from the server, retrying once on 404.
// The sender sets file-info immediately, so it's usually available on the
// first attempt. A single retry handles the rare race where the receiver
// opens the link before the sender's file-info message is processed.
async function fetchFileInfo(
  sessionId: string,
  seedRaw: Uint8Array
): Promise<{ name: string; size: number; isFolder: boolean; fileCount: number } | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const resp = await fetch(`/api/file-info/${sessionId}`);
      if (resp.ok) {
        const json = await resp.json();
        const encrypted = base64ToBytes(json.data);
        const plaintext = await decryptFileInfo(seedRaw, encrypted);
        return JSON.parse(new TextDecoder().decode(plaintext));
      }
      if (resp.status === 404 && attempt < 1) {
        await new Promise((r) => setTimeout(r, 500));
        continue;
      }
    } catch {
      if (attempt < 1) {
        await new Promise((r) => setTimeout(r, 500));
        continue;
      }
    }
    break;
  }
  return null;
}

async function initReceive(): Promise<void> {
  const confirmContainer = $(".confirm-transfer");
  const stepsContainer = $(".steps");
  const progressContainer = $(".progress-container");
  const progressBar = $(".progress-bar-fill");
  const progressInfo = $(".progress-info");
  const completeContainer = $(".complete");
  const statusText = $(".status-text");

  // Read code from URL fragment.
  const hash = location.hash.substring(1);
  if (!hash) {
    show(stepsContainer);
    showError(stepsContainer, "No transfer code found in URL");
    return;
  }

  // Clear the hash from URL immediately for security.
  history.replaceState(null, "", location.pathname);

  let sigClient: SignalClient | null = null;
  let pc: RTCPeerConnection | null = null;

  try {
    const { sessionId, seed: seedEncoded } = parseCode(hash);
    log(`parsed transfer code: session ${sessionId}`);
    const seedRaw = decodeSeed(seedEncoded);
    const code = `${sessionId}-${seedEncoded}`;

    // Show steps immediately so the user sees progress right away.
    show(stepsContainer);
    setStepStatus($(".step-connect"), "active");

    // Fetch preview before opening a socket: user decisions have no deadline.
    const fileInfoPromise = fetchFileInfo(sessionId, seedRaw);

    // Wait for file-info (runs in parallel with WS connect, so usually instant).
    // If available, show confirmation card BEFORE joining so the sender doesn't
    // start its crypto timer while the user is deciding.
    const fileInfo = await fileInfoPromise;
    if (fileInfo) {
      // Populate confirmation card.
      const nameEl = confirmContainer.querySelector(".confirm-file")!;
      const sizeEl = confirmContainer.querySelector(".confirm-size")!;
      nameEl.textContent = fileInfo.name;
      sizeEl.textContent = fileInfo.size ? formatBytes(fileInfo.size) : "Unknown size";
      if (fileInfo.fileCount > 0) {
        sizeEl.textContent += ` (${fileInfo.fileCount} files)`;
      }

      // Populate CLI commands.
      const origin = location.origin;
      const curlEl = confirmContainer.querySelector(".confirm-curl")!;
      const wgetEl = confirmContainer.querySelector(".confirm-wget")!;
      const psEl = confirmContainer.querySelector(".confirm-powershell")!;
      const cliEl = confirmContainer.querySelector(".confirm-cli")!;
      curlEl.textContent = `curl -f ${origin}/r | sh -s ${code}`;
      wgetEl.textContent = `wget -O- ${origin}/r | sh -s ${code}`;
      psEl.textContent = `& ([scriptblock]::Create((irm ${origin}/ps/r))) '${code}'`;
      cliEl.textContent = `sp2p receive -server ${origin} ${code}`;

      // Set up click-to-copy on confirmation copy-boxes.
      for (const box of confirmContainer.querySelectorAll<HTMLElement>(".copy-box")) {
        box.addEventListener("click", async () => {
          const codeEl = box.querySelector("code");
          if (!codeEl?.textContent) return;
          await navigator.clipboard.writeText(codeEl.textContent);
          const hint = box.querySelector(".copy-hint");
          if (hint) {
            hint.textContent = "copied!";
            box.classList.add("copied");
            setTimeout(() => {
              hint.textContent = "click to copy";
              box.classList.remove("copied");
            }, 2000);
          }
        });
      }

    }

    // Invoke the picker in the click handler itself, before transient activation
    // expires during ICE/key exchange. Even a missing preview needs a gesture.
    let saveHandle: any = null;
    if (!fileInfo) {
      confirmContainer.querySelector(".confirm-file")!.textContent = "Incoming transfer";
      confirmContainer.querySelector(".confirm-size")!.textContent = "Size unknown";
    }
    hide(stepsContainer);
    show(confirmContainer);
    const downloadButton = confirmContainer.querySelector<HTMLButtonElement>(".confirm-btn")!;
    const canStreamToDisk = "showSaveFilePicker" in window;
    downloadButton.textContent = canStreamToDisk
      ? "Choose file and save to disk"
      : "Download in browser (up to 256 MiB)";
    await new Promise<void>((resolve, reject) => {
      const choose = async () => {
        if (downloadButton.disabled) return;
        downloadButton.disabled = true;
        try {
          if (canStreamToDisk) {
            saveHandle = await (window as any).showSaveFilePicker({ suggestedName: fileInfo?.name || "received-file" });
          } else if (fileInfo && fileInfo.size > 256 * 1024 * 1024) {
            throw new Error("File exceeds the 256 MiB memory limit; choose disk streaming or use the CLI");
          }
          resolve();
        } catch (err) { reject(err); }
      };
      downloadButton.addEventListener("click", () => { void choose(); }, { once: true });
    });
    confirmContainer.remove();
    show(stepsContainer);
    sigClient = await SignalClient.connect(getWsUrl());
    setStepStatus($(".step-connect"), "done");

    // Join session and wait for welcome (or error).
    setStepStatus($(".step-join"), "active");
    sigClient.send("join", { version: PROTOCOL_VERSION, sessionId, clientType: "browser" });
    const welcomeEnv = await waitForWithErrors(sigClient, "welcome");
    const receiverIceServers: ICEServerConfig[] | undefined = welcomeEnv.payload?.iceServers;
    const receiverTurnAvailable: boolean = !!welcomeEnv.payload?.turnAvailable;
    log(`joined session: ${receiverIceServers?.length ?? 0} ICE servers, TURN available: ${receiverTurnAvailable}`);
    setStepStatus($(".step-join"), "done");

    // Key exchange.
    // Pre-subscribe to "crypto" BEFORE generating keys so we don't miss
    // the sender's message if it arrives during key generation.
    setStepStatus($(".step-crypto"), "active");
    const cryptoPromise = waitForWithErrors(sigClient, "crypto");
    log("generating X25519 key pair");
    const kp = await generateKeyPair();
    const myPub = await exportTransferPublicKey(kp.publicKey);
    sigClient.send("crypto", { publicKey: bytesToBase64(myPub) });

    const cryptoMsg = await cryptoPromise;
    const peerPub = base64ToBytes(cryptoMsg.payload.publicKey);
    const protocol = transferProtocol(peerPub, myPub);
    const peerKey = await importPublicKey(peerPub);

    log("public keys exchanged, deriving session keys");
    // Sender's pub is peerPub, receiver's pub is myPub.
    const keys = await deriveKeys(
      kp.privateKey,
      peerKey,
      seedRaw,
      sessionId,
      peerPub,
      myPub
    );
    setStepStatus($(".step-crypto"), "done");

    // Show verification code so both sides can confirm the connection.
    const verifyEl = $(".verify-code");
    verifyEl.innerHTML = `Verify: <code>${keys.verifyCode}</code>`;
    show(verifyEl);

    // Establish WebRTC (with automatic retry on failure).
    setStepStatus($(".step-p2p"), "active");
    const { dc, pc: peerConn } = await establishP2PWithRetry(
      sigClient,
      false,
      receiverIceServers,
      receiverTurnAvailable,
      () => Promise.resolve(confirm(
        "Direct P2P connection failed. Allow relaying encrypted data through the server?\n\n" +
        "Your data remains end-to-end encrypted, but the relay server will see connection metadata."
      )),
      detail => { $(".step-p2p").textContent = `Establishing P2P connection — ${detail}`; },
    );
    pc = peerConn;
    $(".step-p2p").textContent = "Establishing P2P connection — Authenticating peer";

    // All v3 peers authenticate the candidate before key confirmation.
    log("authenticating and confirming data channel");
    const extraBuffered = await confirmDataChannel(dc, keys, peerPub, myPub, false, protocol);
    log("key confirmation successful");
    showProtocol(protocol);
    $(".step-p2p").textContent = "P2P connected via WebRTC";
    setStepStatus($(".step-p2p"), "done");

    // Receive file.
    log("establishing encrypted stream");
    setStepStatus($(".step-transfer"), "active");
    show(progressContainer);
    statusText.textContent = "Receiving file...";

    const enc = new EncryptedChannel(
      keys.receiverToSender,
      keys.senderToReceiver
    );
    const transport = new DataChannelTransport(
      dc,
      enc,
      extraBuffered,
      pc.sctp?.maxMessageSize,
      protocol
    );

    // Close signaling — no longer needed after P2P + key confirmation.
    log("closing signaling connection (P2P established)");
    sigClient.close();

    // Start heartbeat for peer liveness detection over P2P.
    transport.startHeartbeat(() => pc?.close());
    const stopDiagnostics = monitorTransfer(pc, transport, relay => {
      $(".step-p2p").textContent = relay ? "Connected via WebRTC (TURN relay)" : "P2P connected via WebRTC (direct)";
    });

    // Best-effort cancel on tab close.
    const onBeforeUnload = () => { transport.sendCancel(); };
    window.addEventListener("beforeunload", onBeforeUnload);

    const startTime = Date.now();
    let totalSize = 0;
    let fileCount = 0;
    let result: { meta: any; blob: Blob | null; totalBytes: number };
    try {
      result = await receiveFile(
        transport,
        (bytesRecv, fileMeta) => {
          if (fileMeta) {
            totalSize = fileMeta.size;
            fileCount = fileMeta.fileCount || 0;
          }
          updateProgress(progressBar, progressInfo, bytesRecv, totalSize, startTime, fileCount);
        },
        async (fileMeta) => {
          if (!saveHandle) return null;
          const writable = await saveHandle.createWritable();
          return {
            write: (chunk: Uint8Array) => writable.write(chunk),
            close: () => writable.close(),
            abort: (reason?: unknown) => writable.abort(reason),
          };
        }
      );
    } finally {
      stopDiagnostics();
      transport.stopHeartbeat();
      window.removeEventListener("beforeunload", onBeforeUnload);
    }

    const { meta, blob, totalBytes: receivedBytes } = result;

    setStepStatus($(".step-transfer"), "done");
    hide(progressContainer);
    log(`transfer complete: ${formatBytes(receivedBytes)} received (${meta.name})`);

    // Download (only needed for in-memory fallback).
    if (blob) {
      downloadBlob(blob, meta.name);
    }

    hide(stepsContainer);
    statusText.textContent = "";
    const elapsed = (Date.now() - startTime) / 1000;
    const speed = receivedBytes / elapsed;
    const displayName = fileCount > 0 ? `${meta.name} (${fileCount} files)` : meta.name;
    showComplete(completeContainer, "Received", displayName, receivedBytes, elapsed, speed);
    show(completeContainer);
  } catch (err) {
    statusText.textContent = "";
    show(stepsContainer);
    showError(stepsContainer, friendlyReceiveError((err as Error).message));
  } finally {
    pc?.close();
    sigClient?.close();
  }
}

// Map raw server/protocol error messages to user-friendly text.
function friendlyReceiveError(msg: string): string {
  if (msg.includes("protocol version") || msg.includes("unsupported protocol")) {
    return "Unsupported signaling protocol. Upgrade the peer or server; transfer-version selection is automatic.";
  }
  if (msg.includes("transfer session not found")) {
    return "Transfer session not found — the link may have expired or is invalid.";
  }
  if (msg.includes("someone has already connected")) {
    return "Someone has already connected to this transfer session.";
  }
  if (msg.includes("Peer disconnected")) {
    return "Sender disconnected — the transfer was cancelled.";
  }
  return msg;
}

// Render a polished completion card.
function showComplete(
  container: HTMLElement,
  action: string,
  name: string,
  bytes: number,
  elapsed: number,
  speed: number
): void {
  container.innerHTML = "";
  const card = document.createElement("div");
  card.className = "complete-card";
  card.innerHTML =
    `<div class="complete-check">&#10003;</div>` +
    `<div class="complete-title">${action}</div>` +
    `<div class="complete-name">${escapeHtml(name)}</div>` +
    `<div class="complete-stats">` +
      `<span>${formatBytes(bytes)}</span>` +
      `<span class="complete-stats-sep">&middot;</span>` +
      `<span>${elapsed.toFixed(1)}s</span>` +
      `<span class="complete-stats-sep">&middot;</span>` +
      `<span>${formatBytes(speed)}/s</span>` +
    `</div>`;
  container.appendChild(card);
}

function escapeHtml(s: string): string {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

// Initialize the footer version link and tooltip.
function initFooterVersion(): void {
  document.querySelectorAll<HTMLElement>(".footer-version").forEach((el) => {
    const v = el.dataset.version;
    const bt = el.dataset.buildTime;
    if (!v) {
      el.remove();
      return;
    }
    if (bt) el.title = "Built " + bt;
    if (v !== "dev") {
      const tag = "v" + v.replace(/^v/, "");
      const a = document.createElement("a");
      a.href = "https://github.com/zyno-io/sp2p";
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = v;
      el.appendChild(a);
    } else {
      el.textContent = v;
    }
    const sep = document.createElement("span");
    sep.className = "footer-sep";
    sep.innerHTML = "&middot;";
    el.after(sep);
  });
}

// Initialize based on page.
document.addEventListener("DOMContentLoaded", () => {
  initFooterVersion();
  if (document.body.dataset.page === "send") {
    initSend();
  } else if (document.body.dataset.page === "receive") {
    initReceive();
  }
});

// On the receive page, reload when the hash changes so that pasting a new
// transfer-code URL (which only differs in the fragment) re-triggers the flow.
window.addEventListener("hashchange", () => {
  if (document.body.dataset.page === "receive") {
    location.reload();
  }
});
