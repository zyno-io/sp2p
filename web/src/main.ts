// SPDX-License-Identifier: MIT

// SP2P Web UI — entry point.
// Detects whether this is the send or receive page and initializes accordingly.

import { SignalClient, PROTOCOL_VERSION, Envelope } from "./signal";
import { establishWebRTC, ICEServerConfig, splitIceServers } from "./webrtc";
import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveKeys,
  generateSeed,
  decodeSeed,
  parseCode,
  EncryptedChannel,
  computeConfirmation,
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
import { showQRModal, closeQRModal } from "./qr";

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
  confirmRelay: () => Promise<boolean>
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
    return await establishWebRTC(sigClient, isSender, undefined, undefined, 15000, stun);
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
  return await establishWebRTC(sigClient, isSender, undefined, undefined, 15000, [...stun, ...turnServers]);
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

function initCliSection(): void {
  const section = document.querySelector(".cli-section");
  if (!section) return;

  const origin = location.origin;

  // Populate bootstrap send commands.
  const curlEl = section.querySelector(".send-curl");
  const wgetEl = section.querySelector(".send-wget");
  const psEl = section.querySelector(".send-powershell");
  if (curlEl) {
    curlEl.textContent = `curl -f ${origin} | sh -s <file>`;
    (curlEl as HTMLElement).dataset.copyText = `curl -f ${origin} | sh -s `;
  }
  if (wgetEl) {
    wgetEl.textContent = `wget -O- ${origin} | sh -s <file>`;
    (wgetEl as HTMLElement).dataset.copyText = `wget -O- ${origin} | sh -s `;
  }
  if (psEl) {
    psEl.textContent = `& ([scriptblock]::Create((irm ${origin}/ps))) '<file>'`;
    (psEl as HTMLElement).dataset.copyText = `& ([scriptblock]::Create((irm ${origin}/ps))) '`;
  }

  // Set platform-specific download link (lives in its own section).
  const { os, arch, label } = detectPlatform();
  const downloadBtn = document.querySelector(".download-btn") as HTMLAnchorElement | null;
  const platformLabel = document.querySelector(".download-platform");
  if (downloadBtn) downloadBtn.href = `/dl/${os}/${arch}`;
  if (platformLabel) platformLabel.textContent = `for ${label}`;
}

// ─── SEND PAGE ───────────────────────────────────────────────

async function initSend(): Promise<void> {
  initCliSection();

  const dropZone = $(".drop-zone");
  const cliSection = $(".cli-section");
  const downloadSection = $(".download-section");
  const fileInput = $(".file-input") as HTMLInputElement;
  const shareDisplay = $(".share-display");
  const shareUrl = $(".share-url");
  const shareCurl = $(".share-curl");
  const shareWget = $(".share-wget");
  const sharePowershell = $(".share-powershell");
  const shareCli = $(".share-cli");

  // Click-to-copy on share boxes.
  for (const box of document.querySelectorAll<HTMLElement>(".copy-box")) {
    box.addEventListener("click", async () => {
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
    });
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
    const totalSize = files.reduce((sum, f) => sum + f.size, 0);
    hide(dropZone);
    hide(cliSection);
    hide(downloadSection);
    show(stepsContainer);

    let sigClient: SignalClient | null = null;
    let pc: RTCPeerConnection | null = null;

    try {
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
          name: isSingleFile ? file.name : `${files.length} files`,
          size: totalSize,
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
      shareCli.textContent = `sp2p receive ${code}`;
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
      closeQRModal();
      setStepStatus($(".step-wait"), "done");

      // Step 5: Key exchange.
      // Pre-subscribe to "crypto" BEFORE generating keys so we don't miss
      // the receiver's message if it arrives during key generation.
      setStepStatus($(".step-crypto"), "active");
      const cryptoPromise = waitForWithErrors(sigClient, "crypto");
      log("generating X25519 key pair");
      const kp = await generateKeyPair();
      const myPub = await exportPublicKey(kp.publicKey);
      sigClient.send("crypto", { publicKey: bytesToBase64(myPub) });

      const cryptoMsg = await cryptoPromise;
      const peerPub = base64ToBytes(cryptoMsg.payload.publicKey);
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
      setStepStatus($(".step-p2p"), "active");
      const { dc, pc: peerConn } = await establishP2PWithRetry(
        sigClient,
        true,
        serverIceServers,
        serverTurnAvailable,
        () => Promise.resolve(confirm(
          "Direct P2P connection failed. Allow relaying encrypted data through the server?\n\n" +
          "Your data remains end-to-end encrypted, but the relay server will see connection metadata."
        ))
      );
      pc = peerConn;
      $(".step-p2p").textContent = "P2P connected via WebRTC";
      setStepStatus($(".step-p2p"), "done");

      // Step 7: Key confirmation over DataChannel.
      log("performing key confirmation over data channel");
      const myConfirm = await computeConfirmation(
        keys.confirm,
        "sender",
        myPub,
        peerPub
      );
      dc.send(myConfirm);

      // Read peer's confirmation, buffering any extra messages.
      const extraBuffered: Uint8Array[] = [];
      const peerConfirmData = await new Promise<ArrayBuffer>((resolve, reject) => {
        let resolved = false;
        const timer = setTimeout(() => {
          if (!resolved) { resolved = true; reject(new Error("Key confirmation timed out")); }
        }, 15000);
        dc.onclose = () => {
          if (!resolved) { resolved = true; clearTimeout(timer); reject(new Error("Connection closed during key confirmation")); }
        };
        dc.onmessage = (event) => {
          if (!resolved) {
            resolved = true;
            clearTimeout(timer);
            resolve(event.data);
          } else {
            extraBuffered.push(new Uint8Array(event.data));
          }
        };
      });
      const peerConfirm = new Uint8Array(peerConfirmData);
      const expectedPeerConfirm = await computeConfirmation(
        keys.confirm,
        "receiver",
        myPub,
        peerPub
      );
      if (!constantTimeEqual(peerConfirm, expectedPeerConfirm)) {
        throw new Error("Key confirmation failed");
      }
      log("key confirmation successful");

      // Step 8: Transfer file(s).
      log("establishing encrypted stream");
      setStepStatus($(".step-transfer"), "active");
      show(progressContainer);

      const enc = new EncryptedChannel(
        keys.senderToReceiver,
        keys.receiverToSender
      );
      const transport = new DataChannelTransport(dc, enc, extraBuffered);

      // Close signaling — no longer needed after P2P + key confirmation.
      log("closing signaling connection (P2P established)");
      sigClient.close();

      // Start heartbeat for peer liveness detection over P2P.
      transport.startHeartbeat(() => pc?.close());

      // Best-effort cancel on tab close.
      const onBeforeUnload = () => { transport.sendCancel(); };
      window.addEventListener("beforeunload", onBeforeUnload);

      const startTime = Date.now();
      let sentBytes: number;

      log(`starting transfer: ${isSingleFile ? file.name : files.length + " files"} (${formatBytes(totalSize)})`);
      try {
        if (isSingleFile) {
          await sendFile(transport, file, (bytesSent) => {
            updateProgress(progressBar, progressInfo, bytesSent, file.size, startTime);
          });
          sentBytes = file.size;
        } else {
          sentBytes = await sendFiles(transport, files, "sp2p-received-folder.tgz", (bytesSent) => {
            updateProgress(progressBar, progressInfo, bytesSent, totalSize, startTime);
          });
        }
      } finally {
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

    // Start file-info fetch in parallel with the WebSocket connection.
    const fileInfoPromise = fetchFileInfo(sessionId, seedRaw);

    // Connect to signaling server.
    sigClient = await SignalClient.connect(getWsUrl());
    setStepStatus($(".step-connect"), "done");

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
      cliEl.textContent = `sp2p receive ${code}`;

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

      // Show confirmation card and wait for user to click download.
      hide(stepsContainer);
      show(confirmContainer);
      await new Promise<void>((resolve) => {
        confirmContainer.querySelector(".confirm-btn")!.addEventListener("click", () => resolve(), { once: true });
      });
      hide(confirmContainer);
      show(stepsContainer);
    }

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
    const myPub = await exportPublicKey(kp.publicKey);
    sigClient.send("crypto", { publicKey: bytesToBase64(myPub) });

    const cryptoMsg = await cryptoPromise;
    const peerPub = base64ToBytes(cryptoMsg.payload.publicKey);
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
      ))
    );
    pc = peerConn;
    $(".step-p2p").textContent = "P2P connected via WebRTC";
    setStepStatus($(".step-p2p"), "done");

    // Key confirmation.
    log("performing key confirmation over data channel");
    const myConfirm = await computeConfirmation(
      keys.confirm,
      "receiver",
      peerPub,
      myPub
    );
    dc.send(myConfirm);

    const extraBuffered: Uint8Array[] = [];
    const peerConfirmData = await new Promise<ArrayBuffer>((resolve, reject) => {
      let resolved = false;
      const timer = setTimeout(() => {
        if (!resolved) { resolved = true; reject(new Error("Key confirmation timed out")); }
      }, 15000);
      dc.onclose = () => {
        if (!resolved) { resolved = true; clearTimeout(timer); reject(new Error("Connection closed during key confirmation")); }
      };
      dc.onmessage = (event) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          resolve(event.data);
        } else {
          extraBuffered.push(new Uint8Array(event.data));
        }
      };
    });
    const peerConfirm = new Uint8Array(peerConfirmData);
    const expectedPeerConfirm = await computeConfirmation(
      keys.confirm,
      "sender",
      peerPub,
      myPub
    );
    if (!constantTimeEqual(peerConfirm, expectedPeerConfirm)) {
      throw new Error("Key confirmation failed");
    }
    log("key confirmation successful");

    // Receive file.
    log("establishing encrypted stream");
    setStepStatus($(".step-transfer"), "active");
    show(progressContainer);
    statusText.textContent = "Receiving file...";

    const enc = new EncryptedChannel(
      keys.receiverToSender,
      keys.senderToReceiver
    );
    const transport = new DataChannelTransport(dc, enc, extraBuffered);

    // Close signaling — no longer needed after P2P + key confirmation.
    log("closing signaling connection (P2P established)");
    sigClient.close();

    // Start heartbeat for peer liveness detection over P2P.
    transport.startHeartbeat(() => pc?.close());

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
          // Try File System Access API for streaming large files to disk.
          if (!("showSaveFilePicker" in window)) return null;
          try {
            const handle = await (window as any).showSaveFilePicker({
              suggestedName: fileMeta.name,
            });
            const writable = await handle.createWritable();
            return {
              write: (chunk: Uint8Array) => writable.write(chunk),
              close: () => writable.close(),
            };
          } catch {
            return null; // user cancelled or API blocked — fall back to in-memory
          }
        }
      );
    } finally {
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

// Constant-time comparison.
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
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
