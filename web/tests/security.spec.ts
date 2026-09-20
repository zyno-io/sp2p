// SPDX-License-Identifier: MIT

import { test, expect } from "@playwright/test";
import { decompressChunk } from "../src/bounded-zstd";
import { createTar } from "../src/tar";
import { DataChannelTransport, receiveFile, sendFile, sendFiles, MSG_METADATA, MSG_DATA, MSG_DONE, MSG_COMPLETE, MSG_FINACK } from "../src/transfer";
import { createHash } from "node:crypto";

test("zstd is bounded before window allocation and across output blocks", () => {
  const raw = new Uint8Array([0x28,0xb5,0x2f,0xfd,0x20,3,25,0,0,97,98,99]);
  expect(new TextDecoder().decode(decompressChunk(raw,256*1024))).toBe("abc");
  const huge = new Uint8Array([0x28,0xb5,0x2f,0xfd,0xe0,0,0,0,0,2,0,0,0,1,0,0]);
  expect(() => decompressChunk(huge,256*1024)).toThrow();
  const window = new Uint8Array([0x28,0xb5,0x2f,0xfd,0,255,1,0,0]);
  expect(() => decompressChunk(window,256*1024)).toThrow();
  expect(() => decompressChunk(new Uint8Array([...raw,...raw]),256*1024)).toThrow();
  expect(() => decompressChunk(raw,2)).toThrow();
});

test("TAR preserves long Unicode names with PAX and advertises exact bytes", async () => {
  const name = "é".repeat(100)+".txt";
  const tar = createTar([new File(["abc"],name)]);
  const chunks: Uint8Array[] = [];
  for await (const item of tar.stream()) chunks.push(item.chunk);
  expect(chunks.reduce((n,c)=>n+c.length,0)).toBe(tar.totalSize);
  expect(new TextDecoder().decode(chunks[1])).toContain(`path=${name}\n`);
  expect(() => createTar([new File([],"../escape")])).toThrow();
  expect(() => createTar([new File([],"same"),new File([],"same")])).toThrow();
});

for (const failure of ["hash","write","close","none"]) {
  test(`receive output lifecycle: ${failure}`, async () => {
    const bytes = new TextEncoder().encode("abc");
    const hash = createHash("sha256").update(bytes).digest("hex");
    const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
    const frames = [
      {msgType:MSG_METADATA,data:json({name:"file",size:3,type:"text/plain"})},
      {msgType:MSG_DATA,data:bytes},
      {msgType:MSG_DONE,data:json({totalBytes:3,chunkCount:1,sha256:failure==="hash"?"bad":hash})},
      {msgType:MSG_FINACK,data:new Uint8Array()},
    ];
    const events: string[] = [];
    const transport = {readFrame:async()=>frames.shift()!,consumeData:async()=>{},sendError:async()=>{},sendComplete:async()=>{events.push("complete");}} as any;
    const writer = {
      write:async()=>{events.push("write");if(failure==="write")throw new Error("write failed");},
      close:async()=>{events.push("close");if(failure==="close")throw new Error("close failed");},
      abort:async()=>{events.push("abort");},
    };
    const result = receiveFile(transport,undefined,async()=>writer);
    if(failure==="none") { await result; expect(events).toEqual(["write","close","complete"]); }
    else { await expect(result).rejects.toThrow(); expect(events).toContain("abort"); expect(events).not.toContain("complete"); if(failure!=="close")expect(events).not.toContain("close"); }
  });
}

test("single-file sending never reads the entire File", async () => {
  const file = new File([new Uint8Array(1024*1024)],"large.bin");
  file.arrayBuffer = async()=>{throw new Error("whole-file read");};
  let done: any;
  let chunks = 0;
  const transport = {sendMetadata:async()=>{},sendData:async(data:Uint8Array)=>{expect(data.length).toBeLessThanOrEqual(256*1024);chunks++;},
    sendDone:async(totalBytes:number,chunkCount:number,sha256:string)=>{done={totalBytes,chunkCount,sha256};},
    readFrame:async()=>({msgType:MSG_COMPLETE,data:new TextEncoder().encode(JSON.stringify(done))}),sendFrame:async()=>{}} as any;
  await sendFile(transport,file);
  expect(chunks).toBe(4);
});

test("browser TAR sends exact metadata as a bounded transfer", async () => {
  const files = [new File(["abc"], "a.txt"), new File(["defg"], "b.txt")];
  const archive = createTar(files);
  let metadata: any;
  let done: any;
  const transport = {
    sendMetadata: async (value: any) => { metadata = value; },
    sendData: async () => {},
    sendDone: async (totalBytes: number, chunkCount: number, sha256: string) => {
      done = { totalBytes, chunkCount, sha256 };
    },
    readFrame: async () => ({ msgType: MSG_COMPLETE, data: new TextEncoder().encode(JSON.stringify(done)) }),
    sendFrame: async () => {},
  } as any;

  const sentBytes = await sendFiles(transport, files, "bundle.tar", undefined, archive);

  expect(metadata).toMatchObject({ name: "bundle.tar", size: archive.totalSize, streamMode: false });
  expect(sentBytes).toBe(archive.totalSize);
});

for (const testCase of [
  { name: "v2 folder archive accepts an understated legacy TAR size", protocol: 2, isFolder: true, succeeds: true },
  { name: "v3 folder archive requires an exact declared size", protocol: 3, isFolder: true, succeeds: false },
  { name: "v2 regular file requires an exact declared size", protocol: 2, isFolder: false, succeeds: false },
] as const) {
  test(testCase.name, async () => {
    const bytes = new TextEncoder().encode("legacy PAX bytes");
    const hash = createHash("sha256").update(bytes).digest("hex");
    const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
    const frames = [
      { msgType: MSG_METADATA, data: json({ name: "archive", size: 1, type: "", isFolder: testCase.isFolder, streamMode: false }) },
      { msgType: MSG_DATA, data: bytes },
      { msgType: MSG_DONE, data: json({ totalBytes: bytes.length, chunkCount: 1, sha256: hash }) },
      { msgType: MSG_FINACK, data: new Uint8Array() },
    ];
    const transport = {
      protocolVersion: testCase.protocol,
      readFrame: async () => frames.shift()!,
      consumeData: async () => {},
      sendComplete: async () => {},
      sendError: async () => {},
    } as any;

    const receiving = receiveFile(transport);
    if (testCase.succeeds) {
      const result = await receiving;
      expect(result.totalBytes).toBe(bytes.length);
      const text = await result.blob?.text();
      expect(text).toBe("legacy PAX bytes");
    } else {
      await expect(receiving).rejects.toThrow("declared size");
    }
  });
}

for (const testCase of [
  { name: "byte count", totalBytes: 1, chunkCount: 1, sha256: "valid", error: "Verification mismatch" },
  { name: "chunk count", totalBytes: 16, chunkCount: 2, sha256: "valid", error: "Verification mismatch" },
  { name: "checksum", totalBytes: 16, chunkCount: 1, sha256: "0".repeat(64), error: "Integrity check failed" },
] as const) {
  test(`v2 legacy archive rejects invalid final ${testCase.name}`, async () => {
    const bytes = new TextEncoder().encode("legacy PAX bytes");
    const validHash = createHash("sha256").update(bytes).digest("hex");
    const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
    const frames = [
      { msgType: MSG_METADATA, data: json({ name: "archive", size: 1, type: "", isFolder: true, streamMode: false }) },
      { msgType: MSG_DATA, data: bytes },
      { msgType: MSG_DONE, data: json({
        totalBytes: testCase.totalBytes,
        chunkCount: testCase.chunkCount,
        sha256: testCase.sha256 === "valid" ? validHash : testCase.sha256,
      }) },
    ];
    let completed = false;
    let closed = false;
    let aborted = false;
    let errors = 0;
    const transport = {
      protocolVersion: 2,
      readFrame: async () => frames.shift()!,
      consumeData: async () => {},
      sendComplete: async () => { completed = true; },
      sendError: async () => { errors++; },
    } as any;
    const writer = {
      write: async () => {},
      close: async () => { closed = true; },
      abort: async () => { aborted = true; },
    };

    const receiving = receiveFile(transport, undefined, async () => writer);
    await expect(receiving).rejects.toThrow(testCase.error);
    expect(completed).toBe(false);
    expect(closed).toBe(false);
    expect(aborted).toBe(true);
    expect(errors).toBe(1);
  });
}

test("picker cancellation uses live activation and never opens signaling", async ({page}) => {
  let sockets = 0;
  page.on("websocket",()=>{sockets++;});
  await page.addInitScript(()=>{
    (window as any).showSaveFilePicker = () => {
      (window as any).__pickerActivated = navigator.userActivation.isActive;
      return Promise.reject(new DOMException("Cancelled by test", "AbortError"));
    };
  });
  await page.goto("/r#abcdefgh-1");
  const button = page.getByRole("button",{name:"Choose file and save to disk"});
  await expect(button).toBeVisible();
  expect(sockets).toBe(0);
  await button.click();
  await expect(page.locator(".error-message")).toBeVisible();
  const activated = await page.evaluate(()=>(window as any).__pickerActivated);
  expect(activated).toBe(true);
  expect(sockets).toBe(0);
});

test("hostile initial queue closes once and releases pending input", async () => {
  let closes = 0;
  const dc = {close:()=>{closes++;},readyState:"open",bufferedAmount:0} as any;
  const frame = new Uint8Array(29);
  new DataView(frame.buffer).setUint32(0,25);
  const transport = new DataChannelTransport(dc, {} as any, Array.from({length:300},()=>frame));
  await expect(transport.readFrame()).rejects.toThrow("capacity");
  expect(closes).toBe(1);
  expect((transport as any).recvQueue.length).toBe(0);
  expect((transport as any).recvBuffer.length).toBe(0);
});
