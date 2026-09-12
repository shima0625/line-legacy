import dgram from "node:dgram";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  buildRtp,
  buildSdp,
  buildSip,
  cryptoAttr,
  deriveSrtpContext,
  opusCodecFactory,
  parseSdp,
  parseRtp,
  parseSip,
  PlanetTransport,
  readCrypto,
  readRtpmap,
  srtpDecrypt,
  srtpEncrypt,
} from "@evex/linejs/call";
import { createClient, safeError } from "./common.mjs";
import { Eas1Helper } from "./eas1_helper.mjs";

const bindHost = process.env.LINE_LEGACY_CALL_BIND ?? "0.0.0.0";
const bindPort = Number(process.env.LINE_LEGACY_CALL_PORT ?? 19000);
const publicHost = process.env.LINE_LEGACY_CALL_HOST ?? "127.0.0.1";
const answerWaitMs = Number(process.env.LINE_LEGACY_CALL_ANSWER_WAIT_MS ?? 60000);
const mediaPort = Number(process.env.LINE_LEGACY_CALL_MEDIA_PORT ?? 20000);
const legacyUplinkGain = Math.max(0.1, Math.min(1,
  Number(process.env.LINE_LEGACY_UPLINK_GAIN ?? 0.65)));
const stateDir = process.env.LINEJS_BRIDGE_DIR ?? "/opt/line-legacy/linejs-bridge";
const eas1SocketPath = process.env.LINE_LEGACY_EAS1_SOCKET ?? "/run/line-eas1/eas1.sock";
const deviceIdPath = path.join(stateDir, "call-device-id.txt");
// 発信通話の結果置き場。local_worker が追尾して旧アプリのトークへ流す。
const callLogPath = process.env.LINE_LEGACY_CALL_LOG
  ?? path.join(stateDir, "..", "call_log_out.jsonl");
const nonce = crypto.randomBytes(16).toString("hex");
const socket = dgram.createSocket("udp4");
let active = null;
// 旧端末の最新の登録。着信時にここへ INVITE を投げて鳴らす。
let registration = null;
let registrationLogged = false;
// 鳴らしテスト中のダイアログ。着信の本実装が入るまでの暫定。
let ringing = null;
// 次に成功する着信用 REGISTER の直後に INVITE を送る。
let ringArmed = false;
const eas1Helper = new Eas1Helper(eas1SocketPath);

function loadOrCreateCallDeviceId() {
  try {
    const saved = fs.readFileSync(deviceIdPath, "utf8").trim();
    if (/^[A-Za-z0-9+/]{43}=$/.test(saved)) return saved;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const created = crypto.randomBytes(32).toString("base64");
  fs.writeFileSync(deviceIdPath, `${created}\n`, { mode: 0o600, flag: "wx" });
  return created;
}

const callDeviceId = loadOrCreateCallDeviceId();

function log(message) {
  console.log(`${new Date().toISOString()} ${message}`);
}

function capturePcm16(target, samples, maxSamples) {
  if (target.samples >= maxSamples) return;
  const remaining = maxSamples - target.samples;
  const copy = new Int16Array(samples.subarray(0, remaining));
  target.chunks.push(copy);
  target.samples += copy.length;
}

function writeWav16Mono(filePath, chunks, sampleRate = 16000) {
  const sampleCount = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const dataBytes = sampleCount * 2;
  const wav = Buffer.alloc(44 + dataBytes);
  wav.write("RIFF", 0, "ascii");
  wav.writeUInt32LE(36 + dataBytes, 4);
  wav.write("WAVEfmt ", 8, "ascii");
  wav.writeUInt32LE(16, 16);
  wav.writeUInt16LE(1, 20);
  wav.writeUInt16LE(1, 22);
  wav.writeUInt32LE(sampleRate, 24);
  wav.writeUInt32LE(sampleRate * 2, 28);
  wav.writeUInt16LE(2, 32);
  wav.writeUInt16LE(16, 34);
  wav.write("data", 36, "ascii");
  wav.writeUInt32LE(dataBytes, 40);
  let offset = 44;
  for (const chunk of chunks) {
    for (const sample of chunk) {
      wav.writeInt16LE(sample, offset);
      offset += 2;
    }
  }
  fs.writeFileSync(filePath, wav);
}

function finishAudioCapture(call, reason) {
  const capture = call.audioCapture;
  if (!capture || capture.finished) return;
  capture.finished = true;
  try {
    const roundtrip = { chunks: [], samples: 0 };
    const decoder = capture.codecs.newDecoder({ sampleRate: 48000, channels: 1 });
    try {
      for (const packet of capture.opusPackets) {
        const frame = decoder.decode(packet);
        if (!frame) continue;
        capturePcm16(roundtrip, resampleLinear(frame.samples, frame.sampleRate, 16000), capture.maxSamples);
      }
    } finally {
      try { decoder.close?.(); } catch { /* */ }
    }
    writeWav16Mono(`${capture.prefix}.01-eas1-decoded.wav`, capture.legacy.chunks);
    writeWav16Mono(`${capture.prefix}.02-opus-roundtrip.wav`, roundtrip.chunks);
    writeWav16Mono(`${capture.prefix}.03-planet-downlink.wav`, capture.planet.chunks);
    fs.writeFileSync(`${capture.prefix}.timing.json`, JSON.stringify({
      reason,
      uplink: capture.uplinkTiming,
      downlink: capture.downlinkTiming,
    }, null, 2));
    log(`audio diagnostic saved prefix=${capture.prefix} `
      + `eas1Samples=${capture.legacy.samples} opusPackets=${capture.opusPackets.length} `
      + `planetSamples=${capture.planet.samples}`);
  } catch (error) {
    log(`audio diagnostic save failed: ${safeError(error)}`);
  }
}

function header(message, name) {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(message.headers ?? {})) {
    if (key.toLowerCase() === wanted) return value;
  }
  return "";
}

function sendWire(wire, peer) {
  return new Promise((resolve, reject) => {
    socket.send(wire, peer.port, peer.address, (error) => error ? reject(error) : resolve());
  });
}

async function respond(request, peer, code, reason, extraHeaders = {}, body = "") {
  const to = header(request, "To");
  const headers = {
    Via: header(request, "Via"),
    From: header(request, "From"),
    To: code >= 180 && !/;tag=/i.test(to) ? `${to};tag=legacybridge` : to,
    "Call-ID": header(request, "Call-ID"),
    CSeq: header(request, "CSeq"),
    Server: "LINE-Legacy-Bridge/1",
    ...extraHeaders,
    "Content-Length": String(Buffer.byteLength(body)),
  };
  await sendWire(buildSip({ startLine: `SIP/2.0 ${code} ${reason}`, headers, body }), peer);
}

function summarizeInvite(message) {
  try {
    const session = parseSdp(message.body ?? "");
    const audio = session.media.find((entry) => entry.type === "audio");
    if (!audio) return "audio=none";
    const codecs = readRtpmap(audio)
      .map((entry) => `${entry.name}/${entry.rate}`)
      .slice(0, 8)
      .join(",") || audio.formats.slice(0, 8).join(",");
    const cryptoEntries = readCrypto(audio);
    return `audio=${audio.proto}:${audio.port} formats=${audio.formats.slice(0, 12).join(",")} ` +
      `codecs=${codecs || "unknown"} ` +
      `sdes=${cryptoEntries.length > 0 ? "yes" : "no"}`;
  } catch (error) {
    return `sdp=parse-failed(${safeError(error)})`;
  }
}

// 旧アプリは発信時に通話履歴メッセージを作らない(現行LINEは発信側の端末が
// contentType=6 のメッセージを自分で送る)。ここで結果を書き出し、
// local_worker が旧アプリのトークへ流し込む。
function recordOutgoingCall(call, reason) {
  if (!call?.outgoingTarget) return;
  if (call.callLogWritten) return;
  call.callLogWritten = true;
  try {
    const endedAt = Date.now();
    const connectedAt = call.connectedAt ?? null;
    const duration = connectedAt ? Math.max(0, endedAt - connectedAt) : 0;
    const result = connectedAt ? "NORMAL"
      : /no-answer|timeout/i.test(String(reason)) ? "NO_RESPONSE"
      : "CANCELED";
    fs.appendFileSync(callLogPath, JSON.stringify({
      peer: call.outgoingTarget,
      startedAt: call.startedAt ?? endedAt,
      connectedAt,
      endedAt,
      durationMs: duration,
      result,
      reason: String(reason ?? ""),
    }) + "\n");
    log(`call log recorded result=${result} duration=${duration}ms`);
  } catch (error) {
    log(`call log write failed: ${safeError(error)}`);
  }
}

async function closeActive(reason) {
  const call = active;
  active = null;
  if (!call) return;
  recordOutgoingCall(call, reason);
  call.cancelled = true;
  if (call.legacySilenceTimer) clearInterval(call.legacySilenceTimer);
  if (call.legacyStatsTimer) clearInterval(call.legacyStatsTimer);
  logEas1Summary(call, reason);
  finishAudioCapture(call, reason);
  for (const codec of [call.encoder, call.decoder]) {
    try { codec?.close?.(); } catch { /* */ }
  }
  if (call.mediaSocket) {
    await new Promise((resolve) => {
      try { call.mediaSocket.close(resolve); } catch { resolve(); }
    });
  }
  try {
    await call.planet?.close();
  } catch {
    // The PLANET dialog may not have reached SETUP yet.
  }
  log(`call closed reason=${reason}`);
}

async function handlePlanetRelease(transport, release = {}) {
  const call = active;
  if (!call || call.planet !== transport || call.planetReleaseHandled) return;
  call.planetReleaseHandled = true;
  log(`PLANET peer released call relCode=${release.relCode ?? "none"} `
    + `releaser=${release.releaser ?? "none"}`);
  try {
    await call.endLegacy?.("planet-rel");
  } finally {
    await closeActive("planet-rel");
  }
}

async function endOutgoingLegacy(call, reason) {
  if (call.legacyByeSent || !call.request) return;
  call.legacyByeSent = true;
  const request = call.request;
  const requestTo = header(request, "To");
  const taggedFrom = /;tag=/i.test(requestTo) ? requestTo : `${requestTo};tag=legacybridge`;
  const inviteSeq = Number(String(header(request, "CSeq")).split(/\s+/)[0]) || 1;
  const requestTarget = String(request.startLine ?? "").split(/\s+/)[1];
  const target = contactUri(header(request, "Contact")) || requestTarget;
  const headers = {
    Via: `SIP/2.0/UDP ${publicHost}:${bindPort};rport;branch=z9hG4bK${crypto.randomBytes(12).toString("base64url")}`,
    "Max-Forwards": "70",
    From: taggedFrom,
    To: header(request, "From"),
    "Call-ID": header(request, "Call-ID"),
    Contact: `<sip:linebridge@${publicHost}:${bindPort}>`,
    CSeq: `${inviteSeq + 1} BYE`,
    "User-Agent": "IOS;iPhone4,1;WIFI",
    "Content-Length": "0",
  };
  await sendWire(buildSip({ startLine: `BYE ${target} SIP/2.0`, headers, body: "" }), call.peer);
  log(`legacy BYE sent reason=${reason}`);
}

function selectLegacyCodec(audio) {
  const offered = new Set(audio.formats.map(String));
  if (offered.has("0")) return { name: "PCMU", payloadType: 0, rate: 8000, diagnostic: false };
  if (offered.has("8")) return { name: "PCMA", payloadType: 8, rate: 8000, diagnostic: false };
  const eas1 = readRtpmap(audio).find((entry) =>
    offered.has(String(entry.pt)) && entry.name.toLowerCase() === "eas1" && entry.rate === 16000
  );
  if (eas1) {
    return {
      name: eas1.name,
      payloadType: eas1.pt,
      rate: eas1.rate,
      diagnostic: false,
      eas1: true,
    };
  }
  return null;
}

// PLANETの音声ペイロードは先頭1バイトがヘッダだが、値は0x00/0x10だけではない。
// 決め打ちで判定すると未知の値でOpusデコードが例外になるため、剥がした形と
// そのままの形を順に試し、どちらも駄目ならnullを返して呼び出し側で数える。
function decodePlanetOpus(call, payload) {
  const forms = payload.length > 1 ? [payload.subarray(1), payload] : [payload];
  for (const form of forms) {
    try {
      const frame = call.decoder.decode(form);
      if (frame) return frame;
    } catch { /* 次の形を試す */ }
  }
  return null;
}

function logEas1Summary(call, reason, final = true) {
  const stats = call.eas1Stats;
  if (!stats || stats.summaryLogged) return;
  if (final) stats.summaryLogged = true;
  const elapsedMs = stats.firstAt === null ? 0 : Math.max(0, (stats.lastAt ?? stats.firstAt) - stats.firstAt);
  const sizes = [...stats.sizes.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([size, count]) => `${size}:${count}`)
    .join(",") || "none";
  const timestampSteps = [...stats.timestampSteps.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([step, count]) => `${step}:${count}`)
    .join(",") || "none";
  log(`eas1 diagnostic summary reason=${reason} packets=${stats.packets} elapsedMs=${elapsedMs} ` +
    `seqGaps=${stats.seqGaps} markers=${stats.markers} sizes=${sizes} timestampSteps=${timestampSteps}`);
}

function readWireU16(bytes, offset) {
  return ((bytes[offset] << 8) | bytes[offset + 1]) >>> 0;
}

function readWireU32(bytes, offset) {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function probeSrtpAuthentication(context, wire) {
  const matches = [];
  const authKey = Buffer.from(context.authKey);
  for (const tagLength of [10, 4]) {
    if (wire.length <= 12 + tagLength) continue;
    const body = wire.subarray(0, wire.length - tagLength);
    const actual = wire.subarray(wire.length - tagLength);
    for (const roc of [0, 1, 0xffffffff]) {
      const rocBe = Buffer.alloc(4);
      rocBe.writeUInt32BE(roc >>> 0);
      const rocLe = Buffer.alloc(4);
      rocLe.writeUInt32LE(roc >>> 0);
      for (const [mode, suffix] of [["be", rocBe], ["le", rocLe], ["none", null]]) {
        const hmac = crypto.createHmac("sha1", authKey);
        hmac.update(body);
        if (suffix) hmac.update(suffix);
        const expected = hmac.digest().subarray(0, tagLength);
        if (actual.length === expected.length && crypto.timingSafeEqual(actual, expected)) {
          matches.push(`sha1-${tagLength * 8}/roc-${mode}-${roc >>> 0}`);
        }
      }
    }
  }
  return matches;
}

function decodePcmu(byte) {
  const u = (~byte) & 0xff;
  const sign = u & 0x80;
  const exponent = (u >>> 4) & 0x07;
  const mantissa = u & 0x0f;
  let sample = ((mantissa << 3) + 0x84) << exponent;
  sample -= 0x84;
  return sign ? -sample : sample;
}

function encodePcmu(sample) {
  let pcm = Math.max(-32768, Math.min(32767, sample | 0));
  const sign = pcm < 0 ? 0x80 : 0;
  if (pcm < 0) pcm = -pcm;
  pcm = Math.min(32635, pcm + 0x84);
  let exponent = 7;
  for (let mask = 0x4000; exponent > 0 && !(pcm & mask); mask >>>= 1) exponent--;
  const mantissa = (pcm >>> (exponent + 3)) & 0x0f;
  return (~(sign | (exponent << 4) | mantissa)) & 0xff;
}

function decodePcma(byte) {
  const a = byte ^ 0x55;
  let sample = (a & 0x0f) << 4;
  const exponent = (a & 0x70) >>> 4;
  if (exponent === 0) sample += 8;
  else if (exponent === 1) sample += 0x108;
  else sample = (sample + 0x108) << (exponent - 1);
  return (a & 0x80) ? sample : -sample;
}

function encodePcma(sample) {
  let pcm = Math.max(-32768, Math.min(32767, sample | 0));
  let mask;
  if (pcm >= 0) mask = 0xd5;
  else {
    mask = 0x55;
    pcm = Math.min(32767, -pcm - 1);
  }
  let compressed;
  if (pcm < 256) compressed = pcm >>> 4;
  else {
    let exponent = 1;
    for (let value = pcm >>> 8; value > 1 && exponent < 7; value >>>= 1) exponent++;
    compressed = (exponent << 4) | ((pcm >>> (exponent + 3)) & 0x0f);
  }
  return compressed ^ mask;
}

function g711Decode(payload, codecName) {
  const pcm = new Int16Array(payload.length);
  const decode = codecName === "PCMU" ? decodePcmu : decodePcma;
  for (let i = 0; i < payload.length; i++) pcm[i] = decode(payload[i]);
  return pcm;
}

function g711Encode(pcm, codecName) {
  const payload = new Uint8Array(pcm.length);
  const encode = codecName === "PCMU" ? encodePcmu : encodePcma;
  for (let i = 0; i < pcm.length; i++) payload[i] = encode(pcm[i]);
  return payload;
}

function resampleLinear(samples, sourceRate, targetRate) {
  if (sourceRate === targetRate) return new Int16Array(samples);
  const outLength = Math.max(1, Math.round(samples.length * targetRate / sourceRate));
  const out = new Int16Array(outLength);
  const scale = sourceRate / targetRate;
  for (let i = 0; i < outLength; i++) {
    const position = i * scale;
    const left = Math.min(samples.length - 1, Math.floor(position));
    const right = Math.min(samples.length - 1, left + 1);
    const fraction = position - left;
    out[i] = Math.round(samples[left] * (1 - fraction) + samples[right] * fraction);
  }
  return out;
}

function buildLegacyAnswer(codec, key) {
  const now = Math.floor(Date.now() / 1000);
  return buildSdp({
    o: `linebridge ${now} ${now} IN IP4 ${publicHost}`,
    s: "-",
    c: `IN IP4 ${publicHost}`,
    t: "0 0",
    attrs: [],
    media: [{
      type: "audio",
      port: mediaPort,
      proto: "RTP/SAVP",
      formats: [String(codec.payloadType)],
      attrs: [
        `rtpmap:${codec.payloadType} ${codec.name}/${codec.rate}`,
        cryptoAttr({ tag: 1, suite: "AES_CM_128_HMAC_SHA1_80", key }),
        "sendrecv",
        "ptime:20",
      ],
    }],
  });
}

async function startEas1Diagnostics(call, audio, codec) {
  const remoteCrypto = readCrypto(audio).find((entry) =>
    entry.suite === "AES_CM_128_HMAC_SHA1_80" && entry.key.length === 30
  );
  if (!remoteCrypto) throw new Error("legacy SDP has no supported SDES key");
  const localKey = crypto.randomBytes(30);
  const receiveContexts = [
    { name: "offer-key", context: await deriveSrtpContext(remoteCrypto.key) },
    { name: "answer-key", context: await deriveSrtpContext(localKey) },
  ];
  call.mediaSocket = dgram.createSocket("udp4");
  call.eas1Stats = {
    packets: 0,
    firstAt: null,
    lastAt: null,
    lastSeq: null,
    lastTimestamp: null,
    seqGaps: 0,
    markers: 0,
    sizes: new Map(),
    timestampSteps: new Map(),
    summaryLogged: false,
  };

  call.mediaSocket.on("message", async (wire, sender) => {
    if (call.cancelled) return;
    try {
      let decrypted = null;
      let selected = null;
      const candidates = call.eas1ReceiveKey
        ? receiveContexts.filter((entry) => entry.name === call.eas1ReceiveKey)
        : receiveContexts;
      for (const candidate of candidates) {
        try {
          decrypted = await srtpDecrypt(candidate.context, new Uint8Array(wire));
          selected = candidate;
          break;
        } catch { /* try the other SDES direction */ }
      }
      if (!decrypted || !selected) throw new Error("SRTP auth tag mismatch for offer and answer keys");
      if (!call.eas1ReceiveKey) {
        call.eas1ReceiveKey = selected.name;
        log(`eas1 SRTP receive key selected=${selected.name}`);
      }
      const rtp = parseRtp(decrypted);
      if (rtp.payloadType !== codec.payloadType) return;
      const stats = call.eas1Stats;
      const now = Date.now();
      stats.packets++;
      stats.firstAt ??= now;
      stats.lastAt = now;
      stats.markers += rtp.marker ? 1 : 0;
      stats.sizes.set(rtp.payload.length, (stats.sizes.get(rtp.payload.length) ?? 0) + 1);
      if (stats.lastSeq !== null) {
        const expected = (stats.lastSeq + 1) & 0xffff;
        if (rtp.seq !== expected) stats.seqGaps++;
      }
      if (stats.lastTimestamp !== null) {
        const step = (rtp.timestamp - stats.lastTimestamp) >>> 0;
        stats.timestampSteps.set(step, (stats.timestampSteps.get(step) ?? 0) + 1);
      }
      stats.lastSeq = rtp.seq;
      stats.lastTimestamp = rtp.timestamp;
      if (stats.packets <= 12) {
        const prefix = Buffer.from(rtp.payload.subarray(0, 8)).toString("hex");
        log(`eas1 packet n=${stats.packets} pt=${rtp.payloadType} seq=${rtp.seq} ts=${rtp.timestamp} ` +
          `marker=${rtp.marker ? 1 : 0} bytes=${rtp.payload.length} prefix=${prefix}`);
      } else if (stats.packets === 100) {
        logEas1Summary(call, "first-100-packets", false);
      }
    } catch (error) {
      call.mediaRxErrors = (call.mediaRxErrors ?? 0) + 1;
      if (call.mediaRxErrors <= 6) {
        const header = Buffer.from(wire.subarray(0, Math.min(12, wire.length))).toString("hex");
        const tail = Buffer.from(wire.subarray(Math.max(0, wire.length - 12))).toString("hex");
        const seq = wire.length >= 4 ? readWireU16(wire, 2) : -1;
        const timestamp = wire.length >= 8 ? readWireU32(wire, 4) : -1;
        const ssrc = wire.length >= 12 ? readWireU32(wire, 8) : -1;
        const matches = wire.length >= 22
          ? receiveContexts.flatMap((entry) =>
            probeSrtpAuthentication(entry.context, wire).map((match) => `${entry.name}:${match}`)
          )
          : [];
        log(`eas1 diagnostic receive failed n=${call.mediaRxErrors} error=${safeError(error)} ` +
          `from=${sender.address}:${sender.port} wireBytes=${wire.length} seq=${seq} ts=${timestamp} ` +
          `ssrc=${ssrc} header=${header} tail=${tail} authProbe=${matches.join(",") || "none"}`);
      }
    }
  });
  call.mediaSocket.on("error", (error) => log(`media socket error: ${safeError(error)}`));
  await new Promise((resolve, reject) => {
    call.mediaSocket.once("error", reject);
    call.mediaSocket.bind(mediaPort, bindHost, () => {
      call.mediaSocket.off("error", reject);
      resolve();
    });
  });

  call.planetReceiveTask = (async () => {
    try {
      for await (const _nativePayload of call.planet.receive()) {
        if (call.cancelled) return;
      }
    } catch (error) {
      if (!call.cancelled) log(`PLANET diagnostic receive failed: ${safeError(error)}`);
    }
  })();
  return { localKey, answerSdp: buildLegacyAnswer(codec, localKey) };
}

async function startMediaBridge(call, audio, codec) {
  const remoteCrypto = readCrypto(audio).find((entry) =>
    entry.suite === "AES_CM_128_HMAC_SHA1_80" && entry.key.length === 30
  );
  if (!remoteCrypto) throw new Error("legacy SDP has no supported SDES key");
  const localKey = crypto.randomBytes(30);
  const recvSrtp = await deriveSrtpContext(remoteCrypto.key);
  const sendSrtp = await deriveSrtpContext(localKey);
  const codecs = await opusCodecFactory();
  call.encoder = codecs.newEncoder({ sampleRate: 48000, channels: 1, bitrate: 32000, frameDurationMs: 20 });
  call.decoder = codecs.newDecoder({ sampleRate: 48000, channels: 1 });
  call.mediaSocket = dgram.createSocket("udp4");
  call.legacyMedia = {
    host: call.peer.address,
    port: audio.port,
    seq: crypto.randomInt(0, 0x10000),
    timestamp: crypto.randomInt(0, 0x100000000),
    ssrc: crypto.randomInt(1, 0x100000000),
  };

  call.mediaSocket.on("message", async (wire) => {
    if (call.cancelled) return;
    try {
      const rtp = parseRtp(await srtpDecrypt(recvSrtp, new Uint8Array(wire)));
      if (rtp.payloadType !== codec.payloadType) return;
      const pcm8 = g711Decode(rtp.payload, codec.name);
      const pcm48 = resampleLinear(pcm8, 8000, 48000);
      const opus = call.encoder.encode({ samples: pcm48, sampleRate: 48000, channels: 1 });
      if (!opus) return;
      const nativePayload = new Uint8Array(opus.length + 1);
      nativePayload[0] = 0;
      nativePayload.set(opus, 1);
      await call.planet.send(nativePayload, { timestampStep: pcm48.length });
    } catch (error) {
      if (!call.mediaRxErrorLogged) {
        call.mediaRxErrorLogged = true;
        log(`legacy media receive failed: ${safeError(error)}`);
      }
    }
  });
  call.mediaSocket.on("error", (error) => log(`media socket error: ${safeError(error)}`));
  await new Promise((resolve, reject) => {
    call.mediaSocket.once("error", reject);
    call.mediaSocket.bind(mediaPort, bindHost, () => {
      call.mediaSocket.off("error", reject);
      resolve();
    });
  });

  call.planetReceiveTask = (async () => {
    try {
      for await (const nativePayload of call.planet.receive()) {
        if (call.cancelled) return;
        const opus = nativePayload.length > 1 && (nativePayload[0] === 0 || nativePayload[0] === 0x10)
          ? nativePayload.subarray(1)
          : nativePayload;
        const frame = call.decoder.decode(opus);
        if (!frame) continue;
        const pcm8 = resampleLinear(frame.samples, frame.sampleRate, 8000);
        const payload = g711Encode(pcm8, codec.name);
        const rtp = buildRtp({
          payloadType: codec.payloadType,
          seq: call.legacyMedia.seq++ & 0xffff,
          timestamp: call.legacyMedia.timestamp >>> 0,
          ssrc: call.legacyMedia.ssrc,
          payload,
        });
        call.legacyMedia.timestamp = (call.legacyMedia.timestamp + pcm8.length) >>> 0;
        const wire = await srtpEncrypt(sendSrtp, rtp);
        await new Promise((resolve, reject) => call.mediaSocket.send(
          wire,
          call.legacyMedia.port,
          call.legacyMedia.host,
          (error) => error ? reject(error) : resolve(),
        ));
      }
    } catch (error) {
      if (!call.cancelled) log(`PLANET media receive failed: ${safeError(error)}`);
    }
  })();
  return { localKey, answerSdp: buildLegacyAnswer(codec, localKey) };
}

async function startEas1Bridge(call, audio, codec, opts = {}) {
  const remoteCrypto = readCrypto(audio).find((entry) =>
    entry.suite === "AES_CM_128_HMAC_SHA1_80" && entry.key.length === 30
  );
  if (!remoteCrypto) throw new Error("legacy SDP has no supported SDES key");

  await eas1Helper.resetCodec();
  const remoteKey = await eas1Helper.decryptKey(remoteCrypto.key);
  // With SDES, each endpoint advertises the key used for media it sends.
  // Therefore the peer's key is always our receive key, and our advertised
  // key is always our send key.  For historical reasons incomingReceiveKey
  // contains the local key already advertised in the incoming INVITE.
  const localKey = opts.incomingReceiveKey ?? crypto.randomBytes(30);
  const advertisedLocalKey = opts.incomingReceiveKey
    ? null
    : await eas1Helper.encryptKey(localKey);
  const recvSrtp = await deriveSrtpContext(remoteKey);
  const sendSrtp = await deriveSrtpContext(localKey);
  const codecs = await opusCodecFactory();
  call.encoder = codecs.newEncoder({ sampleRate: 48000, channels: 1, bitrate: 32000, frameDurationMs: 20 });
  call.decoder = codecs.newDecoder({ sampleRate: 48000, channels: 1 });
  const captureDir = path.join(stateDir, "audio-diagnostics");
  fs.mkdirSync(captureDir, { recursive: true });
  const captureStamp = new Date().toISOString().replace(/[:.]/g, "-");
  call.audioCapture = {
    prefix: path.join(captureDir, `${captureStamp}-${call.incoming ? "incoming" : "outgoing"}`),
    codecs,
    maxSamples: 16000 * 15,
    legacy: { chunks: [], samples: 0 },
    planet: { chunks: [], samples: 0 },
    opusPackets: [],
    uplinkTiming: [],
    downlinkTiming: [],
    finished: false,
  };
  log(`audio diagnostic armed prefix=${call.audioCapture.prefix}`);
  call.mediaSocket = dgram.createSocket("udp4");
  call.mediaActive = false;
  call.legacySendBusy = false;
  call.legacyDropped = 0;
  call.legacyPcmQueue = [];
  call.planetDecodeErrors = 0;
  call.planetHeaderSamples = 0;
  call.planetShortFrames = 0;
  call.legacyTxPackets = 0;
  call.legacyLastTxAt = 0;
  call.legacyMicSquares = 0;
  call.legacyMicSamples = 0;
  call.legacyMicPeak = 0;
  // EAS1 decode, Opus encode, and PLANET/SRTP send all keep stream state.
  // UDP "message" callbacks can overlap while awaiting any of those steps,
  // which lets later frames mutate that state before earlier frames finish.
  // Keep the complete 4S -> PLANET path in arrival order.
  call.legacyUplinkChain = Promise.resolve();
  call.legacyUplinkQueued = 0;
  call.legacyUplinkMaxQueued = 0;
  // A callee-side 4S sends SIP 200 OK before its CoreAudio/EAS1 receive
  // stream is ready.  Starting the stateful EAS1 encoder immediately makes
  // the phone join mid-stream and it then reports "corrupted stream" for the
  // rest of the call.  A valid SRTP packet from the phone is our media-ready
  // signal.  Outgoing calls do not need this gate because the 4S is already
  // running its media stream while it waits for the remote answer.
  call.legacyPeerMediaReady = !call.incoming;
  call.legacyMedia = {
    host: call.peer.address,
    port: audio.port,
    seq: crypto.randomInt(0, 0x10000),
    timestamp: crypto.randomInt(0, 0x100000000),
    ssrc: crypto.randomInt(1, 0x100000000),
  };

  // 20msティックから呼ばれる。timestampはティック単位＝実時間で進め、
  // seqは実際に送るパケットだけ進める。
  // 前回の送信がまだ終わっていなければそのフレームは捨てる。送信を直列につないで
  // 待つと、1回でも20msに間に合わないたびに遅延が積み上がり、数十秒後には旧端末へ
  // 過去の音声しか届かなくなる（＝相手の声が聞こえなくなる）。
  const sendLegacyPcm = (pcm16) => {
    const timestamp = call.legacyMedia.timestamp >>> 0;
    call.legacyMedia.timestamp = (call.legacyMedia.timestamp + 320) >>> 0;
    if (!call.legacyPeerMediaReady) return;
    if (call.legacySendBusy) {
      call.legacyDropped += 1;
      return;
    }
    call.legacySendBusy = true;
    void (async () => {
      try {
        if (call.cancelled || !call.mediaActive) return;
        const encoded = await eas1Helper.encode(pcm16);
        // Callee-side LINE 3.x expects each EAS1 frame in the same four-byte
        // packet envelope it emits: type 0x11 followed by a 24-bit BE length.
        // Keep the established caller-side path unchanged.
        const payload = call.incoming
          ? Buffer.concat([
              Buffer.from([0x11, (encoded.length >>> 16) & 0xff,
                (encoded.length >>> 8) & 0xff, encoded.length & 0xff]),
              encoded,
            ])
          : encoded;
        const seq = call.legacyMedia.seq++ & 0xffff;
        const rtp = buildRtp({
          payloadType: codec.payloadType,
          marker: call.legacyTxPackets === 0,
          seq,
          timestamp,
          ssrc: call.legacyMedia.ssrc,
          payload,
        });
        const wire = await srtpEncrypt(sendSrtp, rtp);
        await new Promise((resolve, reject) => call.mediaSocket.send(
          wire,
          call.legacyMedia.port,
          call.legacyMedia.host,
          (error) => error ? reject(error) : resolve(),
        ));
        call.legacyTxPackets += 1;
        call.legacyLastTxAt = Date.now();
      } catch (error) {
        if (!call.cancelled && !call.legacySendErrorLogged) {
          call.legacySendErrorLogged = true;
          log(`eas1 media send failed: ${safeError(error)}`);
        }
      } finally {
        call.legacySendBusy = false;
      }
    })();
  };

  call.mediaSocket.on("message", (wire) => {
    if (call.cancelled || !call.mediaActive) return;
    // dgram may reuse/release its Buffer after this callback; retain our own copy.
    const packet = Buffer.from(wire);
    call.legacyUplinkQueued += 1;
    call.legacyUplinkMaxQueued = Math.max(call.legacyUplinkMaxQueued, call.legacyUplinkQueued);
    call.legacyUplinkChain = call.legacyUplinkChain.then(async () => {
      let rtp;
      try {
        if (call.cancelled || !call.mediaActive) return;
        rtp = parseRtp(await srtpDecrypt(recvSrtp, new Uint8Array(packet)));
        if (rtp.payloadType !== codec.payloadType) return;
        if (!call.legacyPeerMediaReady) {
          call.legacyPeerMediaReady = true;
          log("incoming 4S media ready; starting EAS1 transmit");
        }
        // 着信時の 4S は eas1 の前に 4バイトの枠 `11 00 00 <len>` を付ける
        // (発信は生 eas1 で `48` 始まり)。len は後続バイト数と一致。剥がして生 eas1 を渡す。
        let eas1Payload = rtp.payload;
        // 枠の先頭バイトは 11/12/13.. と変動する(フレーム種別/連番)。先頭値は問わず、
        // [1]=[2]=0x00 かつ [3]=残りバイト数 のときだけ 4バイト枠として剥がす。
        if (eas1Payload.length >= 4 && eas1Payload[1] === 0x00
            && eas1Payload[2] === 0x00 && eas1Payload[3] === eas1Payload.length - 4) {
          eas1Payload = eas1Payload.subarray(4);
        }
        const pcm16 = await eas1Helper.decode(eas1Payload);
        capturePcm16(call.audioCapture.legacy, pcm16, call.audioCapture.maxSamples);
        for (const sample of pcm16) {
          const value = Number(sample);
          call.legacyMicSquares += value * value;
          call.legacyMicSamples += 1;
          call.legacyMicPeak = Math.max(call.legacyMicPeak, Math.abs(value));
        }
        const pcm48 = resampleLinear(pcm16, 16000, 48000);
        if (legacyUplinkGain !== 1) {
          for (let i = 0; i < pcm48.length; i++) {
            pcm48[i] = Math.round(pcm48[i] * legacyUplinkGain);
          }
        }
        const opus = call.encoder.encode({ samples: pcm48, sampleRate: 48000, channels: 1 });
        if (!opus) return;
        if (call.audioCapture.opusPackets.length < 750) {
          call.audioCapture.opusPackets.push(new Uint8Array(opus));
          call.audioCapture.uplinkTiming.push({
            at: Date.now(),
            seq: rtp.seq,
            timestamp: rtp.timestamp,
            bytes: opus.length,
          });
        }
        const nativePayload = opts.rawOpus
          ? new Uint8Array(opus)
          : (() => {
            const value = new Uint8Array(opus.length + 1);
            value[0] = 0;
            value.set(opus, 1);
            return value;
          })();
        if (!call.legacyUplinkFormatLogged) {
          call.legacyUplinkFormatLogged = true;
          const head = [...nativePayload.subarray(0, 8)]
            .map((b) => b.toString(16).padStart(2, "0")).join(" ");
          log(`PLANET uplink format pcm=${pcm48.length} gain=${legacyUplinkGain} `
            + `opus=${opus.length} head=${head}`);
        }
        await call.planet.send(nativePayload, { timestampStep: pcm48.length });
        call.legacyRxPackets = (call.legacyRxPackets ?? 0) + 1;
        if (call.legacyRxPackets === 1) log("eas1 legacy audio receive active");
      } catch (error) {
        call.mediaRxErrors = (call.mediaRxErrors ?? 0) + 1;
        if (call.mediaRxErrors <= 5) {
          const payload = rtp?.payload;
          const head = payload
            ? [...payload.subarray(0, 12)].map((b) => b.toString(16).padStart(2, "0")).join(" ")
            : "none";
          log(`eas1 legacy media receive failed n=${call.mediaRxErrors}: ${safeError(error)} `
            + `pt=${rtp?.payloadType ?? "none"} seq=${rtp?.seq ?? "none"} `
            + `ts=${rtp?.timestamp ?? "none"} payloadBytes=${payload?.length ?? 0} head=${head}`);
        }
      } finally {
        call.legacyUplinkQueued -= 1;
      }
    });
  });
  call.mediaSocket.on("error", (error) => log(`media socket error: ${safeError(error)}`));
  await new Promise((resolve, reject) => {
    call.mediaSocket.once("error", reject);
    call.mediaSocket.bind(mediaPort, bindHost, () => {
      call.mediaSocket.off("error", reject);
      resolve();
    });
  });

  call.planetReceiveTask = (async () => {
    try {
      for await (const nativePayload of call.planet.receive()) {
        if (call.cancelled) return;
        // 1フレームのデコード失敗で受信ループごと終わらせない。ここで抜けると
        // 以降スマホ側の音声が一切届かなくなる（旧実装の実害）。
        try {
          if (call.planetHeaderSamples < 2) {
            call.planetHeaderSamples += 1;
            const head = [...nativePayload.subarray(0, 4)]
              .map((b) => b.toString(16).padStart(2, "0")).join(" ");
            log(`PLANET payload sample #${call.planetHeaderSamples} len=${nativePayload.length} head=${head}`);
          }
          const frame = decodePlanetOpus(call, nativePayload);
          if (!frame) {
            call.planetDecodeErrors += 1;
            if (call.planetDecodeErrors === 1) log("PLANET eas1 opus decode failed (継続)");
            continue;
          }
          const pcm16 = resampleLinear(frame.samples, frame.sampleRate, 16000);
          if (!call.planetFrameLogged) {
            call.planetFrameLogged = true;
            log(`PLANET decoded frame samples=${frame.samples.length} rate=${frame.sampleRate}`
              + ` -> pcm16=${pcm16.length} (320サンプル=20ms)`);
          }
          // PLANETのフレーム長は可変(着信=10ms/480, 40ms/1920 等)。20ms(320)未満を捨てると
          // 音声が歯抜けになり雑音化する。前フレームの端数を溜めて連結し、20ms単位で切り出す。
          let acc = pcm16;
          if (call.planetPcmAccum && call.planetPcmAccum.length) {
            const merged = new Int16Array(call.planetPcmAccum.length + pcm16.length);
            merged.set(call.planetPcmAccum, 0);
            merged.set(pcm16, call.planetPcmAccum.length);
            acc = merged;
          }
          let queued = 0;
          let offset = 0;
          for (; offset + 320 <= acc.length; offset += 320) {
            const chunk = new Int16Array(acc.subarray(offset, offset + 320));
            capturePcm16(call.audioCapture.planet, chunk, call.audioCapture.maxSamples);
            if (call.audioCapture.downlinkTiming.length < 750) {
              call.audioCapture.downlinkTiming.push({ at: Date.now() });
            }
            if (call.legacyPcmQueue.length >= 25) call.legacyPcmQueue.shift();
            call.legacyPcmQueue.push(chunk);
            queued += 1;
          }
          // 端数(320未満)を次回へ持ち越し。溜まりすぎ(>=640)は古い方を捨てて遅延を抑える。
          call.planetPcmAccum = new Int16Array(acc.subarray(offset));
          if (call.planetPcmAccum.length >= 640) {
            call.planetPcmAccum = new Int16Array(call.planetPcmAccum.subarray(call.planetPcmAccum.length - 320));
          }
          if (queued === 0) {
            call.planetShortFrames += 1;
            continue;
          }
          call.planetRxPackets = (call.planetRxPackets ?? 0) + queued;
          if (!call.planetRxLogged) {
            call.planetRxLogged = true;
            log("eas1 PLANET audio receive active");
          }
        } catch (error) {
          call.planetDecodeErrors += 1;
          if (call.planetDecodeErrors === 1) {
            log(`PLANET eas1 frame handling failed (継続): ${safeError(error)}`);
          }
        }
      }
    } catch (error) {
      if (!call.cancelled) log(`PLANET eas1 media receive failed: ${safeError(error)}`);
    }
  })();

  const silence = new Int16Array(320);
  const activate = () => {
    if (call.mediaActive) return;
    call.mediaActive = true;
    const PREROLL = 4;
    call.legacyPrimed = false;
    const tick = () => {
      if (call.cancelled || !call.mediaActive) return;
      // ジッタバッファ: 一定数(PREROLL)溜まるまでは流さず無音。空になったら再度溜め直す。
      if (!call.legacyPrimed) {
        if (call.legacyPcmQueue.length >= PREROLL) call.legacyPrimed = true;
        else { void sendLegacyPcm(silence); return; }
      }
      const pcm16 = call.legacyPcmQueue.shift();
      if (pcm16 === undefined) { call.legacyPrimed = false; void sendLegacyPcm(silence); return; }
      void sendLegacyPcm(pcm16);
    };
    tick();
    call.legacySilenceTimer = setInterval(tick, 20);
    call.legacyStatsTimer = setInterval(() => {
      const idleMs = call.legacyLastTxAt ? Date.now() - call.legacyLastTxAt : -1;
      const micRms = call.legacyMicSamples
        ? Math.round(Math.sqrt(call.legacyMicSquares / call.legacyMicSamples)) : 0;
      log(`media stats legacyTx=${call.legacyTxPackets} dropped=${call.legacyDropped} `
        + `queue=${call.legacyPcmQueue.length} idleMs=${idleMs} `
        + `planetRx=${call.planetRxPackets ?? 0} planetErr=${call.planetDecodeErrors} `
        + `planetShort=${call.planetShortFrames} `
        + `legacyRx=${call.legacyRxPackets ?? 0} decFail=${call.planetDecryptFails ?? 0} `
        + `micRms=${micRms} micPeak=${call.legacyMicPeak} `
        + `uplinkQ=${call.legacyUplinkQueued} uplinkMaxQ=${call.legacyUplinkMaxQueued}`);
      call.legacyMicSquares = 0;
      call.legacyMicSamples = 0;
      call.legacyMicPeak = 0;
      call.legacyUplinkMaxQueued = call.legacyUplinkQueued;
      // イベント件数の一覧は行が長いので30秒に1回だけ。
      call.legacyStatsTicks = (call.legacyStatsTicks ?? 0) + 1;
      if (call.legacyStatsTicks % 3 === 1 && call.planetEventCounts) {
        const counts = [...call.planetEventCounts].map(([k, v]) => `${k}:${v}`).join(" ");
        log(`planet events ${counts}`);
      }
    }, 10000);
  };
  return {
    localKey: advertisedLocalKey,
    answerSdp: advertisedLocalKey ? buildLegacyAnswer(codec, advertisedLocalKey) : null,
    activate,
  };
}

// 旧端末へ INVITE を投げて鳴らす。着信実装の前段として到達性を確かめるためのもの。
// メディアはまだ繋がないので、応答が返ったらすぐ畳む。
function contactUri(contact) {
  const m = String(contact || "").match(/<([^>]+)>/);
  const uri = m ? m[1] : String(contact || "");
  return uri.split(";")[0];
}

// 4S 自身の INVITE と同じ形の SDP。ptime も rtcp 行も本物に合わせる。
function buildLegacyOffer(key) {
  // 4S の AmpKit が実際に送る SDP と同じ並び。media-level c= と
  // NTP epoch が無い buildSdp 版は着信INVITEとして受理されない。
  const ntp = Math.floor(Date.now() / 1000) + 2208988800;
  return [
    "v=0",
    `o=- ${ntp} ${ntp} IN IP4 ${publicHost}`,
    "s=amp",
    `c=IN IP4 ${publicHost}`,
    "t=0 0",
    "a=ph:4",
    `m=audio ${mediaPort} RTP/SAVP 120 96`,
    `c=IN IP4 ${publicHost}`,
    `a=rtcp:${mediaPort + 1} IN IP4 ${publicHost}`,
    "a=sendrecv",
    "a=rtpmap:120 eas1/16000",
    "a=rtpmap:96 telephone-event/8000",
    "a=fmtp:96 0-15",
    "a=ptime:20",
    `a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:${Buffer.from(key).toString("base64")}`,
    "",
  ].join("\r\n");
}

function incomingPlanetRoute(incoming) {
  const raw = incoming?.route;
  if (!raw || typeof raw !== "object") {
    throw new Error("incoming operation has no server route");
  }
  const host = String(raw.h || "").split(",").map((v) => v.trim()).find(Boolean);
  const udpPort = Number(raw.p || 0);
  // op50 uses compact keys: n is the PLANET fromToken/call key, vs is
  // the per-attempt stid, and em is encFromMid.  em is not an auth token.
  const fromToken = String(raw.n || "");
  if (!host || !udpPort || !fromToken) {
    throw new Error("incoming server route is incomplete");
  }
  return {
    fromToken,
    callFlowType: "PLANET",
    voipAddress: String(raw.h || host),
    voipAddress6: String(raw.hv6 || "").split(",")[0] || "",
    voipUdpPort: udpPort,
    voipTcpPort: Number(raw.vp || 0),
    fromZone: String(raw.vfz || ""),
    toZone: String(raw.vtz || ""),
    fakeCall: false,
    toMid: String(incoming.callerMid || ""),
    commParam: typeof raw.vc === "string" ? raw.vc : JSON.stringify(raw.vc || {}),
    stid: String(raw.vs || ""),
    stnpk: String(raw.stnpk || ""),
  };
}

function incomingPlanetCallId(incoming) {
  // The server indexes the incoming communication by the per-attempt UUID
  // (`vs`).  The short `n` value is the credential token, not the Cassini cid.
  return String(incoming.deviceKey || incoming.route?.vs
    || incoming.callMid || incoming.callToken || incoming.route?.n || "");
}

async function prepareIncomingUpstream(incoming) {
  const { client } = await createClient();
  const route = incomingPlanetRoute(incoming);
  const debugCounts = new Map();
  let transport;
  transport = new PlanetTransport({
    localMid: client.profile.mid,
    deviceInfo: "ANDROID\t26.6.2\tAndroid OS\t16",
    deviceId: callDeviceId,
    timeoutMs: 8000,
    keepaliveIntervalMs: 3000,
    // Incoming caller media is plaintext, so receive-side authentication cannot
    // auto-select a candidate.  Incoming push routes carry a distinct mpkey;
    // captures show that key, rather than the VERIFY offer key, is the media
    // ECDH peer key for the reverse (callee -> caller) SRTP direction.
    mediaKeyMode: "audio-reverse-stage/mpkey",
    mediaPlaintext: true,
    mediaCandidateIp: publicHost,
    onRemoteRelease: (release) => {
      setImmediate(() => void handlePlanetRelease(transport, release));
    },
    debug: (event) => {
      const type = String(event?.type || "");
      debugCounts.set(type, (debugCounts.get(type) ?? 0) + 1);
      if (["incoming_verify_req", "incoming_verify_rsp", "incoming_conn_req", "send_planet_msg", "recv", "decrypt_ok",
        "plain_shape", "cc_shape", "planet_msg", "recv_error", "media_configured", "media_key_selected", "keydiag"].includes(type)) {
        log(`incoming PLANET ${type} ${JSON.stringify(event).slice(0, 500)}`);
      } else if ((type === "media_decrypt_fail" && debugCounts.get(type) <= 5)
        || (type === "media_recv" && debugCounts.get(type) === 1)
        || (type === "media_send" && debugCounts.get(type) === 1)) {
        log(`incoming PLANET ${type} #${debugCounts.get(type)} ${JSON.stringify(event).slice(0, 500)}`);
      } else if (type === "keycap") {
        log(`incoming PLANET keycap ${JSON.stringify(event)}`);
      }
    },
  });
  await transport.connect({ route });
  log(`incoming PLANET route ready host=${hostForLog(route.voipAddress)}:${route.voipUdpPort}`);
  const verify = await transport.verifyIncomingDetailed({
    callId: incomingPlanetCallId(incoming),
    from: String(incoming.callerMid || ""),
    timeoutMs: 8000,
  });
  log(`incoming PLANET verify_rsp result=${verify.verifyRsp?.result ?? "none"} `
    + `relCode=${verify.verifyRsp?.relCode ?? "none"} `
    + `relPhrase=${verify.verifyRsp?.relPhrase ?? "none"}`);
  if (verify.verifyRsp?.result !== undefined && verify.verifyRsp.result !== 0) {
    throw new Error(`PLANET verify_rsp rejected relCode=${verify.verifyRsp.relCode ?? "none"} `
      + `relPhrase=${verify.verifyRsp.relPhrase ?? "none"}`);
  }
  return { transport, verify, debugCounts };
}

function hostForLog(value) {
  return String(value || "").split(",")[0] || "missing";
}

async function ringLegacy() {
  if (active) {
    log("RING 送れない: 別の通話が進行中");
    return;
  }
  if (!registration) {
    log("RING 送れない: 端末の登録がまだ無い (4Sから一度発信させると登録される)");
    return;
  }
  if (ringing) {
    log("RING 既に呼び出し中");
    return;
  }
  let target = contactUri(registration.contact) || `sip:${publicHost}`;
  // 端末自身が名乗っている URI(=自分宛て)と、発信者として見せる相手の URI。
  const selfUri = (String(registration.to || "").match(/sip:[^;>\s]+/) || [])[0]
    || `sip:${publicHost}`;
  let incoming = {};
  try {
    incoming = JSON.parse(fs.readFileSync(path.join(stateDir, "incoming_ring.json"), "utf8"));
  } catch {}
  const variant = String(incoming.variant || "baseline");
  if (variant === "aor") target = selfUri;
  const callerMid = String(incoming.callerMid || process.env.LINE_LEGACY_RING_FROM || "");
  const fromUri = `sip:${callerMid}@jpdc.nhn.com`;
  const callId = String(incoming.callToken || crypto.randomBytes(12).toString("hex"));
  const fromTag = crypto.randomBytes(12).toString("base64url");
  const branch = "z9hG4bK" + crypto.randomBytes(12).toString("base64url");
  const diagnosticTiny = variant === "tiny" || variant === "brackets";
  let incomingReceiveKey = null;
  let offerKey = crypto.randomBytes(30);
  if (!diagnosticTiny && incoming.route) {
    await eas1Helper.resetCodec();
    incomingReceiveKey = crypto.randomBytes(30);
    offerKey = await eas1Helper.encryptKey(incomingReceiveKey);
  }
  const body = diagnosticTiny ? "" : buildLegacyOffer(offerKey);
  const headers = {
    Via: `SIP/2.0/UDP ${publicHost}:${bindPort};rport;branch=${branch}`,
    "Max-Forwards": "70",
    // 本物は山括弧を付けない。付けると弾かれる可能性がある。
    From: `${fromUri};tag=${fromTag}`,
    To: selfUri,
    Contact: `<sip:${callerMid}@${publicHost}:${bindPort}>`,
    "Call-ID": callId,
    // AmpKit discards an incoming INVITE before replying when this proprietary
    // LINE header is absent.  The push token (n) is the expected call key.
    "P-Call-Key": callId,
    "P-Call-Cmd": "setup",
    "P-Device-Key": String(incoming.deviceKey || ""),
    "P-Auth-Info": String(incoming.authInfo || ""),
    CSeq: `${crypto.randomInt(1000000, 200000000)} INVITE`,
    // AmpKit 3.7.1 installs a strict User-Agent parser.  A normal product
    // token such as LINE-Legacy-Bridge/1 throws at the first value byte and
    // drops the entire INVITE.  Use the exact legacy format emitted by 4S.
    "User-Agent": "IOS;iPhone4,1;WIFI",
    "Content-Type": "application/sdp",
    "Content-Length": String(Buffer.byteLength(body)),
  };
  if (variant === "brackets") {
    headers.From = `<${fromUri}>;tag=${fromTag}`;
    headers.To = `<${selfUri}>`;
  }
  // Diagnostic replay only: the native operation already supplies the call
  // key.  This variant checks whether the old PJSIP parser is rejecting the
  // two long, newer-generation push headers before AmpKit sees the INVITE.
  if (variant === "compact" || diagnosticTiny) {
    delete headers["P-Device-Key"];
    delete headers["P-Auth-Info"];
  }
  if (diagnosticTiny) delete headers["Content-Type"];
  const upstreamPromise = incoming.route
    ? prepareIncomingUpstream(incoming)
      .then((value) => ({ value }), (error) => ({ error }))
    : Promise.resolve({ error: new Error("diagnostic ring has no real upstream") });
  ringing = {
    callId,
    fromTag,
    branch,
    toUri: selfUri,
    target,
    peer: registration.peer,
    headers,
    incoming,
    incomingReceiveKey,
    upstreamPromise,
  };
  ringing.timer = setTimeout(() => {
    if (!ringing) return;
    log("RING 応答なし -> CANCEL");
    void cancelRing().catch(() => {});
  }, 20000);
  log(`RING INVITE -> ${registration.peer.address}:${registration.peer.port} uri=${target} from=${fromUri}`);
  await sendWire(buildSip({ startLine: `INVITE ${target} SIP/2.0`, headers, body }), registration.peer);
}

function armLegacyRing() {
  if (ringing) {
    log("RING 既に呼び出し中");
    return;
  }
  ringArmed = true;
  log("RING armed for next authenticated REGISTER");
}

async function cancelRing() {
  if (!ringing) return;
  const h = { ...ringing.headers, "Content-Length": "0" };
  h.CSeq = String(ringing.headers.CSeq).replace(/INVITE$/, "CANCEL");
  delete h["Content-Type"];
  await sendWire(buildSip({ startLine: `CANCEL ${ringing.target} SIP/2.0`, headers: h, body: "" }),
    ringing.peer);
  clearTimeout(ringing.timer);
  ringing = null;
}

async function finishRing(message, code) {
  if (!ringing) return;
  if (ringing.finishing) return;
  ringing.finishing = true;
  const dialog = ringing;
  const seq = String(dialog.headers.CSeq).split(/\s+/)[0];
  const base = {
    Via: dialog.headers.Via,
    "Max-Forwards": "70",
    From: dialog.headers.From,
    To: header(message, "To") || dialog.toUri,
    "Call-ID": dialog.callId,
    Contact: dialog.headers.Contact,
    "User-Agent": "IOS;iPhone4,1;WIFI",
    "Content-Length": "0",
  };
  const endLegacy = async (reason) => {
    await sendWire(buildSip({ startLine: `BYE ${dialog.target} SIP/2.0`,
      headers: { ...base, CSeq: `${Number(seq) + 1} BYE` }, body: "" }), dialog.peer)
      .catch(() => undefined);
    log(`incoming bridge ended before media reason=${reason}`);
  };

  await sendWire(buildSip({ startLine: `ACK ${dialog.target} SIP/2.0`,
    headers: { ...base, CSeq: `${seq} ACK` }, body: "" }), dialog.peer);
  clearTimeout(dialog.timer);

  try {
    const session = parseSdp(message.body ?? "");
    const audio = session.media.find((entry) => entry.type === "audio");
    const codec = audio ? selectLegacyCodec(audio) : null;
    if (!audio || !codec?.eas1 || !dialog.incomingReceiveKey) {
      throw new Error("4S incoming answer has no supported EAS1 media");
    }

    const prepared = await dialog.upstreamPromise;
    if (prepared.error) throw prepared.error;
    const planetAnswer = await prepared.value.transport.answerIncomingDetailed({
      // Cassini cid is the per-attempt `vs`; route.fromToken supplies `n`.
      callId: incomingPlanetCallId(dialog.incoming) || dialog.callId,
      from: String(dialog.incoming.callerMid || ""),
      timeoutMs: 8000,
    });
    log(`incoming PLANET conn_rsp result=${planetAnswer.connRsp?.result ?? "none"} `
      + `relCode=${planetAnswer.connRsp?.relCode ?? "none"} `
      + `relPhrase=${planetAnswer.connRsp?.relPhrase ?? "none"} `
      + `mChanId=${planetAnswer.connRsp?.mChanId ?? "none"} `
      + `mediaReady=${planetAnswer.mediaReady ?? false}`);
    if (planetAnswer.connRsp?.result !== undefined && planetAnswer.connRsp.result !== 0) {
      throw new Error(`PLANET conn_rsp rejected relCode=${planetAnswer.connRsp.relCode ?? "none"} `
        + `relPhrase=${planetAnswer.connRsp.relPhrase ?? "none"}`);
    }

    const call = {
      peer: dialog.peer,
      request: null,
      planet: prepared.value.transport,
      cancelled: false,
      incoming: true,
      planetEventCounts: prepared.value.debugCounts,
      endLegacy,
    };
    active = call;
    const media = await startEas1Bridge(call, audio, codec, {
      incomingReceiveKey: dialog.incomingReceiveKey,
      rawOpus: false,
    });
    media.activate?.();
    ringing = null;
    log(`incoming media bridge active codec=${codec.name}/${codec.rate} upstream=PLANET`);
  } catch (error) {
    const text = safeError(error);
    await endLegacy(text);
    const prepared = await dialog.upstreamPromise.catch(() => null);
    try { await prepared?.value?.transport?.close(); } catch { /* best effort */ }
    ringing = null;
    log(`incoming bridge failed: ${text}`);
  }
}

process.on("SIGUSR2", armLegacyRing);

async function bridgeInvite(message, peer) {
  if (active) {
    await respond(message, peer, 486, "Busy Here");
    return;
  }
  const target = `${message.startLine} ${header(message, "To")}`
    .match(/u[0-9a-f]{32}/i)?.[0];
  if (!target) {
    await respond(message, peer, 400, "Bad Request");
    log("INVITE rejected: target MID missing");
    return;
  }

  let audio;
  try {
    audio = parseSdp(message.body ?? "").media.find((entry) => entry.type === "audio");
  } catch { /* handled below */ }
  const legacyCodec = audio ? selectLegacyCodec(audio) : null;
  const call = { peer, request: message, planet: null, cancelled: false,
    outgoingTarget: target, startedAt: Date.now(), connectedAt: null };
  call.endLegacy = (reason) => endOutgoingLegacy(call, reason);
  active = call;
  await respond(message, peer, 100, "Trying");
  log(`INVITE received ${summarizeInvite(message)} target=hidden`);

  try {
    const { client } = await createClient();
    if (call.cancelled) return;
    const route = await client.call.acquireCallRoute({
      to: target,
      callType: "AUDIO",
      fromEnvInfo: { devname: "Android" },
    });
    let planet;
    planet = new PlanetTransport({
      localMid: client.profile.mid,
      timeoutMs: 10000,
      // "auto" は current で開始し、復号に失敗した時点で他の鍵候補へ恒久的に
      // 切り替える。相手は通話途中でメディア鍵を切り替えてくるため、モードを
      // 固定するとその瞬間から全パケットが復号失敗し、受信が無言で止まる。
      mediaKeyMode: "auto",
      // SETUP_RSPがaliveRptIntervalを返さない場合、linejsはkeepaliveを一度も
      // 送らない。その状態だとPLANET側が約10秒でセッションを解放し、双方向とも
      // メディアが止まる。明示指定して必ず送らせる。
      keepaliveIntervalMs: 3000,
      deviceInfo: "ANDROID\t26.6.2\tAndroid OS\t16",
      deviceId: callDeviceId,
      onRemoteRelease: (release) => {
        setImmediate(() => void handlePlanetRelease(planet, release));
      },
      debug: (event) => {
        const type = event?.type;
        if (!type) return;
        // 種類ごとの件数は全部数える。どの層で受信が止まるかは、増える種類と
        // 止まる種類の差でしか分からないため。
        call.planetEventCounts ??= new Map();
        call.planetEventCounts.set(type, (call.planetEventCounts.get(type) ?? 0) + 1);
        if (type === "media_key_selected") {
          log(`PLANET media key switched mode=${event.mode} send=${event.send} recv=${event.recv}`);
          return;
        }
        if (type === "keydiag") {
          log("PLANET keydiag " + JSON.stringify(event).slice(0, 400));
          return;
        }
        if (type === "mc_datareq_raw") {
          log("PLANET mc_datareq_raw " + JSON.stringify(event));
          return;
        }
        if (type === "media_decrypt_fail") {
          call.planetDecryptFails = (call.planetDecryptFails ?? 0) + 1;
          if (call.planetDecryptFails === 1) log(`PLANET media decrypt fail (初回) reason=${event.reason}`);
          return;
        }
        // 中身まで残すのは接続確立の失敗を示すものだけ。それ以外は件数のみ。
        const notable = type === "rel_req" || type === "conn_rsp_duplicate"
          || type === "media_configured" || type === "recv_error" || type === "recv_ignored"
          || type === "info_req_skipped" || type === "conn_rsp_duplicate";
        if (!notable) return;
        const seen = call.planetEventCounts.get(type);
        if (seen <= 3) log(`PLANET event ${type} #${seen} ${JSON.stringify(event).slice(0, 260)}`);
      },
    });
    call.planet = planet;
    await planet.connect({ route });
    if (call.cancelled) return;
    const invitation = await planet.inviteDetailed({ to: target });
    if (call.cancelled) return;
    await respond(message, peer, 180, "Ringing");
    const setup = invitation.setupRsp ?? {};
    log(`PLANET setup accepted result=${setup.result ?? "none"} relCode=${setup.relCode ?? "none"} ` +
      `noAnswerSec=${setup.noAnsToSec ?? "none"} service=${setup.svcId ?? "unknown"} ` +
      `targetService=${setup.tgtSvcId ?? "unknown"} ` +
      `aliveRptInterval=${setup.aliveRptInterval ?? "none"}`);

    const answer = await planet.waitForAnswerDetailed({
      autoConnRsp: true,
      timeoutMs: answerWaitMs,
    });
    if (call.cancelled) return;
    log(`PLANET peer answered mediaReady=${answer.mediaReady === true}`);
    if (answer.mediaReady === true) call.connectedAt = Date.now();
    // CONN_RSPはconnReqの各フィールドをそのまま返す作りなので、ここが欠けていると
    // 相手は応答を自分の要求と結び付けられず、CONN_REQを再送し続けて10秒で諦める。
    {
      const cr = answer.connReq ?? {};
      const shape = (v) => v === undefined ? "undef" : (v === null ? "null"
        : (v instanceof Uint8Array ? `bytes[${v.length}]` : String(v)));
      log(`PLANET connReq svcId=${shape(cr.svcId)} tgtSvcId=${shape(cr.tgtSvcId)} `
        + `netType=${shape(cr.netType)} interDomain=${shape(cr.interDomain)} `
        + `mChanId=${shape(cr.mChanId)} unavailToSec=${shape(cr.unavailToSec)} `
        + `mAddr=${shape(cr.mAddr)} uePublicAddr=${shape(cr.uePublicAddr)} `
        + `keys=${Object.keys(cr).join("|")}`);
    }
    if (!answer.mediaReady) throw new Error("PLANET media was not established");
    if (!audio || !legacyCodec) {
      log(`legacy standard codec unavailable formats=${audio?.formats?.join(",") ?? "none"}`);
      await respond(message, peer, 488, "Not Acceptable Here");
      await closeActive("legacy-codec-unavailable");
      return;
    }
    const media = legacyCodec.eas1
      ? await startEas1Bridge(call, audio, legacyCodec)
      : legacyCodec.diagnostic
        ? await startEas1Diagnostics(call, audio, legacyCodec)
        : await startMediaBridge(call, audio, legacyCodec);
    await respond(message, peer, 200, "OK", {
      Contact: `<sip:linebridge@${publicHost}:${bindPort}>`,
      "Content-Type": "application/sdp",
    }, media.answerSdp);
    media.activate?.();
    log(`${legacyCodec.diagnostic ? "diagnostic media" : "media bridge"} active ` +
      `codec=${legacyCodec.name}/${legacyCodec.rate}`);
  } catch (error) {
    if (!call.cancelled) {
      const text = safeError(error);
      const timeout = /timeout/i.test(text);
      await respond(message, peer, timeout ? 480 : 503,
        timeout ? "Temporarily Unavailable" : "Service Unavailable").catch(() => undefined);
      log(`bridge failed: ${text}`);
      await closeActive(timeout ? "no-answer-or-timeout" : "setup-error");
    }
  }
}

socket.on("message", async (buffer, peer) => {
  try {
    if (buffer.length <= 4 && /^\s*$/.test(buffer.toString("ascii"))) return;
    const message = parseSip(new Uint8Array(buffer));
    const startLine = String(message.startLine ?? "");
    if (/^SIP\/2\.0\s/.test(startLine)) {
      // 旧端末からの応答。鳴らしテスト中だけ意味を持つ。
      const code = Number(startLine.split(/\s+/)[1] || 0);
      log(`RING 応答 ${startLine.trim()}`);
      if (ringing && code >= 200 && code < 300) await finishRing(message, code);
      else if (ringing && code >= 400) { clearTimeout(ringing.timer); ringing = null; }
      return;
    }
    const method = startLine.split(/\s+/)[0].toUpperCase();
    log(`rx method=${method || "unknown"} bytes=${buffer.length} auth=${header(message, "Authorization") ? "yes" : "no"}`);

    if (method === "REGISTER") {
      // 着信で鳴らすための宛先。認証済みの登録だけ覚える。
      const authorized = Boolean(header(message, "Authorization"));
      const unregistering = String(header(message, "Expires") || "").trim() === "0";
      if (authorized && !unregistering) {
        registration = {
          peer: { address: peer.address, port: peer.port },
          contact: header(message, "Contact"),
          from: header(message, "From"),
          to: header(message, "To"),
          userAgent: header(message, "User-Agent"),
          at: Date.now(),
        };
        if (!registrationLogged) {
          registrationLogged = true;
          log(`REGISTER stored peer=${peer.address}:${peer.port}`
            + ` contact=${registration.contact || "none"}`
            + ` from=${registration.from || "none"}`
            + ` to=${registration.to || "none"}`
            + ` ua=${registration.userAgent || "none"}`);
        }
      } else if (authorized && unregistering) {
        registration = null;
        registrationLogged = false;
        log("REGISTER expires=0 -> registration cleared");
      }
      if (!authorized) {
        await respond(message, peer, 401, "Unauthorized", {
          "WWW-Authenticate": `Digest realm="line-legacy.local",nonce="${nonce}",algorithm=MD5,qop="auth"`,
        });
      } else {
        // Return the accepted SIP binding.  On the incoming path LINE 3.7.1
        // also reads a newline-separated "MID,call-token" list from the
        // REGISTER response body before it will accept the pending caller.
        const registerHeaders = { Expires: unregistering ? "0" : "300" };
        const contact = header(message, "Contact");
        if (contact) registerHeaders.Contact = contact;
        let registerBody = "";
        if (!unregistering && ringArmed) {
          try {
            const pending = JSON.parse(fs.readFileSync(path.join(stateDir, "incoming_ring.json"), "utf8"));
            const callerMid = String(pending?.callerMid || "").trim();
            const callToken = String(pending?.callToken || "").trim();
            if (/^u[0-9a-f]{32}$/i.test(callerMid) && callToken) {
              registerBody = `${callerMid},${callToken}\n`;
              registerHeaders["Content-Type"] = "text/plain";
              log("REGISTER accepted-user list attached");
            }
          } catch (error) {
            log(`REGISTER accepted-user list unavailable: ${safeError(error)}`);
          }
        }
        await respond(message, peer, 200, "OK", registerHeaders, registerBody);
        if (!unregistering && ringArmed) {
          ringArmed = false;
          await ringLegacy();
        }
      }
      return;
    }
    if (method === "INVITE") {
      await bridgeInvite(message, peer);
      return;
    }
    if (method === "CANCEL") {
      await respond(message, peer, 200, "OK");
      await closeActive("legacy-cancel");
      return;
    }
    if (method === "BYE") {
      log(`BYE received reason=${header(message, "Reason") || "none"} userAgent=${header(message, "User-Agent") || "none"}`);
      await respond(message, peer, 200, "OK");
      await closeActive("legacy-bye");
      return;
    }
    if (method === "ACK") return;
    if (method === "OPTIONS") {
      await respond(message, peer, 200, "OK");
      return;
    }
    log(`unhandled SIP method=${method || "unknown"}`);
  } catch (error) {
    const prefix = buffer.subarray(0, 8).toString("hex");
    log(`non-SIP or parse failure bytes=${buffer.length} prefix=${prefix} error=${safeError(error)}`);
  }
});

socket.on("error", (error) => {
  log(`socket error: ${safeError(error)}`);
});

socket.bind(bindPort, bindHost, () => {
  log(`legacy call gateway listening udp://${publicHost}:${bindPort}`);
});


for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    await closeActive(signal);
    socket.close(() => process.exit(0));
  });
}
