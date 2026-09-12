import fs from "node:fs";
import path from "node:path";
import { Blob } from "node:buffer";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import { bridgeDir, checkSelfKey, createClient, legacyDir, safeError } from "./common.mjs";

const queuePath = path.join(bridgeDir, "video_in.jsonl");
const resultPath = path.join(bridgeDir, "video_out.jsonl");
const donePath = path.join(bridgeDir, "video_done.txt");
const allowedRoots = [
  path.resolve(path.join(legacyDir, "upload")),
  path.resolve(path.join(bridgeDir, "staging")),
];

function appendLine(file, value) {
  fs.appendFileSync(file, `${JSON.stringify(value)}\n`, "utf8");
}

function loadDone() {
  try {
    return new Set(fs.readFileSync(donePath, "utf8").split(/\r?\n/).filter(Boolean));
  } catch {
    return new Set();
  }
}

function safeMediaPath(input) {
  const resolved = path.resolve(String(input ?? ""));
  const allowed = allowedRoots.some((root) => resolved === root || resolved.startsWith(root + path.sep));
  if (!allowed) throw new Error("media path is outside allowed directories");
  const stat = fs.statSync(resolved);
  if (!stat.isFile() || stat.size === 0) throw new Error("media file is missing or empty");
  return resolved;
}

function videoDurationMs(mediaPath) {
  const output = execFileSync("ffprobe", [
    "-v", "error",
    "-show_entries", "format=duration",
    "-of", "default=noprint_wrappers=1:nokey=1",
    mediaPath,
  ], { encoding: "utf8", timeout: 20_000 }).trim();
  const seconds = Number(output);
  if (!Number.isFinite(seconds) || seconds <= 0) {
    throw new Error("video duration could not be measured");
  }
  return String(Math.max(1, Math.round(seconds * 1000)));
}

function deriveFileKeys(keyMaterial) {
  const derived = Buffer.from(crypto.hkdfSync(
    "sha256",
    keyMaterial,
    Buffer.alloc(0),
    Buffer.from("FileEncryption"),
    76,
  ));
  return {
    encKey: derived.subarray(0, 32),
    macKey: derived.subarray(32, 64),
    iv: Buffer.concat([derived.subarray(64, 76), Buffer.alloc(4)]),
  };
}

function aesCtr(data, encKey, iv) {
  const cipher = crypto.createCipheriv("aes-256-ctr", encKey, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function makeChunkHashes(ciphertext) {
  const values = [];
  for (let offset = 0; offset < ciphertext.length; offset += 131_072) {
    values.push(crypto.createHash("sha256")
      .update(ciphertext.subarray(offset, offset + 131_072))
      .digest());
  }
  return Buffer.concat(values);
}

function encryptPreview(data, keys) {
  const ciphertext = aesCtr(data, keys.encKey, keys.iv);
  const mac = crypto.createHmac("sha256", keys.macKey).update(ciphertext).digest();
  return Buffer.concat([ciphertext, mac]);
}

async function uploadVideo(client, options, durationMs, sourceBytes) {
  const plain = Buffer.from(await options.data.arrayBuffer());
  const keyMaterial = crypto.randomBytes(32);
  const keys = deriveFileKeys(keyMaterial);
  const ciphertext = aesCtr(plain, keys.encKey, keys.iv);
  const hashData = makeChunkHashes(ciphertext);
  // Videos authenticate the concatenated 128 KiB SHA-256 hashes. Images and
  // audio authenticate the ciphertext itself. Official video players require
  // both this MAC and the separate <OID>__ud-hash object for range playback.
  const videoMac = crypto.createHmac("sha256", keys.macKey).update(hashData).digest();
  const encryptedVideo = Buffer.concat([ciphertext, videoMac]);

  const tempId = `reqid-${crypto.randomUUID()}`;
  const main = await client.obs.uploadObjectForService({
    data: new Blob([encryptedVideo]),
    oType: "file",
    obsPath: `talk/emv/${tempId}`,
    params: { type: "file" },
    filename: options.filename ?? "video.mp4",
  });
  if (!main.objId) {
    const responseHeaders = Object.fromEntries(main.headers.entries());
    throw new Error(`video OBS upload returned no object id: ${JSON.stringify(responseHeaders)}`);
  }

  const hashUpload = await client.obs.uploadObjectForService({
    data: new Blob([hashData]),
    oType: "file",
    obsPath: `talk/emv/${main.objId}__ud-hash`,
    params: { type: "file" },
    filename: "hash.bin",
  });
  if (hashUpload.objId && hashUpload.objId !== main.objId) {
    throw new Error("video hash OBS object id did not match");
  }

  if (!options.preview) throw new Error("video preview is required");
  const previewPlain = Buffer.from(await options.preview.arrayBuffer());
  const encryptedPreview = encryptPreview(previewPlain, keys);
  const previewUpload = await client.obs.uploadObjectForService({
    data: new Blob([encryptedPreview]),
    oType: "file",
    obsPath: `talk/emv/${main.objId}__ud-preview`,
    params: { type: "file" },
    filename: "preview.jpg",
  });
  if (previewUpload.objId && previewUpload.objId !== main.objId) {
    throw new Error("video preview OBS object id did not match");
  }

  const chunks = await client.e2ee.encryptE2EEMessage(
    String(options.to),
    { keyMaterial: keyMaterial.toString("base64") },
    2,
  );
  const sent = await client.talk.sendMessage({
    to: String(options.to),
    chunks,
    contentType: 2,
    contentMetadata: {
      FILE_SIZE: String(sourceBytes),
      DURATION: durationMs,
      OID: main.objId,
      SID: "emv",
      e2eeMark: "2",
      e2eeVersion: "2",
      contentType: "2",
    },
  });
  return { sent, hashBytes: hashData.length };
}

async function main() {
  fs.mkdirSync(path.join(bridgeDir, "staging"), { recursive: true });
  const { client, storage } = await createClient();
  const keyState = await checkSelfKey(client, storage);
  if (!keyState.localKey || !keyState.serverKey) {
    throw new Error("E2EE self key validation failed");
  }

  const done = loadDone();
  console.log(JSON.stringify({ ok: true, ready: true, backend: "linejs", media: "video" }));

  for (;;) {
    let lines = [];
    try {
      lines = fs.readFileSync(queuePath, "utf8").split(/\r?\n/);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }

    for (const line of lines) {
      if (!line.trim()) continue;
      let request;
      try {
        request = JSON.parse(line);
      } catch {
        continue;
      }
      const id = String(request?.id ?? "");
      if (!id || done.has(id)) continue;

      const result = { id, ok: false, backend: "linejs", contentType: 2 };
      try {
        const mediaPath = safeMediaPath(request.path);
        const bytes = fs.readFileSync(mediaPath);
        const data = new Blob([bytes], { type: "video/mp4" });
        const durationMs = videoDurationMs(mediaPath);
        let preview;
        if (request.previewPath) {
          const previewPath = safeMediaPath(request.previewPath);
          preview = new Blob([fs.readFileSync(previewPath)], { type: "image/jpeg" });
        }
        const uploaded = await uploadVideo(client, {
          data,
          preview,
          oType: "video",
          to: String(request.to ?? ""),
          filename: String(request.filename ?? "video.mp4"),
        }, durationMs, bytes.length);
        result.ok = true;
        result.serverMsgId = uploaded.sent?.id ? String(uploaded.sent.id) : "";
        result.durationMs = durationMs;
        result.hashBytes = uploaded.hashBytes;
      } catch (error) {
        result.error = safeError(error);
      }

      appendLine(resultPath, result);
      fs.appendFileSync(donePath, `${id}\n`, "utf8");
      done.add(id);
      console.log(JSON.stringify({ id, ok: result.ok, backend: "linejs" }));
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, fatal: safeError(error) }));
  process.exit(1);
});
