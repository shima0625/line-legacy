import fs from "node:fs";
import path from "node:path";
import { BaseClient } from "@evex/linejs/base";
import { FileStorage } from "@evex/linejs/storage";

export const legacyDir = process.env.LINE_LEGACY_DIR ?? "/opt/line-legacy";
export const bridgeDir = process.env.LINEJS_BRIDGE_DIR ?? path.join(legacyDir, "linejs-bridge");

export function safeError(error) {
  return String(error?.message ?? error ?? "unknown error")
    .replace(/[ucrpmstv][0-9a-f]{32}/gi, "[mid]")
    .replace(/[A-Za-z0-9_+\/=.-]{80,}/g, "[secret]")
    .slice(0, 240);
}

// ★端末種別・版・ストレージは bridge_worker.json で一元管理する。
//   ここを DESKTOPWIN 固定にしていたため、ブリッジを IOSIPAD の別アカウントへ
//   切り替えたあと video_worker と call_route_helper だけが
//   AUTHENTICATION_FAILED になっていた(2026-09-09)。トークンだけ差し替えても駄目で、
//   種別・版・ストレージが揃っている必要がある。
//
//   既定値もワーカー間で揃える。ここだけ DESKTOPWIN/storage.json にしていたため、
//   bridge_worker.json が無い環境では bridge_worker が iosipad-storage.json を
//   読む一方で video/call が空の storage.json を作り、そちらだけ
//   AUTHENTICATION_FAILED で再起動を繰り返していた。
export const WORKER_CONF_DEFAULTS = {
  device: "IOSIPAD",
  version: "26.14.1",
  tokenFile: "authtoken.txt",            // legacyDir からの相対でも絶対でも可
  storageFile: "iosipad-storage.json",   // bridgeDir 基準
};

export function loadWorkerConf(extraDefaults = {}) {
  const defaults = { ...WORKER_CONF_DEFAULTS, ...extraDefaults };
  try {
    return { ...defaults,
      ...JSON.parse(fs.readFileSync(path.join(bridgeDir, "bridge_worker.json"), "utf8")) };
  } catch {
    return defaults;
  }
}

export async function createClient() {
  const conf = loadWorkerConf();
  const resolve = (base, file) => path.isAbsolute(file) ? file : path.join(base, file);
  const tokenPath = resolve(legacyDir, conf.tokenFile);
  const storagePath = resolve(bridgeDir, conf.storageFile);
  const authToken = fs.readFileSync(tokenPath, "utf8").trim();
  if (!authToken) throw new Error("auth token is empty");

  const storage = new FileStorage(storagePath);
  const client = new BaseClient({
    device: conf.device,
    version: conf.version,
    storage,
  });
  await client.loginProcess.login({ authToken });
  if (!client.profile?.mid) throw new Error("profile was not loaded");
  return { client, storage };
}

export async function checkSelfKey(client, storage) {
  const localRaw = await storage.get(`e2eeKeys:${client.profile.mid}`);
  if (typeof localRaw !== "string") {
    return { localKey: false, serverKey: false };
  }
  let local;
  try {
    local = JSON.parse(localRaw);
  } catch {
    return { localKey: false, serverKey: false };
  }
  const registered = await client.talk.getE2EEPublicKeys();
  const serverKey = Array.isArray(registered) && registered.some((item) => {
    const id = item?.keyId ?? item?.[2];
    return String(id) === String(local?.keyId);
  });
  return {
    localKey: Boolean(local?.keyId && local?.privKey && local?.pubKey),
    serverKey,
  };
}
