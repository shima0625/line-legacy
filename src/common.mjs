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
function loadWorkerConf() {
  const defaults = {
    device: "DESKTOPWIN", version: "9.8.0.3597",
    tokenFile: "authtoken.txt", storageFile: "storage.json",
  };
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
