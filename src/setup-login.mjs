import fs from "node:fs";
import path from "node:path";
import readline from "node:readline/promises";
import process from "node:process";
import { Buffer } from "node:buffer";
import crypto from "node:crypto";
import qr from "qrcode-terminal";
import { BaseClient } from "@evex/linejs/base";
import { FileStorage } from "@evex/linejs/storage";

const LEGACY_DIR = process.env.LINE_LEGACY_DIR ?? "/opt/line-legacy";
const BRIDGE_DIR = process.env.LINEJS_BRIDGE_DIR ?? path.join(LEGACY_DIR, "linejs-bridge");
const choices = {
  "1": { label: "iPad版（推奨・Windows版と共存）", device: "IOSIPAD", version: "26.14.1", model: "IOSIPAD", system: "iOS" },
  "2": { label: "Windows版（公式Windows版と枠を共有）", device: "DESKTOPWIN", version: "9.8.0.3597", model: "Windows", system: "WINDOWS" },
  "3": { label: "Mac版", device: "DESKTOPMAC", version: "9.8.0", model: "Mac", system: "MAC" },
};

function atomicWrite(file, value) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, value, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function backup(file) {
  if (!fs.existsSync(file)) return;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  fs.copyFileSync(file, `${file}.bak-${stamp}`);
}

/** QRハンドシェイクの鍵束から、このアカウントの既存鍵を取り出して保存する。
 *
 * ★linejsの`decodeE2EEKeyV1`は使えない。鍵束は**アカウントの鍵の履歴が古い順に
 *   並んだ配列**なのに、無条件に先頭(=一番古い鍵)を取るため、サーバ登録鍵との
 *   照合に必ず失敗してundefinedを返す。その結果「既存鍵を再利用できない」と
 *   誤判定し、新規登録に落ちて**利用者の他端末のLetter Sealingを奪う**。
 *   正しくは、サーバに登録されているkeyIdの公開鍵と一致する要素を選ぶ。
 */
async function adoptKeyFromChain(client, storage, info, secret, selfMid) {
  const publicKey = Buffer.from(info.publicKey, "base64");
  const encrypted = Buffer.from(info.encryptedKeyChain, "base64");
  const shared = client.e2ee.generateSharedSecret(Buffer.from(secret), publicKey);
  const aesKey = client.e2ee.getSHA256Sum(Buffer.from(shared), "Key");
  const aesIv = client.e2ee.xor(client.e2ee.getSHA256Sum(Buffer.from(shared), "IV"));
  const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, aesIv);
  decipher.setAutoPadding(false);
  const plain = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  const list = client.thrift.readThriftStruct(plain)[1];
  if (!Array.isArray(list) || !list.length) throw new Error("鍵束が空です");

  // サーバに登録されているkeyIdの公開鍵を正とする。
  let target = null;
  try {
    for (const key of (await client.talk.getE2EEPublicKeys()) ?? []) {
      if (String(key?.keyId ?? key?.[2]) !== String(info.keyId)) continue;
      const data = key?.keyData ?? key?.[4];
      if (data) target = Buffer.from(data);
      break;
    }
  } catch { /* 照合できないときは最新の鍵で代用する */ }

  const usable = [];
  for (const entry of list) {
    if (!entry?.[4] || !entry?.[5]) continue;
    const pub = Buffer.from(entry[4]);
    const priv = Buffer.from(entry[5]);
    if (!client.e2ee.verifyE2EEKeyPair(priv, pub)) continue;
    usable.push({ pub, priv });
  }
  // 一致するものを選ぶ。選べないときは**最後(最新)**。先頭は一番古い鍵なので使わない。
  const chosen = (target && usable.find((k) => k.pub.equals(target))) || usable[usable.length - 1];
  if (!chosen) throw new Error("鍵束から使える鍵を選べませんでした");

  const keyData = {
    keyId: info.keyId,
    privKey: chosen.priv.toString("base64"),
    pubKey: chosen.pub.toString("base64"),
    e2eeVersion: Number(info.e2eeVersion ?? 1),
  };
  // ★keyId 名義と mid 名義の両方で保存する。linejs の `saveE2EESelfKeyData()` は
  //   `client.profile?.mid` を見るが、このスクリプトは `login()` を通さないので
  //   その値が未設定で、`e2eeKeys:undefined` という使えない名前で保存されてしまう。
  //   ブリッジ側(`bridge_worker.mjs` の ensureE2EEKey)は mid 名義で探す。
  await storage.set("e2eeKeys:" + info.keyId, JSON.stringify(keyData));
  await storage.set("e2eeKeys:" + selfMid, JSON.stringify(keyData));
  return { keyId: info.keyId, chainSize: list.length,
           matchedServer: Boolean(target && chosen.pub.equals(target)) };
}

async function chooseDevice() {
  if (process.argv.includes("--help")) {
    console.log("使い方: node setup-login.mjs\n対話画面でクライアント種別を選び、表示されたQRをLINEで読み取ります。");
    process.exit(0);
  }
  const ui = readline.createInterface({ input: process.stdin, output: process.stdout });
  console.log("\nLINE Bridge 初回ログイン\n");
  for (const [key, item] of Object.entries(choices)) console.log(`  ${key}. ${item.label}`);
  const answer = (await ui.question("\n接続種別 [1]: ")).trim() || "1";
  ui.close();
  if (!choices[answer]) throw new Error("1〜3を選んでください");
  return choices[answer];
}

async function main() {
  const selected = await chooseDevice();
  const workDir = fs.mkdtempSync(path.join(BRIDGE_DIR, ".login-"));
  const storageFile = path.join(workDir, "storage.json");
  const storage = new FileStorage(storageFile);
  const client = new BaseClient({ device: selected.device, version: selected.version, storage });
  const lp = client.loginProcess;

  console.log(`\n${selected.label} としてQRを生成しています…`);
  const { 1: session } = await lp.createSession();
  const secure = await lp.createQrCodeForSecure(session);
  const secretPair = client.e2ee.createSqrSecret();
  const secret = secretPair[0];
  const loginUrl = secure[1] + secretPair[1];
  const maxCount = secure[2] ?? 12;
  const interval = secure[3] ?? 30;
  const nonce = secure[4] ?? "";

  console.log("\nLINEのQRコードリーダーで読み取ってください。\n");
  qr.generate(loginUrl, { small: true });
  console.log("\n承認を待っています…");
  if (!await lp.checkQrCodeVerified(session, maxCount, interval)) throw new Error("QRコードの有効期限が切れました");

  try {
    await lp.verifyCertificate(session, await lp.getQrCert());
  } catch {
    const { 1: pin } = await lp.createPinCode(session);
    console.log(`\n確認番号: ${pin}\nLINE側でこの番号を確認してください。`);
    await lp.checkPinCodeVerified(session, maxCount, interval);
  }

  const response = await client.request.request(
    [[12, 1, [[11, 1, session], [11, 2, selected.system], [2, 3, true], [11, 4, nonce]]]],
    "qrCodeLoginForSecure", 4, false, "/acct/lgn/sq/v1",
  );
  const { 1: certificate, 2: authToken, 4: metadata } = response;
  if (!authToken) throw new Error("認証トークンを取得できませんでした");
  if (certificate) await lp.registerQrCert(certificate);
  client.authToken = authToken;
  // ★鍵の保存は profile.mid を使うので、E2EE の前にプロフィールを取る。
  const profile = await client.talk.getProfile();
  if (!profile?.mid) throw new Error("プロフィールを確認できませんでした");

  // ★Token V2(qrCodeLoginForSecure)は鍵束を**metaDataの直下**に入れて返す。
  //   linejsのV3実装に合わせて`metaData.e2eeInfo`だけを見ると毎回「無い」と判定し、
  //   新規登録のフォールバックに落ちる。実際のキーは
  //   encryptedKeyChain / hashKeyChain / keyId / publicKey / e2eeVersion。
  const e2eeInfo = metadata?.e2eeInfo
    ?? (metadata?.encryptedKeyChain ? metadata : null);
  let adopted = null;
  if (e2eeInfo?.encryptedKeyChain) {
    adopted = await adoptKeyFromChain(client, storage, e2eeInfo, secret, profile.mid);
    console.log(`E2EE鍵を引き継ぎました keyId=${adopted.keyId} `
      + `鍵束=${adopted.chainSize}本 サーバ照合=${adopted.matchedServer ? "一致" : "未照合"}`);
  } else if (process.env.ALLOW_E2EE_REGISTER === "1") {
    // ★専用アカウント限定。本アカウントで実行すると、送信側は受信者の最新鍵しか
    //   使わないため、同じアカウントの他端末(スマホ)のLetter Sealingを奪う。
    const registered = await client.e2ee.registerE2EEKeyPair();
    if (!registered) throw new Error("E2EE鍵の新規登録に失敗しました");
    console.log(`E2EE鍵を新規登録しました keyId=${registered.keyId}`);
  } else {
    throw new Error(
      "QRの応答に鍵束が含まれていませんでした。E2EE鍵なしで続けると暗号化メッセージを"
      + "送受信できません。どうしても新規登録する場合のみ ALLOW_E2EE_REGISTER=1 を付けて"
      + "再実行してください（他端末のLetter Sealingを奪うため専用アカウント限定です）。",
    );
  }
  const tokenFile = path.join(LEGACY_DIR, "authtoken.txt");
  const finalStorage = path.join(BRIDGE_DIR, `${selected.device.toLowerCase()}-storage.json`);
  const configFile = path.join(BRIDGE_DIR, "bridge_worker.json");
  const identityFile = path.join(LEGACY_DIR, "bridge_identity.json");
  backup(tokenFile); backup(finalStorage); backup(configFile); backup(identityFile);
  fs.copyFileSync(storageFile, finalStorage);
  fs.chmodSync(finalStorage, 0o600);
  atomicWrite(tokenFile, `${authToken}\n`);
  atomicWrite(configFile, `${JSON.stringify({
    device: selected.device,
    version: selected.version,
    tokenFile: "authtoken.txt",
    storageFile: path.basename(finalStorage),
  }, null, 2)}\n`);
  // ★Python側のゲートウェイは bridge_worker.json を読まない。トークン・mid・
  //   X-Line-Application の3点が揃っていないと、中継した要求が実サーバに
  //   Authentication Failed で弾かれる。同じログインから3点まとめて書き出す。
  atomicWrite(identityFile, `${JSON.stringify({
    label: profile.displayName ?? selected.device,
    token_file: "authtoken.txt",
    mid: profile.mid,
    app: client.request.systemType,
  }, null, 2)}
`);
  fs.rmSync(workDir, { recursive: true, force: true });
  console.log(`\nログイン完了: ${profile.displayName ?? "LINEユーザー"}`);
  console.log("LINE Bridgeサービスを再起動すると新しいセッションが有効になります。");
}

main().catch((error) => {
  console.error(`\nエラー: ${String(error?.message ?? error)}`);
  process.exitCode = 1;
});
