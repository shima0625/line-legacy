/**
 * linejs 版ブリッジ常駐ワーカー。bridge_daemon.py(CHRLINE) の中核部分を置き換える。
 *
 * なぜ linejs か: CHRLINE 版は起動のたびに **メール+パスワードで新規ログイン**する作りで、
 * 別アカウントへ切り替えるには資格情報とログイン1回分のリスクが要る。linejs なら
 * **保存済みトークンをそのまま使う**ので、ログインを一切踏まずにアカウントを替えられる。
 * PC版LINEの枠も奪わない(IOSIPAD 枠を使う)。
 *
 * ファイル入出力は bridge_daemon.py と**同じ形式**にしてあるので、母艦側
 * (recv_worker_371 / local_worker / legy_proxy) は変更不要。
 *   受信: talk.sync を回して recv_out.jsonl に追記
 *   送信: send_in.jsonl を追尾して配送し、結果を send_out.jsonl / send_done.txt へ
 *   認証: authtoken.txt を書く(local_worker が real_token.txt へ複製する)
 *   ダンプ: profile.json / contacts.json / groups.json
 *
 * メディア、スタンプ、既読、着信通知を含む現行アカウント側の処理を担当し、
 * 旧クライアント固有の変換はPythonゲートウェイとCDNプロキシが担当する。
 *
 * Run: cd ~/line-legacy/linejs-bridge && node bridge_worker.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { Buffer } from "node:buffer";
import dgram from "node:dgram";
import { execFileSync } from "node:child_process";
import nacl from "tweetnacl";
import { BaseClient } from "@evex/linejs/base";
import { FileStorage } from "@evex/linejs/storage";
import { loadWorkerConf } from "./common.mjs";

const legacyDir = process.env.LINE_LEGACY_DIR ?? "/opt/line-legacy";
const bridgeDir = process.env.LINEJS_BRIDGE_DIR ?? path.join(legacyDir, "linejs-bridge");

// 端末種別・版・トークン・ストレージは common.mjs と共通の既定値を使い、
// bridge_worker.json で上書きする。ここに別の既定値を置くと、動画・通話の
// ワーカーと違うアカウントやストレージを掴む事故に戻る。
const WORKER_DEFAULTS = {
  writeAuthToken: true,   // authtoken.txt を書く(= real_token.txt へ波及する)
  dumpMaxAgeHours: 12,
  syncIntervalMs: 1500,
  sendPollMs: 700,
};

const RECV_OUT = path.join(legacyDir, "recv_out.jsonl");
const SEND_IN = path.join(legacyDir, "send_in.jsonl");
const SEND_OUT = path.join(legacyDir, "send_out.jsonl");
const SEND_DONE = path.join(legacyDir, "send_done.txt");
const AUTH_TOKEN = path.join(legacyDir, "authtoken.txt");
const PROFILE_JSON = path.join(legacyDir, "profile.json");
const CONTACTS_JSON = path.join(legacyDir, "contacts.json");
const GROUPS_JSON = path.join(legacyDir, "groups.json");
const HIDDEN_MIDS_JSON = path.join(legacyDir, "hidden_mids.json");
const RECOMMENDATION_MIDS_JSON = path.join(legacyDir, "recommendation_mids.json");
const RECOMMENDATION_CONTACTS_JSON = path.join(legacyDir, "recommendation_contacts.json");
const REV_STATE = path.join(bridgeDir, "worker_revision.json");
const CALL_OPS = path.join(legacyDir, "call_ops.jsonl");
const INCOMING_RING = path.join(bridgeDir, "incoming_ring.json");
const NATIVE_CALL_FLAG = path.join(legacyDir, "skyglow_native_call.enabled");
const PHONE_IP = process.env.LINE_LEGACY_PHONE_IP ?? "127.0.0.1";
const RING_PORT = Number(process.env.RING_PORT ?? 17390);
const SERVER_IP = process.env.LINE_LEGACY_SERVER_IP ?? "127.0.0.1";
const MEDIA = path.join(legacyDir, "media");
const UPLOAD = path.join(legacyDir, "upload");   // cdn_proxy が実機の実体を置く
const VIDEO_IN = path.join(bridgeDir, "video_in.jsonl");
const VIDEO_OUT = path.join(bridgeDir, "video_out.jsonl");
const VIDEO_ENABLED = path.join(bridgeDir, "video_enabled");
const PREVIEW_MAX = Number(process.env.PREVIEW_MAX ?? 720);
const OBJ_TYPE_BY_CONTENT = { 1: "image", 2: "video", 3: "audio" };
const MEDIA_EXT = { image: "jpg", video: "mp4", audio: "m4a" };

function log(message) {
  const t = new Date().toTimeString().slice(0, 8);
  console.log(`[${t}] ${message}`);
}

function safeError(error) {
  return String(error?.message ?? error ?? "unknown error")
    .replace(/[A-Za-z0-9_+/=.-]{80,}/g, "[secret]")
    .slice(0, 240);
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJsonAtomic(file, value) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(value, (_k, v) =>
    typeof v === "bigint" ? String(v) : v), "utf8");
  fs.renameSync(tmp, file);
}

function appendLine(file, value) {
  fs.appendFileSync(file, JSON.stringify(value, (_k, v) =>
    typeof v === "bigint" ? String(v) : v) + "\n", "utf8");
}

function removeRecommendation(mid) {
  const mids = readJson(RECOMMENDATION_MIDS_JSON, []);
  const contacts = readJson(RECOMMENDATION_CONTACTS_JSON, []);
  if (Array.isArray(mids)) writeJsonAtomic(RECOMMENDATION_MIDS_JSON,
    mids.filter((value) => String(value) !== mid));
  if (Array.isArray(contacts)) writeJsonAtomic(RECOMMENDATION_CONTACTS_JSON,
    contacts.filter((value) => String(value?.mid ?? "") !== mid));
}

const CONF = loadWorkerConf(WORKER_DEFAULTS);

function resolveIn(base, file) {
  return path.isAbsolute(file) ? file : path.join(base, file);
}

// ---------------------------------------------------------------- ログイン
// ★保存済みトークンでの login のみ。QR もパスワードも踏まない。
// 空のストレージで login を呼ぶと別端末扱いになり、生きているセッションを蹴るので
// ストレージは**取得時と同じファイル**を必ず使うこと。
const tokenPath = resolveIn(legacyDir, CONF.tokenFile);
const storagePath = resolveIn(bridgeDir, CONF.storageFile);
const authToken = fs.readFileSync(tokenPath, "utf8").trim();
if (!authToken) throw new Error(`${tokenPath} が空です`);
if (!fs.existsSync(storagePath)) {
  throw new Error(`${storagePath} が見つかりません。トークンを取得したときのストレージが要ります`);
}

const storage = new FileStorage(storagePath);
const client = new BaseClient({ device: CONF.device, version: CONF.version, storage });
await client.loginProcess.login({ authToken });
const SELF_MID = client.profile?.mid;
if (!SELF_MID) throw new Error("プロフィールを取得できませんでした");
log(`ログイン成功 ${client.request.systemType} mid=${SELF_MID}`);

// ★E2EE 自己鍵。QR ForSecure ログインは鍵を作らないので、ストレージが空のままだと
//   1対1トークの送信が丸ごと
//   "E2EE Key has not been saved" で失敗する。新しい端末と同じ手順で登録する。
async function ensureE2EEKey() {
  // ★鍵を勝手に新規登録してはいけない。
  //   LINE の送信側は受信者の**最新の鍵だけ**を使うので、ここで登録すると
  //   同じアカウントの他端末(利用者のスマホ)の Letter Sealing を奪う。
  //   正しい鍵は QR ログイン時に鍵束から取り込む(setup-login.mjs の adoptKeyFromChain)。
  //   ここは「今ある鍵が使えるか」を確かめて、駄目なら**声を上げて止まる**だけにする。
  //   どうしても登録したい場合だけ ALLOW_E2EE_REGISTER=1(専用アカウント限定)。
  let local = null;
  try {
    const raw = await storage.get(`e2eeKeys:${SELF_MID}`);
    if (typeof raw === "string" && raw) local = JSON.parse(raw);
  } catch { /* 無い扱い */ }

  let newest = null;
  try {
    const registered = await client.talk.getE2EEPublicKeys();
    const keys = (Array.isArray(registered) ? registered : []).map((item) => ({
      keyId: item?.keyId ?? item?.[2],
      createdTime: Number(item?.createdTime ?? item?.[5] ?? 0),
    }));
    newest = keys.reduce((a, b) => (b.createdTime > (a?.createdTime ?? -1) ? b : a), null);
  } catch (error) {
    log(`E2EE 鍵一覧の取得に失敗 ${safeError(error)}`);
  }

  if (local && newest && String(newest.keyId) === String(local.keyId)) {
    log(`E2EE 自己鍵あり(最新) keyId=${local.keyId}`);
    return;
  }
  if (local) {
    log(`⚠ E2EE 自己鍵 keyId=${local.keyId} は最新ではありません(最新=${newest?.keyId})。`);
    log("  一次端末が鍵を更新した可能性があります。QRログインし直して鍵束を取り込んでください:");
    log(`  node setup-login.mjs`);
    log("  ここで新規登録すると利用者のスマホの Letter Sealing を奪うので、登録はしません。");
    if (process.env.ALLOW_E2EE_REGISTER !== "1") return;
  } else {
    log("E2EE 自己鍵がありません。QRログインで鍵束を取り込んでください。");
    if (process.env.ALLOW_E2EE_REGISTER !== "1") return;
  }

  log("ALLOW_E2EE_REGISTER=1 のため新規登録します(専用アカウント以外では使わないこと)");
  const pair = nacl.box.keyPair();
  const registered = await client.talk.registerE2EEPublicKey({
    publicKey: {
      version: 1, keyId: 0,
      keyData: Buffer.from(pair.publicKey), createdTime: 0,
    },
  });
  const keyData = {
    keyId: registered.keyId,
    privKey: Buffer.from(pair.secretKey).toString("base64"),
    pubKey: Buffer.from(pair.publicKey).toString("base64"),
    e2eeVersion: 1,
  };
  await storage.set("e2eeKeys:" + registered.keyId, JSON.stringify(keyData));
  await client.e2ee.saveE2EESelfKeyData(keyData);
  log(`E2EE 鍵を登録 keyId=${registered.keyId}`);
}

await ensureE2EEKey();

if (CONF.writeAuthToken) {
  fs.writeFileSync(AUTH_TOKEN, client.authToken ?? authToken, "utf8");
  log(`authtoken.txt を更新 (${(client.authToken ?? authToken).length} chars)`);
}

// -------------------------------------------------------------- ダンプ類
// profile.json は旧アプリ向けに **Thrift のフィールド番号をキー**にした形で持つ。
// legy_proxy がこれをそのまま Profile 構造体へ組み立て直すため、名前ではなく番号。
const PROFILE_FIELD_IDS = {
  mid: 1, userid: 3, phone: 10, email: 11, regionCode: 12,
  displayName: 20, phoneticName: 21, pictureStatus: 22, thumbnailUrl: 23,
  statusMessage: 24, allowSearchByUserid: 31, allowSearchByEmail: 32,
  picturePath: 33, musicProfile: 34, videoProfile: 35,
  statusMessageContentMetadata: 36, avatarProfile: 37, nftProfile: 38,
};

async function dumpProfile() {
  try {
    const profile = await client.talk.getProfile();
    const out = {};
    for (const [name, id] of Object.entries(PROFILE_FIELD_IDS)) {
      const value = profile?.[name];
      if (value !== undefined && value !== null) out[String(id)] = value;
    }
    writeJsonAtomic(PROFILE_JSON, out);
    log(`profile dumped: name=${out["20"]} picture=${Boolean(out["22"])}`);
    return true;
  } catch (error) {
    log(`profile dump err ${safeError(error)}`);
    return false;
  }
}

function dumpIsFresh() {
  if (process.env.FORCE_DUMP === "1") return false;
  const maxAge = Number(CONF.dumpMaxAgeHours) * 3600 * 1000;
  for (const file of [CONTACTS_JSON, GROUPS_JSON]) {
    try {
      if (Date.now() - fs.statSync(file).mtimeMs > maxAge) return false;
    } catch {
      return false;
    }
  }
  return true;
}

async function dumpContactsAndGroups(force = false) {
  if (!force && dumpIsFresh()) {
    log("連絡先/グループのダンプは十分新しいので省略");
    return;
  }
  try {
    const ids = await client.talk.getAllContactIds();
    const contacts = [];
    // getContacts は一度に取れる件数に上限があるので分割する。
    for (let i = 0; i < ids.length; i += 100) {
      const chunk = await client.talk.getContacts({ mids: ids.slice(i, i + 100) });
      for (const c of chunk ?? []) contacts.push(legacyContact(c));
    }
    writeJsonAtomic(CONTACTS_JSON, contacts);
    log(`contacts dumped: ${contacts.length}`);
    // 非表示は Contact.settings の CONTACT_SETTING_CONTACT_HIDE(4)。linejs に
    // getHiddenContactMids は無いので、ダンプのたびにここから作り直す。
    const hidden = contacts.filter((c) => Number(c.settings ?? 0) & 4).map((c) => String(c.mid));
    fs.writeFileSync(HIDDEN_MIDS_JSON + ".tmp", JSON.stringify(hidden.sort()), { mode: 0o600 });
    fs.renameSync(HIDDEN_MIDS_JSON + ".tmp", HIDDEN_MIDS_JSON);
    log(`hidden contacts: ${hidden.length}`);
  } catch (error) {
    log(`contacts dump err ${safeError(error)}`);
  }
  try {
    // getAllChatMids は request を1段包む(素で渡すと ILLEGAL_ARGUMENT)。
    const chatMids = await client.talk.getAllChatMids({
      request: { withMemberChats: true, withInvitedChats: true },
      syncReason: "INTERNAL",
    });
    // getAllChatMids は {memberChatMids, invitedChatMids} を返す実装と
    // 素の配列を返す実装がある。どちらでも拾えるようにする。
    const mids = Array.isArray(chatMids)
      ? chatMids
      : [...(chatMids?.memberChatMids ?? []), ...(chatMids?.invitedChatMids ?? [])];
    const groups = [];
    for (let i = 0; i < mids.length; i += 50) {
      const chats = await client.talk.getChats({ chatMids: mids.slice(i, i + 50) });
      for (const chat of chats?.chats ?? chats ?? []) {
        groups.push(legacyGroup(chat));
      }
    }
    writeJsonAtomic(GROUPS_JSON, groups);
    log(`groups dumped: ${groups.length}`);
    // グループの非友だちメンバー/招待者を解決する。3.7.1 の「トークメンバー」画面と
    // 参加/招待の名前表示は getContacts の応答を使うが、友だち以外は contacts.json に
    // 居ないので名前もアイコンも出ない。member_contacts.json に補完する。
    await refreshMemberContacts(groups);
  } catch (error) {
    log(`groups dump err ${safeError(error)}`);
  }
}

const MEMBER_CONTACTS_JSON = path.join(legacyDir, "member_contacts.json");

/** グループ参加者のうち友だち以外の Contact を解決して保存する(名前・アイコン用)。 */
async function refreshMemberContacts(groups) {
  const valid = (mid) => /^u[0-9a-f]{32}$/.test(mid);
  const friends = new Set((readJson(CONTACTS_JSON, []) || []).map((c) => String(c.mid)));
  const wanted = new Set();
  for (const g of groups || []) {
    for (const list of [g.members, g.invitee]) {
      for (const m of list || []) {
        const mid = String(m?.mid ?? m ?? "");
        if (valid(mid) && mid !== SELF_MID && !friends.has(mid)) wanted.add(mid);
      }
    }
  }
  if (!wanted.size) return;
  const prev = readJson(MEMBER_CONTACTS_JSON, {});
  const records = prev && typeof prev === "object" && !Array.isArray(prev) ? prev : {};
  const targets = [...wanted];
  let got = 0;
  for (let i = 0; i < targets.length; i += 100) {
    try {
      for (const contact of await client.talk.getContacts({ mids: targets.slice(i, i + 100) }) ?? []) {
        const r = legacyContact(contact);
        if (!valid(String(r.mid ?? ""))) continue;
        got++;
        records[r.mid] = {
          mid: r.mid, type: r.type, status: r.status, relation: r.relation,
          displayName: r.displayName ?? "", pictureStatus: r.pictureStatus ?? "",
          picturePath: r.picturePath ?? "", statusMessage: r.statusMessage ?? "",
          attributes: r.attributes, capableBuddy: Boolean(r.capableBuddy),
        };
      }
    } catch (error) {
      log(`MEMBER-CONTACTS getContacts failed ${safeError(error)}`);
    }
  }
  // 友だちになった/グループから消えた mid は残しても害はないが、肥大を防ぐため現メンバーだけ残す。
  for (const mid of Object.keys(records)) if (!wanted.has(mid)) delete records[mid];
  fs.writeFileSync(MEMBER_CONTACTS_JSON + ".tmp", JSON.stringify(records), { mode: 0o600 });
  fs.renameSync(MEMBER_CONTACTS_JSON + ".tmp", MEMBER_CONTACTS_JSON);
  log(`MEMBER-CONTACTS ${Object.keys(records).length} (resolved ${got}/${targets.length})`);
}

// ★linejs は enum を**名前(文字列)**で返す。CHRLINE 版は数値で書いていたので、
// そのまま渡すと legy_proxy の encode_contact が
// `int('QRCODE')` で落ちて友だち一覧ごと出なくなる。数値へ戻してから書く。
const CONTACT_TYPE = {
  MID: 0, PHONE: 1, EMAIL: 2, USERID: 3, PROXIMITY: 4, GROUP: 5, USER: 6,
  QRCODE: 7, PROMOTION_BOT: 8, CONTACT_MESSAGE: 9, FRIEND_REQUEST: 10,
  BEACON: 11, REPAIR: 128, FACEBOOK: 2305, SINA: 2306, RENREN: 2307,
  FEIXIN: 2308, BBM: 2309,
};
const CONTACT_STATUS = {
  UNSPECIFIED: 0, FRIEND: 1, FRIEND_BLOCKED: 2, RECOMMEND: 3,
  RECOMMEND_BLOCKED: 4, DELETED: 5, DELETED_BLOCKED: 6,
};
// ContactRelation は linejs の enums に無いので自前で持つ。
const CONTACT_RELATION = { ONEWAY: 0, BOTH: 1, NOT_REGISTERED: 2 };
// ★メッセージの contentType / toType も linejs は名前で返す。数値で書かないと
//   母艦の local_worker が int("STICKER") で落ち、**受信キューが丸ごと止まる**。
const CONTENT_TYPE = {
  NONE: 0, IMAGE: 1, VIDEO: 2, AUDIO: 3, HTML: 4, PDF: 5, CALL: 6, STICKER: 7,
  PRESENCE: 8, GIFT: 9, GROUPBOARD: 10, APPLINK: 11, LINK: 12, CONTACT: 13,
  FILE: 14, LOCATION: 15, POSTNOTIFICATION: 16, RICH: 17, CHATEVENT: 18,
  MUSIC: 19, PAYMENT: 20, EXTIMAGE: 21, FLEX: 22,
};
const MID_TYPE = {
  USER: 0, ROOM: 1, GROUP: 2, SQUARE: 3, SQUARE_CHAT: 4, SQUARE_MEMBER: 5,
  BOT: 6, SQUARE_THREAD: 7, PEER: 0,
};

function enumToInt(value, table) {
  if (typeof value === "number") return value;
  if (typeof value === "string" && table[value] !== undefined) return table[value];
  return 0;
}

/** 現行 Contact を、旧アプリ向け contacts.json の形へ寄せる。 */
function legacyContact(contact) {
  return {
    ...contact,
    type: enumToInt(contact?.type, CONTACT_TYPE),
    status: enumToInt(contact?.status, CONTACT_STATUS),
    relation: enumToInt(contact?.relation, CONTACT_RELATION),
    attributes: Number(contact?.attributes ?? 0),
  };
}

/** 現行 Chat を、旧アプリ向け groups.json の形へ寄せる。

    legy_proxy の `_load_legacy_groups` は members / invitee に自分の mid が
    居るかで「参加中」と「招待中」を振り分ける。members が空だとそのグループは
    旧アプリから消えるので、`extra.groupExtra.memberMids` を必ず展開すること。
    名前と画像は `_encode_group_contact` が contacts.json から引くので mid だけでよい。 */
function legacyGroup(chat) {
  const extra = chat?.extra?.groupExtra ?? {};
  const mids = (value) => Object.keys(value ?? {}).map((mid) => ({ mid }));
  return {
    id: chat?.chatMid ?? "",
    name: chat?.chatName ?? "",
    // encode_group が先頭の "/" を落とすが、旧ダンプに合わせてここでも外す。
    picture: String(chat?.picturePath ?? "").replace(/^\//, ""),
    creator: extra.creator ?? "",
    members: mids(extra.memberMids),
    invitee: mids(extra.inviteeMids),
    createdTime: chat?.createdTime != null ? Number(chat.createdTime) : undefined,
    notificationDisabled: Boolean(chat?.notificationDisabled),
  };
}

// ------------------------------------------------------------------ 受信
const LEGACY_GROUP_OPS = new Map([
  [120, 9], [121, 10], [122, 11], [123, 12], [124, 13], [125, 31], [126, 32],
  [127, 14], [128, 15], [129, 16], [130, 17], [131, 34], [132, 18],
]);
for (let n = 9; n < 20; n++) LEGACY_GROUP_OPS.set(n, n);
for (const n of [31, 32, 34, 35]) LEGACY_GROUP_OPS.set(n, n);

// linejs は op.type を名前(文字列)で返す。bridge_daemon は番号で分岐していたので
// 突き合わせ表を持つ。知らない名前は数値化を試みる。
const OP_TYPE_IDS = {
  UPDATE_PROFILE: 1, NOTIFIED_UPDATE_PROFILE: 2,
  ADD_CONTACT: 4, NOTIFIED_ADD_CONTACT: 5, BLOCK_CONTACT: 6,
  UNBLOCK_CONTACT: 7, NOTIFIED_RECOMMEND_CONTACT: 8, UPDATE_CONTACT: 49,
  SEND_MESSAGE: 25, RECEIVE_MESSAGE: 26,
  NOTIFIED_READ_MESSAGE: 55,
  NOTIFIED_RECEIVED_CALL: 50, NOTIFIED_CANCEL_CALL: 51,
  CREATE_CHAT: 120, UPDATE_CHAT: 121, NOTIFIED_UPDATE_CHAT: 122,
  INVITE_INTO_CHAT: 123, NOTIFIED_INVITE_INTO_CHAT: 124,
  CANCEL_CHAT_INVITATION: 125, NOTIFIED_CANCEL_CHAT_INVITATION: 126,
  DELETE_SELF_FROM_CHAT: 127, NOTIFIED_DELETE_SELF_FROM_CHAT: 128,
  ACCEPT_CHAT_INVITATION: 129, NOTIFIED_ACCEPT_CHAT_INVITATION: 130,
  REJECT_CHAT_INVITATION: 131, DELETE_OTHER_FROM_CHAT: 132,
};

function opTypeId(op) {
  const raw = op?.type;
  if (typeof raw === "number") return raw;
  if (typeof raw === "string") {
    if (OP_TYPE_IDS[raw] !== undefined) return OP_TYPE_IDS[raw];
    const n = Number(raw);
    if (Number.isFinite(n)) return n;
  }
  return -1;
}

const seenOpTypes = new Set();
const revState = readJson(REV_STATE, {});
const sync = {
  revision: BigInt(revState.revision ?? 0),
  globalRev: BigInt(revState.globalRev ?? 0),
  individualRev: BigInt(revState.individualRev ?? 0),
};

function saveRev() {
  writeJsonAtomic(REV_STATE, {
    revision: String(sync.revision),
    globalRev: String(sync.globalRev),
    individualRev: String(sync.individualRev),
  });
}

async function messageRecord(msg) {
  let message = msg;
  // E2EE のトークは復号しないと text が null のままになる。
  if (message?.contentMetadata?.e2eeVersion || message?.chunks?.length) {
    try {
      message = await client.e2ee.decryptE2EEMessage(message);
    } catch (error) {
      log(`decrypt err ${safeError(error)}`);
    }
  }
  const record = {
    from: message?._from ?? message?.from ?? message?.from_ ?? null,
    to: message?.to ?? null,
    toType: enumToInt(message?.toType, MID_TYPE),
    text: message?.text ?? null,
    id: message?.id != null ? String(message.id) : null,
    createdTime: Number(message?.createdTime ?? Date.now()),
    contentType: enumToInt(message?.contentType, CONTENT_TYPE),
    contentMetadata: message?.contentMetadata ?? {},
  };
  return { record, message };
}

/** 受信メディアを実機が取りに来る場所へ置く。

    LINE 3.7.1 は /os/m/<msgid> と /os/m/<msgid>/preview を要求する。cdn_proxy が
    media/<msgid> と media/<msgid>_preview を返すので、ここで両方作る。
    原寸をそのままプレビューに使うと iOS6 側がデコードできないので必ず縮小する。 */
/** 音声の長さ(ミリ秒)。ffprobe が無ければ null。 */
function audioDurationMs(mediaPath) {
  try {
    const out = execFileSync("ffprobe", [
      "-v", "error", "-show_entries", "format=duration",
      "-of", "default=noprint_wrappers=1:nokey=1", mediaPath,
    ], { timeout: 30_000 }).toString().trim();
    const seconds = Number(out);
    if (Number.isFinite(seconds) && seconds > 0) return Math.round(seconds * 1000);
  } catch { /* ffprobe が無い構成でも音声そのものは送受信できる */ }
  return null;
}


async function saveIncomingMedia(record, message) {
  const messageId = record.id;
  if (!messageId) return;
  const destination = path.join(MEDIA, messageId);
  if (fs.existsSync(destination) && fs.statSync(destination).size > 0) return;
  fs.mkdirSync(MEDIA, { recursive: true });
  let bytes = null;
  try {
    const file = await client.obs.downloadMediaByE2EE(message);
    if (file) {
      let buffer = Buffer.from(await file.arrayBuffer());
      // E2EE オブジェクトは 暗号文 + 32バイトMAC。FILE_SIZE は平文長なので、
      // そこまでで切らないと末尾にゴミが 32 バイト付く。
      const plainSize = Number(record.contentMetadata?.FILE_SIZE ?? 0);
      if (plainSize > 0 && buffer.length > plainSize) {
        buffer = buffer.subarray(0, plainSize);
      }
      bytes = buffer;
    }
  } catch (error) {
    log(`MEDIA E2EE取得エラー ${safeError(error)}`);
  }
  if (!bytes) {
    // 平文経路(E2EEでない相手・公式アカウント等)。
    try {
      const file = await client.obs.downloadMessageData({ messageId });
      bytes = Buffer.from(await file.arrayBuffer());
    } catch (error) {
      log(`MEDIA 平文経路も失敗 ${safeError(error)}`);
    }
  }
  if (!bytes || !bytes.length) {
    log(`MEDIA 取得失敗 ${messageId} (oid=${record.contentMetadata?.OID})`);
    return;
  }
  fs.writeFileSync(destination, bytes);
  // 3.7.1 は AUDLEN が無いと 0:00 と表示する。現行クライアントは DURATION を
  // 付けてくるが、E2EE の相手からは平文メタに入ってこないことがあるので、
  // 落とした実体から測って埋める(local_worker が AUDLEN へ移す)。
  if (record.contentType === 3 && !record.contentMetadata?.DURATION) {
    const ms = audioDurationMs(destination);
    if (ms) {
      record.contentMetadata = { ...(record.contentMetadata ?? {}), DURATION: String(ms) };
    }
  }
  fs.writeFileSync(destination + ".json", JSON.stringify({
    id: messageId, contentType: record.contentType,
    contentMetadata: record.contentMetadata,
  }), "utf8");
  log(`MEDIA 保存 ${messageId} (${bytes.length}B)`);
  makePreview(destination, messageId, record.contentType);
}

function makePreview(source, messageId, contentType) {
  const out = path.join(MEDIA, messageId + "_preview");
  try {
    if (contentType === 2) {
      execFileSync("ffmpeg", ["-y", "-ss", "0.1", "-i", source,
        "-vf", `scale='min(${PREVIEW_MAX},iw)':-2`, "-frames:v", "1",
        "-q:v", "4", "-f", "image2", out], { timeout: 30_000, stdio: "ignore" });
    } else if (contentType === 1) {
      execFileSync("ffmpeg", ["-y", "-i", source,
        "-vf", `scale='min(${PREVIEW_MAX},iw)':-2`, "-q:v", "4",
        "-f", "image2", out], { timeout: 30_000, stdio: "ignore" });
    } else {
      return;
    }
    log(`MEDIA プレビュー生成 ${messageId}`);
  } catch (error) {
    try { if (fs.existsSync(out)) fs.unlinkSync(out); } catch { /* noop */ }
    log(`MEDIA プレビュー生成エラー ${safeError(error)}`);
  }
}

// ------------------------------------------------ 自分が別端末から送ったメッセージ
// 現行サーバは自分の送信を SEND_MESSAGE(25)(稀に from=自分の 26)で全端末へ配る。
// 3.7.1 から送った分(このワーカーが sendMessage した分)はアプリ側に既にあるので除き、
// 残りを kind:"sent" で書く。legy_proxy が op25(reqSeq無し)で配ると、3.7.1 は
// insertWithMessage:reqSeq: で送信済みメッセージとして取り込む。
const SELF_SENT_GRACE_MS = 8000;
const SELF_SENT_MEDIA_GRACE_MS = 60000;   // 実体待ち・動画ワーカー経由の送信は遅い
const ownSentIds = new Set();
const selfPending = [];

/** 送信結果ファイルにも無いか確かめる(再起動後や動画ワーカー経由の送信の取りこぼし対策)。 */
function sentByBridge(id) {
  for (const file of [SEND_OUT, VIDEO_OUT]) {
    try {
      const text = fs.readFileSync(file, "utf8");
      if (text.slice(-200000).includes(`"${id}"`)) return true;
    } catch { /* 無ければ次 */ }
  }
  return false;
}

let flushingSelf = false;
async function flushSelfPending() {
  if (flushingSelf) return;
  flushingSelf = true;
  try {
    await flushSelfPendingOnce();
  } finally {
    flushingSelf = false;
  }
}
// sync は long-poll なので、op が来ない間も待ち行列を掃けるようにしておく。
setInterval(() => { flushSelfPending().catch(() => {}); }, 2000);

async function flushSelfPendingOnce() {
  const now = Date.now();
  while (selfPending.length && selfPending[0].due <= now) {
    const { message: raw } = selfPending.shift();
    const id = raw?.id != null ? String(raw.id) : null;
    if (!id || ownSentIds.has(id) || sentByBridge(id)) continue;
    try {
      const { record, message } = await messageRecord(raw);
      if ([1, 2, 3].includes(record.contentType)) {
        await saveIncomingMedia(record, message);
      }
      appendLine(RECV_OUT, { ...record, kind: "sent", text: record.text ?? "" });
      log(`SELF-SENT to=${record.to} type=${record.contentType} id=${record.id}`);
    } catch (error) {
      log(`SELF-SENT err ${safeError(error)}`);
    }
  }
}

async function handleOperations(ops) {
  const contactEvents = [];
  const profileEvents = [];
  const groupEvents = [];
  for (const op of ops) {
    const rev = op?.revision;
    if (rev != null && BigInt(rev) > sync.revision) sync.revision = BigInt(rev);
    const t = opTypeId(op);
    const createdTime = Number(op?.createdTime ?? Date.now());

    if (t === 1 || t === 2) {
      profileEvents.push({
        kind: "profile", id: `profile_${rev}_${t}`, opType: 1, createdTime,
      });
      log(`PROFILE-OP type=${t} rev=${rev}`);
    }
    const legacyGroupOp = LEGACY_GROUP_OPS.get(t);
    if (legacyGroupOp !== undefined) {
      groupEvents.push({
        kind: "group", id: `group_${rev}_${t}`, opType: legacyGroupOp,
        param1: op?.param1 ?? null, param2: op?.param2 ?? null,
        param3: op?.param3 ?? null, createdTime,
      });
      log(`GROUP-OP type=${t}->${legacyGroupOp} rev=${rev}`);
    } else if (!seenOpTypes.has(t) && ![25, 26, 55, 50, 51].includes(t)) {
      seenOpTypes.add(t);
      log(`OP-UNSEEN type=${op?.type}(${t}) rev=${rev}`);
    }
    if ([4, 5, 6, 7, 8].includes(t)) {
      const contactMid = op?.param1;
      // 6/7 は別端末でのブロック/解除。3.7.1 の OperationService は同じ番号を
      // OwnOperationService user:blockContactInContext: / ContactDAO
      // user:unblockContactInContext: で処理し、端末DBに居ない相手は getContact で
      // 取り寄せてからブロックにする。捨てると現行側のブロックが旧端末に届かない。
      if ([4, 5, 6, 7].includes(t) && contactMid) {
        contactEvents.push({
          kind: "contact", id: `contact_${rev}_${t}_${contactMid}`,
          mid: String(contactMid), opType: t, createdTime,
        });
      }
      log(`CONTACT-OP type=${t} mid=${contactMid} rev=${rev}`);
    }
    // 49 = UPDATE_CONTACT(非表示・通知などの ContactSetting 変更)。旧プロトコルでも同じ番号で、
    // 3.7.1 は OwnOperationService updateContactWithMID:contactSettingAttribute: で
    // getContact し直して settings の非表示ビットを反映する。param2 = 変わった設定。
    if (t === 49 && /^u[0-9a-f]{32}$/.test(String(op?.param1 ?? ""))) {
      contactEvents.push({
        kind: "contact", id: `contact_${rev}_${t}_${op.param1}`,
        mid: String(op.param1), opType: t, param2: op?.param2 ?? null, createdTime,
      });
      log(`CONTACT-OP type=49 mid=${op.param1} param2=${op?.param2} param3=${op?.param3} rev=${rev}`);
    }
    if (t === 50 || t === 51) {
      handleCallOp(t, op, rev, createdTime);
      continue;
    }
    if (t === 55) {
      const reader = op?.param2 ? String(op.param2) : null;
      // 自分の別端末が読んでも旧アプリの既読表示にはならないので捨てる。
      if (reader && reader !== SELF_MID) {
        const p1 = op?.param1 ? String(op.param1) : null;
        const chat = p1 && p1 !== SELF_MID ? p1 : reader;
        const record = {
          kind: "read", chatMid: chat, reader,
          messageId: op?.param3 ? String(op.param3) : null, createdTime,
        };
        appendLine(RECV_OUT, record);
        log("READ " + JSON.stringify(record));
      }
      continue;
    }
    if (t === 25 || t === 26) {
      const from = op?.message?._from ?? op?.message?.from ?? op?.message?.from_;
      if (from === SELF_MID) {
        // 自分発。3.7.1 から送った分と区別するため、送信結果が返るまで少し待つ。
        const media = [1, 2, 3].includes(enumToInt(op.message?.contentType, CONTENT_TYPE));
        selfPending.push({
          message: op.message,
          due: Date.now() + (media ? SELF_SENT_MEDIA_GRACE_MS : SELF_SENT_GRACE_MS),
        });
        selfPending.sort((a, b) => a.due - b.due);
        continue;
      }
    }
    if (t !== 26) continue;
    try {
      const { record, message } = await messageRecord(op?.message);
      // 3.7.1 が解釈できない通知系(16=POSTNOTIFICATION など)は text にenum名がそのまま
      // 入ってくるので配らない。配ると「POSTNOTIFICATION」という生の文字が吹き出しで出る。
      if (record.contentType === 16) {
        log(`RECV skip POSTNOTIFICATION id=${record.id}`);
        continue;
      }
      if ([1, 2, 3].includes(record.contentType)) {
        await saveIncomingMedia(record, message);
      }
      appendLine(RECV_OUT, record);
      log(`RECV from=${record.from} type=${record.contentType} id=${record.id}`);
    } catch (error) {
      log(`recv err ${safeError(error)}`);
    }
  }
  if (contactEvents.length) {
    // ブロック状態を先に確定させる。3.7.1 は op を受けてすぐ getContact/getContacts を
    // 呼ぶので、op より後に書くと古い status を掴む。
    const blockOps = contactEvents.filter((e) => e.opType === 6 || e.opType === 7);
    if (blockOps.length) {
      const expected = new Map(blockOps.map((e) => [e.mid, e.opType === 6]));
      const blocked = await refreshBlockState([...expected.keys()], { expected });
      // 3.7.1 の op 6 処理は相手の状態を見ずに blocking=1 にする。公式がリストに出さない
      // 相手(DELETED_BLOCKED)への op 6 は流さない。解除(op 7)は常に流す。
      for (let i = contactEvents.length - 1; i >= 0; i--) {
        const e = contactEvents[i];
        if (e.opType === 6 && !blocked.has(e.mid)) {
          log(`CONTACT-OP type=6 mid=${e.mid} は公式のブロックリスト対象外なので旧アプリへ流さない`);
          contactEvents.splice(i, 1);
        }
      }
    }
    if (contactEvents.some((e) => [4, 5, 49].includes(e.opType))) {
      await dumpContactsAndGroups(true);
    }
    for (const e of contactEvents) appendLine(RECV_OUT, e);
    log(`CONTACT-SYNC queued ${contactEvents.length}`);
  }
  if (profileEvents.length) {
    await dumpProfile();
    for (const e of profileEvents) appendLine(RECV_OUT, e);
    log(`PROFILE-SYNC queued ${profileEvents.length}`);
  }
  if (groupEvents.length) {
    await dumpContactsAndGroups(true);
    for (const e of groupEvents) appendLine(RECV_OUT, e);
    log(`GROUP-SYNC queued ${groupEvents.length}`);
  }
}

/** 着信 op(50) / キャンセル op(51)。

    実際の通話メディアは line-legacy-call.service(SIPゲートウェイ)が扱う。
    ここでやるのは「ゲートウェイを先に待機させて、旧端末の着信UIを起こす」だけ。
    op51(CANCEL) は通知しない — 発信側が切れば旧端末は自然に畳む。 */
function handleCallOp(t, op, rev, createdTime) {
  const caller = op?.param1 ? String(op.param1) : null;
  try {
    appendLine(CALL_OPS, {
      type: t, revision: rev != null ? String(rev) : null,
      callMid: op?.param1 ?? null, from: caller,
      kind: op?.param3 ?? null, createdTime,
    });
    log(`CALLOP type=${t} from=${caller} rev=${rev}`);
  } catch (error) {
    log(`call op 記録失敗 ${safeError(error)}`);
  }
  if (t !== 50 || !caller) return;
  try {
    const serverPayload = JSON.parse(op?.param3 || "{}");
    // ゲートウェイ用には**サーバの経路情報をそのまま**渡す。旧端末へ送る写しだけ
    // 自分(Pi)のSIPゲートウェイへ向け直す。
    const ring = { ...serverPayload, m: caller, h: SERVER_IP, p: 19000 };
    for (const [k, v] of Object.entries(ring)) {
      if (k === "p") continue;
      ring[k] = typeof v === "boolean" ? String(v)
        : typeof v === "number" ? String(v) : v;
    }
    fs.writeFileSync(INCOMING_RING, JSON.stringify({
      callToken: serverPayload.n, callerMid: caller,
      callMid: op?.param2 ?? null, deviceKey: serverPayload.vs ?? "",
      authInfo: serverPayload.em ?? "", route: serverPayload,
    }), "utf8");
    // 先にゲートウェイを待機させる。後からログを見て動くのでは間に合わない。
    try {
      execFileSync("sudo", ["systemctl", "kill", "-s", "SIGUSR2",
                            "line-legacy-call.service"], { timeout: 5000 });
      log("着信INVITE待機を先行");
    } catch (error) {
      log(`着信INVITE待機の起動に失敗 ${safeError(error)}`);
    }
    if (fs.existsSync(NATIVE_CALL_FLAG)) {
      log(`Skyglow純正APNsモード: tweak向けRINGを省略: ${caller}`);
      return;
    }
    const socket = dgram.createSocket("udp4");
    const payload = Buffer.from("RINGJSON " + JSON.stringify(ring), "utf8");
    socket.send(payload, RING_PORT, PHONE_IP, (error) => {
      socket.close();
      if (error) log(`ring send err ${safeError(error)}`);
      else log(`RING を tweak へ送信: ${caller}`);
    });
  } catch (error) {
    log(`call op err ${safeError(error)}`);
  }
}

async function recvLoop() {
  log(`recv_loop start rev=${sync.revision}`);
  for (;;) {
    try {
      const res = await client.talk.sync({
        limit: 100,
        revision: sync.revision,
        globalRev: sync.globalRev,
        individualRev: sync.individualRev,
      });
      if (res?.fullSyncResponse?.nextRevision) {
        // revision=0 から始めたときはここで現在位置に追い付く。
        sync.revision = BigInt(res.fullSyncResponse.nextRevision);
        log(`full sync -> rev=${sync.revision}`);
      }
      const opRes = res?.operationResponse;
      if (opRes?.globalEvents?.lastRevision) {
        sync.globalRev = BigInt(opRes.globalEvents.lastRevision);
      }
      if (opRes?.individualEvents?.lastRevision) {
        sync.individualRev = BigInt(opRes.individualEvents.lastRevision);
      }
      if (opRes?.operations?.length) {
        await handleOperations(opRes.operations);
      }
      await flushSelfPending();
      saveRev();
    } catch (error) {
      log(`sync err ${safeError(error)}`);
      await sleep(5000);
      continue;
    }
    await sleep(Number(CONF.syncIntervalMs));
  }
}

// ------------------------------------------------------------------ 送信
function loadDone() {
  try {
    return new Set(fs.readFileSync(SEND_DONE, "utf8").split(/\r?\n/).filter(Boolean));
  } catch {
    return new Set();
  }
}
const done = loadDone();

function markDone(id) {
  done.add(id);
  fs.appendFileSync(SEND_DONE, id + "\n", "utf8");
}

async function handleSend(job) {
  const to = String(job.to ?? "");
  if (job.kind === "read") {
    await client.talk.sendChatChecked({
      chatMid: to, lastMessageId: String(job.messageId),
    });
    return { ok: true };
  }
  if (job.kind === "group_cmd") {
    return await handleGroupCommand(job);
  }
  if (job.kind) {
    // メディア送信など未移植のものは黙って捨てず、はっきり失敗として返す。
    return { ok: false, err: `linejs ワーカーは kind=${job.kind} に未対応です` };
  }
  const contentType = Number(job.contentType ?? 0);
  let contentMetadata = job.contentMetadata ?? {};
  if (typeof contentMetadata === "string") {
    try { contentMetadata = JSON.parse(contentMetadata); } catch { contentMetadata = {}; }
  }
  // 0=テキスト, 7=スタンプ, 1/2/3=画像/動画/音声。
  if ([1, 2, 3].includes(contentType)) {
    return await handleMediaSend(job, to, contentType);
  }
  if (contentType === 13) {
    // 連絡先。3.7.1 は mid と displayName だけを載せてくる。
    const mid = String(contentMetadata.mid ?? "");
    if (!/^u[0-9a-f]{32}$/i.test(mid)) {
      return { ok: false, err: "連絡先に mid がありません" };
    }
    const message = await client.talk.sendMessage({
      to, contentType: 13,
      contentMetadata: {
        mid,
        displayName: String(contentMetadata.displayName ?? ""),
      },
    });
    return { ok: true, messageId: message?.id != null ? String(message.id) : null };
  }
  if (contentType !== 0 && contentType !== 7) {
    return { ok: false, err: `linejs ワーカーは contentType=${contentType} に未対応です` };
  }
  if (contentType === 7) {
    const { STKID, STKPKGID, STKVER } = contentMetadata;
    if (!STKID || !STKPKGID) {
      return { ok: false, err: "スタンプに STKID / STKPKGID がありません" };
    }
    const message = await client.talk.sendMessage({
      to, contentType: 7,
      contentMetadata: {
        STKID: String(STKID), STKPKGID: String(STKPKGID),
        STKVER: String(STKVER ?? 1),
      },
    });
    return { ok: true, messageId: message?.id != null ? String(message.id) : null };
  }
  const message = await client.talk.sendMessage({
    to, text: String(job.text ?? ""), contentMetadata,
  });
  return { ok: true, messageId: message?.id != null ? String(message.id) : null };
}

/** 画像/動画/音声の送信。

    実機は sendMessage で採番された ID のパス(os.line.naver.jp/os/m/<msgid>)へ
    実体を後から POST する。cdn_proxy がそれを upload/<msgid>.bin に落とすので、
    **実体が来るまで待ってから**上げる。まだ来ていなければ defer を返して次周に回す。 */
async function handleMediaSend(job, to, contentType) {
  const oType = OBJ_TYPE_BY_CONTENT[contentType];
  const messageId = String(job.id ?? "").split("_")[0];
  const source = path.join(UPLOAD, messageId + ".bin");
  if (!fs.existsSync(source) || fs.statSync(source).size === 0) {
    const queuedAt = Number(String(job.id ?? "").split("_")[1] ?? 0) / 1000;
    if (queuedAt && Date.now() / 1000 - queuedAt < 120) {
      return { defer: true };
    }
    return { ok: false, err: "upload body が来ないままタイムアウト" };
  }
  if (oType === "video") {
    // 動画は既に実績のある video_worker へ回す(ud-hash と MAC の作りが特殊で、
    // linejs の uploadMediaByE2EE では通らない)。
    return await delegateVideo(job, to, source);
  }
  const data = fs.readFileSync(source);
  // 3.7.1 は音声の長さを AUDLEN(ミリ秒)で渡してくる。現行クライアントは
  // DURATION を見るので、載せ替えないと相手側の表示が 0:00 になる。
  const metadata = {};
  if (contentType === 3) {
    const audlen = Number(job.contentMetadata?.AUDLEN ?? job.contentMetadata?.DURATION ?? 0);
    const ms = Number.isFinite(audlen) && audlen > 0
      ? Math.round(audlen)
      : audioDurationMs(source);
    if (ms) metadata.DURATION = String(ms);
  }
  const message = await client.obs.uploadMediaByE2EE({
    data: new Blob([data]),
    oType,
    to,
    filename: `media.${MEDIA_EXT[oType]}`,
    metadata,
  });
  return { ok: true, messageId: message?.id != null ? String(message.id) : null };
}

/** 動画を line-legacy-video の linejs ワーカーへ渡し、結果が出るまで待つ。 */
async function delegateVideo(job, to, source) {
  if (!fs.existsSync(VIDEO_ENABLED)) {
    return { ok: false, err: "video_enabled が無いので動画送信は無効です" };
  }
  const id = String(job.id);
  fs.mkdirSync(path.join(bridgeDir, "staging"), { recursive: true });
  let previewPath = null;
  try {
    const safeId = id.replace(/[^A-Za-z0-9_-]/g, "");
    previewPath = path.join(bridgeDir, "staging", safeId + ".jpg");
    execFileSync("ffmpeg", ["-y", "-ss", "0.1", "-i", source,
      "-vf", `scale='min(${PREVIEW_MAX},iw)':-2`, "-frames:v", "1",
      "-q:v", "4", "-f", "image2", previewPath],
      { timeout: 60_000, stdio: "ignore" });
  } catch (error) {
    log(`動画サムネイル生成失敗 ${safeError(error)}`);
    previewPath = null;
  }
  const request = { id, to, path: path.resolve(source), filename: "video.mp4" };
  if (previewPath) request.previewPath = previewPath;
  appendLine(VIDEO_IN, request);
  try { fs.chmodSync(VIDEO_IN, 0o600); } catch { /* noop */ }
  const deadline = Date.now() + 300_000;
  while (Date.now() < deadline) {
    await sleep(1000);
    let lines = [];
    try {
      lines = fs.readFileSync(VIDEO_OUT, "utf8").split(/\r?\n/).filter(Boolean);
    } catch { continue; }
    for (const line of lines.reverse()) {
      let result;
      try { result = JSON.parse(line); } catch { continue; }
      if (String(result.id) !== id) continue;
      return result.ok
        ? { ok: true, messageId: result.serverMsgId ?? null }
        : { ok: false, err: String(result.err ?? "video worker failed") };
    }
  }
  return { ok: false, err: "video worker がタイムアウトしました" };
}

async function handleGroupCommand(job) {
  const to = String(job.to ?? job.groupId ?? "");
  switch (job.op) {
    case "contact_block": {
      const mid = String(job.mid ?? "");
      await client.talk.blockContact({
        reqSeq: await client.getReqseq(), id: mid,
      });
      await refreshBlockState([mid], { expected: new Map([[mid, true]]) });
      removeRecommendation(mid);
      return { ok: true };
    }
    case "contact_unblock": {
      const mid = String(job.mid ?? "");
      await client.talk.unblockContact({
        reqSeq: await client.getReqseq(), id: mid, reference: "",
      });
      await refreshBlockState([mid], { expected: new Map([[mid, false]]) });
      return { ok: true };
    }
    case "contact_hide":
    case "contact_unhide": {
      const mid = String(job.mid ?? "");
      const hidden = job.op === "contact_hide";
      await client.talk.updateContactSetting({
        reqSeq: await client.getReqseq(), mid,
        flag: "CONTACT_SETTING_CONTACT_HIDE", value: hidden ? "true" : "false",
      });
      updateContactState("hidden_mids.json", mid, hidden);
      return { ok: true };
    }
    case "rename":
      await client.talk.updateChat({
        chatMid: to, chatName: String(job.name ?? ""), updatedAttribute: 1,
      });
      return { ok: true };
    case "invite": {
      const members = typeof job.members === "string"
        ? JSON.parse(job.members) : (job.members ?? []);
      await client.talk.inviteIntoChat({ chatMid: to, targetUserMids: members });
      return { ok: true };
    }
    case "leave":
      await client.talk.deleteSelfFromChat({ chatMid: to });
      return { ok: true };
    case "kickout": {
      const members = typeof job.members === "string"
        ? JSON.parse(job.members) : (job.members ?? []);
      await client.talk.deleteOtherFromChat({ chatMid: to, targetUserMids: members });
      return { ok: true };
    }
    case "create": {
      const members = typeof job.members === "string"
        ? JSON.parse(job.members) : (job.members ?? []);
      const chat = await client.talk.createChat({
        name: String(job.name ?? ""), targetUserMids: members,
      });
      return { ok: true, chatMid: chat?.chatMid ?? chat?.id ?? null };
    }
    default:
      // set_picture / note_media は OBS 経由。cdn_proxy 側にある実装を使うので
      // ここでは受けない。
      return { ok: false, err: `linejs ワーカーは group_cmd op=${job.op} に未対応です` };
  }
}

function updateContactState(filename, mid, enabled) {
  const target = path.join(legacyDir, filename);
  let values = [];
  try {
    const parsed = JSON.parse(fs.readFileSync(target, "utf8"));
    if (Array.isArray(parsed)) values = parsed.map(String);
  } catch { /* first write */ }
  const state = new Set(values);
  if (enabled) state.add(mid); else state.delete(mid);
  const temp = target + ".tmp";
  fs.writeFileSync(temp, JSON.stringify([...state].sort()), { mode: 0o600 });
  fs.renameSync(temp, target);
}

const BLOCKED_MIDS_JSON = path.join(legacyDir, "blocked_mids.json");
const BLOCKED_CONTACTS_JSON = path.join(legacyDir, "blocked_contacts.json");
// ★DELETED_BLOCKED(友だち削除済み+ブロック)は含めない。公式アプリ(Windows/スマホ)は
//   この状態の相手をブロックリストに出さない(2026-09-11 実機で確認)。
const BLOCKED_STATUSES = new Set([
  CONTACT_STATUS.FRIEND_BLOCKED, CONTACT_STATUS.RECOMMEND_BLOCKED,
]);

/** ブロック状態を getContacts の status で確かめて保存する。

    ★getBlockedContactIds と getUserFriendIds(BLOCK) は**友だちのブロックしか返さない**。
      友だちを削除してからブロックした相手(DELETED_BLOCKED)はどの一覧にも出ず、
      op 6 と getContacts の status でしか分からない。
      なので一覧APIの結果は「候補」に留め、判定は status で行う。
    blocked_mids.json    = ブロック中の MID(友だち/友だち以外とも)
    blocked_contacts.json = 同じ相手の Contact。legy_proxy が友だち以外の分を
                            getContacts / getBlockedRecommendationIds で返すのに使う。
    expected: 自分で block/unblock した直後など、status が反映される前でも
              結果を確定させたい MID -> true/false。 */
async function refreshBlockState(candidates, { expected = new Map() } = {}) {
  const valid = (mid) => /^u[0-9a-f]{32}$/.test(mid);
  const previous = readJson(BLOCKED_MIDS_JSON, []);
  const blocked = new Set(Array.isArray(previous) ? previous.map(String).filter(valid) : []);
  const stored = readJson(BLOCKED_CONTACTS_JSON, {});
  const records = stored && typeof stored === "object" && !Array.isArray(stored) ? stored : {};
  const targets = [...new Set([...candidates, ...blocked].map(String))].filter(valid);
  for (const mid of candidates) if (valid(mid)) blocked.add(String(mid));
  const verified = new Set();
  for (let i = 0; i < targets.length; i += 100) {
    try {
      for (const contact of await client.talk.getContacts({ mids: targets.slice(i, i + 100) }) ?? []) {
        const record = legacyContact(contact);
        if (!valid(String(record.mid ?? ""))) continue;
        verified.add(record.mid);
        if (BLOCKED_STATUSES.has(record.status)) {
          blocked.add(record.mid);
          records[record.mid] = {
            mid: record.mid, type: record.type, status: record.status,
            relation: record.relation, displayName: record.displayName ?? "",
            pictureStatus: record.pictureStatus ?? "", picturePath: record.picturePath ?? "",
            statusMessage: record.statusMessage ?? "", attributes: record.attributes,
            capableBuddy: Boolean(record.capableBuddy),
          };
        } else {
          blocked.delete(record.mid);
        }
      }
    } catch (error) {
      log(`BLOCK-STATE getContacts failed ${safeError(error)}`);
    }
  }
  // expected は status を確かめられなかった相手にだけ使う(確かめた値のほうが正しい)。
  for (const [mid, isBlocked] of expected) {
    if (verified.has(mid)) continue;
    if (isBlocked) blocked.add(mid); else blocked.delete(mid);
  }
  for (const mid of Object.keys(records)) if (!blocked.has(mid)) delete records[mid];
  fs.writeFileSync(BLOCKED_CONTACTS_JSON + ".tmp", JSON.stringify(records), { mode: 0o600 });
  fs.renameSync(BLOCKED_CONTACTS_JSON + ".tmp", BLOCKED_CONTACTS_JSON);
  fs.writeFileSync(BLOCKED_MIDS_JSON + ".tmp", JSON.stringify([...blocked].sort()), { mode: 0o600 });
  fs.renameSync(BLOCKED_MIDS_JSON + ".tmp", BLOCKED_MIDS_JSON);
  log(`BLOCK-STATE ${blocked.size} blocked (verified ${verified.size}/${targets.length})`);
  return blocked;
}

async function syncContactState() {
  const fetchBlocked = async () => {
    const mids = new Set();
    let token = "";
    for (let page = 0; page < 100; page++) {
      const request = { blockStatus: "BLOCK" };
      if (token) request.userPageToken = token;
      const result = await client.relation.getUserFriendIds({ request });
      for (const mid of result?.userFriendMids ?? []) mids.add(String(mid));
      const next = String(result?.nextUserPageToken ?? "");
      if (!next || next === token) break;
      token = next;
    }
    // Old Talk endpoints still carry blocked recommendations on some accounts.
    // Merge them instead of assuming every blocked user remains a friend.
    for (const fetch of [
      () => client.talk.getBlockedContactIds({ syncReason: "USER_INITIATED" }),
      () => client.talk.getBlockedRecommendationIds({ syncReason: "USER_INITIATED" }),
    ]) {
      try {
        for (const mid of await fetch() ?? []) mids.add(String(mid));
      } catch (error) {
        log(`CONTACT-SYNC supplemental failed ${safeError(error)}`);
      }
    }
    return [...mids];
  };
  try {
    await refreshBlockState(await fetchBlocked());
  } catch (error) {
    log(`CONTACT-SYNC blocked failed ${safeError(error)}`);
  }
  // ダンプを省略した起動でも、手元の contacts.json から非表示一覧を作っておく。
  const contacts = readJson(CONTACTS_JSON, []);
  if (Array.isArray(contacts)) {
    const hidden = contacts.filter((c) => Number(c?.settings ?? 0) & 4).map((c) => String(c.mid));
    fs.writeFileSync(HIDDEN_MIDS_JSON + ".tmp", JSON.stringify(hidden.sort()), { mode: 0o600 });
    fs.renameSync(HIDDEN_MIDS_JSON + ".tmp", HIDDEN_MIDS_JSON);
    log(`CONTACT-SYNC hidden ${hidden.length}`);
  }

  // 「知り合いかも？」は友だち一覧やグループメンバーとは別に保存する。
  // Contact.status=3 (RECOMMEND) を保つことで、3.7.1側でも友だち追加されない。
  try {
    const mids = [...new Set((await client.talk.getRecommendationIds({
      syncReason: "USER_INITIATED",
    }) ?? []).map(String))];
    const recommendations = [];
    for (let i = 0; i < mids.length; i += 100) {
      for (const contact of await client.talk.getContacts({ mids: mids.slice(i, i + 100) }) ?? []) {
        const record = legacyContact(contact);
        // サーバが曖昧な値を返しても、推薦スナップショットを友だちとして配らない。
        record.status = 3;
        recommendations.push(record);
      }
    }
    writeJsonAtomic(RECOMMENDATION_MIDS_JSON, mids);
    writeJsonAtomic(RECOMMENDATION_CONTACTS_JSON, recommendations);
    log(`CONTACT-SYNC recommendations ${mids.length} ids / ${recommendations.length} contacts`);
  } catch (error) {
    // 一時障害で既存の推薦一覧を空にしない。
    log(`CONTACT-SYNC recommendations failed ${safeError(error)}`);
  }
}

// 実体待ちで保留になった送信。次の周回で拾い直す。
const deferred = [];

async function dispatchSend(job, id) {
  let result;
  try {
    result = await handleSend(job);
  } catch (error) {
    result = { ok: false, err: safeError(error) };
  }
  if (result?.defer) {
    if (!deferred.some((entry) => entry.id === id)) deferred.push({ job, id });
    return;
  }
  // 3.7.1 から送った分。サーバから自分発として戻ってきても二重に入れない。
  if (result?.messageId) ownSentIds.add(String(result.messageId));
  const index = deferred.findIndex((entry) => entry.id === id);
  if (index >= 0) deferred.splice(index, 1);
  appendLine(SEND_OUT, { id, kind: job.kind ?? null, ...result });
  markDone(id);
  log(`SEND ${id} ${result.ok ? "ok" : "NG " + result.err}`);
}

async function sendLoop() {
  let offset = 0;
  try { offset = fs.statSync(SEND_IN).size; } catch { offset = 0; }
  // 起動時点より前の行は bridge_daemon が処理済みとみなす(二重送信を防ぐ)。
  log(`send_loop start offset=${offset}`);
  let buffer = "";
  for (;;) {
    try {
      const size = fs.existsSync(SEND_IN) ? fs.statSync(SEND_IN).size : 0;
      if (size < offset) offset = 0;   // ローテートされた
      if (size > offset) {
        const fd = fs.openSync(SEND_IN, "r");
        const chunk = Buffer.alloc(size - offset);
        fs.readSync(fd, chunk, 0, chunk.length, offset);
        fs.closeSync(fd);
        offset = size;
        buffer += chunk.toString("utf8");
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          let job;
          try { job = JSON.parse(line); } catch { continue; }
          const id = String(job.id ?? "");
          if (!id || done.has(id)) continue;
          await dispatchSend(job, id);
        }
      }
      for (const entry of [...deferred]) {
        await dispatchSend(entry.job, entry.id);
      }
    } catch (error) {
      log(`send loop err ${safeError(error)}`);
    }
    await sleep(Number(CONF.sendPollMs));
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ------------------------------------------------------------------ 起動
await dumpProfile();
await dumpContactsAndGroups(process.env.FORCE_DUMP === "1");
await syncContactState();
if (process.env.DUMP_ONLY === "1") {
  log("DUMP_ONLY=1 のため受信/送信ループは起動しません");
} else {
  await Promise.all([recvLoop(), sendLoop()]);
}
