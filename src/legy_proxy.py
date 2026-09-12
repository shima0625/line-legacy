#!/usr/bin/env python3
"""
LINE legacy - LEGY passthrough proxy (v3)
-----------------------------------------
443で待受。接続開始時のTLS ClientHelloを覗いて2種類に振り分ける:

  * ClientHello に "spdy/2" を含む = LEGY本接続(SPDY)
      -> TLSを張り直さず、本物のLINEへ **生TCP素通し**。
         NPN(spdy/2)は実機と本物LINEが直接ネゴシエートするので遅延しない。
  * それ以外 = /R2 等のHTTPS GET
      -> 我々の証明書でTLS終端し、本物へ転送。/R2応答は secure:"tls" に書き換え。

狙い: v2で判明した「TLS張り直しでNPNが失われ応答が10秒遅延→ログインtimeout」を回避。
これが製品リレーの正しい形(LEGYは素通し、/R2だけ介入)。

使い方: python legy_proxy.py --cert server.pem --port 443
"""
import argparse
import base64 as _b64
import datetime
import gzip
import http.client
import json
import os
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import time
import zlib
import threading
import secrets
import base64

FETCHOPS_HOLD = int(os.environ.get("FOPS_HOLD", "20"))  # fetchOps長ポーリング保持秒

# 同時に「保持」してよい fetchOperations の本数。アプリのLEGY接続プールは小さく、
# ロングポールが複数の接続を同時に占有すると /C5(送信) を出す接続が残らず、
# proxyには /P4 しか来なくなる=送信が「送信中」のまま止まる(2026-08-02 実測)。
# ∴保持は1本だけ許し、2本目以降は即座に空応答を返して接続を解放する。
FETCHOPS_MAX_HOLD = int(os.environ.get("FOPS_MAX_HOLD", "1"))
_hold_lock = threading.Lock()
_holding = 0


def _acquire_hold():
    """保持枠を取れたら True。取れなければ保持せず即応答する。"""
    global _holding
    with _hold_lock:
        if _holding >= FETCHOPS_MAX_HOLD:
            return False
        _holding += 1
        return True


def _release_hold():
    global _holding
    with _hold_lock:
        _holding = max(0, _holding - 1)

LOG_LOCK = threading.Lock()
LOG_PATH = "proxy.log"

UP_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
UP_CTX.check_hostname = False
UP_CTX.verify_mode = ssl.CERT_NONE

HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"PATC")
LEGY_DEFAULT = "gw.line.naver.jp"
_ip_cache = {}


def now() -> str:
    return datetime.datetime.now().isoformat(timespec="milliseconds")


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def log(text: str) -> None:
    with LOG_LOCK:
        try:
            print(text, flush=True)
        except Exception:
            print(text.encode("utf-8", "replace").decode("ascii", "replace"), flush=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(text + "\n")


def real_ip(host: str) -> str:
    if host not in _ip_cache:
        _ip_cache[host] = socket.gethostbyname(host)  # PCの実DNS=本物
    return _ip_cache[host]


NPN_EXT = 13172   # 0x3374 Next Protocol Negotiation (client sends it empty)
ALPN_EXT = 16     # 0x0010 Application-Layer Protocol Negotiation


def parse_hello(data: bytes):
    """TLS ClientHello から (SNI, 拡張タイプ集合) を取り出す。"""
    sni, exts = None, set()
    try:
        if len(data) < 45 or data[0] != 0x16:
            return sni, exts
        i = 5 + 4 + 2 + 32
        i += 1 + data[i]
        i += 2 + int.from_bytes(data[i:i + 2], "big")
        i += 1 + data[i]
        ext_end = i + 2 + int.from_bytes(data[i:i + 2], "big")
        i += 2
        while i + 4 <= ext_end:
            etype = int.from_bytes(data[i:i + 2], "big")
            elen = int.from_bytes(data[i + 2:i + 4], "big")
            i += 4
            exts.add(etype)
            if etype == 0x00:
                try:
                    j = i + 2 + 1
                    nlen = int.from_bytes(data[j:j + 2], "big")
                    sni = data[j + 2:j + 2 + nlen].decode("latin1")
                except Exception:
                    pass
            i += elen
    except Exception:
        pass
    return sni, exts


FORCE_PROTOCOL = os.environ.get("LEGY_PROTO", "http")  # spdyを避けてHTTP転送へ
XLA_OVERRIDE = os.environ.get("XLA", "IOS\t14.20.0\tiPhone OS\t14.8")  # 版ゲート回避
SYNTH_COUNTRY = os.environ.get("COUNTRY", "JP")  # 廃止メソッドの合成応答用


def uvarint(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, i
        s += 7


def put_uvarint(n):
    out = bytearray()
    while True:
        x = n & 0x7f
        n >>= 7
        out.append(x | 0x80 if n else x)
        if not n:
            return bytes(out)


def _zigzag64(n):
    return (n << 1) ^ (n >> 63)


def build_c5_ack(msg_id, created_time, i32val=0, seq=None, hdr=None):
    """/C5送信の bespoke ack。応答処理ブロック(0x211b05)が
    readBool→readI32→readI64(id)→readI64(createdTime) の順に positional 読みする。

    読み手は **TCompactProtocol**(バイナリ中で readBool/readI64 を実装する唯一のクラス)なので
      readBool = 1byte(0x01=true) / readI32・readI64 = **zigzag varint**
    かつ **トランスポートは先頭を1バイトも消費しない**(∴ヘッダを付けてはいけない)。
    2026-08-02 実測で確定: hdr=seq で送ると app は ZID=zigzag(seqのvarint), ZTIMESTAMP=zigzag(boolの1)=-1
    と読み、日付が 1970/1/1 になっていた。env C5_HDR は比較用に残置(既定 none)。"""
    body = (b"\x01" + put_uvarint(_zigzag64(i32val))
            + put_uvarint(_zigzag64(int(msg_id)))
            + put_uvarint(_zigzag64(int(created_time))))
    mode = hdr if hdr is not None else os.environ.get("C5_HDR", "none")
    if mode == "seq" and seq is not None:
        return b"\x01\x00" + put_uvarint(int(seq)) + body
    if mode == "ver":
        return b"\x01\x00" + body
    return body


FAKE_AUTHTOKEN = "BRIDGE_SESSION_TOKEN"

NATIVE_REGISTRATION_METHODS = frozenset({
    "startVerification", "startUpdateVerification", "verifyPhone",
    "finishUpdateVerification", "registerDevice", "registerDeviceWithIdentityCredential",
})
AUTH_PRIVATE_METHODS = NATIVE_REGISTRATION_METHODS | frozenset({
    "verifyIdentityCredential", "verifyIdentityCredentialWithResult",
    "registerDeviceWithoutPhoneNumber", "registerDeviceWithoutPhoneNumberWithIdentityCredential",
})
_native_sessions = {}
_native_lock = threading.Lock()
_PRIVATE_HEADERS = frozenset({"x-line-access", "x-line-a", "x-lt", "authorization", "cookie"})


def _native_phone(region, phone):
    """Normalize local setup metadata, not proof of phone ownership."""
    if region != "JP" or not re.fullmatch(r"[+0-9 ()-]{9,32}", phone):
        raise ValueError("Use a Japanese phone number for this compatibility test")
    digits = re.sub(r"[ ()-]", "", phone)
    if digits.startswith("+81"):
        national = digits[3:]
    elif digits.startswith("0"):
        national = digits[1:]
    else:
        raise ValueError("Invalid Japanese phone number")
    if not re.fullmatch(r"[1-9][0-9]{8,9}", national):
        raise ValueError("Invalid Japanese phone number")
    return "+81" + national, "81", national


def _native_registration_reply(method, seqid, payload):
    """Local bridge enrollment through stock v3.7.1 RPCs; NEVER calls LINE auth.

    Only the already-configured bridge account is used. SKIP is a local setup
    decision, not SMS verification. Phone metadata stays in memory; the client
    itself saves normalizedPhone as tel. No device DB/plist/keychain writes.
    """
    if method not in NATIVE_REGISTRATION_METHODS:
        return None
    if os.environ.get("NATIVE_REGISTRATION") != "1":
        return build_app_exception(method, seqid, "Local native registration is disabled")
    try:
        maybe_reload_profile()
        mid = PROFILE.get(1)
        if not isinstance(mid, str) or not re.fullmatch(r"u[0-9a-f]{32}", mid) or not real_token():
            raise ValueError("The configured bridge account is not ready")
        if len(payload) > 8192 or not payload.startswith(b"\x82\x21"):
            raise ValueError("Invalid registration request")
        request_seq, pos = uvarint(payload, 2)
        size, pos = uvarint(payload, pos)
        if request_seq != seqid or payload[pos:pos + size].decode("ascii") != method:
            raise ValueError("Invalid registration method")
        args, end = _tc_read_struct(payload, pos + size)
        if end != len(payload):
            raise ValueError("Invalid registration arguments")

        def string_arg(fid, default=""):
            typ, value = args.get(fid, (8, default.encode()))
            if typ != 8 or not isinstance(value, bytes) or len(value) > 2048:
                raise ValueError("Invalid registration string")
            return value.decode("utf-8")

        with _native_lock:
            now_mono = time.monotonic()
            for sid in list(_native_sessions):
                if _native_sessions[sid]["expires"] <= now_mono:
                    del _native_sessions[sid]
            if method in ("startVerification", "startUpdateVerification"):
                if len(_native_sessions) >= 64:
                    raise ValueError("Too many local registration sessions")
                if method == "startVerification" and string_arg(8) not in ("", mid):
                    raise ValueError("This bridge is configured for a different account")
                normalized, country, national = _native_phone(string_arg(2), string_arg(4))
                sid = "local-" + secrets.token_hex(24)
                _native_sessions[sid] = {"mid": mid, "expires": now_mono + 900,
                                         "kind": method, "token": None}
                session = (_tc_str(1, sid) + _tc_i32(1, 10) + _tc_str(1, "")
                           + _tc_str(1, normalized) + _tc_str(1, country)
                           + _tc_str(1, national) + b"\x00")
                log(f"  [native-registration] {method} -> local SKIP session (no SMS)")
                return build_struct_result(method, seqid, session)
            session = _native_sessions.get(string_arg(2))
            if session is None or session["mid"] != mid:
                raise ValueError("Local registration expired; enter the phone number again")
            if method == "verifyPhone":
                # SAME_DEVICE(2) here describes enrollment in this local bridge,
                # not a verified claim made by the official LINE server.
                reply = (b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(method))
                         + method.encode() + b"\x05\x00" + put_uvarint(4) + b"\x00")
            elif method == "finishUpdateVerification":
                if session["kind"] != "startUpdateVerification":
                    raise ValueError("Wrong local registration flow")
                reply = build_empty_reply(method, seqid)  # v371 returns void
            else:
                if session["kind"] != "startVerification":
                    raise ValueError("Wrong local registration flow")
                if session["token"] is None:
                    # Valid legacy token syntax, but only for this local proxy.
                    # NEVER disclose or reuse the modern account's real token.
                    session["token"] = mid + ":" + base64.b64encode(secrets.token_bytes(32)).decode()
                reply = synth_string_reply(method, seqid, session["token"])
            log(f"  [native-registration] {method} -> local reply")
            return reply
    except Exception as exc:
        log(f"  [native-registration] {method} rejected ({type(exc).__name__})")
        return build_app_exception(method, seqid, "Local registration failed; check bridge setup")


def _zigzag32(n):
    return (n << 1) ^ (n >> 31)


def build_login_result_reply(name, seqid, auth_token=FAKE_AUTHTOKEN, cert="BRIDGECERT"):
    """verifyIdentityCredential の成功応答(TCompact REPLY, field0=LoginResult SUCCESS)を合成。"""
    atk = auth_token.encode()
    c = cert.encode()
    ls = bytearray()
    ls += b"\x18" + put_uvarint(len(atk)) + atk          # fid1 authToken (delta1, binary)
    ls += b"\x18" + put_uvarint(len(c)) + c              # fid2 certificate (delta1, binary)
    ls += b"\x35" + put_uvarint(_zigzag32(1))            # fid5 type=SUCCESS (delta3, i32)
    ls += b"\x00"                                        # LoginResult STOP
    body = b"\x0c\x00" + bytes(ls) + b"\x00"             # reply field0=STRUCT(0c,id0) + reply STOP
    hdr = b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode()
    return hdr + body


# 応答を空成功(field0なし=void/null)で合成するメソッド群(移行/セットアップ系を通す)
SYNTH_EMPTY = {
    "createAccountMigrationPincodeSession",
}


def build_empty_reply(name, seqid):
    """TCompact REPLY で field0 無し(=void/null成功)。"""
    return b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode() + b"\x00"


def build_empty_struct_reply(name, seqid):
    """TCompact REPLY で field0=空の構造体(=空オブジェクト成功)。"""
    hdr = b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode()
    return hdr + b"\x0c\x00" + b"\x00" + b"\x00"  # field0 STRUCT(id0) + 空struct STOP + reply STOP


def build_app_exception(name, seqid, msg=None, extype=1):
    """TApplicationException(TCompact, msg type=3=EXCEPTION)。実gwの getCountryWithRequestIp
    応答(Invalid method name, 78B)を再現。extype=1=UNKNOWN_METHOD。"""
    if msg is None:
        msg = f"Invalid method name: '{name}'"
    mb = msg.encode()
    hdr = b"\x82\x61" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode()
    body = b"\x18" + put_uvarint(len(mb)) + mb          # fid1 message (string)
    body += b"\x15" + put_uvarint(_zigzag32(extype))    # fid2 type (i32)
    body += b"\x00"                                     # STOP
    return hdr + body


def _tc_i64(fid_delta, val):
    """TCompact I64 field (type6)。fid_delta=前フィールドからの差(1-15)。"""
    return bytes([(fid_delta << 4) | 6]) + put_uvarint(_zigzag64(val))


def _tc_i32(fid_delta, val):
    return bytes([(fid_delta << 4) | 5]) + put_uvarint(_zigzag32(val))


def _zigzag64(n):
    return (n << 1) ^ (n >> 63)


def _tc_field(out, prev, fid, typ, payload=b""):
    """TCompact field header(long-form対応) + payload を out に追記。新prevを返す。"""
    d = fid - prev
    if 1 <= d <= 15:
        out += bytes([(d << 4) | typ])
    else:
        out += bytes([typ]) + put_uvarint(_zigzag32(fid))  # delta0 = long form
    out += payload
    return fid


def encode_message(m):
    """Message struct(TCompact, STOP付き)。text message: from(1),to(2),toType(3,i32),
    id(4),createdTime(5,i64),deliveredTime(6),text(10),contentType(15,i32)。"""
    out = bytearray(); prev = 0
    def s(fid, val):
        nonlocal prev
        b = (val or "").encode(); prev = _tc_field(out, prev, fid, 8, put_uvarint(len(b)) + b)
    def i32(fid, val):
        nonlocal prev
        prev = _tc_field(out, prev, fid, 5, put_uvarint(_zigzag32(val)))
    def i64(fid, val):
        nonlocal prev
        prev = _tc_field(out, prev, fid, 6, put_uvarint(_zigzag64(val)))
    if m.get("from") is not None: s(1, m["from"])
    if m.get("to") is not None: s(2, m["to"])
    i32(3, m.get("toType", 0))
    if m.get("id") is not None: s(4, m["id"])
    if m.get("createdTime") is not None: i64(5, m["createdTime"])
    if m.get("deliveredTime") is not None: i64(6, m["deliveredTime"])
    if m.get("text") is not None: s(10, m["text"])
    content_type = int(m.get("contentType", 0) or 0)
    # field 14 is required by LINE 3.7.1.  It means that a separate binary
    # payload exists, not merely that contentMetadata exists.  Stickers have
    # metadata but no separate payload, so they must carry an explicit false.
    has_binary_content = content_type in (1, 2, 3, 4)
    out.append(((14 - prev) << 4) | (1 if has_binary_content else 2)); prev = 14
    i32(15, content_type)
    # contentPreview(17, binary)。3.7.1 は動画のサムネイルを取りに来ないので、
    # ここへ小さなJPEGを載せないとトークが再生ボタンだけの表示になる。
    preview_b64 = m.get("contentPreviewB64")
    if preview_b64:
        try:
            blob = _b64.b64decode(preview_b64)
        except Exception:
            blob = b""
        if blob:
            prev = _tc_field(out, prev, 17, 8, put_uvarint(len(blob)) + blob)
    # contentMetadata(18, map<string,string>)。スタンプ受信に必須
    # (STKPKGID/STKID/STKVER が無いとアプリは描画できない)。
    meta = m.get("contentMetadata") or {}
    if meta:
        body = bytearray(put_uvarint(len(meta)))
        body.append(0x88)                     # key type 8(binary) | value type 8(binary)
        for k, v in meta.items():
            kb = str(k).encode(); vb = str(v).encode()
            body += put_uvarint(len(kb)) + kb + put_uvarint(len(vb)) + vb
        prev = _tc_field(out, prev, 18, 11, bytes(body))
    out += b"\x00"
    return bytes(out)


def encode_operation(op):
    """Operation struct(TCompact, STOP付き)。revision(1,i64),createdTime(2,i64),
    type(3,i32),reqSeq(4,i32),param1-3(10-12,str),message(20,struct)。"""
    out = bytearray(); prev = 0
    if "revision" in op:    prev = _tc_field(out, prev, 1, 6, put_uvarint(_zigzag64(op["revision"])))
    if "createdTime" in op: prev = _tc_field(out, prev, 2, 6, put_uvarint(_zigzag64(op["createdTime"])))
    if "type" in op:        prev = _tc_field(out, prev, 3, 5, put_uvarint(_zigzag32(op["type"])))
    if "reqSeq" in op:      prev = _tc_field(out, prev, 4, 5, put_uvarint(_zigzag32(op["reqSeq"])))
    for i, pk in enumerate(("param1", "param2", "param3"), start=10):
        if op.get(pk) is not None:
            b = op[pk].encode()
            prev = _tc_field(out, prev, i, 8, put_uvarint(len(b)) + b)
    if op.get("message") is not None:
        prev = _tc_field(out, prev, 20, 12, encode_message(op["message"]))
    out += b"\x00"  # struct STOP
    return bytes(out)


import json as _json
import ast as _ast
CONTACTS = []
PROFILE = {}
_contacts_delivered = False
_contacts_mtime = None
_profile_mtime = None

# ---- メッセージ送受信(トーク) ----
_ARTIFACTS = os.environ.get("ARTIFACTS_DIR") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "artifacts")
_delivered_msg_ids = None    # 既に old LINE へ配信した message id(起動時に復元)


_FWD_CACHE = {}          # method -> (bodyバイト列, 取得時刻)
_FWD_CACHE_TTL = float(os.environ.get("FORWARD_CACHE_TTL", "3600"))


def _fwd_cache_methods():
    spec = os.environ.get("FORWARD_CACHE_METHODS", "").strip()
    return {x.strip() for x in spec.split(",") if x.strip()}


def _fwd_cache_get(tname):
    """キャッシュ対象かつ有効期間内なら保存済み応答を返す。"""
    if tname not in _fwd_cache_methods():
        return None
    ent = _FWD_CACHE.get(tname)
    if ent and (time.time() - ent[1]) < _FWD_CACHE_TTL:
        return ent[0]
    return None


def _fwd_cache_put(tname, body):
    if tname in _fwd_cache_methods() and body:
        _FWD_CACHE[tname] = (body, time.time())
        log(f"  [forward] {tname} の応答をキャッシュ({len(body)}B, {int(_FWD_CACHE_TTL)}秒)")


def _should_forward(tname):
    """env FORWARD_METHODS(カンマ区切り, `*`で全部)にあるメソッドは実gwへ中継する。"""
    if not tname:
        return False
    # 3.7.1 は受信した音声・動画の再生直前に、このRPCでCDN用Cookieを得る。
    # 空structを返すと本体GETへ進まないため、正しいstring応答を実gwから受け取る。
    if tname == "acquireEncryptedAccessToken":
        return True
    spec = os.environ.get("FORWARD_METHODS", "").strip()
    if tname in _fwd_cache_methods():
        return True
    if not spec:
        return False
    if spec == "*":
        return True
    return tname in {s.strip() for s in spec.split(",") if s.strip()}


_TOKEN_CACHE = {"mtime": 0.0, "value": None}


_IDENTITY_CACHE = {"mtime": None, "value": {}}
_DEFAULT_APP = "DESKTOPWIN\t9.8.0\tWINDOWS\t10.0.0-NT-x64"


def bridge_identity():
    """ブリッジが名乗るアカウントの3点セットを返す。

    `bridge_identity.json` が置いてあればそれを使う。無ければ従来どおり
    (real_token.txt / PROFILE の mid / DESKTOPWIN 9.8.0)。

    ★トークン・mid・X-Line-Application は**必ず揃っていること**。
      2026-09-09 実測: あるアカウントのトークンに別アカウントの mid を付けると現行 Home API が
      code=401「一時的なエラー」を返す。片方だけ差し替えると必ず嵌る。
    """
    p = os.path.join(_ARTIFACTS, "bridge_identity.json")
    try:
        st = os.stat(p)
    except OSError:
        if _IDENTITY_CACHE["value"]:
            _IDENTITY_CACHE.update({"mtime": None, "value": {}})
            log("[identity] bridge_identity.json が無くなったので既定へ戻す")
        return {}
    if st.st_mtime != _IDENTITY_CACHE["mtime"]:
        try:
            with open(p, encoding="utf-8") as f:
                value = json.load(f)
            if not isinstance(value, dict):
                raise ValueError("bridge_identity.json is not an object")
        except Exception as e:
            log(f"[identity] 読めないので既定を使う {e!r}")
            return {}
        _IDENTITY_CACHE.update({"mtime": st.st_mtime, "value": value})
        log("[identity] %s (mid=%s app=%s)" % (
            value.get("label") or "?", str(value.get("mid"))[:12] + "...",
            str(value.get("app") or _DEFAULT_APP).split("\t")[0]))
    return _IDENTITY_CACHE["value"]


def bridge_app_string():
    """現行サーバへ中継するときの X-Line-Application。"""
    return os.environ.get("XLA_FWD") or bridge_identity().get("app") or _DEFAULT_APP


def bridge_user_agent():
    app = bridge_app_string().split("\t")
    version = app[1] if len(app) > 1 else "9.8.0"
    return bridge_identity().get("user_agent") or ("Line/" + version)


def bridge_mid(default=None):
    """X-Line-Access のトークンと同じアカウントの mid。"""
    return bridge_identity().get("mid") or default or PROFILE.get(1)


def real_token():
    """RasPi の CHRLINE セッションの本物アクセストークン。
    recv_worker_371 が artifacts/real_token.txt に定期更新する。
    bridge_identity.json の token_file が指定されていればそちらを読む。"""
    p = bridge_identity().get("token_file") or "real_token.txt"
    if not os.path.isabs(p):
        p = os.path.join(_ARTIFACTS, p)
    try:
        st = os.stat(p)
        # 差し替えたファイルの mtime がたまたま同じでも取り違えないよう path も見る。
        if (st.st_mtime, p) != (_TOKEN_CACHE["mtime"], _TOKEN_CACHE.get("path")):
            _TOKEN_CACHE["value"] = open(p, encoding="utf-8").read().strip()
            _TOKEN_CACHE["mtime"] = st.st_mtime
            _TOKEN_CACHE["path"] = p
            log(f"[forward] real_token 読込 ({len(_TOKEN_CACHE['value'] or '')} chars)")
    except FileNotFoundError:
        return None
    except Exception as e:
        log(f"[forward] token err {e!r}")
        return None
    return _TOKEN_CACHE["value"]


def _outbox_path():
    return os.path.join(_ARTIFACTS, "outbox.json")


def wait_send_result(result_id, timeout=10.0):
    """Wait until bridge_daemon confirms that LINE accepted this message.

    /C5 used to return a success ACK immediately after queueing.  That made
    LINE 3.7.1 stamp a delivery time even when bridge_daemon later rejected
    the message.  send_out.jsonl is the authoritative delivery result.
    """
    result_path = os.path.join(_ARTIFACTS, "send_out.jsonl")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(result_path, encoding="utf-8") as f:
                lines = f.readlines()
            for raw in reversed(lines[-256:]):
                try:
                    result = _json.loads(raw)
                except Exception:
                    continue
                if str(result.get("id") or "") == str(result_id):
                    return result
        except FileNotFoundError:
            pass
        except Exception as e:
            log(f"  [delivery wait err] {e!r}")
        time.sleep(0.1)
    return {"id": str(result_id), "ok": False, "err": "delivery timeout"}


def load_outbox():
    """受信予定メッセージのリスト(JSON)。要素 {id,from,to,text,createdTime,toType?}。"""
    try:
        p = _outbox_path()
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return _json.load(f)
    except Exception as e:
        log(f"[outbox] load err {e!r}")
        return []


def _delivered_path():
    return os.path.join(_ARTIFACTS, "delivered_ids.json")


def _load_delivered():
    """配信済みidを復元。永続化しないと proxy 再起動で outbox 全件が再配信され重複する。"""
    try:
        p = _delivered_path()
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return set(_json.load(f))
    except Exception as e:
        log(f"[outbox] delivered load err {e!r}")
    return set()


def _save_delivered():
    try:
        with open(_delivered_path(), "w", encoding="utf-8") as f:
            _json.dump(sorted(_delivered_msg_ids), f)
    except Exception as e:
        log(f"[outbox] delivered save err {e!r}")


_pending_ops = []   # /C5送信の確認op(SEND_MESSAGE=25)等、即時配信したいop列


_sent_media = {}          # msgId -> 送信したMessage(dict)。SEND_CONTENT op の材料
_upload_done_file = os.path.join(_ARTIFACTS, "upload_done.jsonl")
# 再起動時に過去の完了通知を再処理すると、古いメディアを重複配送してしまう。
_upload_done_pos = [os.path.getsize(_upload_done_file)
                    if os.path.exists(_upload_done_file) else 0]


def _recover_sent_media(mid):
    """再起動前の失敗メディアを sent.jsonl から復元し、未配送なら再キューする。"""
    try:
        sent_path = os.path.join(_ARTIFACTS, "sent.jsonl")
        with open(sent_path, encoding="utf-8") as f:
            lines = f.readlines()
        msg = None
        for raw in reversed(lines):
            try:
                candidate = _json.loads(raw)
            except Exception:
                continue
            if str(candidate.get("id") or "") == mid and candidate.get("contentType"):
                msg = candidate
                break
        if not msg:
            return None

        queue_path = os.path.join(_ARTIFACTS, "send_queue.jsonl")
        queued = False
        if os.path.exists(queue_path):
            with open(queue_path, encoding="utf-8") as f:
                for raw in f:
                    try:
                        if str(_json.loads(raw).get("seq") or "") == mid:
                            queued = True
                            break
                    except Exception:
                        continue
        if not queued:
            snd = {"seq": mid, "to": msg.get("to"), "text": msg.get("text", ""),
                   "contentType": msg.get("contentType", 0),
                   "contentMetadata": msg.get("contentMetadata", {}),
                   "via": "S4-retry", "ts": int(time.time() * 1000)}
            with open(queue_path, "a", encoding="utf-8") as f:
                f.write(_json.dumps(snd, ensure_ascii=False) + "\n")
            log(f"  [send content] 再起動前メディアを再キュー id={mid}")
        _sent_media[mid] = dict(msg)
        return msg
    except Exception as e:
        log(f"  [send content] 復元 err {e!r}")
        return None


# 自分が送った動画のサムネイル。
# アプリの送信経路(line_uploadAV:)はサムネイルを作らず、画像のように
# ZTHUMBNAIL を自分で埋めることもしない。本来のサーバは動画アップロード後に
# NOTIFIED_UPDATE_CONTENT_PREVIEW(op45) を送っていた。3.7.1 の該当ハンドラ
# (+[NLMessageThumbnailUpdater updateThumbnailUsingOperation:], 逆アセンブルで確認)は
# **op.param3 だけ**を見て spaceID="m" / thumbID="preview" の OBS 取得を投げる。
# = /os/m/<param3>/preview。cdn_proxy は media/<id>_preview をそこで返すので、
# アップロードされた実体からサムネイルを作って置いておけばよい。
_OWN_PREVIEW_MAX = int(os.environ.get("PREVIEW_MAX", "720"))


def _make_own_video_preview(message_id):
    source = os.path.join(_ARTIFACTS, "upload", str(message_id) + ".bin")
    if not os.path.exists(source):
        return False
    media_dir = os.path.join(_ARTIFACTS, "media")
    target = os.path.join(media_dir, "%s_preview" % message_id)
    if os.path.exists(target) and os.path.getsize(target) > 0:
        return True
    try:
        os.makedirs(media_dir, exist_ok=True)
        subprocess.run(
            ["ffmpeg", "-y", "-ss", "0.1", "-i", source,
             "-vf", "scale='min(%d,iw)':-2" % _OWN_PREVIEW_MAX,
             "-frames:v", "1", "-q:v", "4", "-f", "image2", target],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=120, check=True)
    except Exception as e:
        log(f"  [preview] サムネイル生成失敗 {message_id} {e!r}")
        return False
    return os.path.exists(target) and os.path.getsize(target) > 0


def _queue_thumbnail_update_op(message_id):
    """ffmpeg は遅いので SEND_CONTENT の経路を塞がないよう別スレッドで呼ぶ。"""
    if not _make_own_video_preview(message_id):
        return
    op_type = int(os.environ.get("THUMBNAIL_UPDATE_OP", "45"))
    _pending_ops.append({"type": op_type, "createdTime": int(time.time() * 1000),
                         "param3": str(message_id)})
    log(f"  [preview] NOTIFIED_UPDATE_CONTENT_PREVIEW(op{op_type}) param3={message_id}")


def drain_upload_done():
    """cdn_proxy が記録したアップロード完了を SEND_CONTENT(op type 27) に変換する。

    旧アプリのメディア送信は、本文(sendMessage)とは別に「コンテンツ送信完了」の
    通知を待っている。それを受けるのが
      +[TalkMessageObject messageSendContent:withRequestSequence:inContext:](0x309b7d)
    で、内部で **setSendStatusValue:1** と createdTime からの setTimestamp: を行う。
    ∴ アップロードが終わった時点で type27 を配れば「送信済み+時刻」になる。
    (type25=SEND_MESSAGE 側は line_messageSent: 経由で必ず status 3 に戻るので不可)
    """
    path = _upload_done_file
    try:
        if not os.path.exists(path):
            return
        size = os.path.getsize(path)
        if size < _upload_done_pos[0]:
            _upload_done_pos[0] = 0
        if size <= _upload_done_pos[0]:
            return
        with open(path, "rb") as f:
            f.seek(_upload_done_pos[0])
            data = f.read().decode("utf-8", "replace")
            _upload_done_pos[0] = size
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ent = _json.loads(line)
            except Exception:
                continue
            mid = str(ent.get("id") or "")
            msg = _sent_media.get(mid) or _recover_sent_media(mid)
            if not msg:
                log(f"  [send content] {mid} は未知の送信(スキップ)")
                continue
            # ★2026-08-20: 正しい SEND_CONTENT は op43(CHRLINE enum で確定)。
            #   型43ハンドラ(0x42e1fe)が messageSendContent:withRequestSequence:inContext:
            #   を呼び status1＋正しい timestamp を設定する。アップロード完了契機(=ここ)で
            #   message＋reqSeq を載せて送る。env SENDCONTENT_OP で切替(既定43)。
            _sop = int(os.environ.get("SENDCONTENT_OP", "43"))
            _o = {"type": _sop, "createdTime": int(time.time() * 1000), "message": msg}
            # ★reqSeq を付けると isProcessedRequestSequenceInOperation=1 で捨てられる
            #   (/S4応答時点でアプリが送信reqSeqを消費済みのため。2026-08-20 tweakログで確定)。
            #   ∴既定では付けない。messageSendContent: は message.id で突き合わせる想定。
            #   env SENDCONTENT_REQSEQ=1 で従来動作(付与)に戻せる。
            if _sop == 43 and os.environ.get("SENDCONTENT_REQSEQ") == "1" \
                    and msg.get("reqSeq") is not None:
                _o["reqSeq"] = msg["reqSeq"]
            _pending_ops.append(_o)
            if int(msg.get("contentType") or 0) == 2:
                threading.Thread(target=_queue_thumbnail_update_op,
                                 args=(mid,), daemon=True).start()
            _sent_media.pop(mid, None)   # upload_done は同idが複数行来るので二重送出防止
            log(f"  [send content] SEND_CONTENT(op{_sop}) を予約 id={mid} "
                f"reqSeq={'付与' if 'reqSeq' in _o else '無し'}")
    except Exception as e:
        log(f"  [send content] err {e!r}")


def parse_chat_checked_arg(payload):
    """sendChatChecked CALL から chatMid と lastMessageId を取り出す。失敗時 None。
    fid1=reqSeq(i32), fid2=chatMid(binary), fid3=lastMessageId(binary)。"""
    try:
        i = 2
        _, i = uvarint(payload, i)      # seqid
        nl, i = uvarint(payload, i)     # メソッド名長
        i += nl
        vals = {}
        prev = 0
        while i < len(payload):
            fb = payload[i]; i += 1
            if fb == 0:
                break
            delta = fb >> 4; typ = fb & 0x0f
            if delta:
                fid = prev + delta
            else:
                zz, i = uvarint(payload, i); fid = (zz >> 1) ^ -(zz & 1)
            prev = fid
            if typ == 8:                # binary
                ln, i = uvarint(payload, i)
                vals[fid] = payload[i:i + ln].decode("utf-8", "replace"); i += ln
            elif typ in (5, 6):         # i32 / i64
                _, i = uvarint(payload, i)
            elif typ in (1, 2):         # bool は型フィールドに値が入る
                pass
            elif typ == 3:              # byte
                i += 1
            else:
                break
        chat, last = vals.get(2), vals.get(3)
        if chat and last:
            return {"chatMid": chat, "messageId": last}
    except Exception:
        pass
    return None


def record_chat_checked(payload):
    """既読を送信キューへ積む。legy は SPDY と HTTP で入口が2つあるので共通化する。"""
    rc = parse_chat_checked_arg(payload)
    if not rc:
        log("  [read] sendChatChecked 引数解析に失敗 (既読は送らない)")
        return False
    try:
        with open(os.path.join(_ARTIFACTS, "send_queue.jsonl"), "a", encoding="utf-8") as f:
            f.write(_json.dumps({"kind": "read", "to": rc["chatMid"],
                                 "messageId": rc["messageId"],
                                 "ts": int(time.time() * 1000)},
                                ensure_ascii=False) + "\n")
    except Exception as e:
        # 権限などで書けなくても既読1件を捨てるだけ。送信や通話は止めない。
        log(f"  [read record err] {e!r}")
        return False
    log(f"  [read] sendChatChecked chat={rc['chatMid']} last={rc['messageId']} -> queued")
    return True


# 旧アプリへ返す送信メッセージIDは legy のローカル採番で、実LINEのIDとは別物。
# 既読opの param3 に実IDを載せてもアプリは該当メッセージを見つけられないので、
# チャットごとに、まだ既読を返していないローカルIDを順番に覚えておく。
# 現行LINEの既読は「この位置まで読んだ」というまとめ通知だが、3.7.1 の
# op28 は対象IDの明示リストなので、最後の1件だけでなく未処理分を全部渡す。
_pending_local_msg_ids = {}
_group_read_ids = {}  # chat -> local message ID -> readers already notified
_group_read_watermarks = {}  # chat -> reader -> last modern read position
_read_receipt_lock = threading.RLock()
_outbox_drain_lock = threading.Lock()


def note_local_msg_id(chat_mid, local_id):
    """旧アプリへ渡した送信メッセージIDを記録する。"""
    if chat_mid and local_id:
        chat = str(chat_mid)
        msg_id = str(local_id)
        with _read_receipt_lock:
            pending = _pending_local_msg_ids.setdefault(chat, [])
            if msg_id not in pending:
                pending.append(msg_id)
                if len(pending) > 200:
                    expired = pending[:-200]
                    del pending[:-200]
                    receipts = _group_read_ids.get(chat, {})
                    for old_id in expired:
                        receipts.pop(old_id, None)


_last_read_positions = {}  # 1対1チャット -> reader -> 最後に来た既読位置


def take_read_catch_up(chat, msg_id):
    """先に来ていた既読に、あとから配ったメッセージを追いつかせる。

    戻り値は既読を出した相手のMID。対象外なら None。
    """
    chat = str(chat or "")
    msg_id = str(msg_id or "")
    if not chat or chat.startswith(("c", "r")) or not msg_id.isdecimal():
        return None
    with _read_receipt_lock:
        for reader, position in _last_read_positions.get(chat, {}).items():
            if not position.isdecimal() or int(position) < int(msg_id):
                continue
            pending = _pending_local_msg_ids.get(chat)
            if pending and msg_id in pending:
                pending.remove(msg_id)
            return reader
    return None


def take_local_read_ids(receipt):
    """Select IDs for one reader; keep group IDs for the other members.

    Direct chats retain their existing consume-once behavior. Group receipts
    are deduplicated per (message, reader), not per chat. Repeated/older modern
    read positions must not mark a newly sent message read.
    """
    chat = str(receipt.get("chatMid") or "")
    reader = str(receipt.get("reader") or "")
    if not re.fullmatch(r"u[0-9a-f]{32}", reader):
        return []
    with _read_receipt_lock:
        pending = list(_pending_local_msg_ids.get(chat, ()))
        if not chat.startswith(("c", "r")):
            # 配信より先に既読が来ることがある。そのときは対象IDがまだ無いので
            # 位置だけ覚えておき、あとで配るメッセージを take_read_catch_up が拾う。
            position = str(receipt.get("messageId") or "")
            if position:
                _last_read_positions.setdefault(chat, {})[reader] = position
            if pending:
                _pending_local_msg_ids.pop(chat, None)
            return pending
        if not pending:
            return []
        position = str(receipt.get("messageId") or "")
        watermarks = _group_read_watermarks.setdefault(chat, {})
        previous = watermarks.get(reader)
        if position and previous:
            if position == previous or (position.isdecimal() and previous.isdecimal()
                                        and int(position) < int(previous)):
                return []
        seen = _group_read_ids.setdefault(chat, {})
        ids = [mid for mid in pending if reader not in seen.get(mid, ())]
        # Local message IDs are millisecond timestamps. Do not apply delayed
        # receipts to messages sent after the receipt's creation time.
        # 別端末発のメッセージはサーバの実ID(18桁)で入るので、時刻として比べない。
        created = receipt.get("createdTime")
        if isinstance(created, (int, float)) and created > 0:
            ids = [mid for mid in ids
                   if not (mid.isdecimal() and len(mid) <= 13) or int(mid) <= created]
        for mid in ids:
            seen.setdefault(mid, set()).add(reader)
        if position and ids:
            watermarks[reader] = position
        return ids


def _drain_outbox_unlocked(localRev):
    """未配信メッセージを RECEIVE_MESSAGE(26) op に変換。revision は localRev+1.. で採番。
    加えて _pending_ops(送信確認 SEND_MESSAGE=25 等)も配信する。"""
    ops = []
    rev = localRev
    drain_upload_done()
    # 送信確認op(type25)を先に流す(アプリの pending メッセージを reqSeq で成功確定)。
    while _pending_ops:
        op = _pending_ops.pop(0)
        rev += 1
        op["revision"] = rev
        ops.append(op)
    global _delivered_msg_ids
    if _delivered_msg_ids is None:
        _delivered_msg_ids = _load_delivered()
    added = False
    for m in load_outbox():
        mid = m.get("id")
        if mid in _delivered_msg_ids:
            continue
        _delivered_msg_ids.add(mid)
        added = True
        ct = m.get("createdTime") or int(time.time() * 1000)
        if m.get("kind") == "contact":
            contact_mid = str(m.get("mid") or "")
            if not contact_mid:
                continue
            rev += 1
            op_type = int(m.get("opType") or 4)
            # 4/5 = 友だち追加、6/7 = 別端末でのブロック/解除(param1 = 相手の mid)、
            # 49 = UPDATE_CONTACT(非表示など。param2 = 変わった ContactSetting)。
            if op_type not in (4, 5, 6, 7, 49):
                op_type = 4
            contact_op = {
                "revision": rev, "createdTime": ct, "type": op_type,
                "param1": contact_mid,
            }
            if op_type == 49 and m.get("param2") is not None:
                contact_op["param2"] = str(m.get("param2"))
            ops.append(contact_op)
            log(f"  [contact] op{op_type} rev={rev} mid={contact_mid}")
            continue
        if m.get("kind") == "profile":
            op_type = int(m.get("opType") or 1)
            if op_type not in (1, 2):
                op_type = 1
            rev += 1
            ops.append({
                "revision": rev, "createdTime": ct, "type": op_type,
                # UPDATE_PROFILE is dispatched by LINE 3.7.1 to
                # updateProfileAttribute:.  param1 is the ProfileAttribute
                # bit, not the user's MID; 16 means STATUS_MESSAGE.
                "param1": "16",
                "param2": str(PROFILE.get(24) or ""),
            })
            log(f"  [profile] op{op_type} rev={rev}")
            continue
        if m.get("kind") == "group":
            op_type = int(m.get("opType") or 9)
            # 9..19 はグループの作成/更新/招待/退会/強制退会。31/32 は招待取消、
            # 34/35 は招待拒否で、3.7.1 の OperationService も扱える範囲。
            if op_type not in LEGACY_GROUP_OP_TYPES:
                log(f"  [group] op{op_type} は旧アプリが解釈できないので捨てる")
                continue
            rev += 1
            group_op = {
                "revision": rev, "createdTime": ct, "type": op_type,
            }
            for key in ("param1", "param2", "param3"):
                if m.get(key) is not None:
                    group_op[key] = str(m.get(key))
            ops.append(group_op)
            log(f"  [group] op{op_type} rev={rev} id={m.get('param1')}")
            continue
        if m.get("kind") == "sent":
            # 自分が出したメッセージ(発信通話履歴など)。RECEIVE_MESSAGE(26)で送ると
            # +[ChatDAO receivedMessage:inContext:notificationContext:] に渡され、
            # 差出人が自分のものは取り込まれない(実機DBで未挿入を確認)。
            # SEND_MESSAGE(25) は message.contentType で分岐したあと
            # insertWithMessage:reqSeq: へ落ちるので、こちらなら入る。
            # ★reqSeq は付けない。付けると isProcessedRequestSequenceInOperation:
            #   が真になり、opごと捨てられる(0x42d6fe の分岐)。
            rev += 1
            ops.append({
                "revision": rev, "createdTime": ct, "type": 25,
                "message": {"from": m["from"], "to": m["to"],
                            "toType": m.get("toType", 0),
                            "id": mid, "createdTime": ct,
                            "text": m.get("text", ""),
                            "contentType": m.get("contentType", 0),
                            "contentMetadata": m.get("contentMetadata") or {},
                            "contentPreviewB64": m.get("contentPreviewB64")},
            })
            # 別端末から送った分も、あとから来る既読opの対象になる。3.7.1 は
            # op25 で入れた ID をそのまま持つので、既読対象として覚えておく。
            note_local_msg_id(m.get("to"), mid)
            log(f"  [sent] op25 rev={rev} to={str(m.get('to'))[:12]} "
                f"ct={m.get('contentType')}")
            reader = take_read_catch_up(m.get("to"), mid)
            if reader:
                rev += 1
                ops.append({"revision": rev, "createdTime": ct, "type": 28,
                            "param1": reader, "param2": str(mid)})
                log(f"  [read] op28 rev={rev} catch-up id={mid}")
            continue
        if m.get("kind") == "read":
            # LINE 3.7.1 の OperationService は type 0..54 までしか扱わず、
            # 現行クライアントの NOTIFIED_READ_MESSAGE(55) は未対応。旧版は
            # RECEIVE_MESSAGE_RECEIPT(28) を ChatDAO messagesRead:by:inContext:
            # へ渡す。param1=読んだ相手MID、param2=0x1e区切りのローカル
            # メッセージIDであり、現行op55のparam配置とは互換性がない。
            chat = str(m.get("chatMid") or "")
            local_msg_ids = take_local_read_ids(m)
            if not local_msg_ids:
                log("  [read] op28 skip (no new matching IDs for this reader)")
                continue
            joined_ids = "\x1e".join(local_msg_ids)
            rev += 1
            ops.append({
                "revision": rev, "createdTime": ct, "type": 28,
                "param1": m.get("reader"), "param2": joined_ids,
            })
            log(f"  [read] op28 rev={rev} group={chat.startswith(('c', 'r'))} "
                f"localMsgs={len(local_msg_ids)}")
            continue
        # RECEIVE_MESSAGE を自分発で配ってはいけない。
        # +[ChatDAO receivedMessage:...] は 1対1のとき message.from をトーク相手と
        # みなすので、自分のMIDだと**自分自身との空トーク**が作られる(実機で発生)。
        # 自分が出したメッセージは kind="sent" にして op25 で配ること。
        maybe_reload_profile()
        if m.get("from") and m["from"] == PROFILE.get(1):
            log(f"  [outbox] 自分発の op26 は配らない id={mid}")
            continue
        rev += 1
        ops.append({
            "revision": rev, "createdTime": ct, "type": 26, "reqSeq": rev,
            "message": {"from": m["from"], "to": m["to"], "toType": m.get("toType", 0),
                        "id": mid, "createdTime": ct, "text": m.get("text", ""),
                        "contentType": m.get("contentType", 0),
                        "contentMetadata": m.get("contentMetadata") or {},
                        "contentPreviewB64": m.get("contentPreviewB64")},
        })
    if added:
        _save_delivered()
    return ops


def drain_outbox(localRev):
    """Serialize outbox claims across concurrent fetchOperations requests.

    Without this lock, request A can mark an item in the in-memory delivered
    set before it sends/saves it, while request B observes the item as already
    delivered. If A then loses the race/connection, the operation disappears.
    """
    with _outbox_drain_lock:
        return _drain_outbox_unlocked(localRev)


def _uv(buf, i):
    return uvarint(buf, i)


def _tc_read_value(buf, i, typ):
    """TCompact 値を読む。(value, next_i)。"""
    if typ in (1, 2):            # bool true/false (field context: no body)
        return (typ == 1), i
    if typ == 3:                 # byte
        return buf[i], i + 1
    if typ in (4, 5, 6):         # i16/i32/i64 zigzag varint
        zz, i = _uv(buf, i); return (zz >> 1) ^ -(zz & 1), i
    if typ == 7:                 # double
        import struct as _st; return _st.unpack_from("<d", buf, i)[0], i + 8
    if typ == 8:                 # binary/string
        ln, i = _uv(buf, i); return buf[i:i + ln], i + ln
    if typ == 12:                # struct
        return _tc_read_struct(buf, i)
    if typ in (9, 10):           # list/set
        h = buf[i]; i += 1; sz = h >> 4; et = h & 0x0f
        if sz == 15:
            sz, i = _uv(buf, i)
        vals = []
        for _ in range(sz):
            v, i = _tc_read_value(buf, i, et); vals.append(v)
        return vals, i
    if typ == 11:                # map
        ln, i = _uv(buf, i)
        if ln == 0:
            return {}, i
        kv = buf[i]; i += 1; kt = kv >> 4; vt = kv & 0x0f; d = {}
        for _ in range(ln):
            k, i = _tc_read_value(buf, i, kt); v, i = _tc_read_value(buf, i, vt); d[k] = v
        return d, i
    return None, i               # 不明型: これ以上読めない


def _tc_read_struct(buf, i):
    """TCompact struct を {fid:(typ,value)} で返す。(dict, next_i)。"""
    fields = {}; prev = 0
    while i < len(buf):
        fb = buf[i]; i += 1
        if fb == 0:
            break
        delta = fb >> 4; typ = fb & 0x0f
        if delta == 0:
            zz, i = _uv(buf, i); fid = (zz >> 1) ^ -(zz & 1)
        else:
            fid = prev + delta
        prev = fid
        val, i = _tc_read_value(buf, i, typ)
        fields[fid] = (typ, val)
    return fields, i


def _s(v):
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else v


def parse_c5_send(payload):
    """/C5 の bespoke LEGY sendMessage フレームを解析。
    3.7.1 HTTP形式: 01 00 <seq varint> ... <mid ascii "u"+32hex> 09 <text UTF-8>
    旧SPDY形式: 02 00 <seq:varint> <mid:16bytes> <textlen:1> <UTF-16LE+BOM text> 02
    → {"seq","to"(mid),"text"} を返す。失敗時 None。"""
    try:
        b = payload
        # 新形式(3.7.1 HTTP): mid(ascii "u"+32hex)を走査し、その後(09区切り)をUTF-8テキストに。
        if len(b) >= 4 and b[0] == 0x01 and b[1] == 0x00:
            # 宛先midの先頭文字: u=ユーザ / c=グループ / r=ルーム。
            # 以前は u だけを見ていたためグループ宛送信が解析できず、ackも返らず
            # 「送信できない」状態だった(2026-08-02)。
            mm = re.search(rb'[ucr][0-9a-fA-F]{32}', b)
            if mm:
                to = mm.group(0).decode('latin1')
                rest = b[mm.end():]
                if rest[:1] == b'\x09':
                    rest = rest[1:]
                text = rest.decode('utf-8', 'replace').rstrip('\x00')
                try:
                    seq, _ = _uv(b, 2)
                except Exception:
                    seq = 1
                to_type = {"u": 0, "r": 1, "c": 2}.get(to[0], 0)
                return {"seq": seq, "to": to, "toType": to_type, "text": text}
            return None
        if len(b) < 21 or b[0] != 0x02 or b[1] != 0x00:
            return None
        i = 2
        seq, i = _uv(b, i)                      # reqSeq varint
        mid_bytes = b[i:i + 16]; i += 16        # 宛先 mid (raw 16 bytes)
        to = "u" + mid_bytes.hex()
        tlen = b[i]; i += 1                      # UTF-16 byte length
        text = b[i:i + tlen].decode("utf-16", "replace")  # BOM込みUTF-16LE
        i += tlen
        return {"seq": seq, "to": to, "text": text}
    except Exception as e:
        log(f"  [C5 parse err] {e!r}")
        return None


def parse_message_arg(payload):
    """sendMessage CALL 引数(seq=fid1, message=fid2 struct)から Message を dict で返す。"""
    i = 2
    _, i = _uv(payload, i)          # seqid
    nl, i = _uv(payload, i)         # namelen
    i += nl                         # skip name
    fields, _ = _tc_read_struct(payload, i)  # args struct
    msg_f = fields.get(2)           # fid2 = Message struct
    if not msg_f or msg_f[0] != 12:
        return {}
    reqseq = fields.get(1, (0, None))[1]     # fid1 = reqSeq(i32)。送信確定opの紐付けに使う
    mf = msg_f[1]
    # fid18 = contentMetadata(map<string,string>)。スタンプは
    # {STKPKGID,STKID,STKVER}、音声は {AUDLEN} 等。ここを捨てると
    # スタンプ/画像/音声が「画面上は成功、実際は届かない」になる(2026-08-02)。
    meta_raw = mf.get(18, (0, None))[1]
    meta = {}
    if isinstance(meta_raw, dict):
        for k, v in meta_raw.items():
            meta[_s(k)] = _s(v)
    return {
        "from": _s(mf.get(1, (0, None))[1]),
        "to": _s(mf.get(2, (0, None))[1]),
        "toType": mf.get(3, (0, 0))[1],
        "text": _s(mf.get(10, (0, ""))[1]),
        "contentType": mf.get(15, (0, 0))[1],
        "contentMetadata": meta,
        "reqSeq": reqseq,
    }


def load_profile():
    global PROFILE, _profile_mtime
    try:
        path = os.path.join(_ARTIFACTS, "profile.json")
        s = _json.load(open(path, encoding="utf-8"))
        raw = _ast.literal_eval(s) if isinstance(s, str) else s
        PROFILE = {}
        for key, value in (raw or {}).items():
            try:
                key = int(key)
            except (TypeError, ValueError):
                pass
            PROFILE[key] = value
        _profile_mtime = os.path.getmtime(path)
        log(f"[profile] loaded name={PROFILE.get(20)}")
    except Exception as e:
        log(f"[profile] load failed: {e!r}")
        PROFILE = {}


def maybe_reload_profile():
    """Reload an atomically-replaced profile dump without restarting LEGY."""
    try:
        current = os.path.getmtime(os.path.join(_ARTIFACTS, "profile.json"))
    except OSError:
        return
    if _profile_mtime is None or current != _profile_mtime:
        load_profile()


def encode_settings():
    """旧Settings struct(TCompact)。notification系true, phoneRegistration(43)=true,
    identityProvider(40)=0, emailConfirmationStatus(44)=1 等。セッション正常を示す。"""
    out = bytearray(); prev = 0
    def _fh(fid, typ):  # field header (long-form対応)
        nonlocal prev
        d = fid - prev
        if 1 <= d <= 15:
            out.append((d << 4) | typ)
        else:
            out.append(typ)                       # delta0 = long form
            out.extend(put_uvarint(_zigzag32(fid)))
        prev = fid
    def boolf(fid, val):
        _fh(fid, 1 if val else 2)
    def i32f(fid, val):
        _fh(fid, 5); out.extend(put_uvarint(_zigzag32(val)))
    boolf(10, True)   # notificationEnable
    boolf(12, True)   # notificationNewMessage
    boolf(13, True)   # notificationGroupInvitation
    boolf(14, True)   # notificationShowMessage
    boolf(20, True)   # privacySyncContacts
    i32f(40, 0)       # identityProvider=UNKNOWN
    boolf(43, True)   # phoneRegistration=true(電話登録済み)
    i32f(44, 1)       # emailConfirmationStatus
    out.append(0x00)
    return bytes(out)


def build_struct_result(name, seqid, struct_bytes):
    """REPLY, field0 = STRUCT。"""
    hdr = b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode()
    return hdr + b"\x0c\x00" + struct_bytes + b"\x00"   # field0 STRUCT(id0) + struct + reply STOP


# validUntil は 0 = 無期限。遠い未来を入れると『期間限定』扱いになり
# purchaseStatus が 3(=期限切れ側の経路)になる疑いがあるため 0 に戻す。
# env STICKER_VALID_UNTIL で上書き可。
STICKER_VALID_UNTIL = int(os.environ.get('STICKER_VALID_UNTIL', '4102444800000'))


def load_owned_stickers():
    """所持スタンプ一覧。artifacts/owned_stickers.json に
    [{"packageId":1354986,"version":1}, ...] 形式で置く。
    受信したスタンプの STKPKGID から自動追記もされる。"""
    try:
        p = os.path.join(_ARTIFACTS, "owned_stickers.json")
        if not os.path.exists(p):
            return []
        data = _json.load(open(p, encoding="utf-8"))
        out = []
        for it in data:
            if isinstance(it, dict) and it.get("packageId"):
                pkg = int(it["packageId"])
                ver = int(it.get("version") or 1)
                # 2026-09-05: 実機が組み立てるURLは /products/0/0/100/<pkg>/ なので
                # 同梱1～5は version=100 で返す(8/26からの挙動に戻す)。
                # 変えたのは STICKER_PSTATUS_FIELDS の総当り注入を止めた点のみ。
                if 1 <= pkg <= 5:
                    ver = 100
                out.append((pkg, ver))
            elif isinstance(it, (int, str)) and str(it).isdigit():
                pkg = int(it)
                out.append((pkg, 100 if 1 <= pkg <= 5 else 1))
        return out
    except Exception as e:
        log(f"[stickers] load err {e!r}")
        return []


def encode_product_simple(package_id, version):
    """ProductSimple(TCompact): 1:productId(str) 2:packageId(i64) 3:version(i32)
    4:onSale(bool) 5:validUntil(i64)。v371バイナリの write: から確定。"""
    out = bytearray(); prev = 0
    pid = str(package_id).encode()
    prev = _tc_field(out, prev, 1, 8, put_uvarint(len(pid)) + pid)
    prev = _tc_field(out, prev, 2, 6, put_uvarint(_zigzag64(int(package_id))))
    prev = _tc_field(out, prev, 3, 5, put_uvarint(_zigzag32(int(version))))
    out.append(((4 - prev) << 4) | 1); prev = 4          # onSale = true
    # validUntil=0 は「1970年に期限切れ」と解釈され、マイスタンプで期限切れ表示に
    # なり画像も描画されない(実測)。無期限のつもりでも遠い未来を入れる。
    prev = _tc_field(out, prev, 5, 6, put_uvarint(_zigzag64(STICKER_VALID_UNTIL)))
    # ★2026-08-20: updateActivePurchasesWithProducts は各productの purchaseStatus を読み、
    #   `==2 ? status2(active) : status3(stray)` を決めていた(逆アセンブルで確定)。
    #   ProductSimple に purchaseStatus を入れていなかった=0=stray の元凶。2 を足す。
    #   フィールド番号は未確定なので env STICKER_PSTATUS_FIELD(既定6)で調整可。
    _psv = int(os.environ.get("STICKER_PSTATUS", "2"))
    _fields = os.environ.get("STICKER_PSTATUS_FIELDS", "6")
    for _f in sorted(int(x) for x in _fields.split(",") if x.strip()):
        if _f > prev:
            prev = _tc_field(out, prev, _f, 5, put_uvarint(_zigzag32(_psv)))  # i32=2 at each id
    out.append(0x00)
    return bytes(out)


def build_active_purchase_versions(name, seqid):
    """getActivePurchaseVersions / getActivePurchases の応答を合成する。

    旧アプリは所持スタンプをこのRPCでしか知り得ない。現行サーバの /SHOP4 は
    既に撤去されており(400)中継もできないため、合成するしかない。
    ProductSimpleList: 1:hasNext(bool) 2:reinvokeHour(i32) 3:lastVersionSeq(i64)
                       4:productList(list<ProductSimple>)
    """
    items = load_owned_stickers()
    body = bytearray(); prev = 0
    body.append(((1 - prev) << 4) | 2); prev = 1          # hasNext = false
    prev = _tc_field(body, prev, 2, 5, put_uvarint(_zigzag32(24)))
    prev = _tc_field(body, prev, 3, 6, put_uvarint(_zigzag64(len(items))))
    lst = bytearray()
    n = len(items)
    if n < 15:
        lst.append((n << 4) | 0x0c)
    else:
        lst.append(0xf0 | 0x0c); lst += put_uvarint(n)
    for pkg, ver in items:
        lst += encode_product_simple(pkg, ver)
    prev = _tc_field(body, prev, 4, 9, bytes(lst))        # 9 = LIST
    body.append(0x00)
    log(f"  [stickers] {name} -> {len(items)} パッケージを応答")
    return build_struct_result(name, seqid, bytes(body))


def build_active_purchases(name, seqid):
    """Return ProductList for getActivePurchases.

    Unlike getActivePurchaseVersions, this RPC does not return
    ProductSimpleList.  LINE 3.7.1 needs the full Product entries (including
    ownFlag) to mark downloaded packages as owned instead of stray.
    """
    items = load_owned_stickers()
    body = bytearray(); prev = 0
    body.append(((1 - prev) << 4) | 2); prev = 1  # hasNext = false
    products = bytearray()
    n = len(items)
    if n < 15:
        products.append((n << 4) | 0x0c)
    else:
        products.append(0xf0 | 0x0c); products += put_uvarint(n)
    for pkg, version in items:
        meta = dict(cached_product_meta(pkg) or {})
        meta["version"] = version
        products += encode_product(pkg, meta)
    # ProductList.productList は field 7(field 5 は bannerTargetType の i32)。
    # -[LineProductList read:] のフィールド分岐表で確定。
    prev = _tc_field(body, prev, 7, 9, bytes(products))
    body.append(0x00)
    log(f"  [stickers] {name} -> {len(items)} owned products")
    return build_struct_result(name, seqid, bytes(body))


_PRODUCT_META = {}          # packageId -> productInfo.meta(dict)
_STICKER_META_FILE = os.path.join(_ARTIFACTS, "sticker_meta.json")
_STICKER_META_DISK = None


def cached_product_meta(pkg):
    """Return real product metadata without startup network I/O."""
    global _STICKER_META_DISK
    pkg = int(pkg)
    if pkg in _PRODUCT_META:
        return _PRODUCT_META[pkg]
    if _STICKER_META_DISK is None:
        try:
            with open(_STICKER_META_FILE, encoding="utf-8") as f:
                raw = _json.load(f)
            _STICKER_META_DISK = {int(k): v for k, v in raw.items() if isinstance(v, dict)}
        except Exception:
            _STICKER_META_DISK = {}
    meta = _STICKER_META_DISK.get(pkg)
    if isinstance(meta, dict):
        _PRODUCT_META[pkg] = meta
        return meta
    return None


def fetch_product_meta(pkg):
    """現行CDNの productInfo.meta を取得(キャッシュ付き)。"""
    meta = cached_product_meta(pkg)
    if meta:
        return meta
    url = f"https://stickershop.line-scdn.net/stickershop/v1/product/{pkg}/iphone/productInfo.meta"
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            meta = _json.loads(r.read().decode("utf-8"))
        _PRODUCT_META[pkg] = meta
        return meta
    except Exception as e:
        log(f"  [stickers] meta取得失敗 {pkg}: {e!r}")
        return None


def _pick_lang(d, default=""):
    if not isinstance(d, dict):
        return default
    for k in ("ja", "en"):
        if d.get(k):
            return d[k]
    return next(iter(d.values()), default) or default


def product_price(meta, country="JP"):
    """(price, currency, symbol) from the CDN meta, or None when unpriced.

    productInfo.meta carries price[] per country; "@@" is the LINE Coin
    fallback.  -[LineProduct priceText] builds an NSDecimalNumber from the
    price string and shows "stickers.shop.detail.price.free" when it is zero
    or not a number -- which is why every pack read as free while we sent no
    price at all.  currency "NLC" switches the label to the coin balance
    (-[LineProduct isLineCoinProduct]), so prefer the local currency row.
    """
    rows = (meta or {}).get("price")
    if not isinstance(rows, list):
        return None
    chosen = None
    for row in rows:
        if not isinstance(row, dict) or row.get("price") is None:
            continue
        if row.get("country") == country:
            chosen = row
            break
        if chosen is None and row.get("country") not in ("@@",):
            chosen = row
    if chosen is None:
        return None
    value = float(chosen.get("price") or 0)
    text = str(int(value)) if value == int(value) else ("%.2f" % value)
    return text, str(chosen.get("currency") or ""), str(chosen.get("symbol") or "")


def encode_product(pkg, meta, owned=True, with_price=False):
    """Product struct(TCompact)。v371バイナリの write: から確定:
    1:productId(str) 2:packageId(i64) 3:version(i32) 4:authorName(str)
    5:onSale(bool) 6:validDays(i32) 7:saleType(i32) 8:copyright(str)
    9:title(str) 10:descriptionText(str) ... 21:ownFlag(bool)"""
    out = bytearray(); prev = 0

    def sf(fid, val):
        nonlocal prev
        b = (val or "").encode()
        prev = _tc_field(out, prev, fid, 8, put_uvarint(len(b)) + b)

    def i32f(fid, val):
        nonlocal prev
        prev = _tc_field(out, prev, fid, 5, put_uvarint(_zigzag32(int(val))))

    def boolf(fid, val):
        nonlocal prev
        out.append(((fid - prev) << 4) | (1 if val else 2)); prev = fid

    meta = meta or {}
    sf(1, str(pkg))
    prev = _tc_field(out, prev, 2, 6, put_uvarint(_zigzag64(int(pkg))))
    i32f(3, meta.get("version") or 1)
    sf(4, _pick_lang(meta.get("author"), "LINE"))
    boolf(5, True)                                   # onSale
    # ★validDays: 0 だと app が validUntil=0(=1970=期限切れ)を計算する疑い。
    #   大きな値にして validUntil を未来に押し出す(env STICKER_VALIDDAYS で調整, 既定36500=100年)。
    i32f(6, int(meta.get("validDays") or 0))
    i32f(7, 0)                                       # saleType
    sf(8, "")                                        # copyright
    sf(9, _pick_lang(meta.get("title"), str(pkg)))
    sf(10, "")                                       # descriptionText
    prev = _tc_field(out, prev, 14, 6, put_uvarint(_zigzag64(STICKER_VALID_UNTIL)))  # validUntil
    # ★paymentType(19): 0=GOOGLE を送っていたが iOS クライアントなので APPLE(6)。
    #   「stray(所持と紐付かない)」判定の回避を狙う。env STICKER_PAYMENTTYPE で調整可(既定6)。
    # 15 priceTier(i32) / 16 price(str) / 17 currency(str) / 18 currencySymbol(str)。
    # 型は -[LineProduct read:] のフィールド分岐で確定。ショップ一覧では入れないと
    # 全部「無料」になる。所持一覧(getActivePurchases)では今までどおり省く。
    if with_price:
        priced = product_price(meta)
        if priced:
            price, currency, symbol = priced
            # LINE 3.7.1's -[LineProduct isFree] uses priceTier as the paid/free
            # discriminator.  A price string alone is not enough.
            i32f(15, 1)
            sf(16, price)
            sf(17, currency)
            sf(18, symbol)
    i32f(19, int(os.environ.get("STICKER_PAYMENTTYPE", "6")))
    boolf(21, bool(owned))                           # ownFlag
    out.append(0x00)
    return bytes(out)


def build_get_product(name, seqid, payload):
    """getProduct の応答を合成する。引数から packageId を拾い、現行CDNの
    productInfo.meta から詳細を作って返す。これを返さないとアプリは
    パッケージのダウンロードに進まない(実測: 一覧は受け取るが無反応)。"""
    pkg = None
    try:
        i = 2
        _, i = _uv(payload, i)
        nl, i = _uv(payload, i)
        i += nl
        fields, _ = _tc_read_struct(payload, i)
        for fid in sorted(fields):
            typ, val = fields[fid]
            if typ == 6 and isinstance(val, int) and val > 0:
                pkg = val; break
            if typ == 8 and val:
                sv = _s(val)
                if sv and sv.isdigit():
                    pkg = int(sv); break
    except Exception as e:
        log(f"  [stickers] getProduct 引数解析失敗 {e!r}")
    if not pkg:
        return build_empty_struct_reply(name, seqid)
    meta = fetch_product_meta(pkg)
    log(f"  [stickers] getProduct pkg={pkg} title={_pick_lang((meta or {}).get('title'), '?')!r}")
    owned = any(int(owned_pkg) == int(pkg) for owned_pkg, _version in load_owned_stickers())
    return build_struct_result(name, seqid, encode_product(
        pkg, meta, owned=owned, with_price=True))


def legacy_profile_phone():
    """Return only a real E.164 value understood by LINE 3.7.1.

    Modern profile dumps may expose an opaque encrypted phone value in field
    10.  Passing that through can make the legacy client discard its saved
    `tel` and show the phone-verification gate again.
    """
    candidates = [os.environ.get("LINE_LEGACY_PHONE", "")]
    try:
        candidates.append(open(os.path.join(_ARTIFACTS, "legacy_phone.txt"),
                               encoding="utf-8").read().strip())
    except OSError:
        pass
    candidates.append(str(PROFILE.get(10) or ""))
    for value in candidates:
        compact = re.sub(r"[ ()-]", "", value)
        if re.fullmatch(r"\+[1-9][0-9]{7,14}", compact):
            return compact
    return ""


def encode_profile():
    """旧Profile struct(TCompact): 1mid,10phone,12regionCode,20displayName,22pictureStatus,
    24statusMessage,31/32 bool,33picturePath。"""
    p = PROFILE
    out = bytearray(); prev = 0
    def sf(fid, s):
        nonlocal prev
        b = (str(s) if s is not None else "").encode()
        out.extend(bytes([((fid - prev) << 4) | 8]) + put_uvarint(len(b)) + b); prev = fid
    if p.get(1): sf(1, p[1])            # mid
    if p.get(3): sf(3, p[3])            # userid
    phone = legacy_profile_phone()
    if phone: sf(10, phone)              # phone (E.164 only; never opaque data)
    if p.get(12): sf(12, p[12])         # regionCode
    if p.get(20): sf(20, p[20])         # displayName
    if p.get(22): sf(22, p[22])         # pictureStatus
    if p.get(24) is not None: sf(24, p[24])  # statusMessage
    # 31 allowSearchByUserid, 32 allowSearchByEmail = false(BOOLEAN_FALSE=2)
    out.extend(bytes([((31 - prev) << 4) | 2])); prev = 31
    out.extend(bytes([((32 - prev) << 4) | 2])); prev = 32
    if p.get(33): sf(33, p[33])         # picturePath
    out.append(0x00)
    return bytes(out)
AVATAR_MAP = {}   # mid/groupId -> pictureStatus(obsハッシュ)。obs中継のパス書き換えに使う


def load_contacts():
    global CONTACTS, AVATAR_MAP, _contacts_mtime
    _art = _ARTIFACTS
    contacts_path = os.path.join(_art, "contacts.json")
    try:
        CONTACTS = _json.load(open(contacts_path, encoding="utf-8"))
        _contacts_mtime = os.path.getmtime(contacts_path)
        log(f"[contacts] loaded {len(CONTACTS)} contacts")
    except Exception as e:
        log(f"[contacts] load failed: {e!r}")
        CONTACTS = []
    # アバターマップ: 友だち(pictureStatus) + グループ(picture)
    AVATAR_MAP = {}
    for c in CONTACTS:
        if c.get("pictureStatus"):
            AVATAR_MAP[c["mid"]] = c["pictureStatus"]
    try:
        gs = _json.load(open(os.path.join(_art, "groups.json"), encoding="utf-8"))
        for g in gs:
            if g.get("picture"):
                AVATAR_MAP[g["id"]] = g["picture"]
    except Exception:
        pass
    log(f"[avatars] map {len(AVATAR_MAP)} entries")


def maybe_reload_contacts():
    """Reload an atomically-replaced contact dump without restarting LEGY."""
    try:
        current = os.path.getmtime(os.path.join(_ARTIFACTS, "contacts.json"))
    except OSError:
        return
    if _contacts_mtime is None or current != _contacts_mtime:
        load_contacts()


def _tc_str(fid_delta, s):
    b = (s or "").encode()
    return bytes([(fid_delta << 4) | 8]) + put_uvarint(len(b)) + b


def encode_contact(c, blocked=None):
    """旧Contact struct(TCompact)。mid(1),type(10),status(11),relation(21),
    displayName(22),pictureStatus(24),statusMessage(26),capable*(31-34)。"""
    out = bytearray()
    prev = 0
    def f(fid, typ, payload):
        nonlocal prev
        out.extend(bytes([((fid - prev) << 4) | typ]) + payload)
        prev = fid
    # getAllContactIds 由来のレコードはすべて友だち。status=UNSPECIFIED(0)を
    # 返すとLINE 3.7.1はstatusMessageだけ更新し、pictureStatusを消してしまう。
    # 現行Contactの属性を保存しつつ、欠損時もFRIENDとして返す。
    is_official = bool(c.get("capableBuddy") if c.get("capableBuddy") is not None
                       else c.get("isOfficial"))
    contact_type = c.get("type")
    if contact_type is None:
        contact_type = 8 if is_official else 0
    contact_status = legacy_contact_status(c, blocked)
    contact_relation = c.get("relation")
    if contact_relation is None:
        contact_relation = 1                  # ContactRelation.BOTH
    f(1, 8, put_uvarint(len((c.get("mid") or "").encode())) + (c.get("mid") or "").encode())
    f(10, 5, put_uvarint(_zigzag32(int(contact_type))))
    f(11, 5, put_uvarint(_zigzag32(int(contact_status))))
    f(21, 5, put_uvarint(_zigzag32(int(contact_relation))))
    dn = (c.get("displayName") or "").encode()
    f(22, 8, put_uvarint(len(dn)) + dn)
    ps = (c.get("pictureStatus") or "").encode()
    f(24, 8, put_uvarint(len(ps)) + ps)
    thumbnail = (c.get("thumbnailUrl") or "").encode()
    if thumbnail:
        f(25, 8, put_uvarint(len(thumbnail)) + thumbnail)
    sm = (c.get("statusMessage") or "").encode()
    f(26, 8, put_uvarint(len(sm)) + sm)
    # capableBuddy=true は公式アカウントとして保存するために必要。
    for fid, key in ((31, "capableVoiceCall"),
                     (32, "capableVideoCall"),
                     (33, "capableMyhome")):
        capable = c.get(key)
        if capable is None:
            capable = True
        out.extend(bytes([((fid - prev) << 4) | (1 if capable else 2)])); prev = fid
    out.extend(bytes([((34 - prev) << 4) | (1 if is_official else 2)])); prev = 34  # buddy
    attributes = int(c.get("attributes") or (32 if is_official else 0))
    f(35, 5, put_uvarint(_zigzag32(attributes)))
    # 36 = settings(i64)。3.7.1 の updateWithContact: は bit 4(CONTACT_HIDE)で isHidden を
    # 立てる。送らないと連絡先を読み直すたびに非表示が外れる。通知(bit 1)などは従来どおり送らない。
    hidden = c.get("mid") in contact_state_set("hidden_mids.json")
    f(36, 6, put_uvarint(_zigzag64(4 if hidden else 0)))
    picture_path = (c.get("picturePath") or "").encode()
    if picture_path:
        f(37, 8, put_uvarint(len(picture_path)) + picture_path)
    out.append(0x00)  # struct STOP
    return bytes(out)


GROUP_READ_METHODS = frozenset({"getGroupIdsJoined", "getGroupIdsInvited", "getGroup", "getGroups"})
LEGACY_GROUP_OP_TYPES = frozenset(set(range(9, 20)) | {31, 32, 34, 35})


def _load_legacy_groups():
    """Read the bridge snapshot, distinguishing joined/invited/left groups."""
    maybe_reload_profile()
    own_mid = PROFILE.get(1)
    if not own_mid:
        raise ValueError("Own profile unavailable")
    with open(os.path.join(_ARTIFACTS, "groups.json"), encoding="utf-8") as source:
        data = json.load(source)
    if not isinstance(data, list):
        raise ValueError("Invalid groups snapshot")
    joined, invited = {}, {}
    for group in data:
        if not isinstance(group, dict):
            raise ValueError("Invalid group record")
        gid = group.get("id", "")
        if not isinstance(gid, str) or not re.fullmatch(r"c[0-9a-f]{32}", gid):
            continue  # r-prefixed rooms are not legacy groups
        members = group.get("members")
        invitees = group.get("invitee", group.get("invitees", []))
        if not isinstance(members, list) or not isinstance(invitees, list):
            raise ValueError("Group membership missing")
        if any(not isinstance(m, dict) or not re.fullmatch(r"u[0-9a-f]{32}", str(m.get("mid", "")))
               for m in members + invitees):
            raise ValueError("Invalid group membership")
        if own_mid in [m.get("mid") for m in members if isinstance(m, dict)]:
            joined[gid] = group
        elif own_mid in [m.get("mid") for m in invitees if isinstance(m, dict)]:
            invited[gid] = group
        # If absent from both, do not resurrect departed groups.
    return joined, invited


def load_member_contacts():
    """Non-friend group members resolved by the worker (mid -> Contact dict)."""
    try:
        with open(os.path.join(_ARTIFACTS, "member_contacts.json"), encoding="utf-8") as src:
            values = _json.load(src)
        return values if isinstance(values, dict) else {}
    except Exception:
        return {}


def _encode_group_contact(member):
    """Show a non-friend member's name/icon WITHOUT friending or recommending.

    ★status MUST stay 0 (UNSPECIFIED) and must NOT go through encode_contact.
      Verified the hard way (2026-09-11):
      - encode_contact() rewrites an empty/0 status to 1 (FRIEND) -> everyone
        became a friend.
      - status 3 (RECOMMEND) sets isFriend=NO but the app files it under
        「知り合いかも」.
      Original group syncs used exactly this status-0 minimal struct and those
      members ended up isFriend=0 / isRecommended=0, which is what we want.
      So here we keep the status-0 minimal struct and only fill in the real
      displayName(22) / pictureStatus(24) from member_contacts.json.
    """
    if isinstance(member, str):
        member = {"mid": member}
    mid = member.get("mid", "")
    if not re.fullmatch(r"u[0-9a-f]{32}", mid):
        raise ValueError("Invalid group member")
    existing = next((c for c in CONTACTS if c.get("mid") == mid), None)
    if existing is not None:
        return encode_contact(existing)  # preserve existing official/friend flags
    resolved = load_member_contacts().get(mid) or {}
    name = (member.get("displayName") or member.get("name")
            or resolved.get("displayName") or "")
    picture = member.get("pictureStatus") or resolved.get("pictureStatus") or ""
    if mid == PROFILE.get(1):
        name = PROFILE.get(20) or name
        picture = PROFILE.get(22) or picture
    # field10=type(0), field11=status(0=UNSPECIFIED), field21=relation(2=NOT_REGISTERED),
    # field22=displayName, field24=pictureStatus.  status 0 => not friend, not recommend.
    return (_tc_str(1, mid) + _tc_i32(9, 0) + _tc_i32(1, 0)
            + _tc_i32(10, 2) + _tc_str(1, name) + _tc_str(2, picture)
            + b"\x00")


def encode_group(group):
    """Stock v3.7.1 Group: 1 id, 2 time, 10 name, 11 picture,
    20 members, 21 creator, 22 invitee, 31 notificationDisabled.
    """
    if not isinstance(group.get("name"), str) or not group["name"]:
        raise ValueError("Group name unavailable")
    out = bytearray()
    prev = 0

    def field(fid, typ, value):
        nonlocal prev
        prev = _tc_field(out, prev, fid, typ, value)

    def string(fid, value):
        value = value.encode("utf-8")
        field(fid, 8, put_uvarint(len(value)) + value)

    def contacts(fid, values):
        values = list({m["mid"]: m for m in values}.values())
        count = len(values)
        header = bytes([(count << 4) | 12]) if count < 15 else b"\xfc" + put_uvarint(count)
        field(fid, 9, header + b"".join(_encode_group_contact(m) for m in values))

    string(1, group["id"])
    if group.get("createdTime") is not None:
        field(2, 6, put_uvarint(_zigzag64(int(group["createdTime"]))))
    string(10, group["name"])
    string(11, (group.get("pictureStatus") or group.get("picture") or "").lstrip("/"))
    contacts(20, group["members"])
    if group.get("creator"):
        creator = group["creator"]
        if isinstance(creator, str):
            creator = next((m for m in group["members"] if m.get("mid") == creator), {"mid": creator})
        field(21, 12, _encode_group_contact(creator))
    contacts(22, group.get("invitee", group.get("invitees", [])))
    field(31, 1 if group.get("notificationDisabled", False) else 2, b"")
    out.append(0)
    return bytes(out)


def _group_rpc_reply(method, seqid, payload):
    if method not in GROUP_READ_METHODS:
        return None
    try:
        joined, invited = _load_legacy_groups()
        if method in ("getGroupIdsJoined", "getGroupIdsInvited"):
            ids = list(joined if method == "getGroupIdsJoined" else invited)
            log(f"  [groups] {method} -> {len(ids)} IDs")
            return build_string_list_result(method, seqid, ids)
        if len(payload) > 65536 or not payload.startswith(b"\x82\x21"):
            raise ValueError("Invalid group request")
        request_seq, pos = uvarint(payload, 2)
        length, pos = uvarint(payload, pos)
        if request_seq != seqid or payload[pos:pos + length].decode() != method:
            raise ValueError("Wrong group method")
        args, end = _tc_read_struct(payload, pos + length)
        if end != len(payload):
            raise ValueError("Invalid group arguments")
        kind, value = args.get(2, (None, None))
        if method == "getGroup":
            if kind != 8 or not isinstance(value, bytes):
                raise ValueError("Group ID missing")
            requested = [value.decode()]
        else:
            if kind != 9 or not isinstance(value, list) or len(value) > 1000:
                raise ValueError("Group ID list missing")
            requested = [v.decode() for v in value]
        by_id = {**invited, **joined}
        # An empty synthetic Group caused 'unknown' chats. Reject incomplete
        # snapshots instead of returning a nameless group or clearing entries.
        if any(gid not in by_id for gid in requested):
            raise ValueError("Requested group not available in current membership")
        maybe_reload_contacts()
        groups = [by_id[gid] for gid in dict.fromkeys(requested)]
        if method == "getGroup":
            result = build_struct_result(method, seqid, encode_group(groups[0]))
        else:
            result = build_list_struct_result(method, seqid, groups, encode_group)
        log(f"  [groups] {method} -> {len(groups)} group(s)")
        return result
    except Exception as exc:
        log(f"  [groups] {method} unavailable ({type(exc).__name__})")
        return build_app_exception(method, seqid, "Group snapshot unavailable")


def build_legacy_group_resync(name, seqid, local_rev):
    """3.7.1: op39 -> syncRequestedForMID:type:severity:, type2=group.

    Verified in stock binary at 0x42dee6 and 0x26a7b0. The callback
    inserts/updates only the requested group (0x26af34..0x26afa4).
    fetchOperations in this version reads LineTalkException, not the newer
    ShouldSyncException; the latter cannot request a scoped resync here.
    """
    joined, _invited = _load_legacy_groups()
    ops = []
    revision = local_rev
    for gid in joined:
        revision += 1
        ops.append({"revision": revision, "createdTime": int(time.time() * 1000),
                    "type": 39, "param1": gid, "param2": "2", "param3": "0"})
    revision += 1
    ops.append({"revision": revision, "type": 0})
    return build_operations_result(name, seqid, ops), revision


def build_should_sync(name, seqid, syncRev, scopes=None):
    """Return a narrowly-scoped legacy ShouldSyncException.

    scopes defaults to the historical full-sync shape. A one-shot repair can
    request only profile/contact so chat and group state are left untouched.
    """
    if scopes is None:
        scopes = {"profile", "settings", "contact", "group", "room", "chat"}
    hdr = b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode()
    body = b"\x1c"                                    # field1 STRUCT (ShouldSyncException)
    body += b"\x16" + put_uvarint(_zigzag64(syncRev)) # 1:syncOpRevision(i64)
    body += b"\x1c"                                   # 2:syncScope STRUCT
    previous = 0
    for field_id, scope in ((1, "profile"), (2, "settings")):
        if scope in scopes:
            body += bytes([((field_id - previous) << 4) | 1])
            previous = field_id
    for field_id, scope in ((10, "contact"), (11, "group"),
                            (12, "room"), (13, "chat")):
        if scope in scopes:
            body += bytes([((field_id - previous) << 4) | 12])
            body += b"\x11\x00"                       # child scope: syncAll=true
            previous = field_id
    body += b"\x00"                                   #   syncScope STOP
    body += b"\x15\x02"                               # 3:syncReason=1
    body += b"\x18\x00"                               # 4:message=""
    body += b"\x00"                                   # ShouldSyncException STOP
    body += b"\x00"                                   # reply STOP
    return hdr + body


_forced_sync_lock = threading.Lock()


def claim_forced_sync():
    """Atomically claim an optional one-shot legacy sync marker."""
    marker = os.path.join(_ARTIFACTS, "force_legacy_sync_once.json")
    with _forced_sync_lock:
        if not os.path.exists(marker):
            return None
        try:
            with open(marker, encoding="utf-8") as source:
                request = _json.load(source)
            claimed = marker + ".consumed-" + str(int(time.time()))
            os.replace(marker, claimed)
            scopes = {key for key in ("profile", "settings", "contact",
                                      "group", "room", "chat")
                      if request.get(key)}
            return scopes or None
        except Exception as error:
            log(f"[forced-sync] claim failed {error!r}")
            return None


def build_string_list_result(name, seqid, strs):
    """REPLY, field0 = list<string>。getAllContactIds 等。"""
    hdr = b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode()
    body = b"\x09\x00"                                # field0 LIST, id0
    n = len(strs)
    if n < 15:
        body += bytes([(n << 4) | 0x08])             # size<<4 | elemtype(BINARY=8)
    else:
        body += bytes([0xF0 | 0x08]) + put_uvarint(n)
    for s in strs:
        b = (s or "").encode()
        body += put_uvarint(len(b)) + b
    body += b"\x00"
    return hdr + body


SYNC_REV = 1000  # ShouldSyncException で示す同期後revision


def parse_getcontacts_mids(payload):
    """getContacts CALL 引数(field2 = list<string> mids)を取り出す。"""
    try:
        i = 2
        _, i = uvarint(payload, i)          # seqid
        nl, i = uvarint(payload, i); i += nl  # method name
        # 引数struct: field2(list) を探す
        while i < len(payload):
            fb = payload[i]; i += 1
            if fb == 0:
                break
            typ = fb & 0x0f
            if typ == 9:  # LIST
                sz_b = payload[i]; i += 1
                size = sz_b >> 4
                if size == 0x0f:
                    size, i = uvarint(payload, i)
                mids = []
                for _ in range(size):
                    ln, i = uvarint(payload, i)
                    mids.append(payload[i:i+ln].decode("latin1")); i += ln
                return mids
            else:
                break
    except Exception:
        pass
    return None


def build_list_struct_result(name, seqid, items, encoder):
    """REPLY, field0 = list<struct>。"""
    hdr = b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode()
    body = b"\x09\x00"
    n = len(items)
    if n < 15:
        body += bytes([(n << 4) | 0x0C])
    else:
        body += bytes([0xF0 | 0x0C]) + put_uvarint(n)
    for it in items:
        body += encoder(it)
    body += b"\x00"
    return hdr + body


def build_operations_result(name, seqid, ops):
    """fetchOps 応答(REPLY, field0 = list<Operation>)を合成。"""
    hdr = b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode()
    # field0 = LIST(type9), long-form id 0
    body = b"\x09\x00"
    n = len(ops)
    if n < 15:
        body += bytes([(n << 4) | 0x0C])   # size<<4 | elemtype(STRUCT=12)
    else:
        body += bytes([0xF0 | 0x0C]) + put_uvarint(n)
    for op in ops:
        body += encode_operation(op)
    body += b"\x00"  # result struct STOP
    return hdr + body


def parse_fetchops_localrev(payload):
    """fetchOps CALL の引数から localRev(fid2,i64) を取り出す。失敗時0。"""
    try:
        m, seqid = thrift_call_name(payload)
        # ヘッダ長を飛ばす: 82 21 <seqid uv> <namelen uv> <name>
        i = 2
        _, i = uvarint(payload, i)          # seqid
        nl, i = uvarint(payload, i)         # namelen
        i += nl                             # skip name
        # 引数struct: 最初のフィールドが fid2(localRev, i64)
        prev = 0
        while i < len(payload):
            fb = payload[i]; i += 1
            if fb == 0:
                break
            delta = fb >> 4; typ = fb & 0x0f
            fid = prev + delta if delta else None
            if delta == 0:
                zz, i = uvarint(payload, i); fid = (zz >> 1) ^ -(zz & 1)
            prev = fid
            if typ == 6:  # i64
                zz, i = uvarint(payload, i); v = (zz >> 1) ^ -(zz & 1)
                if fid == 2:
                    return v
            elif typ == 5:  # i32
                zz, i = uvarint(payload, i)
            elif typ in (1, 2):  # bool (value in type)
                pass
            elif typ == 8:  # binary
                ln, i = uvarint(payload, i); i += ln
            else:
                break
    except Exception:
        pass
    return 0


def thrift_call_name(body):
    """TCompact CALL(82 21 ..) から (method名, seqid) を取り出す。失敗時 (None,0)。"""
    try:
        if len(body) < 4 or body[0] != 0x82 or (body[1] >> 5) != 1:
            return None, 0
        i = 2
        seqid, i = uvarint(body, i)
        namelen, i = uvarint(body, i)
        return body[i:i + namelen].decode("latin1"), seqid
    except Exception:
        return None, 0


def synth_string_reply(name, seqid, value):
    """メソッドが string を返す想定の TCompact REPLY(82 41 ..) を合成。"""
    hdr = b"\x82\x41" + put_uvarint(seqid) + put_uvarint(len(name)) + name.encode()
    field0 = b"\x08\x00" + put_uvarint(len(value)) + value.encode()  # id0 binary(string)
    return hdr + field0 + b"\x00"


def acquire_legacy_call_route(payload):
    """Fetch a modern LINEJS CallRoute and map it to LINE 3.7.1's 7 strings."""
    found = re.search(rb"u[0-9a-fA-F]{32}", payload or b"")
    if not found:
        log("  [call] acquireCallRoute: target MID was not found")
        return None
    target = found.group(0).decode("ascii")
    helper = os.path.join(
        os.environ.get("LINEJS_BRIDGE_DIR", "/opt/line-legacy/linejs-bridge"),
        "call_route_helper.mjs",
    )
    env = os.environ.copy()
    env["LINE_CALL_TO"] = target
    try:
        proc = subprocess.run(
            ["/usr/bin/node", helper],
            cwd=os.path.dirname(helper),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        result = json.loads((proc.stdout or "").strip())
        values = result.get("values") if result.get("ok") else None
        if (not isinstance(values, list) or len(values) != 7 or
                not all(isinstance(v, str) for v in values)):
            log(f"  [call] LINEJS route failed: {result.get('error', 'invalid response')!r}")
            return None
        meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
        flow = str(meta.get("callFlowType", "unknown"))[:16]
        parts = meta.get("addressParts", "?")
        gateway = "local-gateway" if meta.get("localGateway") else f"first-of-{parts}"
        log(f"  [call] LINEJS route -> legacy 7 strings "
            f"(flow={flow}, host={gateway}, token hidden)")
        return values
    except Exception as e:
        log(f"  [call] LINEJS route helper error: {type(e).__name__}: {e}")
        return None


def rewrite_r2(body: bytes) -> bytes:
    try:
        data = json.loads(body.decode("utf-8"))
        changed = 0
        for srv in data.get("servers", []):
            if "legy" in srv.get("server_type", ""):
                for e in srv.get("list", []):
                    e["secure"] = "tls"
                    if FORCE_PROTOCOL:
                        e["protocol"] = FORCE_PROTOCOL
                    changed += 1
        log(f"[r2] rewrote {changed} legy entries -> secure:tls protocol:{FORCE_PROTOCOL}")
        return json.dumps(data).encode("utf-8")
    except Exception as e:
        log(f"[r2] rewrite skipped: {e!r}")
        return body


def pump(src, dst, counter, idx):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            counter[idx] += len(data)
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def passthrough(client, sni):
    target = sni if (sni and sni.endswith("line.naver.jp")) else LEGY_DEFAULT
    try:
        up = socket.create_connection((real_ip(target), 443), timeout=20)
    except Exception as e:
        log(f"[legy] passthrough connect FAILED ({target}): {e!r}")
        return
    log(f"{now()}  ~~~ LEGY passthrough  sni={sni} -> {target}")
    counter = [0, 0]
    t = threading.Thread(target=pump, args=(up, client, counter, 0), daemon=True)
    t.start()
    pump(client, up, counter, 1)
    t.join(timeout=2)
    try:
        up.close()
    except OSError:
        pass
    log(f"{now()}  ~~~ LEGY closed  sni={sni}  down={counter[0]}B up={counter[1]}B")


def hx(data, limit=256, width=16):
    data = data[:limit]
    return "\n".join("    " + data[i:i+width].hex() for i in range(0, len(data), width))


def pump_logged(src, dst, tag):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            log(f"  [{tag}] {len(data)}B\n{hx(data)}")
            dst.sendall(data)
    except Exception as e:
        log(f"  [{tag}] err {e!r}")
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def terminate_relay(tls, first, host):
    """非HTTP(SPDY等)の復号ストリームを本物gwへTLSで生中継し、全バイト記録。"""
    log(f"{now()}  ### NON-HTTP relay -> {host}\n  [C->S first] {len(first)}B\n{hx(first)}")
    try:
        raw = socket.create_connection((real_ip(host), 443), timeout=20)
        up = UP_CTX.wrap_socket(raw, server_hostname=host)
        up.sendall(first)
    except Exception as e:
        log(f"  relay connect FAILED: {e!r}")
        return
    t = threading.Thread(target=pump_logged, args=(up, tls, "S->C"), daemon=True)
    t.start()
    pump_logged(tls, up, "C->S")
    t.join(timeout=3)
    try:
        up.close()
    except OSError:
        pass
    log(f"{now()}  ### relay closed  {host}")


SPDY2_DICT = (
    b"optionsgetheadpostputdeletetraceacceptaccept-charsetaccept-encodingaccept-language"
    b"authorizationexpectfromhostif-modified-sinceif-matchif-none-matchif-rangeif-unmodifiedsince"
    b"max-forwardsproxy-authorizationrangerefererteuser-agent100101200201202203204205206300301302"
    b"303304305306307400401402403404405406407408409410411412413414415416417500501502503504505"
    b"accept-rangesageetaglocationproxy-authenticatepublicretry-afterservervarywarning"
    b"www-authenticateallowcontent-basecontent-encodingcache-controlconnectiondatetrailer"
    b"transfer-encodingupgradeviawarningcontent-languagecontent-lengthcontent-locationcontent-md5"
    b"content-rangecontent-typeetagexpireslast-modifiedset-cookieMondayTuesdayWednesdayThursday"
    b"FridaySaturdaySundayJanFebMarAprMayJunJulAugSepOctNovDecchunkedtext/htmlimage/pngimage/jpg"
    b"image/gifapplication/xmlapplication/xhtmltext/plainpublicmax-agecharset=iso-8859-1utf-8"
    b"gzipdeflateHTTP/1.1statusversionurl\x00")


def spdy_parse_nv(data):
    n = int.from_bytes(data[0:2], "big")
    i = 2
    pairs = []
    for _ in range(n):
        ln = int.from_bytes(data[i:i + 2], "big"); i += 2
        name = data[i:i + ln]; i += ln
        lv = int.from_bytes(data[i:i + 2], "big"); i += 2
        val = data[i:i + lv]; i += lv
        pairs.append([name, val])
    return pairs


def spdy_build_nv(pairs):
    out = len(pairs).to_bytes(2, "big")
    for name, val in pairs:
        out += len(name).to_bytes(2, "big") + name + len(val).to_bytes(2, "big") + val
    return out


def spdy_rewrite_syn(frame, ftype, inflate, deflate):
    """SYN_STREAM(1)/HEADERS(8)のNVを解いて x-la を版偽装し再圧縮。"""
    off = 8 + (10 if ftype == 1 else 6)  # frame header + (streamid/assoc/pri or streamid/unused)
    prefix = frame[8:off]
    nvc = frame[off:]
    raw = inflate.decompress(nvc)
    pairs = spdy_parse_nv(raw)
    hit = False
    hdrdump = []
    for p in pairs:
        if p[0].lower() == b"x-la":
            p[1] = XLA_OVERRIDE.encode()
            hit = True
        # 捕獲: 全ヘッダを可読ログ(x-line-access/method/path等を確認)
        try:
            k = p[0].decode("latin1", "replace")
            v = p[1].decode("latin1", "replace")
        except Exception:
            k, v = repr(p[0]), repr(p[1])
        if len(v) > 200:
            v = v[:200] + f"...(+{len(v)-200}B)"
        hdrdump.append(f"      {k}: {v}")
    newc = deflate.compress(spdy_build_nv(pairs)) + deflate.flush(zlib.Z_SYNC_FLUSH)
    newpayload = prefix + newc
    newframe = frame[:5] + len(newpayload).to_bytes(3, "big") + newpayload
    log(f"  [spdy syn type{ftype}] x-la rewritten={hit} nv {len(nvc)}->{len(newc)}B\n"
        + "\n".join(hdrdump))
    return newframe


def thrift_peek(data):
    """SPDY DATAフレーム内のThrift(TCompact)の種別/メソッド名を推定。"""
    try:
        if len(data) >= 4 and data[0] == 0x82:
            typ = {1: "CALL", 2: "REPLY", 3: "EXC", 4: "ONEWAY"}.get(data[1] >> 5, "?")
            i = 2
            _, i = uvarint(data, i)
            nl, i = uvarint(data, i)
            name = data[i:i + nl].decode("latin1", "replace")
            tail = bytes(c if 32 <= c < 127 else 46 for c in data[i + nl:i + nl + 40])
            return f"{typ} {name}  tail={tail.decode('latin1')}"
    except Exception:
        pass
    return None


def spdy_log_data(frame, tag):
    """DATAフレーム(制御ビット0)ならThrift内容をログ。"""
    if not (frame[0] & 0x80):  # data frame
        payload = frame[8:]
        info = thrift_peek(payload)
        if info:
            log(f"  [spdy {tag} DATA] {info}")


def spdy_relay(tls, first, host):
    """SPDY/2チャネルを中継しつつ C->S の SYN_STREAM の x-la を版偽装。両方向のDATAを記録。"""
    try:
        up = UP_CTX.wrap_socket(socket.create_connection((real_ip(host), 443), timeout=20),
                                server_hostname=host)
    except Exception as e:
        log(f"  spdy upstream FAILED: {e!r}")
        return
    inflate = zlib.decompressobj(zdict=SPDY2_DICT)
    deflate = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, 15, 8,
                               zlib.Z_DEFAULT_STRATEGY, SPDY2_DICT)
    streams = {}          # stream_id -> (method, seqid)  ※L3: 応答を差し替える対象を記録
    lock = threading.Lock()
    log(f"{now()}  ~~~ SPDY relay -> {host}")

    def s2c():
        sbuf = bytearray()
        try:
            while True:
                d = up.recv(65536)
                if not d:
                    break
                sbuf += d
                out = bytearray()
                while len(sbuf) >= 8:
                    ln = int.from_bytes(sbuf[5:8], "big")
                    if len(sbuf) < 8 + ln:
                        break
                    fr = bytes(sbuf[:8 + ln]); del sbuf[:8 + ln]
                    if not (fr[0] & 0x80):  # DATA frame
                        sid = int.from_bytes(fr[0:4], "big") & 0x7fffffff
                        with lock:
                            info = streams.get(sid)
                        # 捕獲: サーバ->クライアントのThrift応答種別/メソッドを記録
                        spdy_log_data(fr, f"S->C sid{sid} req={info[0] if info else '?'}")
                        synth = None
                        if info and info[0] == "verifyIdentityCredential":
                            synth = build_login_result_reply("verifyIdentityCredential", info[1])
                            log(f"  [spdy L3] verifyIdentityCredential -> SYNTH LoginResult SUCCESS (sid {sid})")
                        elif info and info[0] == "getCountryWithRequestIp":
                            synth = synth_string_reply("getCountryWithRequestIp", info[1], SYNTH_COUNTRY)
                            log(f"  [spdy L3] getCountryWithRequestIp -> SYNTH \"{SYNTH_COUNTRY}\" (sid {sid})")
                        elif info and info[0] in SYNTH_EMPTY:
                            synth = build_empty_struct_reply(info[0], info[1])
                            log(f"  [spdy L3] {info[0]} -> SYNTH empty-struct (sid {sid})")
                        if synth is not None:
                            fr = fr[0:4] + b"\x01" + len(synth).to_bytes(3, "big") + synth
                            with lock:
                                streams.pop(sid, None)
                    out += fr
                if out:
                    tls.sendall(bytes(out))
        except Exception as e:
            log(f"  spdy s2c err {e!r}")
        finally:
            try:
                tls.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=s2c, daemon=True)
    t.start()
    buf = bytearray(first)
    try:
        while True:
            while len(buf) >= 8:
                length = int.from_bytes(buf[5:8], "big")
                total = 8 + length
                if len(buf) < total:
                    break
                frame = bytes(buf[:total])
                del buf[:total]
                if frame[0] & 0x80:  # control frame
                    ftype = int.from_bytes(frame[2:4], "big")
                    if ftype in (1, 8):
                        try:
                            frame = spdy_rewrite_syn(frame, ftype, inflate, deflate)
                        except Exception as e:
                            log(f"  [spdy rewrite ERR] {e!r}")
                else:  # DATA: methodとseqidを記録(応答差し替え用)
                    sid = int.from_bytes(frame[0:4], "big") & 0x7fffffff
                    m, sq = thrift_call_name(frame[8:])
                    if m:
                        with lock:
                            streams[sid] = (m, sq)
                        spdy_log_data(frame, "C->S")
                up.sendall(frame)
            d = tls.recv(65536)
            if not d:
                break
            buf += d
    except Exception as e:
        log(f"  spdy c2s err {e!r}")
    finally:
        try:
            up.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    t.join(timeout=3)
    try:
        up.close()
    except OSError:
        pass
    log(f"{now()}  ~~~ SPDY relay closed  {host}")


# ============================================================
# L3: 独立合成SPDY/2サーバ(実gw中継なし)
#   LINEのSYN_STREAM+DATAを受け、SYN_REPLY(ヘッダ完全合成)+DATA(Thrift応答)を返す。
#   目的: 初期化RPCを通過させ、トークンを載せる認証RPCを捕獲する。
# ============================================================

def spdy_ctrl(ftype, payload, flags=0):
    return b"\x80\x02" + ftype.to_bytes(2, "big") + bytes([flags]) + len(payload).to_bytes(3, "big") + payload


def spdy_syn_reply(stream_id, pairs, deflate_sc, flags=0):
    nv = spdy_build_nv(pairs)
    comp = deflate_sc.compress(nv) + deflate_sc.flush(zlib.Z_SYNC_FLUSH)
    payload = (stream_id & 0x7fffffff).to_bytes(4, "big") + b"\x00\x00" + comp
    return spdy_ctrl(2, payload, flags)


def spdy_data_frame(stream_id, data, fin=True):
    flags = 0x01 if fin else 0x00
    return (stream_id & 0x7fffffff).to_bytes(4, "big") + bytes([flags]) + len(data).to_bytes(3, "big") + data


def reply_headers(body_len, extra=None):
    """LINEが受理する応答ヘッダ。extra で x-lor(op revision) 等を追加可能。"""
    h = [
        [b"status", b"200 OK"],
        [b"version", b"HTTP/1.1"],
        [b"server", b"legy"],
        [b"content-type", b"application/x-thrift"],
        [b"x-line-http", b"P,LP,HC"],
        [b"x-lc", b"200"],
        [b"x-lcr", b"386"],
        [b"content-length", str(body_len).encode()],
    ]
    if extra:
        h.extend(extra)
    return h


# ISO country/territory choices, NOT a claim of official-account availability.
# The retired country-list RPC needs a picker fallback. Never rewrite the
# country sent by the client: HK users and explicit selections must be retained.
BUDDY_COUNTRY_CHOICES = tuple((
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ "
    "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR "
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP "
    "KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ "
    "NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW "
    "SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ "
    "UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"
).split())


def load_contact_state(filename):
    """Read the linejs worker's confirmed blocked/hidden MID snapshot."""
    try:
        with open(os.path.join(_ARTIFACTS, filename), encoding="utf-8") as state_file:
            values = _json.load(state_file)
        return [mid for mid in values
                if isinstance(mid, str) and re.fullmatch(r"u[0-9a-f]{32}", mid)]
    except Exception:
        return []


_STATE_CACHE = {}


def contact_state_set(filename):
    """load_contact_state の set 版。連絡先1件ごとに呼ばれるので mtime で覚えておく。"""
    path = os.path.join(_ARTIFACTS, filename)
    try:
        st = os.stat(path)
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        return frozenset()
    cached = _STATE_CACHE.get(filename)
    if cached and cached[0] == key:
        return cached[1]
    value = frozenset(load_contact_state(filename))
    _STATE_CACHE[filename] = (key, value)
    return value


def load_blocked_contacts():
    """Blocked users' Contact records written by the linejs worker (mid -> dict)."""
    try:
        with open(os.path.join(_ARTIFACTS, "blocked_contacts.json"), encoding="utf-8") as src:
            values = _json.load(src)
        return values if isinstance(values, dict) else {}
    except Exception:
        return {}


def load_recommendation_contacts():
    """Current-client recommendation snapshot, kept separate from friends."""
    try:
        with open(os.path.join(_ARTIFACTS, "recommendation_contacts.json"), encoding="utf-8") as src:
            values = _json.load(src)
        return values if isinstance(values, list) else []
    except Exception:
        return []


def blocked_split():
    """(friends, others) among the blocked MIDs.

    LINE 3.7.1's +[CoreDataSyncService syncBlockList] runs on every
    didBecomeActive: it asks getBlockedContactIds and getBlockedRecommendationIds,
    passes both lists to getContacts, and TalkUserObject updateWithContact:
    sets `blocking` only for status 2 (FRIEND_BLOCKED) / 4 (RECOMMEND_BLOCKED).
    The worker verifies every candidate by Contact.status and keeps only 2/4,
    matching what the official clients show; this splits the result.
    """
    blocked = load_contact_state("blocked_mids.json")
    records = load_blocked_contacts()
    friend_mids = {c.get("mid") for c in CONTACTS}
    friends, others = [], []
    for mid in blocked:
        status = (records.get(mid) or {}).get("status")
        is_friend = status == 2 if status in (2, 4, 6) else mid in friend_mids
        (friends if is_friend else others).append(mid)
    return friends, others


def legacy_contact_status(c, blocked=None):
    """Contact.status as LINE 3.7.1 must see it (blocked state from the worker)."""
    mid = c.get("mid")
    if blocked is None:
        blocked = set(load_contact_state("blocked_mids.json"))
    status = int(c.get("status") or 1)
    if mid in blocked:
        # 3.7.1 knows 1..4 only and lists every `blocking == true` user.  The worker
        # keeps DELETED_BLOCKED(6) out of blocked_mids.json, because the official
        # clients do not list those users either.
        return 2 if status in (1, 2) else 4
    # contacts.json can be older than an unblock; never keep a stale block.
    return {2: 1, 4: 3, 6: 5}.get(status, status)


def contacts_for_request(payload):
    """getContacts(2: list<string> ids) の対象。要求に無い相手は返さない。

    解析できない呼び出しは従来どおり友だち全員を返す。ブロック中の友だち以外は
    contacts.json に居ないので blocked_contacts.json から補う。推薦は専用スナップ
    ショットから補い、友だち一覧には混ぜない。"""
    mids = parse_getcontacts_mids(payload)
    if mids is None:
        return list(CONTACTS)
    by_mid = {c.get("mid"): c for c in CONTACTS}
    records = load_blocked_contacts()
    recommendations = {c.get("mid"): c for c in load_recommendation_contacts()}
    out = []
    for mid in dict.fromkeys(mids):
        contact = by_mid.get(mid) or records.get(mid) or recommendations.get(mid)
        if contact:
            out.append(contact)
    return out


def synth_for_method(method, seqid, payload=b""):
    """メソッド名からThrift応答本文を合成。未知はNone(=呼び出し元がEXC/emptyで対応)。"""
    if method == "getCountriesHavingBuddy":
        return build_string_list_result(method, seqid, BUDDY_COUNTRY_CHOICES)
    native = _native_registration_reply(method, seqid, payload)
    if native is not None:
        return native
    group_reply = _group_rpc_reply(method, seqid, payload)
    if group_reply is not None:
        return group_reply
    import legacy_groups_write
    group_write = legacy_groups_write.handle(globals(), method, seqid, payload)
    if group_write is not None:
        return group_write
    import legacy_sticker_shop
    shop = legacy_sticker_shop.handle(globals(), method, seqid, payload)
    if shop is not None:
        return shop
    maybe_reload_contacts()
    if method == "getCountryWithRequestIp":
        # 5.0.1はEXCが正解だったが3.7.1は"JP"成功が要るかも(env GETCOUNTRYで切替)
        if os.environ.get("GETCOUNTRY") == "jp":
            return synth_string_reply(method, seqid, "JP")
        return build_app_exception(method, seqid)
    # list<string> を返すメソッド群: 空listで応答(empty-structは型不一致でクラッシュ誘発)
    if method in ("getAllContactIds", "getBlockedContactIds", "getFavoriteMids",
                  "getRecommendationIds",
                  "getBlockedRecommendationIds", "getHiddenContactMids",
                  "getBlockedContactIdsByRange"):
        if method == "getAllContactIds":
            mids = [c.get("mid") for c in CONTACTS]
        elif method in ("getBlockedContactIds", "getBlockedContactIdsByRange"):
            mids = blocked_split()[0]
        elif method == "getBlockedRecommendationIds":
            mids = blocked_split()[1]
        elif method == "getHiddenContactMids":
            mids = load_contact_state("hidden_mids.json")
        elif method == "getRecommendationIds":
            mids = load_contact_state("recommendation_mids.json")
        else:
            mids = []
        return build_string_list_result(method, seqid, mids)
    if method in ("getContacts", "getContactsV2", "getContactsV3"):
        blocked = set(load_contact_state("blocked_mids.json"))
        targets = contacts_for_request(payload) if method == "getContacts" else CONTACTS
        return build_list_struct_result("getContacts", seqid, targets,
                                        lambda c: encode_contact(c, blocked))
    if method == "getProfile":
        maybe_reload_profile()
        return build_struct_result("getProfile", seqid, encode_profile())
    if method == "getSettings":
        return build_struct_result("getSettings", seqid, encode_settings())
    if method == "getSettingsAttributes":
        # ★空で返してはいけない。3.7.1 は +[PushNotificationService
        #   updateServerSettingsWithOptions:] で、要求ビットに 0x100000
        #   (電話番号登録)があると応答の phoneRegistration を保存し、false なら
        #   setTel:nil で端末の電話番号を消す -> 次の起動で番号認証になる。
        #   2026-09-11 22:36 に空応答でこれが起きた(「定期的に番号認証」の真因)。
        return build_struct_result("getSettingsAttributes", seqid, encode_settings())
    if method in SYNTH_EMPTY:
        return build_empty_struct_reply(method, seqid)
    return None


def spdy_synth(tls, first, host):
    """実gwに繋がず、全SPDYフレームをこちらで合成する。"""
    inflate = zlib.decompressobj(zdict=SPDY2_DICT)
    deflate_sc = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, 15, 8,
                                  zlib.Z_DEFAULT_STRATEGY, SPDY2_DICT)
    streams = {}   # sid -> {"headers": pairs}
    log(f"{now()}  ~~~ SPDY SYNTH server (no upstream) sni={host}")
    SDBG = os.environ.get("SPDY_DEBUG", "1") != "0" and os.environ.get("NATIVE_REGISTRATION") != "1"
    _FT = {1: "SYN_STREAM", 2: "SYN_REPLY", 3: "RST_STREAM", 4: "SETTINGS",
           6: "PING", 7: "GOAWAY", 8: "HEADERS", 9: "WINDOW_UPDATE"}
    if SDBG:
        log(f"  [dbg] first={len(first)}B hex={first[:64].hex()}")
    tls.settimeout(60)
    # サーバSETTINGSを先出し(LINEはこれを待ってSYN_STREAMを送る可能性)
    # env SPDY_SETTINGS: off=送らない / v2=SPDY/2正準(id=little-endian, MAX_CONCURRENT_STREAMSのみ)
    #                    / 既定=従来(誤SPDY/3 id含む, A/B比較用に残置)
    _sset = os.environ.get("SPDY_SETTINGS", "").lower()
    try:
        if _sset == "off":
            log("  [synth] SETTINGS suppressed (SPDY_SETTINGS=off)")
        elif _sset == "v2":
            # SPDY/2: SETTINGS entry = 3-byte id(LITTLE-endian) + 1 flags + 4 value
            # id 4 = MAX_CONCURRENT_STREAMS。SPDY/2にwindow size設定は無い。
            entry = bytes([4, 0, 0, 0]) + (100).to_bytes(4, "big")  # id=4 LE + flags0 + val100
            settings_payload = (1).to_bytes(4, "big") + entry
            tls.sendall(spdy_ctrl(4, settings_payload))
            log("  [synth] sent server SETTINGS (v2 canonical)")
        else:
            settings_payload = (b"\x00\x00\x00\x02"          # 2 entries
                                b"\x00\x00\x00\x04" + (100).to_bytes(4, "big")     # MAX_CONCURRENT_STREAMS=100
                                + b"\x00\x00\x00\x07" + (65536).to_bytes(4, "big"))  # INITIAL_WINDOW_SIZE=64K
            tls.sendall(spdy_ctrl(4, settings_payload))
            log("  [synth] sent server SETTINGS (legacy)")
    except Exception as e:
        log(f"  [synth SETTINGS err] {e!r}")

    def respond(sid, method, seqid, hdrs, payload=b""):
        # 認証RPC捕獲: X-Line-Access等のトークンヘッダを目立たせる
        access = None
        for k, v in (hdrs or []):
            if k.lower() in (b"x-line-access", b"x-line-a", b"x-lt"):
                access = v
        if access is not None:
            log(f"  [AUTH-RPC] method={method} X-Line-Access=[REDACTED]")
        global _contacts_delivered
        extra = None
        if method in ("fetchOperations", "fetchOps"):
            localRev = parse_fetchops_localrev(payload)
            # 受信メッセージ配信: outbox の未配信を RECEIVE_MESSAGE op で送る。
            ops = drain_outbox(localRev)
            if not ops:
                # 長ポーリング: HOLD 中に outbox を1秒毎に再チェック(新着に即応)
                waited = 0.0
                while waited < FETCHOPS_HOLD:
                    time.sleep(1.0); waited += 1.0
                    ops = drain_outbox(localRev)
                    if ops:
                        break
            if ops:
                lastrev = ops[-1]["revision"] + 1   # EOOはメッセージopより大きい別revision
                ops.append({"revision": lastrev, "type": 0})   # END_OF_OPERATION
                thrift = build_operations_result(method, seqid, ops)
                if os.environ.get("NO_XLOR_MSG") == "1":
                    extra = None   # 実験: x-lor を付けず本文op解析を促す
                    log(f"  [synth] fetchOps localRev={localRev} -> {len(ops)-1} msg op(s) NO x-lor(body-parse test)")
                else:
                    extra = [[b"x-lor", str(lastrev).encode()]]
                    log(f"  [synth] fetchOps localRev={localRev} -> {len(ops)-1} msg op(s), x-lor={lastrev}")
            else:
                thrift = build_operations_result(method, seqid,
                                                 [{"revision": localRev, "type": 0}])
                extra = [[b"x-lor", str(localRev).encode()]]
                log(f"  [synth] fetchOps localRev={localRev} -> END_OF_OPERATION x-lor={localRev} (held {FETCHOPS_HOLD}s)")
        elif method == "sendChatChecked":
            # 旧アプリがトークを開いた時の既読。応答は従来通り empty-struct でよい。
            record_chat_checked(payload)
            thrift = build_empty_struct_reply(method, seqid)
        elif method == "sendMessage":
            # old LINE からの送信: Message を取り出し記録。応答は送信済み Message を返す。
            msg = parse_message_arg(payload)
            nowms = int(time.time() * 1000)
            msg["id"] = str(nowms)
            msg["createdTime"] = nowms
            try:
                with open(os.path.join(_ARTIFACTS, "sent.jsonl"), "a", encoding="utf-8") as f:
                    f.write(_json.dumps(msg, ensure_ascii=False) + "\n")
            except Exception as e:
                log(f"  [sendMessage] record err {e!r}")
            try:
                snd = {"seq": msg["id"], "to": msg.get("to"), "text": msg.get("text", ""),
                       "contentType": msg.get("contentType", 0),
                       "contentMetadata": msg.get("contentMetadata", {}),
                       "via": "S4", "ts": nowms}
                with open(os.path.join(_ARTIFACTS, "send_queue.jsonl"), "a", encoding="utf-8") as f:
                    f.write(_json.dumps(snd, ensure_ascii=False) + "\n")
            except Exception as e:
                log(f"  [sendMessage spdy] queue err {e!r}")
            if msg.get("contentType"):
                _sent_media[str(msg["id"])] = dict(msg)
                log("  [media confirm spdy] upload_done 待ち")
            log(f"  [★SEND spdy] to={msg.get('to')} ct={msg.get('contentType')} id={msg['id']}")
            thrift = build_struct_result("sendMessage", seqid, encode_message(msg))
        elif method == "getProduct":
            # 3.7.1 は SHOP4 も SPDY 経由で呼ぶ。HTTP 経路だけに実装すると
            # 空structを返してしまい、スタンプメタデータ更新が壊れる。
            thrift = build_get_product(method, seqid, payload)
            log(f"  [synth] {method} -> product reply {len(thrift)}B (sid {sid})")
        elif method == "getActivePurchaseVersions":
            thrift = build_active_purchase_versions(method, seqid)
            log(f"  [synth] {method} -> active purchases reply {len(thrift)}B (sid {sid})")
        elif method == "getActivePurchases":
            thrift = build_active_purchase_versions(method, seqid)
            log(f"  [synth] {method} -> active purchases reply {len(thrift)}B (sid {sid})")
        elif method in ("getContacts", "getContactsV2", "getContactsV3"):
            # 要求されたmidだけ返す(全件返すとLINEが混乱してクラッシュ)
            maybe_reload_contacts()
            req = parse_getcontacts_mids(payload)
            sel = contacts_for_request(payload)
            blocked = set(load_contact_state("blocked_mids.json"))
            thrift = build_list_struct_result("getContacts", seqid, sel,
                                              lambda c: encode_contact(c, blocked))
            log(f"  [synth] getContacts req={len(req) if req is not None else '?'} -> {len(sel)} contacts ({len(thrift)}B)")
        else:
            thrift = synth_for_method(method, seqid, payload)
            if thrift is None:
                thrift = build_empty_struct_reply(method, seqid)
                log(f"  [synth] {method} -> empty-struct (未実装; sid {sid})")
            else:
                log(f"  [synth] {method} -> reply {len(thrift)}B (sid {sid})")
        try:
            rep = spdy_syn_reply(sid, reply_headers(len(thrift), extra), deflate_sc)
            dat = spdy_data_frame(sid, thrift, fin=True)
            tls.sendall(rep)
            tls.sendall(dat)
            if SDBG:
                log(f"  [dbg->C sid{sid}] SYN_REPLY {len(rep)}B hex={rep[:48].hex()} | "
                    f"DATA {len(dat)}B fin=1")
        except Exception as e:
            log(f"  [synth send err] {e!r}")

    buf = bytearray(first)
    try:
        while True:
            while len(buf) >= 8:
                length = int.from_bytes(buf[5:8], "big")
                total = 8 + length
                if len(buf) < total:
                    break
                frame = bytes(buf[:total]); del buf[:total]
                if frame[0] & 0x80:  # control frame
                    ftype = int.from_bytes(frame[2:4], "big")
                    cflags = frame[4]
                    if SDBG and ftype not in (1, 8):
                        log(f"  [dbg<-C {_FT.get(ftype, ftype)}] flags={cflags:#04x} "
                            f"len={length} hex={frame[:min(total, 32)].hex()}")
                    if ftype == 1:   # SYN_STREAM
                        sid = int.from_bytes(frame[8:12], "big") & 0x7fffffff
                        raw = inflate.decompress(frame[18:])
                        pairs = spdy_parse_nv(raw)
                        streams[sid] = {"headers": pairs}
                        hd = "\n".join(f"      {k.decode('latin1','replace')}: "
                                       + ("[REDACTED]" if k.decode('latin1').lower() in _PRIVATE_HEADERS
                                          else v.decode('latin1','replace')[:200])
                                       for k, v in pairs)
                        finflag = " FIN" if (cflags & 0x01) else ""
                        log(f"  [SYN_STREAM sid{sid} flags={cflags:#04x}{finflag}]\n{hd}")
                    elif ftype == 8:  # HEADERS (inflate状態維持のため復号だけ)
                        try:
                            inflate.decompress(frame[14:])
                        except Exception:
                            pass
                    elif ftype == 6:  # PING -> echo
                        tls.sendall(frame)
                    elif ftype == 3:  # RST_STREAM
                        sid = int.from_bytes(frame[8:12], "big") & 0x7fffffff
                        status = int.from_bytes(frame[12:16], "big") if total >= 16 else -1
                        log(f"  [RST_STREAM sid{sid}] status={status}")
                    elif ftype == 7:  # GOAWAY
                        last = int.from_bytes(frame[8:12], "big") & 0x7fffffff if total >= 12 else -1
                        log(f"  [GOAWAY] last_good_sid={last}")
                    # SETTINGS(4)/WINDOW_UPDATE(9)等は無視(上でdbgログ済)
                else:  # DATA frame
                    sid = int.from_bytes(frame[0:4], "big") & 0x7fffffff
                    payload = frame[8:]
                    hdrs = streams.get(sid, {}).get("headers", [])
                    url = next((v.decode("latin1") for k, v in hdrs if k == b"url"), "?")
                    m, sq = thrift_call_name(payload)
                    if m:
                        argslog = f"  args={payload.hex()}" if m in ("fetchOps","getConfigurations","getSettingsAttributes","getContacts","getContactsV2","getAllContactIds","sendMessage") else ""
                        log(f"  [C->S DATA sid{sid}] url={url} CALL {m}{argslog}")
                        respond(sid, m, sq, hdrs, payload)
                    elif url == "/C5" and parse_c5_send(payload):
                        # LEGY bespoke sendMessage(/C5)。宛先mid+本文を抽出して記録。
                        snd = parse_c5_send(payload)
                        # ACKのmessage IDと既読対象IDは必ず同じ値にする。
                        # 別々に現在時刻を採ると、1msずれただけでop28が該当せず
                        # 既読表示が飛び飛びになる。
                        ack_msg_id = int(time.time() * 1000)
                        snd["via"] = "C5"; snd["ts"] = ack_msg_id
                        note_local_msg_id(snd.get("to"), ack_msg_id)
                        try:
                            with open(os.path.join(_ARTIFACTS, "send_queue.jsonl"), "a", encoding="utf-8") as f:
                                f.write(_json.dumps(snd, ensure_ascii=False) + "\n")
                        except Exception as e:
                            log(f"  [C5 record err] {e!r}")
                        log(f"  [★SEND /C5] seq={snd['seq']} to={snd['to']} text={snd['text']!r}")
                        try:
                            seq = snd.get("seq", 1)
                            _i32 = int(os.environ.get("C5_I32", "0"))
                            reply = build_c5_ack(ack_msg_id, ack_msg_id, _i32, seq=seq)
                            tls.sendall(spdy_syn_reply(sid, reply_headers(len(reply)), deflate_sc))
                            tls.sendall(spdy_data_frame(sid, reply, fin=True))
                            log(f"  [C5 ack spdy] hdr={os.environ.get('C5_HDR','none')} "
                                f"i32={_i32} ({len(reply)}B)")
                        except Exception as e:
                            log(f"  [C5 resp err] {e!r}")
                    elif payload:
                        # 未認識(非82-21)フレーム: 生ログして中身を調べる。空応答でハング回避。
                        log(f"  [C->S DATA sid{sid}] url={url} UNPARSED len={len(payload)} hex={payload.hex()}")
                        try:
                            empty = build_empty_struct_reply("_unknown", sq or 1)
                            tls.sendall(spdy_syn_reply(sid, reply_headers(len(empty)), deflate_sc))
                            tls.sendall(spdy_data_frame(sid, empty, fin=True))
                        except Exception:
                            pass
            d = tls.recv(65536)
            if SDBG:
                log(f"  [dbg] recv {len(d)}B" + (" (EOF)" if not d else f" hex={d[:32].hex()}"))
            if not d:
                break
            buf += d
    except Exception as e:
        log(f"  spdy synth err {e!r}")
    log(f"{now()}  ~~~ SPDY SYNTH closed  sni={host}")


def handle_http(client, sni):
    try:
        tls = SERVER_CTX.wrap_socket(client, server_side=True)
    except OSError as e:
        log(f"[tls] handshake FAILED (sni={sni}): {e!r}")
        return
    # KEEP_ALIVE=1: 1接続で複数リクエストをループ処理(LEGYの持続多重化に合わせる)。
    # 既定(未設定)は従来通り1リクエストで close。
    ka = os.environ.get("KEEP_ALIVE") == "1"
    ch = b"keep-alive" if ka else b"close"
    try:
        tls.settimeout(60 if ka else 30)
        pre = b""
        while True:
            r, pre = _serve_http_once(tls, sni, ch, pre)
            if not r or not ka:
                break
    finally:
        try:
            tls.close()
        except OSError:
            pass


def _frame_resp(status, hdrs, body, ch, extra=b"", content_length=None,
                allow_chunked=True):
    """LEGY応答を組む。CHUNKED=1 で Transfer-Encoding: chunked(終端0)、既定は content-length。
    LEGYは Content-Length を『完了』と認識せず error1000 で捨てる → chunked必須。
    status=b'200 OK', hdrs=フレーミング以外のヘッダ(末尾\\r\\n込), extra=追加ヘッダ."""
    head = b"HTTP/1.1 " + status + b"\r\n" + hdrs + extra
    if allow_chunked and os.environ.get("CHUNKED") == "1":
        cb = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        return head + b"Transfer-Encoding: chunked\r\nConnection: " + ch + b"\r\n\r\n" + cb
    n = len(body) if content_length is None else int(content_length)
    return (head + f"content-length: {n}\r\n".encode()
            + b"Connection: " + ch + b"\r\n\r\n" + body)


_LEGY_HDRS = (b"server: legy\r\n"
              b"content-type: application/x-thrift;charset=UTF-8\r\n"
              b"x-lc: 200\r\nx-lcr: 386\r\nx-line-http: P,LP,HC\r\n")


def _authct_key_json(reply):
    """Translate a public getRSAKeyInfo REPLY into the legacy authct JSON."""
    if len(reply) > 8192 or not reply.startswith(b"\x82\x41"):
        raise ValueError("invalid public-key reply")
    seqid, pos = uvarint(reply, 2)
    size, pos = uvarint(reply, pos)
    if seqid != 0 or reply[pos:pos + size] != b"getRSAKeyInfo":
        raise ValueError("unexpected public-key method")
    fields, end = _tc_read_struct(reply, pos + size)
    if end != len(reply) or set(fields) != {0} or fields[0][0] != 12:
        raise ValueError("public-key result is not success")
    key = fields[0][1]
    values = []
    for fid in (1, 2, 3, 4):
        typ, value = key.get(fid, (None, None))
        if typ != 8 or not isinstance(value, bytes) or not 0 < len(value) <= 2048:
            raise ValueError("missing public-key field")
        values.append(value.decode("ascii"))
    keyname, modulus, exponent, session_key = values
    if not keyname.isdigit() or not re.fullmatch(r"[0-9a-fA-F]+", modulus):
        raise ValueError("invalid RSA key")
    if not re.fullmatch(r"[0-9a-fA-F]+", exponent):
        raise ValueError("invalid RSA exponent")
    if not 1024 <= int(modulus, 16).bit_length() <= 8192 or int(exponent, 16) < 3:
        raise ValueError("invalid RSA parameters")
    return json.dumps({"session_key": session_key,
                       "rsa_key": ",".join((keyname, modulus, exponent))},
                      separators=(",", ":")).encode("ascii")


def _fetch_authct_public_key():
    # The old REST endpoint is gone; the public, unauthenticated RPC survives.
    # Never forward client headers, credentials, cookies, or the bridge token.
    connection = http.client.HTTPSConnection(
        "gd2.line.naver.jp", timeout=12, context=ssl.create_default_context())
    try:
        connection.request("POST", "/api/v4/TalkService.do",
                           body=b"\x82\x21\x00\x0dgetRSAKeyInfo\x25\x02\x00",
                           headers={
                               "Content-Type": "application/x-thrift",
                               "X-Line-Application": bridge_app_string(),
                           })
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("public-key upstream HTTP failure")
        return _authct_key_json(response.read(8193))
    finally:
        connection.close()


def _serve_http_once(tls, sni, ch, pre=b""):
    """Read+dispatch ONE HTTP request. Returns (keep_open, leftover_bytes).
    keep_open=False closes the connection."""
    try:
        buf = pre
        while b"\r\n\r\n" not in buf:
            try:
                chunk = tls.recv(4096)
            except socket.timeout:
                log(f"{now()}  recv timeout (sni={sni}) buf={buf[:40].hex()}")
                return (False, b"")
            if not chunk:
                return (False, b"")
            buf += chunk
            # 非HTTP(SPDY/2): SYNTH=1 なら独立合成サーバ、既定は実gw中継
            if buf and buf[:4] not in HTTP_METHODS:
                target = sni or "gw.line.naver.jp"
                if os.environ.get("SYNTH") == "1":
                    spdy_synth(tls, bytes(buf), target)
                else:
                    spdy_relay(tls, bytes(buf), target)
                return (False, b"")
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        method, path, _ = (lines[0].decode("latin1").split(" ") + ["", "", ""])[:3]
        headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                headers[k.decode("latin1").strip()] = v.decode("latin1").strip()
        host = headers.get("Host", "").split(":")[0] or sni
        # アバター(obs)中継: 旧アプリは /os/p/<mid>/preview を要求するが実obsは404。
        # /preview を外した /os/p/<mid> は200で画像を返すので書き換えて中継する。
        if ("obs" in host and path.endswith("/preview")
                and re.match(r"^/os/[pg]/", path)):
            newp = path[:-len("/preview")]
            log(f"  [obs rewrite] {path} -> {newp}")
            path = newp
        clen = int(headers.get("Content-Length", 0) or 0)
        body = rest
        while len(body) < clen:
            body += tls.recv(4096)
        leftover = body[clen:]   # パイプライン: 本文の後は次リクエストの先頭
        body = body[:clen]

        tname, seqid = thrift_call_name(body)
        hdr_dump = "\n".join(f"    {k}: " + ("[REDACTED]" if k.lower() in _PRIVATE_HEADERS else v)
                             for k, v in headers.items())
        body_note = ""
        if body and tname not in AUTH_PRIVATE_METHODS:
            body_note = "\n  req body hex:\n" + "\n".join(
                f"    {body[i:i+16].hex()}" for i in range(0, min(len(body), 128), 16))
        log("=" * 60 + f"\n{now()}  >>> {method} {path}  (Host {host})\n{hdr_dump}{body_note}")

        # LINE 3.7.1's normal Home/Timeline UI uses a JSON/form REST service.
        # It is independent of TalkService.sendMessageToMyHome (hitokoto).
        if ((host or "").lower() in (
                "myhome.line.naver.jp", "timeline.line.naver.jp",
                "homeapi.line.naver.jp")
                and path.split("?", 1)[0].startswith(("/api/", "/mapi/"))):
            import legacy_timeline_rest
            status, response_headers, payload = legacy_timeline_rest.handle(
                globals(), method, host, path, headers, body, real_token())
            tls.sendall(_frame_resp(status, response_headers, payload, ch))
            return (True, leftover)

        # 廃止メソッドはローカルで合成応答(本物へ投げると Invalid method name)
        # 認証RPC捕獲: トークンヘッダを目立たせる
        access = next((v for k, v in headers.items()
                       if k.lower() in ("x-line-access", "x-line-a", "x-lt")), None)
        if access:
            log(f"  [AUTH-RPC] method={tname} X-Line-Access=[REDACTED]")
        else:
            log(f"  [method] {tname}")
        if tname == "findAndAddContactsByMid":
            import legacy_friend_add
            reply = legacy_friend_add.handle(globals(), body, seqid, real_token())
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        if tname == "getMessageBox":
            import legacy_status_home
            reply = legacy_status_home.handle_get_message_box(globals(), body, seqid)
            log(f"  [status-home] getMessageBox history reply {len(reply)}B")
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        if tname == "sendMessageToMyHome":
            # LINE 3.7.1's "hitokoto" latest value is Profile.statusMessage.
            # Its MyHome-named history path is distinct from normal Timeline
            # REST posts; do not turn every status save into a VOOM post.
            import legacy_status_home
            reply = legacy_status_home.handle(globals(), body, seqid, real_token())
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        # These local setup RPCs must never reach the official auth service,
        # regardless of host routing or FORWARD_METHODS configuration.
        if tname in NATIVE_REGISTRATION_METHODS:
            reply = _native_registration_reply(tname, seqid, body)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        if tname in GROUP_READ_METHODS:
            reply = _group_rpc_reply(tname, seqid, body)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        # createGroup 等は現行サーバに無いので中継できない。CHRLINE セッションを
        # 持つ bridge_daemon に Chat API で実行させ、その結果を旧形式で返す。
        import legacy_groups_write
        if tname in legacy_groups_write.GROUP_WRITE_METHODS:
            reply = legacy_groups_write.handle(globals(), tname, seqid, body)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        # Authentication is not CDN traffic. Handle only this observed public
        # GET; this does not synthesize login success or change account state.
        if (host or "").lower() == "t.line.naver.jp" and method == "GET" \
                and path.split("?", 1)[0] == "/authct/v1/keys/line":
            try:
                payload = _fetch_authct_public_key()
                status = b"200 OK"
                log("  [authct] public key -> 200 (legacy JSON)")
            except Exception as exc:
                payload = b'{"error":"public_key_unavailable"}'
                status = b"502 Bad Gateway"
                log(f"  [authct] public key unavailable ({type(exc).__name__})")
            tls.sendall(_frame_resp(
                status, b"content-type: application/json; charset=utf-8\r\n"
                        b"cache-control: no-store\r\n", payload, ch,
                allow_chunked=False))
            return (True, leftover)

        # ---- 単体構成(RasPi1台)向け: LEGYゲートウェイ以外のホストはCDNへ委譲 ----
        # os.line.naver.jp(アイコン/メディア)は同居の cdn_proxy(127.0.0.1:8081)が
        # 旧URL→現行CDN翻訳を持っているので、そのまま中継する。
        _cdn = os.environ.get("CDN_BACKEND")
        _host_l = (host or "").lower()
        if _cdn and _host_l and not _host_l.startswith(("gw.", "gwx.")):
            try:
                import http.client as _hc
                _h, _, _p = _cdn.partition(":")
                up = _hc.HTTPConnection(_h, int(_p or 80), timeout=30)
                fh = {k: v for k, v in headers.items() if k.lower() != "connection"}
                up.request(method, path, body=body or None, headers=fh)
                r = up.getresponse()
                rb = r.read()
                ct = r.getheader("Content-Type", "application/octet-stream")
                upstream_len = r.getheader("Content-Length")
                passthrough = bytearray()
                for hk in ("Content-Range", "Accept-Ranges", "ETag", "Last-Modified"):
                    hv = r.getheader(hk)
                    if hv:
                        passthrough += f"{hk.lower()}: {hv}\r\n".encode("latin1")
                reason = str(r.reason or "OK").encode("latin1", "replace")
                up.close()
                log(f"  [cdn] {method} {_host_l}{path} -> {r.status} ({len(rb)}B)")
                _hdr = ("content-type: " + ct + chr(13) + chr(10)).encode()
                response_len = int(upstream_len) if method == "HEAD" and upstream_len else len(rb)
                tls.sendall(_frame_resp(str(r.status).encode() + b" " + reason,
                                        _hdr, rb, ch, extra=bytes(passthrough),
                                        content_length=response_len,
                                        allow_chunked=False))
                return (True, leftover)
            except Exception as e:
                log(f"  [cdn] err {e!r}")
                _crlf = (chr(13) + chr(10))
                tls.sendall(("HTTP/1.1 502 Bad Gateway" + _crlf +
                             "Content-Length: 0" + _crlf + _crlf).encode())
                return (False, b"")

        # 送信: LEGY bespoke /C5(旧appの送信経路)。HTTP経路でも捕捉する。
        if path == "/C5":
            log(f"  [/C5 body {len(body)}B] {body.hex()}  parsed={parse_c5_send(body)}")
        if path == "/C5" and parse_c5_send(body):
            snd = parse_c5_send(body)
            # 4Sが保存するIDはこの後のACKに入れる値。その同じ値を既読対象にする。
            nowms = int(time.time() * 1000)
            snd["via"] = "C5"; snd["ts"] = nowms
            queued = False
            try:
                with open(os.path.join(_ARTIFACTS, "send_queue.jsonl"), "a", encoding="utf-8") as f:
                    f.write(_json.dumps(snd, ensure_ascii=False) + "\n")
                queued = True
            except Exception as e:
                log(f"  [C5 http record err] {e!r}")
            log(f"  [★SEND /C5 http] seq={snd.get('seq')} to={snd.get('to')} text={snd.get('text')!r}")
            seq = snd.get("seq", 1)
            result_id = f"{seq}_{nowms}"
            delivery = wait_send_result(result_id) if queued else {
                "id": result_id, "ok": False, "err": "queue write failed"
            }
            if not delivery.get("ok"):
                # Do not send the bespoke success ACK: it commits the local
                # message id and timestamp in LINE 3.7.1.  A non-2xx response
                # leaves the message unsent instead of showing a fake time.
                log(f"  [C5 delivery failed] id={result_id} err={delivery.get('err')}")
                tls.sendall(_frame_resp(b"503 Service Unavailable", _LEGY_HDRS, b"", ch))
                return (True, leftover)
            note_local_msg_id(snd.get("to"), nowms)
            log(f"  [C5 delivery ok] id={result_id}")
            # 送信確認: SEND_MESSAGE op(type25)。※これは元メッセージを更新せず
            # 別メッセージを作ってしまい「成功1+失敗1」の二重表示になった(2026-08-02)。
            # 正しくは /C5応答自体を成功ackにすべき。env SEND_CONFIRM=1 の時だけ配信(既定OFF)。
            if os.environ.get("SEND_CONFIRM") == "1":
                _nowms = int(time.time() * 1000)
                _pending_ops.append({
                    "type": 25, "reqSeq": seq, "createdTime": _nowms,
                    "message": {"from": bridge_mid(), "to": snd.get("to"),
                                "toType": 0, "id": str(_nowms), "createdTime": _nowms,
                                "text": snd.get("text", ""), "contentType": 0},
                })
                log(f"  [★SEND] queued SEND_MESSAGE op(type25) reqSeq={seq}")
            if os.environ.get("C5_RESP") == "thrift":
                # 旧: 標準sendMessage Thrift(アプリは受理せず!になる)。比較用に残置。
                mm = {"from": bridge_mid(), "to": snd.get("to"),
                      "toType": 0, "id": str(nowms), "createdTime": nowms,
                      "text": snd.get("text", ""), "contentType": 0}
                reply = build_struct_result("sendMessage", seq, encode_message(mm))
            else:
                # 既定: bespoke ack(readBool,readI32,readI64 id,readI64 createdTime)。
                # createdTimeの単位を実験(env C5_CT_UNIT): ms(既定)/sec/us。表示日付調整用。
                _u = os.environ.get("C5_CT_UNIT", "ms")
                _ct = nowms if _u == "ms" else (nowms // 1000 if _u == "sec" else nowms * 1000)
                # 送信メッセージのtimestampは高位フラグ 0x2000000000000000 を期待する説。
                if os.environ.get("C5_CT_FLAG") == "1":
                    _ct = _ct | 0x2000000000000000
                # env C5_I32: readI32 の値。値自体はアプリで捨てられる(0x211b38の戻りは未保存)ので、
                # ヘッダ消費バイト数がずれていないかの探針として使う。ずれていれば
                # この非0バイトが readBool に読まれ、msg が生成される(=ID が化ける)。
                _i32 = int(os.environ.get("C5_I32", "0"))
                reply = build_c5_ack(nowms, _ct, _i32, seq=seq)
                log(f"  [C5 ack] hdr={os.environ.get('C5_HDR','none')} i32={_i32} id={nowms} ct={_ct}({_u}) ({len(reply)}B) hex={reply.hex()}")
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        if tname == "getCountryWithRequestIp" and os.environ.get("FORWARD_ALL") != "1":
            # env GETCOUNTRY=jp なら "JP" 成功を返す(コールドブートのgetCountryループ対策)。
            # 既定は実gw同様EXC。HTTP側も SPDY合成と同じ挙動に揃える。
            gc = os.environ.get("GETCOUNTRY", "").upper()
            if gc:
                reply = synth_string_reply(tname, seqid, gc)
                log(f"--- <<< 200 OK  SYNTH {tname} -> \"{gc}\" ({len(reply)}B) ---")
            else:
                reply = build_app_exception(tname, seqid)  # 実gw同様EXC
                log(f"--- <<< 200 OK  SYNTH {tname} -> EXC InvalidMethod ({len(reply)}B) ---")
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        if tname in ("fetchOperations", "fetchOps"):
            # 3.7.1受信の本体は /P4 HTTPロングポールの fetchOperations(v3同名)。
            # 空structでは同期をやり直すため、OperationsResult+END_OF_OPERATION+x-lor を返す
            # (outbox即ドレイン=3.1.3 http_bridge_v3 / SPDY respond() と同方式)。
            localRev = parse_fetchops_localrev(body)
            forced_scopes = claim_forced_sync()
            if forced_scopes:
                if forced_scopes == {"group"}:
                    reply, sync_rev = build_legacy_group_resync(tname, seqid, localRev)
                    log(f"  [forced-sync] native op39 group refresh localRev={localRev} x-lor={sync_rev}")
                else:
                    reply = build_should_sync(tname, seqid, localRev, forced_scopes)
                    sync_rev = localRev
                    log(f"  [forced-sync] localRev={localRev} scopes={sorted(forced_scopes)}")
                tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch,
                                        extra=f"x-lor: {sync_rev}\r\n".encode()))
                return (True, leftover)
            ops = drain_outbox(localRev)
            if not ops:
                # 保持枠が空いていれば通常のロングポール。埋まっていれば短時間だけ待って
                # 接続を返す(即返しにするとアプリが即再ポールしてstormになるため)。
                got = _acquire_hold()
                hold_secs = FETCHOPS_HOLD if got else float(os.environ.get("FOPS_MINI", "0.8"))
                try:
                    # 送信確認op/受信を素早く届けるため 0.2s 間隔でドレイン(既定1sだと
                    # 送信のtimeout窓に間に合わず!になる)。env FOPS_TICK で調整可。
                    tick = float(os.environ.get("FOPS_TICK", "0.2"))
                    waited = 0.0
                    while waited < hold_secs:
                        time.sleep(tick); waited += tick
                        ops = drain_outbox(localRev)
                        if ops:
                            break
                finally:
                    if got:
                        _release_hold()
            if ops:
                lastrev = ops[-1]["revision"]
                eoo = lastrev + 1   # END_OF_OPERATION は必ずメッセージopより大きい別revision
                ops.append({"revision": eoo, "type": 0})
                reply = build_operations_result(tname, seqid, ops)
                xlor = eoo
                log(f"  [synth http] {tname} localRev={localRev} -> {len(ops)-1} op(s) EOO_rev={eoo} x-lor={eoo}")
            else:
                # デバッグ: FOPS_ADV=1 で空ポールでも EOO を localRev+step で返し、
                # x-lor/op-rev による revision前進機構が3.7.1 HTTPで効くか切り分ける。
                adv = int(os.environ.get("FOPS_ADV", "0"))
                eoo = localRev + adv if adv else localRev
                reply = build_operations_result(tname, seqid, [{"revision": eoo, "type": 0}])
                xlor = eoo
                log(f"  [synth http] {tname} localRev={localRev} -> END_OF_OPERATION rev={eoo} x-lor={eoo} (held {FETCHOPS_HOLD}s)")
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch,
                                    extra=f"x-lor: {xlor}\r\n".encode()))
            return (True, leftover)
        if tname == "sendMessage":
            # HTTP経由の送信も捕捉(実gwへ転送しない)。SPDY経路と同じ処理。
            msg = parse_message_arg(body)
            nowms = int(time.time() * 1000)
            msg["id"] = str(nowms); msg["createdTime"] = nowms
            note_local_msg_id(msg.get("to"), msg["id"])
            try:
                with open(os.path.join(_ARTIFACTS, "sent.jsonl"), "a", encoding="utf-8") as f:
                    f.write(_json.dumps(msg, ensure_ascii=False) + "\n")
            except Exception as e:
                log(f"  [sendMessage http] record err {e!r}")
            # ★ブリッジへ渡す: /C5(テキスト)と同じ send_queue.jsonl に積む。
            # 従来は sent.jsonl に記録するだけで send_worker に渡らず、
            # スタンプ/画像/音声が実配送されていなかった(2026-08-02)。
            try:
                snd = {"seq": msg["id"], "to": msg.get("to"), "text": msg.get("text", ""),
                       "contentType": msg.get("contentType", 0),
                       "contentMetadata": msg.get("contentMetadata", {}),
                       "via": "S4", "ts": nowms}
                with open(os.path.join(_ARTIFACTS, "send_queue.jsonl"), "a", encoding="utf-8") as f:
                    f.write(_json.dumps(snd, ensure_ascii=False) + "\n")
            except Exception as e:
                log(f"  [sendMessage http] queue err {e!r}")
            log(f"  [★SEND http] to={msg.get('to')} ct={msg.get('contentType')} "
                f"meta={msg.get('contentMetadata')} text={msg.get('text')!r} id={msg['id']}")
            # ★メディア送信の完了確定: `-[TalkMessageObject line_uploadImage]` の完了
            # ブロックは line_contentUploadType==5 のときしか sendStatus を 1 にしない。
            # 画像等はそこを通らないので「送信中(status 3)」のまま時刻も出ない。
            # ∴ fetchOperations で SEND_MESSAGE(type25) op を返して確定させる。
            # reqSeq は /S4 リクエストの fid1 をそのまま使う(正確に紐付く)。
            if msg.get("contentType") and msg.get("reqSeq") is not None \
                    and os.environ.get("MEDIA_CONFIRM", "1") == "1":
                # ★reqSeq を載せると isProcessedRequestSequenceInOperation が
                # 「処理済み」と判定して op を捨てる(2026-08-19 実測: =1)。
                # アプリは /S4 応答時点で既に reqSeq を消費しているため。
                # ∴ 既定では reqSeq を付けずに送る(env MEDIA_CONFIRM_REQSEQ=1 で従来動作)。
                # ★2026-08-20: メディア確定は SEND_CONTENT(op43)が正路と判明。
                #   逆アセンブル: _processOperations の型43ハンドラ(0x42e1fe)が
                #   messageSendContent:withRequestSequence:inContext:(0x309b7d)を呼び、
                #   status1 と正しい timestamp を設定する(=母艦主導で確定・時刻正常)。
                #   従来の型25は画像だと messageSent:(status3固定)へ流れて確定不能だった。
                #   OpType 43=SEND_CONTENT は CHRLINE enum でも確定。
                #   env MEDIA_CONFIRM_OPTYPE で切替(既定43)。43は reqSeq が要る
                #   (messageSendContent:withRequestSequence: が pending を突き止めるため)。
                _sent_media[str(msg["id"])] = dict(msg)
                _optype = int(os.environ.get("MEDIA_CONFIRM_OPTYPE", "25"))
                _op = {"type": _optype, "createdTime": nowms, "message": msg}
                if _optype == 43:
                    if os.environ.get("MEDIA43_NO_REQSEQ") != "1" and msg.get("reqSeq") is not None:
                        _op["reqSeq"] = msg["reqSeq"]
                elif os.environ.get("MEDIA_CONFIRM_REQSEQ") == "1":
                    _op["reqSeq"] = msg["reqSeq"]
                _pending_ops.append(_op)
                log(f"  [media confirm] type{_optype} op を予約 "
                    f"(reqSeq={'付与' if 'reqSeq' in _op else '無し'})")
            reply = build_struct_result("sendMessage", seqid, encode_message(msg))
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        # 3.7.1(v4): 認証トークンは実gwで無効=中継すると Auth Failed。全RPCをローカル合成する。
        # ただし env FORWARD_METHODS に挙げたメソッドだけは実gwへ中継する
        # (X-Line-Access を RasPi の本物トークンへ、X-Line-Application を現行版へ書換)。
        # 現行サーバの応答は旧クライアントの想定と構造が違いクラッシュしうるので、
        # 全部素通しではなくメソッド単位で1つずつ有効化して確認する方針。
        if tname == "acquireCallRoute":
            values = acquire_legacy_call_route(body) or []
            reply = build_string_list_result(tname, seqid, values)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            log(f"--- <<< 200 CALL_ROUTE ({len(values)} fields, {len(reply)}B) ---")
            return (True, leftover)
        if tname == "sendChatChecked":
            record_chat_checked(body)
            reply = build_empty_struct_reply(tname, seqid)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            log(f"--- <<< 200 SYNTH {tname} ({len(reply)}B) ---")
            return (True, leftover)
        if tname == "getProduct":
            reply = build_get_product(tname, seqid, body)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        # 旧ショップ一覧は現行サーバに無い。現行ショーケースから作り直す。
        import legacy_sticker_shop
        if tname in legacy_sticker_shop.SHOP_METHODS:
            reply = legacy_sticker_shop.handle(globals(), tname, seqid, body)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        if tname == "getActivePurchaseVersions":
            reply = build_active_purchase_versions(tname, seqid)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        if tname == "getActivePurchases":
            reply = build_active_purchase_versions(tname, seqid)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, reply, ch))
            return (True, leftover)
        _cached = _fwd_cache_get(tname)
        if _cached is not None:
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, _cached, ch))
            log(f"--- <<< 200 CACHED {tname} ({len(_cached)}B) ---")
            return (True, leftover)
        if os.environ.get("HTTP_SYNTH") == "1" and not _should_forward(tname):
            if tname is None:
                synth = b""   # 非thrift GET(/promotion/spdy, /R 等)は空200
            else:
                synth = synth_for_method(tname, seqid, body)
                if synth is None:
                    synth = build_empty_struct_reply(tname, seqid)
            tls.sendall(_frame_resp(b"200 OK", _LEGY_HDRS, synth, ch))
            log(f"--- <<< 200 SYNTH {tname} ({len(synth)}B) ---")
            return (True, leftover)
        try:
            up = http.client.HTTPSConnection(real_ip(host), 443, timeout=20, context=UP_CTX)
            fwd = {k: v for k, v in headers.items() if k.lower() not in ("connection", "host")}
            fwd["Host"] = host
            # 版ゲート(403)回避: X-Line-Application の版を現行に偽装。
            if XLA_OVERRIDE:
                for k in list(fwd):
                    if k.lower() == "x-line-application":
                        fwd[k] = XLA_OVERRIDE
            # 中継するメソッドは、我々の合成トークンでは実gwに弾かれるので
            # RasPi の本物トークンへ差し替える。
            if _should_forward(tname):
                tok = real_token()
                if tok:
                    for k in list(fwd):
                        if k.lower() in ("x-line-access", "x-line-application"):
                            fwd.pop(k)
                    fwd["X-Line-Access"] = tok
                    # ★トークンは CHRLINE の device='DESKTOPWIN' で発行されている。
                    # IOS を名乗ると実gwは "ApplicationType mismatch" を返す(実測)。
                    # 種別を揃えると本物の応答が返る。
                    fwd["X-Line-Application"] = bridge_app_string()
                    log(f"  [forward] {tname} -> 実gw (本物トークン+{bridge_app_string().split(chr(9))[0]}で中継)")
                else:
                    log(f"  [forward] {tname}: real_token.txt が無いので合成トークンのまま中継")
            up.request(method, path, body=body or None, headers=fwd)
            r = up.getresponse()
            rbody, rhdrs, status, reason = r.read(), r.getheaders(), r.status, r.reason
            up.close()
        except Exception as e:
            log(f"--- UPSTREAM ERROR: {e!r} ---")
            tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return (False, b"")

        enc = next((v.lower() for k, v in rhdrs if k.lower() == "content-encoding"), "")
        shown = rbody
        if enc == "gzip":
            try:
                shown = gzip.decompress(rbody)
            except Exception:
                pass
        if tname == "findContactByUserTicket" and status == 200:
            import legacy_friend_add
            legacy_friend_add.remember(globals(), body, shown, real_token())
        out_body = rewrite_r2(shown) if path.startswith("/R2") else shown
        # 高頻度RPCは1回の中継結果を再利用する(レート制限対策)
        if status == 200:
            _fwd_cache_put(tname, out_body)
        rhdr_dump = "\n".join(f"    {k}: {v}" for k, v in rhdrs)
        # 応答Thriftの種別/メソッド/例外文言をデコードしてログ
        tinfo = thrift_peek(shown) if not path.startswith("/R2") else None
        tinfo_s = f"\n    THRIFT: {tinfo}" if tinfo else ""
        log(f"--- <<< {status} {reason}  ({len(out_body)}B){' [R2 rewritten]' if path.startswith('/R2') else ''} ---{tinfo_s}\n{rhdr_dump}")

        resp = [f"HTTP/1.1 {status} {reason}".encode("latin1")]
        for k, v in rhdrs:
            if k.lower() in ("content-encoding", "content-length", "transfer-encoding", "connection"):
                continue
            resp.append(f"{k}: {v}".encode("latin1"))
        resp.append(f"Content-Length: {len(out_body)}".encode("latin1"))
        resp.append(b"Connection: " + ch)
        tls.sendall(b"\r\n".join(resp) + b"\r\n\r\n" + (out_body if method != "HEAD" else b""))
        return (True, leftover)
    except Exception as e:
        log(f"  [serve_once err] {e!r}")
        return (False, b"")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        cip = self.client_address[0]
        try:
            peek = self.request.recv(4096, socket.MSG_PEEK)
        except OSError as e:
            log(f"{now()}  conn from {cip}: peek error {e!r}")
            return
        if not peek:
            log(f"{now()}  conn from {cip}: empty peek")
            return
        rec_ver = f"{peek[1]:02x}{peek[2]:02x}" if len(peek) >= 3 else "??"
        sni, exts = parse_hello(peek)
        # NPN拡張あり(=SPDYクライアント) or ALPNにspdy → LEGYとみなし素通し。
        is_legy = (NPN_EXT in exts) or (ALPN_EXT in exts and b"spdy" in peek)
        log(f"{now()}  conn from {cip} rec_ver={rec_ver} sni={sni} exts={sorted(exts)} "
            f"npn={NPN_EXT in exts} -> {'PASSTHROUGH' if is_legy else 'HTTP/terminate'}\n"
            f"  peek[:48]={peek[:48].hex()}")
        if is_legy:
            passthrough(self.request, sni)
        else:
            handle_http(self.request, sni)


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


SERVER_CTX: ssl.SSLContext = None


def main() -> None:
    global LOG_PATH, SERVER_CTX
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", default="server.pem")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--log", default="proxy.log")
    args = ap.parse_args()
    if not os.path.exists(args.cert):
        sys.exit("cert not found")
    LOG_PATH = args.log
    load_contacts()
    load_profile()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # ★TLS1.0 まで受ける。3.7.1 は TLSFix 経由が UNKNOWN_CA で落ちると
    #   純正の TLS1.0 → SSLv3 へフォールバックする。ここを TLSv1_2 に
    #   していたためその再試行が全部失敗し、ホーム更新がエラー扱いになって
    #   `reloadSections:2` でクラッシュしていた。
    _tls_min = {
        "1.0": ssl.TLSVersion.TLSv1,
        "1.1": ssl.TLSVersion.TLSv1_1,
        "1.2": ssl.TLSVersion.TLSv1_2,
    }.get(os.environ.get("LEGY_TLS_MIN", "1.0"), ssl.TLSVersion.TLSv1)
    try:
        ctx.minimum_version = _tls_min
    except (ValueError, OSError):
        pass
    for c in ("ALL:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0", "ALL"):
        try:
            ctx.set_ciphers(c)
            break
        except ssl.SSLError:
            continue
    ctx.load_cert_chain(args.cert)
    SERVER_CTX = ctx

    srv = ThreadingTCPServer(("0.0.0.0", args.port), Handler)
    print(f"[legy] v3 listening on 0.0.0.0:{args.port}  (spdy/2 -> passthrough, else /R2 rewrite)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[legy] bye", flush=True)


if __name__ == "__main__":
    main()
