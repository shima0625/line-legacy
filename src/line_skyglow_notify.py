#!/usr/bin/env python3
"""Forward new LINE bridge messages to the local Skyglow server."""
import base64
import json
import os
import re
import subprocess
import time
import urllib.request


BASE = os.environ.get("LINE_LEGACY_HOME", "/opt/line-legacy")
RECV_OUT = os.path.join(BASE, "recv_out.jsonl")
MESSAGE_OFFSET_FILE = os.path.join(BASE, "skyglow_notify.offset")
CALL_OPS = os.path.join(BASE, "call_ops.jsonl")
CALL_OFFSET_FILE = os.path.join(BASE, "skyglow_call_notify.offset")
NATIVE_CALL_PUSH_FLAG = os.path.join(BASE, "skyglow_native_call.enabled")
SERVER_URL = os.environ.get("LINE_LEGACY_SKYGLOW_URL", "http://127.0.0.1:3023/send")
# The address the device registered against.  The Skyglow server matches this
# against the routing token, so it has to be the value shown in the tweak's
# settings, not the URL this process posts to.
SERVER_ADDRESS = os.environ.get(
    "LINE_LEGACY_SKYGLOW_SERVER_ADDRESS", "linepush.test")
MID_RE = re.compile(r"^[ucr][0-9a-f]{32}$", re.IGNORECASE)


def _bridge_self_mid(default=""):
    """ブリッジが今名乗っているアカウントの mid。

    profile.json は bridge のダンプで書き換わるので、そこを正とする。
    env SELF_MID が最優先(切り分け用)。profile.json がまだ無い初回起動では
    ログイン時に書かれる bridge_identity.json を見る。
    """
    value = os.environ.get("SELF_MID")
    if value:
        return value
    try:
        with open(os.path.join(BASE, "profile.json"), encoding="utf-8") as stream:
            mid = json.load(stream).get("1")
        if isinstance(mid, str) and mid:
            return mid
    except Exception:
        pass
    try:
        with open(os.path.join(BASE, "bridge_identity.json"), encoding="utf-8") as stream:
            mid = json.load(stream).get("mid")
        if isinstance(mid, str) and mid:
            return mid
    except Exception:
        pass
    return default


_SELF_MID = _bridge_self_mid()


def self_mid():
    """最初のダンプより先に起動していると mid を取り損ねる。空のままだと
    自分の発言と通話履歴が誰のものか決まらず旧アプリに出ないので、
    値が入るまでは呼ばれるたびに読み直す。"""
    global _SELF_MID
    if not _SELF_MID:
        _SELF_MID = _bridge_self_mid()
    return _SELF_MID


def log(message):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), message), flush=True)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)
    except Exception:
        return default


def display_name(mid):
    for contact in load_json(os.path.join(BASE, "contacts.json"), []):
        if str(contact.get("mid") or "") == str(mid or ""):
            return contact.get("displayName") or "LINE"
    return "LINE"


def group_name(mid):
    for group in load_json(os.path.join(BASE, "groups.json"), []):
        if str(group.get("id") or "") == str(mid or ""):
            return group.get("name") or None
    return None


def chat_mid_for_message(record):
    """Return a validated destination MID for an actual message record."""
    if record.get("kind") not in (None, "message"):
        return None
    sender_mid = str(record.get("from") or "")
    if not MID_RE.fullmatch(sender_mid) or sender_mid == self_mid():
        return None
    chat_mid = str(record.get("to") if int(record.get("toType") or 0) in (1, 2)
                   else sender_mid)
    return chat_mid if MID_RE.fullmatch(chat_mid) else None


def message_alert(record):
    sender = display_name(record.get("from"))
    text = record.get("text")
    if text:
        text = str(text).replace("\r", " ").replace("\n", " ")[:180]
        return {"loc-key": "MT", "loc-args": [sender, text]}
    loc_key = {
        1: "MI",   # image
        2: "MV",   # video
        3: "MA",   # audio message
        7: "MS",   # sticker
        9: "MG",   # gift
        13: "MC",  # contact
        14: "MF",  # file
        15: "ML",  # location
    }.get(int(record.get("contentType") or 0))
    if loc_key:
        return {"loc-key": loc_key, "loc-args": [sender]}
    return {"loc-key": "M"}


def line_routing_keys():
    """[(routing key, end-to-end key or None)] for every device to notify.

    An entry may carry the device's end-to-end key as `<routing>:<e2ee>`, in
    which case the payload is encrypted before it leaves this host and the
    Skyglow server only relays an opaque blob.  Both halves are 64 hexadecimal
    characters; the device stores them in `notifications` in its own
    `SkyglowNotifications/sqlite.db`.
    """
    configured = os.environ.get("LINE_LEGACY_SKYGLOW_ROUTING_KEYS", "")
    if configured:
        values = []
        seen = set()
        for value in configured.split(","):
            routing, _, e2ee = value.strip().lower().partition(":")
            if not re.fullmatch(r"[0-9a-f]{64}", routing) or routing in seen:
                continue
            if e2ee and not re.fullmatch(r"[0-9a-f]{64}", e2ee):
                raise RuntimeError(
                    "LINE_LEGACY_SKYGLOW_ROUTING_KEYS has an invalid end-to-end key")
            seen.add(routing)
            values.append((routing, bytes.fromhex(e2ee) if e2ee else None))
        if not values:
            raise RuntimeError("LINE_LEGACY_SKYGLOW_ROUTING_KEYS is invalid")
        return values
    sql = (
        "select encode(routing_token,'hex') from notification_tokens "
        "where bundle_id='jp.naver.line' and is_valid=true "
        "order by issued_at desc;"
    )
    output = subprocess.check_output([
        "/usr/bin/docker", "exec", "skyglow-server-postgres-1",
        "psql", "-U", "skyglownotify", "-d", "skyglownotify",
        "-Atc", sql,
    ], text=True, timeout=15)
    values = []
    seen = set()
    for value in output.splitlines():
        value = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", value) and value not in seen:
            seen.add(value)
            # The local server is trusted with the plaintext, so nothing is
            # encrypted on this path.
            values.append((value, None))
    if not values:
        raise RuntimeError("LINE routing key is unavailable")
    return values


def encrypted_fields(e2ee_key, data):
    """AES-256-GCM the payload the way the Skyglow daemon decrypts it.

    The key is the one the device derived at registration time and keeps in
    its `notifications` table, which `SG_CryptoDecryptAESGCM` then uses
    verbatim: HKDF runs once during registration, never per notification.  The
    IV is 12 bytes, there is no additional authenticated data, and the 16-byte
    tag is appended to the ciphertext.  `data_type` names the format of the
    plaintext and only `json` and `plist` are understood; the daemon's JSON
    branch canonicalises the result exactly like the server-side encoding of a
    plaintext `data` object, so the dictionary reaches the app unchanged either
    way.  Anything else reaches the device as a malformed frame and drops its
    connection.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError(
            "an end-to-end key is configured but the cryptography package "
            "is missing; install src/requirements.txt")
    iv = os.urandom(12)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return {
        "is_encrypted": True,
        "data_type": "json",
        "ciphertext": base64.b64encode(
            AESGCM(e2ee_key).encrypt(iv, plaintext, None)).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
    }


def post_payload(routing_key, e2ee_key, data):
    payload = {"routing_key": routing_key, "server_address": SERVER_ADDRESS}
    if e2ee_key:
        payload.update(encrypted_fields(e2ee_key, data))
    else:
        payload["data"] = data
    request = urllib.request.Request(
        SERVER_URL,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError("Skyglow HTTP %s" % response.status)
        result = json.loads(response.read().decode("utf-8"))
        if result.get("status") != "success":
            raise RuntimeError("Skyglow rejected notification")


def send_notification(routing_key, e2ee_key, record):
    chat_mid = chat_mid_for_message(record)
    if not chat_mid:
        raise ValueError("record is not a routable LINE message")
    post_payload(routing_key, e2ee_key, {
        "aps": {
            # Use LINE 3.7.1's own localization keys so punctuation and
            # media wording exactly match the installed Japanese bundle.
            "alert": message_alert(record),
            "sound": "default",
        },
        # Native LINE 3.7.1 message-notification field.  Do not include
        # `inapp-alert`: its mere presence makes 3.7.1 treat a foreground
        # notification like an opened notification and navigate to `m`.
        "m": chat_mid,
    })


def call_payload(record):
    raw = record.get("kind") or {}
    route = json.loads(raw) if isinstance(raw, str) else dict(raw)
    route["m"] = str(record.get("from") or "")
    route["h"] = os.environ.get("LINE_LEGACY_CALL_HOST", "127.0.0.1")
    route["p"] = 19000
    return {
        key: format(value, "x") if key == "l" and isinstance(value, int)
        else value if key == "p"
        else "true" if value is True
        else "false" if value is False
        else str(value) if isinstance(value, (int, float))
        else value
        for key, value in route.items()
    }


def send_call_notification(routing_key, e2ee_key, record):
    caller = str(record.get("from") or "")
    route = call_payload(record)
    if not caller or not route.get("n"):
        raise RuntimeError("incoming call payload is incomplete")
    data = {
        "aps": {
            "alert": {
                "loc-key": "CA",
                "loc-args": [display_name(caller)],
                "action-loc-key": "AA",
            },
            "sound": "default",
        },
    }
    if os.path.exists(NATIVE_CALL_PUSH_FLAG):
        # LINE 3.7.1's original APNs handler reads the route fields from the
        # notification's top level.  Keeping this behind a flag gives us an
        # instant rollback to the proven MobileSubstrate bridge path.
        data.update(route)
    else:
        data["line_bridge_call"] = route
    post_payload(routing_key, e2ee_key, data)


def read_offset(path, offset_file):
    try:
        with open(offset_file, encoding="ascii") as stream:
            return int(stream.read().strip())
    except Exception:
        try:
            return os.path.getsize(path)
        except OSError:
            return 0


def write_offset(offset_file, offset):
    tmp = offset_file + ".tmp"
    with open(tmp, "w", encoding="ascii") as stream:
        stream.write(str(offset))
    os.replace(tmp, offset_file)


def read_line(path, offset):
    with open(path, encoding="utf-8") as stream:
        size = os.fstat(stream.fileno()).st_size
        if offset > size:
            offset = 0
        stream.seek(offset)
        line = stream.readline()
        return line, stream.tell()


def main():
    message_offset = read_offset(RECV_OUT, MESSAGE_OFFSET_FILE)
    call_offset = read_offset(CALL_OPS, CALL_OFFSET_FILE)
    log("LINE Skyglow notification worker ready")
    while True:
        processed = False
        try:
            line, next_offset = read_line(RECV_OUT, message_offset)
            if line:
                processed = True
                try:
                    record = json.loads(line)
                except Exception:
                    record = None
                if record and chat_mid_for_message(record):
                    routing_keys = line_routing_keys()
                    for routing_key, e2ee_key in routing_keys:
                        send_notification(routing_key, e2ee_key, record)
                    log("message notification sent to %d device(s)" % len(routing_keys))
                elif record:
                    log("non-message record skipped: %s" %
                        str(record.get("kind") or "invalid"))
                message_offset = next_offset
                write_offset(MESSAGE_OFFSET_FILE, message_offset)
        except FileNotFoundError:
            pass
        except Exception as error:
            log("message notification retry: %s" % type(error).__name__)
            time.sleep(3)
            continue

        try:
            line, next_offset = read_line(CALL_OPS, call_offset)
            if line:
                processed = True
                try:
                    record = json.loads(line)
                except Exception:
                    record = None
                if record and int(record.get("type") or 0) == 50:
                    routing_keys = line_routing_keys()
                    for routing_key, e2ee_key in routing_keys:
                        send_call_notification(routing_key, e2ee_key, record)
                    log("call notification sent to %d device(s)" % len(routing_keys))
                call_offset = next_offset
                write_offset(CALL_OFFSET_FILE, call_offset)
        except FileNotFoundError:
            pass
        except Exception as error:
            log("call notification retry: %s" % type(error).__name__)
            time.sleep(3)
            continue

        if not processed:
            time.sleep(0.5)


if __name__ == "__main__":
    main()
