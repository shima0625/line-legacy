#!/usr/bin/env python3
"""Forward new LINE bridge messages to the local Skyglow server."""
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
SERVER_ADDRESS = "linepush.test"
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
    for value in output.splitlines():
        value = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", value) and value not in values:
            values.append(value)
    if not values:
        raise RuntimeError("LINE routing key is unavailable")
    return values


def send_notification(routing_key, record):
    chat_mid = chat_mid_for_message(record)
    if not chat_mid:
        raise ValueError("record is not a routable LINE message")
    payload = {
        "data": {
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
        },
        "routing_key": routing_key,
        "server_address": SERVER_ADDRESS,
    }
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


def send_call_notification(routing_key, record):
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
    payload = {
        "data": data,
        "routing_key": routing_key,
        "server_address": SERVER_ADDRESS,
    }
    request = urllib.request.Request(
        SERVER_URL,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError("Skyglow call HTTP %s" % response.status)
        result = json.loads(response.read().decode("utf-8"))
        if result.get("status") != "success":
            raise RuntimeError("Skyglow rejected call notification")


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
                    for routing_key in routing_keys:
                        send_notification(routing_key, record)
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
                    for routing_key in routing_keys:
                        send_call_notification(routing_key, record)
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
