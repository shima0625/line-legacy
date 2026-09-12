"""Map LINE 3.7.1's legacy hitokoto action to the current profile status.

The friend/profile UI reads Profile.statusMessage rather than the newest
Timeline post.  ``sendMessageToMyHome(Message)`` also carried legacy hitokoto
history, but that is not evidence that it was a normal Timeline/VOOM post.
This adapter restores the observable status behavior; Timeline REST is handled
separately.
"""
import hashlib
import json
import os
import re
import threading
import time

import legacy_friend_add


_lock = threading.RLock()
_completed = {}
_MAX_STATUS_CHARS = 500


def _history_path(g):
    return os.path.join(g["_ARTIFACTS"], "status_history.json")


def _save_history(g, status, created):
    path = _history_path(g)
    try:
        with open(path, encoding="utf-8") as f:
            history = json.load(f)
        if not isinstance(history, list):
            history = []
    except (OSError, ValueError):
        history = []
    history.insert(0, {"text": status, "createdTime": created})
    history = history[:20]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, separators=(",", ":"))
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)


def handle_get_message_box(g, request, seq):
    from thrift.protocol import TCompactProtocol
    from thrift.transport import TTransport
    from akad.ttypes import Message, TMessageBox
    g["maybe_reload_profile"]()
    mid = g["PROFILE"].get(1) or ""
    try:
        with open(_history_path(g), encoding="utf-8") as f:
            history = json.load(f)
    except (OSError, ValueError):
        history = []
    messages = []
    for item in history[:20]:
        created = int(item.get("createdTime") or 0)
        messages.append(Message(_from=mid, to=mid, toType=0, id=str(created),
                                createdTime=created, text=str(item.get("text") or ""),
                                contentType=0))
    last = int(history[0].get("createdTime") or 0) if history else 0
    box = TMessageBox(id=mid, channelId="myhome", lastSeq=len(messages),
                      unreadCount=0, lastModifiedTime=last, status=0,
                      midType=0, lastMessages=messages)
    trans = TTransport.TMemoryBuffer()
    box.write(TCompactProtocol.TCompactProtocol(trans))
    return g["build_struct_result"]("getMessageBox", seq, trans.getvalue())


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, str):
        return value
    raise ValueError("Status text is not a string")


def handle(g, request, seq, token):
    name = "sendMessageToMyHome"

    def error(message):
        return g["build_app_exception"](name, seq, message, extype=6)

    try:
        if not token:
            raise ValueError("Bridge account token is unavailable")
        args, _raw = legacy_friend_add.fields(g, request)
        reqseq = args.get(1, (5, seq))[1]
        message = args.get(2)
        if not message or message[0] != 12:
            raise ValueError("Missing legacy MyHome message")
        fields = message[1]
        status = _text(fields.get(10, (8, b""))[1]).strip()
        if not status or len(status) > _MAX_STATUS_CHARS or len(status.encode("utf-8")) > 2048:
            raise ValueError("Invalid status message length")

        key = (hashlib.sha256(token.encode()).digest(), int(reqseq),
               hashlib.sha256(status.encode("utf-8")).digest())
        with _lock:
            now = time.monotonic()
            for old_key, (_, expiry) in list(_completed.items()):
                if expiry <= now:
                    del _completed[old_key]
            cached = _completed.get(key)
            if cached:
                g["log"]("  [status-home] duplicate legacy request; reused completed result")
                return cached[0]

            # Current clients use updateProfileAttributes with a sparse map:
            # request.profileAttributes[STATUS_MESSAGE=16] = ProfileContent(value).
            value = status.encode("utf-8")
            pc = bytearray()
            g["_tc_field"](pc, 0, 1, 8, g["put_uvarint"](len(value)) + value)
            g["_tc_field"](pc, 1, 2, 11, b"\x00")
            pc.append(0)
            attrs = (g["put_uvarint"](1) + b"\x5c"
                     + g["put_uvarint"](g["_zigzag32"](16)) + bytes(pc))
            request = bytearray()
            g["_tc_field"](request, 0, 1, 11, attrs)
            request.append(0)
            rpc_args = bytearray()
            g["_tc_field"](rpc_args, 0, 1, 5,
                            g["put_uvarint"](g["_zigzag32"](int(time.time() * 1000) & 0x7fffffff)))
            g["_tc_field"](rpc_args, 1, 2, 12, bytes(request))
            rpc_args.append(0)
            result, _ = legacy_friend_add.rpc(
                g, token, "updateProfileAttributes", "/S4", bytes(rpc_args), seq)
            if result:
                raise ValueError("Current status update was rejected")

            profile_path = os.path.join(g["_ARTIFACTS"], "profile.json")
            with open(profile_path, encoding="utf-8") as f:
                profile = json.load(f)
            if not isinstance(profile, dict):
                raise ValueError("Local profile is not an object")
            profile["24"] = status
            tmp = profile_path + ".status.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(profile, f, ensure_ascii=False, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, profile_path)
            _save_history(g, status, int(time.time() * 1000))
            g["maybe_reload_profile"]()
            mid = g["PROFILE"].get(1)
            if not isinstance(mid, str) or not re.fullmatch(r"u[0-9a-f]{32}", mid):
                mid = None
            created = int(time.time() * 1000)
            legacy_message = {
                "from": mid,
                "to": mid,
                "toType": 0,
                "id": str(created),
                "createdTime": created,
                "text": status,
                "contentType": 0,
            }
            reply = g["build_struct_result"](
                name, seq, g["encode_message"](legacy_message))
            _completed[key] = (reply, now + 900)
            if len(_completed) > 256:
                _completed.pop(next(iter(_completed)))
            g["log"]("  [status-home] current status updated; legacy timestamp returned")
            return reply
    except (ValueError, KeyError, IndexError, TypeError, OSError, UnicodeError):
        g["log"]("  [status-home] update failed; no automatic retry")
        return error("Unable to update status message")
