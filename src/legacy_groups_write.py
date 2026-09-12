"""LINE 3.7.1 のグループ書き込みRPCを現行の Chat API へ橋渡しする。

3.7.1 の TalkService は createGroup / updateGroup / inviteIntoGroup /
leaveGroup … を投げるが、現行サーバはこれらを撤去済みで、実測でも /S4 は
"unknown method" を返す(getProfile は通るので framing の問題ではない)。
生きているのは Chat 系(createChat / updateChat / inviteIntoChat /
deleteSelfFromChat …)なので、bridge_daemon の CHRLINE セッションに実行させ、
結果を旧形式で返す。

経路はメッセージ送信と同じ:
  send_queue.jsonl -> local_worker -> send_in.jsonl -> bridge_daemon
                   -> send_out.jsonl -> wait_send_result

呼び出し規約(実機 LINE371_phone.bin の LineTalkServiceClient より):
  createGroup(1:i32 reqSeq, 2:string name, 3:list<string> contactIds) -> Group
  updateGroup(1:i32 reqSeq, 2:Group group) -> void
  inviteIntoGroup(1:i32 reqSeq, 2:string groupId, 3:list<string> contactIds)
  cancelGroupInvitation(1:i32 reqSeq, 2:string groupId, 3:list<string> ids)
  kickoutFromGroup(1:i32 reqSeq, 2:string groupId, 3:list<string> ids)
  leaveGroup / acceptGroupInvitation / rejectGroupInvitation(1:i32, 2:string)
"""
import json
import os
import re
import time
import uuid


GROUP_WRITE_METHODS = frozenset({
    "createGroup", "updateGroup", "inviteIntoGroup", "cancelGroupInvitation",
    "leaveGroup", "acceptGroupInvitation", "rejectGroupInvitation",
    "kickoutFromGroup",
    "blockContact", "unblockContact", "updateContactSetting",
    "blockRecommendation", "unblockRecommendation",
})

_MID = re.compile(r"u[0-9a-f]{32}")
_GID = re.compile(r"c[0-9a-f]{32}")
_MAX_NAME = 100
_MAX_MEMBERS = 500


def _timeout():
    try:
        return max(5.0, float(os.environ.get("GROUP_CMD_TIMEOUT", "25")))
    except ValueError:
        return 25.0


def _call_args(g, method, seqid, payload):
    """TCompact の呼び出しフレームを {fid: (typ, value)} にする。"""
    if len(payload) > 262144 or not payload.startswith(b"\x82\x21"):
        raise ValueError("not a TCompact call")
    request_seq, pos = g["uvarint"](payload, 2)
    length, pos = g["uvarint"](payload, pos)
    if request_seq != seqid or payload[pos:pos + length].decode() != method:
        raise ValueError("method/seq mismatch")
    fields, end = g["_tc_read_struct"](payload, pos + length)
    if end != len(payload):
        raise ValueError("trailing bytes")
    return fields


def _text(fields, fid, limit=_MAX_NAME):
    typ, value = fields.get(fid, (None, None))
    if typ != 8 or not isinstance(value, (bytes, bytearray)):
        raise ValueError("field %d is not a string" % fid)
    text = value.decode("utf-8", "replace").strip()
    if not text or len(text) > limit:
        raise ValueError("field %d has an unusable length" % fid)
    return text


def _mid(fields, fid, pattern):
    value = _text(fields, fid, 40)
    if not pattern.fullmatch(value):
        raise ValueError("field %d is not a MID" % fid)
    return value


def _mid_list(fields, fid):
    typ, value = fields.get(fid, (None, None))
    if typ != 9 or not isinstance(value, list) or len(value) > _MAX_MEMBERS:
        raise ValueError("field %d is not a MID list" % fid)
    mids = []
    for item in value:
        if not isinstance(item, (bytes, bytearray)):
            raise ValueError("field %d holds a non-string" % fid)
        mid = item.decode("utf-8", "replace")
        if not _MID.fullmatch(mid):
            raise ValueError("field %d holds a non-MID" % fid)
        if mid not in mids:
            mids.append(mid)
    return mids


def _dispatch(g, command, timeout=None):
    """コマンドを送信キューへ積み、bridge_daemon の結果を待つ。"""
    request_id = "gcmd_%s" % uuid.uuid4().hex[:16]
    record = dict(command)
    record.update({"kind": "group_cmd", "id": request_id,
                   "ts": int(time.time() * 1000)})
    queue_path = os.path.join(g["_ARTIFACTS"], "send_queue.jsonl")
    with open(queue_path, "a", encoding="utf-8") as queue:
        queue.write(json.dumps(record, ensure_ascii=False) + "\n")
    g["log"]("  [group-write] %s queued id=%s" % (record.get("op"), request_id))
    result = g["wait_send_result"](request_id, timeout=timeout or _timeout())
    g["log"]("  [group-write] %s -> ok=%s %s"
             % (record.get("op"), result.get("ok"),
                str(result.get("err") or result.get("groupId") or "")[:120]))
    return result


def _created_group_reply(g, method, seqid, gid, name, invitee):
    """createGroup の応答は Group 1件。3.7.1 はこれを直接DBへ入れる。

    作成直後の実LINEと同じく、メンバーは自分だけで相手は invitee に入る。
    """
    self_mid = g["PROFILE"].get(1)
    group = {
        "id": gid,
        "name": name,
        "createdTime": int(time.time() * 1000),
        "pictureStatus": "",
        "members": [{"mid": self_mid}],
        "creator": {"mid": self_mid},
        "invitee": [{"mid": mid} for mid in invitee if mid != self_mid],
    }
    return g["build_struct_result"](method, seqid, g["encode_group"](group))


def handle(g, method, seqid, payload):
    """書き込み系ならThrift応答を返す。対象外は None。"""
    if method not in GROUP_WRITE_METHODS:
        return None
    try:
        fields = _call_args(g, method, seqid, payload)
        g["maybe_reload_profile"]()
        if not g["PROFILE"].get(1):
            raise ValueError("own profile unavailable")

        if method in ("blockContact", "unblockContact",
                      "blockRecommendation", "unblockRecommendation"):
            # 友だち以外(RECOMMEND_BLOCKED として見せている削除済み+ブロックの相手)を
            # 3.7.1 で解除すると unblockRecommendation が来る。現行側は同じ相手を
            # blockContact / unblockContact で扱うので、そちらへ寄せる。
            mid = _mid(fields, 2, _MID)
            op = "contact_block" if method.startswith("block") else "contact_unblock"
            result = _dispatch(g, {"op": op, "mid": mid})
            if not result.get("ok"):
                raise RuntimeError(result.get("err") or (method + " failed"))
            return g["build_empty_struct_reply"](method, seqid)

        if method == "updateContactSetting":
            mid = _mid(fields, 2, _MID)
            typ, flag = fields.get(3, (None, None))
            if typ != 5 or int(flag) != 4:  # CONTACT_SETTING_CONTACT_HIDE
                return None
            value = _text(fields, 4, 16).lower()
            hidden = value in ("1", "true", "yes", "on")
            result = _dispatch(g, {"op": "contact_hide" if hidden else "contact_unhide",
                                   "mid": mid})
            if not result.get("ok"):
                raise RuntimeError(result.get("err") or "updateContactSetting failed")
            return g["build_empty_struct_reply"](method, seqid)

        if method == "createGroup":
            name = _text(fields, 2)
            members = _mid_list(fields, 3)
            result = _dispatch(g, {"op": "create", "name": name,
                                   "members": members})
            gid = str(result.get("groupId") or "")
            if not result.get("ok") or not _GID.fullmatch(gid):
                raise RuntimeError(result.get("err") or "createChat failed")
            return _created_group_reply(g, method, seqid, gid, name, members)

        if method == "updateGroup":
            typ, group = fields.get(2, (None, None))
            if typ != 12 or not isinstance(group, dict):
                raise ValueError("Group struct missing")
            gid = _mid(group, 1, _GID)
            # 3.7.1 の Group: 10=name, 11=pictureStatus。改名だけを反映する。
            # アイコンは端末が OBS へ上げた実体が要るので別経路。
            name = _text(group, 10)
            result = _dispatch(g, {"op": "rename", "groupId": gid,
                                   "name": name})
            if not result.get("ok"):
                raise RuntimeError(result.get("err") or "updateChat failed")
            return g["build_empty_struct_reply"](method, seqid)

        gid = _mid(fields, 2, _GID)
        if method in ("inviteIntoGroup", "cancelGroupInvitation",
                      "kickoutFromGroup"):
            targets = _mid_list(fields, 3)
            if not targets:
                raise ValueError("no target MIDs")
            op = {"inviteIntoGroup": "invite",
                  "cancelGroupInvitation": "cancel_invite",
                  "kickoutFromGroup": "kickout"}[method]
            result = _dispatch(g, {"op": op, "groupId": gid,
                                   "members": targets})
        else:
            op = {"leaveGroup": "leave",
                  "acceptGroupInvitation": "accept",
                  "rejectGroupInvitation": "reject"}[method]
            result = _dispatch(g, {"op": op, "groupId": gid})
        if not result.get("ok"):
            raise RuntimeError(result.get("err") or "chat command failed")
        return g["build_empty_struct_reply"](method, seqid)
    except Exception as exc:
        g["log"]("  [group-write] %s failed: %s" % (method, repr(exc)[:200]))
        return g["build_app_exception"](method, seqid, "Group command failed")
