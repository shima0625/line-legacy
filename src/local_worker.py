"""RasPi単体構成用ワーカー: 受信/送信/トークンの受け渡しを同一ホスト内で行う。

母艦Windowsを挟む構成では recv_worker_371.py と send_worker_371.py が
SFTP でファイルを往復させていたが、RasPi 1台に寄せると単なるローカルの
ファイル操作で済む。本スクリプトが両方を担う。

  受信: bridge_daemon が書く recv_out.jsonl を追尾し、legy_proxy が読む
        outbox.json(JSON配列) へ追記する
  送信: legy_proxy が書く send_queue.jsonl を追尾し、bridge_daemon が読む
        send_in.jsonl へ積む
  認証: bridge_daemon が書く authtoken.txt を real_token.txt へ複製
        (legy_proxy の実サーバ中継が読む)
"""
import base64, json, os, subprocess, time

BASE = os.path.dirname(os.path.abspath(__file__))
RECV_OUT = os.path.join(BASE, "recv_out.jsonl")
OUTBOX = os.path.join(BASE, "outbox.json")
SEND_QUEUE = os.path.join(BASE, "send_queue.jsonl")
SEND_IN = os.path.join(BASE, "send_in.jsonl")
AUTHTOKEN = os.path.join(BASE, "authtoken.txt")
REAL_TOKEN = os.path.join(BASE, "real_token.txt")
CALL_LOG = os.path.join(BASE, "call_log_out.jsonl")
CUR_CALLLOG = os.path.join(BASE, ".cur_calllog")
CUR_RECV = os.path.join(BASE, ".cur_recv")
CUR_SEND = os.path.join(BASE, ".cur_send")
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


# ---- 発信通話履歴の重複よけ -------------------------------------------------
# 通話ゲートウェイが書いた履歴を outbox へ流す一方、サーバも同じ通話について
# contentType=6 のメッセージを「自分が送ったもの」として配ってくる。両方入れると
# 1回の通話がトークに2件並ぶので、こちらが作った分と重なるサーバ側の分を落とす。
CALLOUT_MATCH_MS = 60000
_recent_callouts = []


def note_callout(peer, ended_at):
    _recent_callouts.append((str(peer), int(ended_at)))
    if len(_recent_callouts) > 50:
        del _recent_callouts[:-50]


def is_duplicate_callout(message):
    if int(message.get("contentType") or 0) != 6:
        return False
    peer = str(message.get("to") or "")
    created = int(message.get("createdTime") or 0)
    for known_peer, ended in _recent_callouts:
        if known_peer == peer and abs(created - ended) <= CALLOUT_MATCH_MS:
            return True
    return False


def log(m):
    print(f"[worker {time.strftime('%H:%M:%S')}] {m}", flush=True)


def read_int(p):
    try:
        with open(p) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def write_int(p, n):
    with open(p, "w") as f:
        f.write(str(n))


def legacy_metadata(content_type, metadata):
    """3.7.1 向けに contentMetadata を整える。

    音声の長さは現行クライアントが DURATION、3.7.1 が AUDLEN(ミリ秒)。
    移し替えないとトークで 0:00 と出る。
    """
    meta = dict(metadata or {})
    if int(content_type or 0) == 3 and not meta.get("AUDLEN"):
        duration = meta.get("DURATION")
        if duration:
            meta["AUDLEN"] = str(duration)
    return meta


# ---- 動画のサムネイル -------------------------------------------------------
# 3.7.1 は画像なら /os/m/<id>/preview を取りに来るが、動画では一度も取りに来ない。
# Message の contentPreview(フィールド17)へ小さなJPEGを載せて渡す。
# 3.7.1 はセルに合わせて拡大し、はみ出した分を右上寄せで切る。セル実寸(168x200px)
# へ収めて黒で埋める案も試したが、黒帯が目立つのでアスペクト比のまま渡す。
MEDIA_DIR = os.path.join(BASE, "media")
CONTENT_PREVIEW_MAX = int(os.environ.get("CONTENT_PREVIEW_MAX", "240"))
CONTENT_PREVIEW_LIMIT = int(os.environ.get("CONTENT_PREVIEW_LIMIT", "60000"))


def content_preview(content_type, message_id):
    """動画メッセージ用の小さなJPEG。作れなければ None。"""
    if int(content_type or 0) != 2 or not message_id:
        return None
    source = os.path.join(MEDIA_DIR, str(message_id) + "_preview")
    if not os.path.exists(source):
        source = os.path.join(MEDIA_DIR, str(message_id))
        if not os.path.exists(source):
            return None
    thumb = os.path.join(MEDIA_DIR, str(message_id) + "_thumb")
    if not os.path.exists(thumb):
        try:
            subprocess.run(
                ["ffmpeg", "-y", "-i", source,
                 "-vf", "scale='min(%d,iw)':-2" % CONTENT_PREVIEW_MAX,
                 "-frames:v", "1", "-q:v", "6", "-f", "image2", thumb],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=True)
        except Exception as e:
            log("サムネイル生成失敗 %s %r" % (message_id, e))
            return None
    try:
        with open(thumb, "rb") as stream:
            data = stream.read()
    except OSError:
        return None
    if not data or len(data) > CONTENT_PREVIEW_LIMIT:
        return None
    return base64.b64encode(data).decode("ascii")


def read_event(m):
    """A read position belongs to one reader, not to the whole chat."""
    chat, reader = m.get("chatMid"), m.get("reader")
    position = m.get("messageId") or m.get("createdTime")
    if not chat or not reader or not position:
        return None
    return {"kind": "read", "id": "read_%s_%s_%s" % (chat, reader, position),
            "chatMid": chat, "reader": reader, "messageId": m.get("messageId"),
            "createdTime": m.get("createdTime") or int(time.time() * 1000)}


def outbox_key(item):
    if item.get("kind") == "read":
        # Also recognizes receipts queued with the previous reader-less ID.
        return ("read", str(item.get("chatMid")), str(item.get("reader")),
                str(item.get("messageId") or item.get("createdTime")))
    return ("id", item.get("id"))


def append_outbox(items):
    cur = []
    if os.path.exists(OUTBOX):
        try:
            with open(OUTBOX, encoding="utf-8") as f:
                cur = json.load(f)
        except Exception:
            cur = []
    have = {outbox_key(m) for m in cur}
    added = []
    for it in items:
        key = outbox_key(it)
        if key not in have:
            added.append(it)
            have.add(key)
    if added:
        cur.extend(added)
        tmp = OUTBOX + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False)
        os.replace(tmp, OUTBOX)
    return len(added)


def pump_recv():
    """recv_out.jsonl(追記型) -> outbox.json"""
    if not os.path.exists(RECV_OUT):
        return
    size = os.path.getsize(RECV_OUT)
    cur = read_int(CUR_RECV)
    if size < cur:
        cur = 0
    if size <= cur:
        return
    with open(RECV_OUT, "rb") as f:
        f.seek(cur)
        data = f.read().decode("utf-8", "replace")
    items = []
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue
        if m.get("kind") == "contact":
            mid = m.get("mid")
            if mid:
                items.append({
                    "kind": "contact",
                    "id": str(m.get("id") or "contact_%s_%s" % (m.get("opType"), mid)),
                    "mid": str(mid),
                    "opType": int(m.get("opType") or 4),
                    # op 49 UPDATE_CONTACT は param2 に変わった ContactSetting が入る。
                    "param2": m.get("param2"),
                    "createdTime": m.get("createdTime") or int(time.time() * 1000),
                })
            continue
        if m.get("kind") == "profile":
            items.append({
                "kind": "profile",
                "id": str(m.get("id") or "profile_%s" % m.get("createdTime")),
                "opType": int(m.get("opType") or 1),
                "createdTime": m.get("createdTime") or int(time.time() * 1000),
            })
            continue
        if m.get("kind") == "group":
            items.append({
                "kind": "group",
                "id": str(m.get("id") or "group_%s_%s" %
                          (m.get("opType"), m.get("createdTime"))),
                "opType": int(m.get("opType") or 9),
                "param1": m.get("param1"),
                "param2": m.get("param2"),
                "param3": m.get("param3"),
                "createdTime": m.get("createdTime") or int(time.time() * 1000),
            })
            continue
        if m.get("kind") == "read":
            event = read_event(m)
            if event is not None:
                items.append(event)
            continue
        if m.get("kind") == "sent":
            # 自分が別の端末から送ったメッセージ。linejs ワーカーが 3.7.1 自身の送信を
            # 除いてから書く。legy_proxy が SEND_MESSAGE(25) で配る(受信opでは入らない)。
            to = m.get("to")
            if not to or m.get("from") != self_mid():
                continue
            if is_duplicate_callout(m):
                continue
            ttype = m.get("toType")
            if ttype is None:
                ttype = {"u": 0, "r": 1, "c": 2}.get(str(to)[:1], 0)
            items.append({
                "kind": "sent",
                "id": str(m.get("id") or int(time.time() * 1000)),
                "from": self_mid(), "to": to, "toType": int(ttype),
                "text": m.get("text") or "",
                "contentType": int(m.get("contentType") or 0),
                "contentMetadata": legacy_metadata(m.get("contentType"),
                                                   m.get("contentMetadata")),
                "contentPreviewB64": content_preview(m.get("contentType"), m.get("id")),
                "createdTime": m.get("createdTime") or int(time.time() * 1000),
            })
            continue
        frm = m.get("from")
        text = m.get("text")
        ctype = int(m.get("contentType") or 0)
        if not frm or (not text and ctype == 0) or frm == self_mid():
            continue
        to = m.get("to") or self_mid()
        ttype = m.get("toType")
        if ttype is None:
            ttype = {"u": 0, "r": 1, "c": 2}.get(str(to)[:1], 0)
        items.append({
            "id": str(m.get("id") or int(time.time() * 1000)),
            "from": frm, "to": to, "toType": int(ttype),
            "text": text or "", "contentType": ctype,
            "contentMetadata": legacy_metadata(ctype, m.get("contentMetadata")),
            "contentPreviewB64": content_preview(ctype, m.get("id")),
            "createdTime": m.get("createdTime") or int(time.time() * 1000),
        })
    if items:
        log(f"outbox へ {append_outbox(items)} 件")
    write_int(CUR_RECV, size)


def pump_calllog():
    """call_log_out.jsonl(発信通話の結果) -> outbox.json

    3.7.1 の通話履歴は contentType=6 のメッセージそのもので、
    contentMetadata の DURATION(ミリ秒) と RESULT を
    -[TalkMessageObject initWithLineMessage:from:inContext:] が読む。
    from が自分だと messageType="S" になり、発信として表示される
    (受信は現行サーバが相手から本物のメッセージを届けるのでそのまま動く)。
    ただし配信は RECEIVE_MESSAGE ではなく SEND_MESSAGE op で行う必要があるので、
    kind="sent" を付けて legy_proxy に op25 で出させる。
    """
    if not os.path.exists(CALL_LOG):
        return
    size = os.path.getsize(CALL_LOG)
    cur = read_int(CUR_CALLLOG)
    if size < cur:
        cur = 0
    if size <= cur:
        return
    with open(CALL_LOG, "rb") as f:
        f.seek(cur)
        data = f.read().decode("utf-8", "replace")
    items = []
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            call = json.loads(line)
        except Exception:
            continue
        peer = call.get("peer")
        if not peer:
            continue
        ended = int(call.get("endedAt") or time.time() * 1000)
        duration = int(call.get("durationMs") or 0)
        result = str(call.get("result") or "CANCELED")
        note_callout(peer, ended)
        items.append({
            "kind": "sent",
            "id": "callout_%s_%s" % (peer, ended),
            "from": self_mid(), "to": peer, "toType": 0,
            "text": "Call History : %d millisecs, Result: %s" % (duration, result),
            "contentType": 6,
            "contentMetadata": {"VERSION": "M", "TYPE": "A",
                                "RESULT": result, "DURATION": str(duration)},
            "createdTime": ended,
        })
    if items:
        log("発信通話履歴 %d 件を outbox へ (%d 追加)"
            % (len(items), append_outbox(items)))
    write_int(CUR_CALLLOG, size)


def pump_send():
    """send_queue.jsonl(行追記) -> send_in.jsonl"""
    if not os.path.exists(SEND_QUEUE):
        return
    lines = open(SEND_QUEUE, encoding="utf-8").read().splitlines()
    pos = read_int(CUR_SEND)
    if pos > len(lines):
        pos = 0
    out = []
    for i in range(pos, len(lines)):
        ln = lines[i].strip()
        if not ln:
            continue
        try:
            snd = json.loads(ln)
        except Exception:
            continue
        if snd.get("kind") == "group_cmd":
            # createGroup 等。宛先(to)を持たないので通常の送信分岐には乗せない。
            out.append({k: v for k, v in snd.items() if k != "ts"})
            continue
        if snd.get("kind") == "read":
            out.append({"kind": "read",
                        "id": "read_%s_%s" % (snd.get("to"), snd.get("messageId")),
                        "to": snd.get("to"), "messageId": snd.get("messageId")})
            continue
        if not snd.get("to"):
            continue
        out.append({"id": f"{snd.get('seq')}_{snd.get('ts')}",
                    "to": snd["to"], "text": snd.get("text", ""),
                    "contentType": snd.get("contentType", 0),
                    "contentMetadata": snd.get("contentMetadata", {})})
    if out:
        with open(SEND_IN, "a", encoding="utf-8") as f:
            for o in out:
                f.write(json.dumps(o, ensure_ascii=False) + "\n")
        # The append completed successfully, so advance the source cursor
        # before diagnostic logging.  Read-receipt records intentionally do
        # not have contentType/text; the old logger raised KeyError here and
        # replayed the same records forever on the next loop.
        write_int(CUR_SEND, len(lines))
        for o in out:
            if o.get("kind") == "group_cmd":
                log(f"send_in へグループ操作 op={o.get('op')} id={o.get('id')}")
            elif o.get("kind") == "read":
                log(f"send_in へ既読 to={o.get('to')} messageId={o.get('messageId')}")
            else:
                log(f"send_in へ to={o['to']} ct={o.get('contentType', 0)} {o.get('text', '')!r}")
    else:
        write_int(CUR_SEND, len(lines))


def pump_token():
    if not os.path.exists(AUTHTOKEN):
        return
    tok = open(AUTHTOKEN, encoding="utf-8").read().strip()
    if not tok:
        return
    old = open(REAL_TOKEN, encoding="utf-8").read().strip() if os.path.exists(REAL_TOKEN) else ""
    if tok != old:
        open(REAL_TOKEN, "w", encoding="utf-8").write(tok)
        log(f"real_token 更新 ({len(tok)} chars)")


def main():
    log("start (recv/send/token をローカルで受け渡し)")
    last_tok = 0.0
    while True:
        try:
            pump_recv()
            pump_calllog()
            pump_send()
            if time.time() - last_tok > 60:
                last_tok = time.time()
                pump_token()
        except Exception as e:
            log(f"err {e!r}")
        time.sleep(1.5)


if __name__ == "__main__":
    main()
