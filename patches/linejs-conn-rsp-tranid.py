#!/usr/bin/env python3
# Applies a compatibility modification to @evex/linejs 3.2.1 (MIT License).
# Copyright (c) 2024-2026 Evex Developers.
"""linejs 3.2.1 の PlanetTransport にあてるパッチ。

`#planetHdr()` は送信のたびに 16 バイトのランダムな tranId を新規生成する。
そのため応答が相手の要求と別のトランザクションIDで返り、相手は応答を自分の要求に
結び付けられない。CONN_RSP でこれが起きると、相手は CONN_REQ を約2秒間隔で再送し続け、
10秒後に `rel_req relCode=511 CONN_REQ_FAIL.timeout` で通話を解放する
（スマホ側の表示は T103）。

要求側になる SETUP_REQ 等はこちらが tranId を決めるので影響を受けない。そのため
発信・呼出・応答・音声開通までは正常に見え、確立後10秒で切れる症状になっていた。

CONN_RSP に加えて INFO_RSP と MC の各応答（JOIN_RSP / DATA_RSP / CHANGE_RSP）にも
同じ echo を適用する。CONN_RSP だけ直した状態でも通話は成立したが、MC JOIN_REQ が
7回再送されており、相手が応答を取りこぼしていた形跡があったため。

npm install で node_modules が入れ替わったら再適用すること。

  python patches/linejs-conn-rsp-tranid.py <linejs-bridge のパス>
"""
import io, os, sys, shutil

REL = "node_modules/@evex/linejs/client/features/call/planet/transport.js"

OLD_HDR = '''  #planetHdr(msgId = this.#msgIdCounter++) {
    if (!this.#sessId) throw new Error("connect first");
    const tranId = new Uint8Array(16);
    crypto.getRandomValues(tranId);
    return {
      userId: this.#opts.localMid,
      msgId,
      sessId: this.#sessId,
      tranId,
      tranSeq: this.#tranSeq++,
'''

NEW_HDR = '''  #planetHdr(msgId = this.#msgIdCounter++, echo) {
    if (!this.#sessId) throw new Error("connect first");
    let tranId;
    let tranSeq;
    if (echo?.tranId && echo.tranId.length === 16) {
      // 応答は要求と同じトランザクションIDで返す。新しいIDを振ると相手は応答を
      // 自分の要求と結び付けられず、要求を再送し続けてタイムアウトする。
      tranId = echo.tranId;
      tranSeq = echo.tranSeq ?? this.#tranSeq++;
    } else {
      tranId = new Uint8Array(16);
      crypto.getRandomValues(tranId);
      tranSeq = this.#tranSeq++;
    }
    return {
      userId: this.#opts.localMid,
      msgId,
      sessId: this.#sessId,
      tranId,
      tranSeq,
'''

OLD_ENV = '''    const hdr = this.#planetHdr(opts.msgId);
    const planetMsg = packPlanetMsg(hdr, body);
    this.#debug({
      type: "send_planet_msg",
      kind: body.kind,
      msgId: hdr.msgId,
'''

NEW_ENV = '''    const hdr = this.#planetHdr(opts.msgId, opts.echoHdr);
    const planetMsg = packPlanetMsg(hdr, body);
    this.#debug({
      type: "send_planet_msg",
      kind: body.kind,
      tranIdEchoed: !!(opts.echoHdr?.tranId),
      msgId: hdr.msgId,
'''

# request を持つ応答はすべて要求の tranId を返す。
RESPONSES = [
    "ccMsgId(CC_MSG.CONN_RSP)",
    "ccMsgId(CC_MSG.INFO_RSP)",
    "CASSINI_MSG_ID_MC_JOIN_RSP",
    "CASSINI_MSG_ID_MC_DATA_RSP",
    "CASSINI_MSG_ID_MC_CHANGE_RSP",
]


def rsp_old(expr):
    return "      msgId: " + expr + "\n    });\n"


def rsp_new(expr):
    return "      msgId: " + expr + ",\n      echoHdr: request.message?.hdr\n    });\n"


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "."
    path = os.path.join(base, REL)
    src = io.open(path, encoding="utf-8").read()

    if "opts.echoHdr" in src:
        print("already patched:", path)
        return

    targets = [("planetHdr", OLD_HDR), ("sendEnvelope", OLD_ENV)]
    targets += [(expr, rsp_old(expr)) for expr in RESPONSES]
    for name, old in targets:
        if src.count(old) != 1:
            print("PATTERN MISMATCH (%s): %d hits" % (name, src.count(old)), file=sys.stderr)
            sys.exit(1)

    backup = path + ".bak_pre_tranid"
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
        print("backup:", backup)

    src = src.replace(OLD_HDR, NEW_HDR).replace(OLD_ENV, NEW_ENV)
    for expr in RESPONSES:
        src = src.replace(rsp_old(expr), rsp_new(expr))
    io.open(path, "w", encoding="utf-8").write(src)
    print("patched:", path, "(%d responses)" % len(RESPONSES))


if __name__ == "__main__":
    main()
