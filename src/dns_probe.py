#!/usr/bin/env python3
"""
LINE legacy - DNS probe / redirector
------------------------------------
旧LINEが接続するホスト名の観測と、必要なホストだけの転送に使うDNSサーバ。

動作:
  - すべての問い合わせ名(qname)をログに出す  -> LINEが引くホスト名が丸見えになる
  - 名前に "line" を含むホスト  -> このPCのIPを返す(=443のおとりサーバへ誘導)
  - それ以外                    -> 上流DNSへ転送(実機の他の通信は壊さない)

これで「どのドメインか」を当てずに突き止め、同時に decoy_server.py(443) が
本文をキャプチャする。hostsの手編集はもう不要(DNSが全ホスト名をカバー)。

使い方:
  python dns_probe.py --ip <gateway-ip> --upstream 1.1.1.1 --port 53
"""
import argparse
import datetime
import os
import socket
import struct
import threading

LOG_LOCK = threading.Lock()
QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
         16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 64: "SVCB"}

# Skyglowサーバー探索用のローカルレコード。
_SERVER_IP = os.environ.get("LINE_LEGACY_SERVER_IP", "127.0.0.1")
LOCAL_TXT = {
    "_sgn.linepush.test": (
        f"tcp_addr={_SERVER_IP} tcp_port=21138 "
        f"http_addr=http://{_SERVER_IP}:3023"
    ),
}


def now() -> str:
    return datetime.datetime.now().isoformat(timespec="milliseconds")


def parse_qname(data: bytes, offset: int = 12):
    labels = []
    i = offset
    while True:
        length = data[i]
        if length == 0:
            i += 1
            break
        labels.append(data[i + 1:i + 1 + length].decode("latin1", "replace"))
        i += 1 + length
    return ".".join(labels), i  # i = qname終端の次(qtypeの先頭)


def resp_header(query: bytes, ancount: int) -> bytes:
    # id をコピー、標準応答フラグ(0x8180)、qdcount=1
    return query[:2] + b"\x81\x80" + b"\x00\x01" + struct.pack(">H", ancount) + b"\x00\x00\x00\x00"


def build_a(query: bytes, qend: int, ip: str) -> bytes:
    question = query[12:qend + 4]  # qname + qtype(2) + qclass(2)
    answer = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01"       # name ptr, type A, class IN
              + struct.pack(">I", 30) + b"\x00\x04" + socket.inet_aton(ip))
    return resp_header(query, 1) + question + answer


def build_empty(query: bytes, qend: int) -> bytes:
    # NOERROR で回答0件(AAAA等をここで潰してIPv4に寄せる)
    return resp_header(query, 0) + query[12:qend + 4]


def build_txt(query: bytes, qend: int, text: str) -> bytes:
    question = query[12:qend + 4]
    raw = text.encode("utf-8")
    if len(raw) > 255:
        raise ValueError("TXT record is too long")
    rdata = bytes((len(raw),)) + raw
    answer = (b"\xc0\x0c" + b"\x00\x10" + b"\x00\x01"
              + struct.pack(">I", 30) + struct.pack(">H", len(rdata)) + rdata)
    return resp_header(query, 1) + question + answer


def forward(query: bytes, upstream: str) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        s.sendto(query, (upstream, 53))
        return s.recvfrom(4096)[0]
    finally:
        s.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="LINE legacy DNS probe/redirector")
    ap.add_argument("--ip", default=_SERVER_IP, help="対象ホストに返すA")
    ap.add_argument("--upstream", default="1.1.1.1", help="その他を転送する上流DNS")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--bind", default="0.0.0.0",
                    help="待受アドレス。競合する場合は互換サーバーのIPを指定")
    ap.add_argument("--match", default="line", help="(旧)この文字列を含むqnameを乗っ取る")
    ap.add_argument("--hijack-hosts", default="gw.line.naver.jp,gwx.line.naver.jp",
                    help="この完全一致ホスト名だけ乗っ取る(他は全て本物へ転送)。空なら--matchにフォールバック")
    ap.add_argument("--hijack-map", default="",
                    help="ホストごとに別IPを返す: host=ip,host=ip 形式。"
                         "画像CDN(dl.stickershop/os.line)をRasPiへ向ける等に使う")
    ap.add_argument("--log", default="dns.log")
    args = ap.parse_args()
    hijack_set = {h.strip().lower() for h in args.hijack_hosts.split(",") if h.strip()}
    hijack_map = {}
    for pair in args.hijack_map.split(","):
        pair = pair.strip()
        if "=" in pair:
            h, ip = pair.split("=", 1)
            hijack_map[h.strip().lower()] = ip.strip()
    hijack_set |= set(hijack_map)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    print(f"[dns] listening on {args.bind}:{args.port}   match='{args.match}' -> {args.ip}", flush=True)
    print(f"[dns] 実機のWi-Fi DNSを {args.ip} にしてLINEを起動。Ctrl-Cで停止。", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            qname, qend = parse_qname(data)
            qtype = struct.unpack(">H", data[qend:qend + 2])[0]
            ql = qname.lower()
            hijack = (ql in hijack_set) if hijack_set else (args.match in ql)
            local_txt = LOCAL_TXT.get(ql) if qtype == 16 else None
            tag = "LOCAL-TXT" if local_txt else ("HIJACK" if hijack else "forward")
            line = f"[dns] {now()}  {addr[0]:<15} {QTYPE.get(qtype, qtype)!s:<5} {qname}   [{tag}]"
            with LOG_LOCK:
                print(line, flush=True)
                with open(args.log, "a", encoding="utf-8") as f:
                    f.write(line + "\n")

            if local_txt:                        # Skyglowのローカル探索TXT
                reply = build_txt(data, qend, local_txt)
            elif hijack and qtype == 1:          # A -> 我々のIP(ホスト別指定があればそちら)
                reply = build_a(data, qend, hijack_map.get(ql, args.ip))
            elif hijack and qtype == 28:         # AAAA -> 空応答でIPv4に寄せる
                reply = build_empty(data, qend)
            else:                                # それ以外 -> 上流へ転送
                try:
                    reply = forward(data, args.upstream)
                except Exception:
                    reply = build_empty(data, qend)
            sock.sendto(reply, addr)
        except KeyboardInterrupt:
            print("\n[dns] bye", flush=True)
            break
        except Exception as e:
            print(f"[dns] error: {e!r}", flush=True)


if __name__ == "__main__":
    main()
