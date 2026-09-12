"""LINE 3.7.1 のスタンプショップ一覧を現行のショーケースから作る。

旧 /SHOP4 は現行サーバに存在せず(パス自体が無い)、/TSHOP4 に投げても
getPopularPackages / getNewlyReleasedPackages / getEventPackages は
"unknown method" が返る。一方、現行の getAggregatedHomeNative /
getDynamicHomeNative は本物のトークンで 200 を返す(実測)。そこから
パッケージIDを拾い、CDN の productInfo.meta で肉付けして旧 ProductList に
組み直す。購入はできないが、一覧と個別ページの表示はこれで通る。

旧 LineProductList(実機バイナリの initWithHasNext:bannerSequence:
bannerTargetType:bannerTargetPath:productList:bannerLang: より):
  1 hasNext(bool) 2 bannerSequence(i64) 3 bannerTargetType(i32)
  4 bannerTargetPath(str) 5 productList(list<Product>) 6 bannerLang(str)
"""
import http.client
import re
import ssl
import threading
import time


SHOP_METHODS = frozenset({
    "getPopularPackages", "getNewlyReleasedPackages", "getEventPackages",
})

# 旧一覧 -> 現行ショーケース。イベントに相当するものは現行に無い。
_SOURCE = {
    "getPopularPackages": "getAggregatedHomeNative",
    "getNewlyReleasedPackages": "getDynamicHomeNative",
    "getEventPackages": None,
}

_PACKAGE_ID = re.compile(r"[0-9]{4,12}")
_CACHE_TTL = 1800.0
_MAX_IDS = 60
_lock = threading.RLock()
_cache = {}


def _collect_ids(node, found):
    """Walk a parsed TCompact tree and keep every package-id-looking string."""
    if isinstance(node, dict):
        for value in node.values():
            _collect_ids(value, found)
    elif isinstance(node, (list, tuple)):
        for value in node:
            _collect_ids(value, found)
    elif isinstance(node, (bytes, bytearray)):
        text = node.decode("latin1")
        if _PACKAGE_ID.fullmatch(text) and text not in found:
            found.append(text)


def _showcase_ids(g, method):
    """Package ids the current shop showcase lists, newest call cached."""
    with _lock:
        cached = _cache.get(method)
        if cached and time.monotonic() - cached[0] < _CACHE_TTL:
            return cached[1]
    ids = []
    token = g["real_token"]()
    if not token:
        g["log"]("  [shop] real_token が無いのでショーケースを引けない")
        return ids
    # 引数は request struct(field 2) の中の productType(field 1) = 1(スタンプ)。
    args = bytes([0x2C, 0x15, 0x02, 0x00])
    frame = (b"\x82\x21\x00" + g["put_uvarint"](len(method)) + method.encode()
             + args + b"\x00")
    conn = http.client.HTTPSConnection(
        "gw.line.naver.jp", 443, timeout=20, context=ssl.create_default_context())
    try:
        conn.request("POST", "/TSHOP4", body=frame, headers={
            "Content-Type": "application/x-thrift",
            "X-Line-Access": token,
            "X-Line-Application": g["bridge_app_string"](),
            "User-Agent": g["bridge_user_agent"](),
            "x-lal": "ja_JP",
            "x-lpv": "1",
        })
        response = conn.getresponse()
        body = response.read(2_000_000)
        if response.status != 200 or not body.startswith(b"\x82\x41"):
            raise ValueError("HTTP %s (%dB)" % (response.status, len(body)))
        position = 3
        length, position = g["_uv"](body, position)
        position += length
        fields, _end = g["_tc_read_struct"](body, position)
        _collect_ids(fields, ids)
        del ids[_MAX_IDS:]
        g["log"]("  [shop] %s -> %d パッケージ候補" % (method, len(ids)))
    except Exception as exc:
        g["log"]("  [shop] %s 失敗 %r" % (method, exc))
        ids = []
    finally:
        conn.close()
    with _lock:
        _cache[method] = (time.monotonic(), ids)
    return ids


def _window(g, payload):
    """(start, size) from the legacy call: 1 start(i64) 2 size(i32)."""
    start, size = 0, 20
    try:
        position = 2
        _seq, position = g["_uv"](payload, position)
        length, position = g["_uv"](payload, position)
        fields, _end = g["_tc_read_struct"](payload, position + length)
        for _fid, (typ, value) in sorted(fields.items()):
            if typ == 6 and isinstance(value, int):
                start = max(0, value)
            elif typ == 5 and isinstance(value, int):
                size = value
    except Exception:
        pass
    return start, max(1, min(40, size))


def handle(g, method, seqid, payload):
    """旧ショップ一覧RPCの応答。対象外は None。"""
    if method not in SHOP_METHODS:
        return None
    try:
        start, size = _window(g, payload)
        source = _SOURCE.get(method)
        ids = _showcase_ids(g, source) if source else []
        window = ids[start:start + size]
        products = bytearray()
        entries = []
        for package_id in window:
            meta = g["fetch_product_meta"](int(package_id))
            if meta:
                entries.append((int(package_id), meta))
        count = len(entries)
        if count < 15:
            products.append((count << 4) | 0x0C)
        else:
            products.append(0xF0 | 0x0C)
            products += g["put_uvarint"](count)
        owned = {int(pkg) for pkg, _v in g["load_owned_stickers"]()}
        for package_id, meta in entries:
            products += g["encode_product"](package_id, meta,
                                            owned=package_id in owned,
                                            with_price=True)
        body = bytearray()
        prev = 0
        body.append(((1 - prev) << 4) | (1 if start + size < len(ids) else 2))
        prev = 1
        # productList は field 7。-[LineProductList read:] の tbb 分岐表で確定
        # (1 hasNext / 4 bannerSequence / 5 bannerTargetType / 6 bannerTargetPath
        #  / 7 productList / 8 bannerLang)。5 に入れると型不一致で丸ごと捨てられる。
        prev = g["_tc_field"](body, prev, 7, 9, bytes(products))
        body.append(0x00)
        g["log"]("  [shop] %s start=%d size=%d -> %d 件 (候補 %d)"
                 % (method, start, size, count, len(ids)))
        return g["build_struct_result"](method, seqid, bytes(body))
    except Exception as exc:
        g["log"]("  [shop] %s failed: %r" % (method, exc))
        return g["build_app_exception"](method, seqid, "Shop unavailable")
