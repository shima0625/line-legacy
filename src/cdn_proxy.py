"""RasPi 画像CDNプロキシ: 旧LINE(3.7.1)のCDN要求を現行CDNへ翻訳して中継する。

旧アプリは以下へ画像を取りに行くが、現行サーバは旧パス形式に応答しない:
  dl.stickershop.line.naver.jp   … スタンプ画像(同梱パッケージ以外はここで失敗→クラッシュ)
  os.line.naver.jp               … プロフィール画像(アイコン)

DNS(dns_probe --hijack-map)でこの2ホストをRasPiへ向け、本プロキシが
旧URL → 現行CDN(*.line-scdn.net)へ翻訳して取得し、そのまま返す。

未知のパスは 404 を返しつつ全部ログに残す(パス形式を後から詰めるため)。

起動: sudo ./venv/bin/python cdn_proxy.py   (port 80)
"""
import base64, hashlib, html, http.client, io, json, os, plistlib, random, re, shutil, ssl, struct, subprocess, sys, threading, time, urllib.request, urllib.error, urllib.parse, uuid, zipfile, zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.environ.get("LINE_LEGACY_HOME") or os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "cdn_proxy.log")
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X)"

STICKER_CDN = "https://stickershop.line-scdn.net"
PROFILE_CDN = "https://profile.line-scdn.net"
THEME_CDN = "https://shop.line-scdn.net"
LEGACY_MEDIA_BASE = os.environ.get(
    "LINE_LEGACY_MEDIA_BASE", "http://127.0.0.1:8081").rstrip("/")

# LINE 3.7.1 hard-codes the original Cony package as version 1 and requests it
# from dl.shop.line.naver.jp.  That object has been removed.  The same official
# product is still published on the current CDN, but under its current revision.
# Keep this explicit so an unrelated/owned product is never substituted.
THEME_REVISIONS = {
    "a0768339-c2d3-4189-9653-2909e9bb6f58": 275,
}

_pic = {}     # mid -> pictureStatus
_timeline_pic = {}  # mid -> current HTTPS profile URL
_timeline_pic_mtime = None
_cafe_note_cache = {}
_cafe_note_lock = threading.RLock()
_cafe_create_cache = {}
_cafe_media_targets = {}
_cafe_video_oids = set()
_cafe_uploaded_oids = {}   # ローカルoid -> OBS がその場で採番した oid


def _cafe_user(value):
    """Convert a current Note userInfo object to LCUser's small dictionary."""
    value = value if isinstance(value, dict) else {}
    mid = str(value.get("mid") or value.get("writerMid") or
              value.get("userHash") or "")
    name = str(value.get("nickname") or value.get("displayName") or
               value.get("name") or "LINE")
    return {"userHash": mid, "name": name, "customName": name,
            "isUnregistered": False}


def _cafe_timestamp(value):
    """Return milliseconds as text for LINE 3.7.1's 32-bit JSON reader.

    The client calls ``doubleValue`` and then divides by 1000.  A modern
    13-digit millisecond value is too large for the old numeric JSON path,
    while NSString preserves it and still implements ``doubleValue``.
    """
    try:
        return str(int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return "0"


def _cafe_comment(value):
    """Convert one v57 comment to the exact fields LCComment reads."""
    if not isinstance(value, dict):
        return None
    comment_id = str(value.get("commentId") or value.get("id") or "")
    if not comment_id:
        return None
    try:
        created = int(value.get("createdTime") or value.get("created") or 0)
    except (TypeError, ValueError):
        created = 0
    replies = []
    for reply in value.get("replies") or []:
        converted = _cafe_comment(reply)
        if converted:
            converted["replyComment"] = True
            converted["parentCommentId"] = comment_id
            replies.append(converted)
    return {
        "id": comment_id,
        "text": str(value.get("commentText") or value.get("text") or ""),
        "owner": _cafe_user(value.get("userInfo") or value.get("owner")),
        "replies": replies, "replyComment": bool(value.get("replyComment")),
        "created": _cafe_timestamp(created),
        "status": str(value.get("status") or "NORMAL"),
        "parentCommentId": value.get("parentCommentId"),
        "linkableUsers": [], "linkableUserCount": 0,
        "linkableUserRegularVersion": 0,
    }


def _cafe_like(value):
    """Convert one v57 like to the exact fields LCLike reads."""
    if not isinstance(value, dict):
        return None
    user = value.get("userInfo") or value.get("owner") or value.get("actor") or {}
    owner = _cafe_user(user)
    if not owner.get("userHash") and value.get("actorId"):
        owner["userHash"] = str(value.get("actorId"))
    like_id = str(value.get("likeId") or value.get("id") or
                  owner.get("userHash") or "")
    if not like_id:
        return None
    try:
        created = int(value.get("createdTime") or value.get("created") or 0)
    except (TypeError, ValueError):
        created = 0
    return {"id": like_id, "owner": owner,
            "created": _cafe_timestamp(created)}


def log(m):
    line = f"[{time.strftime('%H:%M:%S')}] {m}"
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


_pic_mtimes = {}


def refresh_pictures():
    """contacts.json / groups.json が更新されていたら _pic を読み直す。

    グループアイコンやプロフィール画像を変えると bridge_daemon がこの2つを
    書き直すが、load_pictures() は起動時にしか走らなかったので、実機からは
    いつまでも「no pictureStatus」に見えていた(2026-09-08)。
    """
    changed = False
    for name in ("contacts.json", "groups.json"):
        f = os.path.join(BASE, name)
        try:
            mtime = os.path.getmtime(f)
        except OSError:
            mtime = None
        if _pic_mtimes.get(name) != mtime:
            _pic_mtimes[name] = mtime
            changed = True
    if changed:
        load_pictures()


def load_pictures():
    _pic.clear()
    for name, key in (("contacts.json", "mid"), ("groups.json", "id")):
        p = os.path.join(BASE, name)
        if not os.path.exists(p):
            continue
        try:
            for it in json.load(open(p, encoding="utf-8")):
                v = it.get("pictureStatus") or it.get("picture")
                # Current official accounts often expose pictureStatus="exist"
                # and put the real image route in picturePath instead of a CDN
                # hash. Preserve that route for the legacy /os/p/<mid> request.
                if v == "exist" and str(it.get("picturePath") or "").startswith("/r/"):
                    v = it.get("picturePath")
                if it.get(key) and v:
                    _pic[it[key]] = v
                # グループの members にも非友だちの pictureStatus が入っている。
                # ここを読まないと「グループにいる非友だちのアイコンだけ出ない」になる。
                for m in (it.get("members") or []):
                    if isinstance(m, dict) and m.get("mid") and m.get("pictureStatus"):
                        _pic.setdefault(m["mid"], m["pictureStatus"])
        except Exception as e:
            log(f"load {name} err {e!r}")
    for name in ("contacts.json", "groups.json"):
        f = os.path.join(BASE, name)
        try:
            _pic_mtimes[name] = os.path.getmtime(f)
        except OSError:
            _pic_mtimes[name] = None
    log(f"pictures loaded: {len(_pic)}")


def timeline_picture(mid):
    """Read the small map produced by legacy_timeline_rest without restarting."""
    global _timeline_pic, _timeline_pic_mtime
    p = os.path.join(BASE, "timeline_pictures.json")
    try:
        mtime = os.path.getmtime(p)
        if mtime != _timeline_pic_mtime:
            value = json.load(open(p, encoding="utf-8"))
            if isinstance(value, dict):
                _timeline_pic = value
                _timeline_pic_mtime = mtime
                log(f"timeline pictures loaded: {len(_timeline_pic)}")
    except (OSError, ValueError) as e:
        log(f"timeline pictures load err {e!r}")
    url = _timeline_pic.get(mid)
    if not isinstance(url, str):
        return None
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {
            "profile.line-scdn.net", "obs.line-apps.com", "obs.line-scdn.net"}:
        return None
    return url


def translate(host, path):
    """旧URL -> 現行CDN URL。対応できなければ None。"""
    h = (host or "").lower()

    # ---- 着せ替え ----
    # 旧: /themeshop/v1/products/a0/76/83/<uuid>/1/iphone/theme.zip
    # 現: /themeshop/v1/products/a0/76/83/<uuid>/<revision>/IOS/theme.zip
    # 現行パッケージもルート直下が theme.json + images/ のため、3.7.1の
    # NLThemePackage が期待するZIP構造と一致する。
    if h.startswith("dl.shop.line.naver.jp"):
        m = re.fullmatch(
            r"/themeshop/v1/products/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{2})/"
            r"([0-9a-f-]+)/\d+/iphone/theme\.zip(?:\?.*)?",
            path,
            re.I,
        )
        if m:
            product_id = m.group(4).lower()
            revision = THEME_REVISIONS.get(product_id)
            if revision is not None:
                return (
                    f"{THEME_CDN}/themeshop/v1/products/"
                    f"{m.group(1).lower()}/{m.group(2).lower()}/{m.group(3).lower()}/"
                    f"{product_id}/{revision}/IOS/theme.zip"
                )

    # ---- スタンプ ----
    # 旧: /products/0/0/1/<pkg>/iphone/stickers/<id>.png
    if "stickershop" in h:
        # 実機の要求形式(実測):
        #   /products/0/0/1/<pkg>/iphone/stickers/<id>.png
        #   /products/0/0/1/<pkg>/iphone/stickers@2x/<id>@2x.png   ← ディレクトリ側にも@2x
        m = re.search(r"/products/\d+/\d+/\d+/(\d+)/[^/]+/stickers(?:@2x)?/(\d+)(@2x)?(_key)?\.png", path)
        if m:
            sid = m.group(2)
            at2 = m.group(3) or ""
            if m.group(4):      # _key.png = 吹き出し用のキー画像
                return f"{STICKER_CDN}/stickershop/v1/sticker/{sid}/iPhone/sticker_key{at2}.png"
            return f"{STICKER_CDN}/stickershop/v1/sticker/{sid}/iPhone/sticker{at2}.png"
        # ダウンロード本体は stickers@2x.zip / stickers.zip(現行CDNに同名で存在)。
        # product.zip だけが現行CDNに無いので、そちらは素材から組み立てる。
        m = re.search(r"/products/\d+/\d+/\d+/(\d+)/[^/]+/"
                      r"(productInfo\.meta|stickers@2x\.zip|stickers\.zip|product_key\.zip)", path)
        if m:
            return f"{STICKER_CDN}/stickershop/v1/product/{m.group(1)}/iphone/{m.group(2)}"
        # パッケージ単位の画像は現行CDNに同名で存在するのでそのまま通す。
        # (main / preview / tab_on / tab_off / thumbnail_shop, @2x 有無)
        # preview@2x.png を落としていたためスタンプ情報画面が描画できず
        # 「接続できませんでした」になっていた(2026-08-20 実測)。
        m = re.search(r"/products/\d+/\d+/\d+/(\d+)/[^/]+/"
                      r"(main|preview|tab_on|tab_off|thumbnail_shop|thumbnail)(@2x)?\.png", path)
        if m:
            return (f"{STICKER_CDN}/stickershop/v1/product/{m.group(1)}/iphone/"
                    f"{m.group(2)}{m.group(3) or ''}.png")
        return None

    # ---- タイムライン動画の再生用 ----
    # 3.7.1 がトークの動画を再生できている実績のあるURL形は /os/m/<id> なので
    # 再生URLもその形にし、oid から OBS の bucket を引いて中継する。
    m = re.fullmatch(r"/os/m/([A-Za-z0-9_-]{8,256})", urllib.parse.urlsplit(path).path)
    if m and not m.group(1).isdigit():
        bucket = _rts_targets.get(m.group(1))
        if bucket:
            return "https://obs.line-apps.com/r/%s/%s" % (bucket, m.group(1))
        log("  (no rts bucket for %s)" % m.group(1)[:24])
        return None


    # MPMoviePlayer は拡張子で形式を判断するので、rts_url が返す再生URLは
    # "/os/v/<serviceName>/<obsNamespace>/<oid>.mp4" という形にしてある。
    m = re.fullmatch(r"/os/v/([A-Za-z0-9_.-]{1,32})/([A-Za-z0-9_.-]{1,32})/"
                     r"([A-Za-z0-9_-]{8,256})\.mp4", urllib.parse.urlsplit(path).path)
    if m:
        return "https://obs.line-apps.com/r/%s/%s/%s" % (m.group(1), m.group(2), m.group(3))

    # ---- タイムライン/ホームのメディア(写真・動画) ----
    # 3.7.1 は旧OBSの download.nhn を叩く:
    #   /<serviceName>/<obsNamespace>/download.nhn?userid=..&tid=612w&oid=<objectId>&ver=1.0
    # 現行OBSは同じ実体を /r/<serviceName>/<obsNamespace>/<oid> で返す(認証不要)。
    # tid はサイズ指定だが現行に対応するものが無いので原寸を返す。
    only_path = urllib.parse.urlsplit(path).path
    m = re.fullmatch(r"/([A-Za-z0-9_.-]{1,32})/([A-Za-z0-9_.-]{1,32})/download\.nhn", only_path)
    if m:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        oid = (query.get("oid") or [""])[0]
        if re.fullmatch(r"[A-Za-z0-9_-]{8,256}", oid or ""):
            service, namespace = m.group(1), m.group(2)
            # Cafe media has no service/namespace fields in LINE 3.7.1. Keep
            # its old cafe/p URL while resolving each oid to the current
            # group-Note-only privnote/post object captured from the list.
            if service == "cafe" and namespace == "p":
                service, namespace = _cafe_media_targets.get(
                    oid, ("privnote", "post"))
            base = "https://obs.line-apps.com/r/%s/%s/%s" % (service, namespace, oid)
            # tid is the legacy size hint ("612w", "640x520") and current OBS
            # accepts the very same token as a path suffix.  Without it a video
            # post answers with the whole 2MB file where a 20KB JPEG thumbnail
            # was wanted, which is far too heavy for an iPhone 5.
            tid = (query.get("tid") or [""])[0]
            # Unlike myhome/lights, current privnote/post rejects every old
            # Cafe m592x170/m592x870 thumbnail suffix with HTTP 400. Return the
            # original image; the legacy client scales it locally.
            if service != "privnote" and re.fullmatch(r"[A-Za-z0-9]{1,16}", tid or ""):
                return base + "/" + tid
            return base
        log("  (download.nhn without a usable oid)")
        return None

    # ---- プロフィール画像 ----
    # 旧: /os/p/<mid> , /os/g/<groupid>  (末尾に /preview 等が付くこともある)
    if h.startswith("os.line") or h.startswith("dl.os.line") or "/os/" in path:
        # 形式1: /os/p/<mid>/large , /os/g/<groupid>  → mid から pictureStatus を引く
        # ★サイズ指定は現行CDNへそのまま引き継ぐ。無指定(原寸)は 46KB 前後あり、
        #   2013年のアプリ/iPhone4S には重すぎて描画が落ちる(アイコンが一瞬で消える)。
        #   large/preview は 7KB、small は 1.3KB。
        m = re.search(r"/os/[pg]/([A-Za-z0-9_-]+)(?:/(large|small|preview))?", path)
        if m:
            refresh_pictures()
            key = m.group(1)
            size = m.group(2) or "preview"
            ps = _pic.get(key)
            if ps:
                if str(ps).startswith("/r/"):
                    return "https://obs.line-apps.com" + str(ps)
                return f"{PROFILE_CDN}/{ps}/{size}"
            current_url = timeline_picture(key)
            if current_url:
                return current_url
            log(f"  (no pictureStatus for {key})")
            return None
        # 形式2: /<obsハッシュ>/large  → 自分自身のアイコン等。そのまま現行CDNへ。
        m = re.fullmatch(r"/([A-Za-z0-9_-]{20,})(?:/(large|small|preview))?/?", path)
        if m:
            return f"{PROFILE_CDN}/{m.group(1)}/{m.group(2) or 'preview'}"
    return None


_cafe_group_names = {}
_cafe_last_group = ""


def _cafe_object(group_mid, post_count=None):
    """LCCafe が読む辞書。投稿の board にもこれを入れないと
    詳細画面が currentCafe を失い、次の要求が X-Line-Cafe: 0 になる。"""
    name = _cafe_group_names.get(group_mid)
    if name is None:
        name = "LINE Group"
        try:
            with open(os.path.join(BASE, "groups.json"), encoding="utf-8") as f:
                for item in json.load(f):
                    if item.get("id") == group_mid:
                        name = str(item.get("name") or name)
                        break
        except Exception:
            pass
        _cafe_group_names[group_mid] = name
    cafe = {"id": group_mid, "type": "GROUP", "name": name,
            "newFlag": False, "joined": True, "lineGroupId": group_mid}
    if post_count is not None:
        cafe["cafeStatistics"] = {"postCount": int(post_count)}
    return cafe


def _cafe_note_item(group_mid, post):
    """Convert one current Note post to the dictionary LCMixPost expects."""
    if not isinstance(post, dict):
        return None
    info = post.get("postInfo") or {}
    user = post.get("userInfo") or {}
    contents = post.get("contents") or {}
    post_id = str(info.get("postId") or "")
    if not post_id:
        return None
    owner = _cafe_user(user)
    board = {"id": group_mid, "status": "NORMAL", "type": "MIX",
             "name": "ノート", "cafe": _cafe_object(group_mid)}
    legacy_media = []
    for media in contents.get("media") or []:
        if not isinstance(media, dict):
            continue
        oid = str(media.get("objectId") or "")
        media_type = str(media.get("type") or "").upper()
        if not oid or media_type not in ("PHOTO", "IMAGE", "VIDEO"):
            continue
        service = str(media.get("serviceName") or "privnote")
        namespace = str(media.get("obsNamespace") or "post")
        with _cafe_note_lock:
            _cafe_media_targets[oid] = (service, namespace)
            if media_type == "VIDEO":
                _cafe_video_oids.add(oid)
        legacy_media.append({
            "id": oid, "type": "V" if media_type == "VIDEO" else "I",
            "oid": oid, "thumbnailOid": oid,
            "fileSize": int(media.get("size") or 0),
            "width": int(media.get("width") or 0),
            "height": int(media.get("height") or 0),
            "runningTime": str(media.get("duration") or ""),
        })
    stickers = []
    for sticker in (contents.get("stickers") or [])[:4]:
        if not isinstance(sticker, dict) or sticker.get("id") is None:
            continue
        stickers.append({
            "stickerId": str(sticker.get("id")),
            "stickerPackageId": str(sticker.get("packageId") or ""),
            "stickerPackageVersion": str(sticker.get("packageVersion") or 1),
            "width": int(sticker.get("width") or 0),
            "height": int(sticker.get("height") or 0),
        })
    location = None
    for current_location in contents.get("locations") or []:
        if not isinstance(current_location, dict):
            continue
        try:
            latitude = float(current_location.get("latitude"))
            longitude = float(current_location.get("longitude"))
        except (TypeError, ValueError):
            continue
        # 現行 Note は name しか保持しないので、address が無ければ name を出す。
        place = str(current_location.get("name") or "")
        location = {
            "name": place,
            "address": str(current_location.get("address") or "") or place,
            "point": {"latitude": latitude, "longitude": longitude},
        }
        break
    links = []
    for link in (contents.get("urls") or contents.get("links") or [])[:4]:
        if not isinstance(link, dict):
            continue
        url = str(link.get("targetUrl") or link.get("url") or "")
        if url:
            links.append({
                "title": str(link.get("title") or ""),
                "summary": str(link.get("summary") or link.get("description") or ""),
                "url": url, "redirected": str(link.get("redirectUrl") or url),
                "image": str(link.get("imageUrl") or link.get("image") or ""),
            })
    comments = []
    for comment in (post.get("comments") or [])[:20]:
        converted = _cafe_comment(comment)
        if converted:
            comments.append(converted)
    likes = []
    for like in (post.get("likes") or [])[:20]:
        converted = _cafe_like(like)
        if converted:
            likes.append(converted)
    url_info = info.get("url") if isinstance(info.get("url"), dict) else {}
    return {
        "id": post_id, "cafeId": group_mid,
        "created": _cafe_timestamp(info.get("createdTime")),
        "type": "M", "status": str(info.get("status") or "NORMAL"),
        "url": str(url_info.get("targetUrl") or ""),
        "board": board,
        "owner": owner,
        "title": "", "text": str(contents.get("text") or ""),
        "location": location, "stickerMedias": stickers, "medias": legacy_media,
        "mediaCount": len(legacy_media),
        "links": links, "likeUsers": likes,
        "likeCount": int(info.get("likeCount") or 0),
        "commentReplyTotalCount": int(info.get("commentCount") or 0),
        "comments": comments, "commentCount": int(info.get("commentCount") or 0),
        "replies": [], "replyCount": 0,
        "liked": bool(info.get("liked")),
        "newFlag": False,
        "linkableUsers": [], "linkableUserCount": 0,
        "linkableUserRegularVersion": 0,
    }


def _cafe_current_client():
    """Return the loaded bridge module and its current Note REST helper."""
    os.environ.setdefault("ARTIFACTS_DIR", BASE)
    import legy_proxy as lp
    import legacy_timeline_rest as timeline
    if not lp.PROFILE:
        lp.load_contacts()
        lp.load_profile()
    return lp, timeline


def cafe_note_items(group_mid, force=False):
    """Fetch current group Notes and convert them to LINE Cafe LCMixPost JSON."""
    now = time.monotonic()
    with _cafe_note_lock:
        cached = _cafe_note_cache.get(group_mid)
        if not force and cached and now - cached[0] < 5:
            return cached[1]
    try:
        # Reuse the already verified Note client and the bridge account token.
        # Importing does not start another LEGY server (main is guarded).
        lp, timeline = _cafe_current_client()
        query = urllib.parse.urlencode({
            "homeId": group_mid, "sourceType": "MYHOME", "postLimit": "20",
            "likeLimit": "7", "commentLimit": "2",
        })
        current = timeline._current_request(
            vars(lp), lp.real_token(), "GET",
            "/ext/note/nt/api/v57/post/list.json?" + query)
        result = current.get("result") or {}
        feeds = result.get("feeds") or []
        items = []
        for feed in feeds:
            post = feed.get("post") if isinstance(feed, dict) else None
            item = _cafe_note_item(group_mid, post)
            if item:
                items.append(item)
    except Exception as e:
        log("CAFEAPI note fetch failed %r" % (e,))
        items = []
    with _cafe_note_lock:
        _cafe_note_cache[group_mid] = (now, items)
    return items


def cafe_note_item_by_id(group_mid, post_id):
    """Fetch the full current Note used by Cafe's slide/detail screen."""
    try:
        query = urllib.parse.urlencode({
            "homeId": group_mid, "postId": post_id, "sourceType": "MYHOME"})
        current = _cafe_current_request(
            "GET", "/ext/note/nt/api/v57/post/get.json?" + query)

        def find_post(value):
            if isinstance(value, dict):
                if isinstance(value.get("postInfo"), dict) and isinstance(value.get("contents"), dict):
                    return value
                for child in value.values():
                    found = find_post(child)
                    if found:
                        return found
            elif isinstance(value, list):
                for child in value:
                    found = find_post(child)
                    if found:
                        return found
            return None

        post = find_post(current.get("result"))
        converted = _cafe_note_item(group_mid, post)
        if converted:
            created = str(converted.get("created") or "")
            owner = converted.get("owner") or {}
            log("CAFEDETAIL shape created=text/%d-digits ownerHash=%s" % (
                len(created) if created.isdigit() else 0,
                "yes" if owner.get("userHash") else "no"))
            return converted
    except Exception as e:
        log("CAFEAPI full post fetch failed %r" % (e,))
    return next((entry for entry in cafe_note_items(group_mid)
                 if str(entry.get("id")) == str(post_id)), None)


def _cafe_obs_exists(object_id):
    conn = http.client.HTTPSConnection(
        "obs.line-apps.com", timeout=20, context=ssl.create_default_context())
    try:
        conn.request("GET", "/r/privnote/post/" + object_id,
                     headers={"Range": "bytes=0-0"})
        response = conn.getresponse()
        response.read(64)
        return response.status in (200, 206)
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()


_CAFE_NOTE_CHANNEL_ID = "1655599932"


def _cafe_note_channel_token(lp, timeline):
    """privnote バケットへのアップロードに必要なチャネルトークン。

    ★2026-09-08 実測: `POST obs.line-apps.com/privnote/post/upload.nhn` は
      HOME(1341209850) / TIMELINE(1341209950) のトークンだと **401**、
      NOTE(1655599932) だけ **201** を返す。ここを HOME にしていたため
      画像は 400、動画は本体送信中に切られて BrokenPipeError になっていた。
      (タイムラインの /myhome/h/upload.nhn は HOME トークンで通るので、
       同じヘッダの作りでもバケットごとに必要なチャネルが違う)
    """
    import legacy_friend_add
    g = vars(lp)
    result, _ = legacy_friend_add.rpc(
        g, lp.real_token(), "approveChannelAndIssueChannelToken", "/CH4",
        g["_tc_str"](1, _CAFE_NOTE_CHANNEL_ID), timeline._rpc_seq())
    channel = result.get(0)
    if not channel or channel[0] != 12:
        raise ValueError("Note channel token was rejected")
    value = channel[1].get(5)
    if not value or value[0] != 8:
        raise ValueError("Note channel access token is missing")
    token = value[1]
    if isinstance(token, bytes):
        token = token.decode("utf-8", "replace")
    token = str(token)
    if not token or len(token) > 8192:
        raise ValueError("Invalid Note channel access token")
    return token


def _cafe_upload_media(lp, timeline, media):
    """Upload one captured Cafe image/video to the current Note bucket."""
    oid = str(media.get("oid") or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", oid):
        raise ValueError("Invalid Cafe media oid")
    upload_path = os.path.join(UPLOAD, oid + ".bin")
    with open(upload_path, "rb") as source:
        data = source.read()
    if not data or len(data) > 64 * 1024 * 1024:
        raise ValueError("Cafe media is empty or too large")
    width = int(media.get("width") or 0)
    height = int(media.get("height") or 0)
    is_video = str(media.get("type") or "I").upper() == "V"
    if is_video and (width <= 0 or height <= 0):
        try:
            probe = subprocess.run([
                "ffprobe", "-v", "error", "-select_streams", "v:0",
                "-show_entries", "stream=width,height", "-of", "csv=p=0",
                upload_path,
            ], check=False, timeout=30, capture_output=True).stdout.decode(
                "ascii", "ignore")
            dimensions = [int(value) for value in re.split(r"[,\s]+", probe.strip())
                          if value.isdigit()]
            if len(dimensions) >= 2:
                width, height = dimensions[:2]
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    if is_video:
        with _cafe_note_lock:
            _cafe_video_oids.add(oid)
        thumbnail_path = upload_path + ".thumb.jpg"
        if not os.path.exists(thumbnail_path):
            try:
                subprocess.run([
                    "ffmpeg", "-v", "error", "-y", "-ss", "0.1",
                    "-i", upload_path, "-frames:v", "1",
                    "-vf", "scale=min(592\\,iw):-2", thumbnail_path,
                ], check=True, timeout=60, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
                log("CAFEAPI generated video thumbnail")
            except (OSError, subprocess.SubprocessError):
                log("CAFEAPI video thumbnail generation failed")
    with _cafe_note_lock:
        server_oid = _cafe_uploaded_oids.get(oid)
    if not server_oid:
        server_oid = _cafe_obs_upload(lp, timeline, oid, data, is_video)
        with _cafe_note_lock:
            _cafe_uploaded_oids[oid] = server_oid
    with _cafe_note_lock:
        _cafe_media_targets[server_oid] = ("privnote", "post")
        _cafe_media_targets[oid] = ("privnote", "post")
        if is_video:
            _cafe_video_oids.add(server_oid)
    # ★2026-09-09 実測(公式 Windows 26.4.2 の TLS 内キャプチャ):
    #   ノートの media には width/height/serviceName/obsNamespace を **付ける**。
    #   以前これで code=500 になったのは、本文に commandType が無かったため。
    entry = {"objectId": server_oid,
             "type": "VIDEO" if is_video else "PHOTO",
             "serviceName": "privnote", "obsNamespace": "post"}
    if width > 0 and height > 0:
        entry.update({"width": width, "height": height})
    return entry


def _cafe_obs_upload(lp, timeline, oid, data, is_video):
    """1件を現行ノートの OBS へ上げ、**サーバが採番した oid** を返す。

    ★2026-09-09、公式 Windows 版 26.4.2 の TLS 内を frida で採って確定した形。
      `POST obs-jp.line-apps.com /r/privnote/post/<32桁hex>tffffffff` へ
      **multipart/form-data**(params + file) で送る。`upload.nhn` +
      `x-obs-params` ではない。応答の `x-obs-oid` が本物の oid(`cj0...`)で、
      create.json にはこちらを渡す。3.7.1 由来のクライアント採番 hex を
      渡していたのが、写真ノートが通らなかった理由のひとつ。
    """
    boundary = "------b%d" % random.randint(100000, 999999)
    params = json.dumps({
        "type": "video" if is_video else "image", "ver": "2.0",
        "name": oid + (".mp4" if is_video else ".jpg"), "quality": "100",
    }, separators=(",", ":"))
    content_type = "video/mp4" if is_video else "image/jpeg"
    filename = uuid.uuid4().hex + (".mp4" if is_video else ".jpg")
    body = b"".join([
        ('--%s\r\nContent-Disposition: form-data; name="params"\r\n\r\n%s\r\n'
         % (boundary, params)).encode("utf-8"),
        ('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
         'Content-Type: %s\r\n\r\n'
         % (boundary, filename, content_type)).encode("utf-8"),
        data,
        ("\r\n--%s--\r\n" % boundary).encode("utf-8"),
    ])
    headers = {
        "Content-Type": "multipart/form-data; boundary=" + boundary,
        "Content-Length": str(len(body)),
        "User-Agent": lp.bridge_user_agent(),
        "X-Line-Application": lp.bridge_app_string(),
        "X-Line-Mid": lp.bridge_mid(),
        "X-Line-Access": lp.real_token(),
        "X-Line-ChannelToken": _cafe_note_channel_token(lp, timeline),
        "x-obs-server-side-encryption": "AES_256",
        "x-lal": "ja_JP",
    }
    conn = http.client.HTTPSConnection(
        "obs-jp.line-apps.com", timeout=120,
        context=ssl.create_default_context())
    try:
        conn.request("POST", "/r/privnote/post/%stffffffff" % oid,
                     body=body, headers=headers)
        response = conn.getresponse()
        response.read(4096)
        server_oid = response.getheader("x-obs-oid") or ""
        if response.status not in (200, 201):
            raise ValueError("Cafe OBS upload rejected with HTTP %d" %
                             response.status)
    finally:
        conn.close()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", server_oid):
        raise ValueError("Cafe OBS upload returned no object id")
    log("CAFEAPI OBS upload ok (%d bytes) oid=%s..." % (len(data), server_oid[:12]))
    return server_oid


def cafe_create_note(group_mid, legacy_post):
    """Create a current group Note from LINE Cafe's POST /post payload.

    The old client retries a failed-looking request, so cache a successful
    body for ten minutes. The cache is populated only after LINE accepts it.
    """
    text = legacy_post.get("text") if isinstance(legacy_post, dict) else None
    medias = legacy_post.get("medias") if isinstance(legacy_post, dict) else None
    sticker_medias = (legacy_post.get("stickerMedias")
                      if isinstance(legacy_post, dict) else None)
    location = legacy_post.get("location") if isinstance(legacy_post, dict) else None
    links = legacy_post.get("links") if isinstance(legacy_post, dict) else None
    if not isinstance(text, str):
        text = ""
    if not isinstance(medias, list):
        medias = []
    if not isinstance(sticker_medias, list):
        sticker_medias = []
    if not isinstance(links, list):
        links = []
    for link in links:
        if not isinstance(link, dict):
            continue
        url = str(link.get("url") or link.get("targetUrl") or "").strip()
        if re.match(r"https?://", url) and url not in text and len(url) <= 2000:
            text = (text + "\n" + url).strip()
    if not text.strip() and not medias and not sticker_medias and not location:
        raise ValueError("Cafe post has no content")
    if len(text) > 10000:
        raise ValueError("Cafe post text is too long")
    signature = json.dumps({"group": group_mid, "text": text, "medias": medias,
                            "stickers": sticker_medias, "location": location},
                           ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    key = hashlib.sha256(signature.encode("utf-8")).hexdigest()
    now = time.monotonic()
    with _cafe_note_lock:
        old = _cafe_create_cache.get(key)
        if old and now - old[0] < 600:
            log("CAFEAPI duplicate POST /post suppressed")
            return old[1]
        for cache_key, cache_value in list(_cafe_create_cache.items()):
            if now - cache_value[0] >= 600:
                del _cafe_create_cache[cache_key]

    lp, timeline = _cafe_current_client()
    # Current group Notes use the ext/note service. MYHOME is also what the
    # verified list request accepts for c... group homes.
    ruid = hashlib.md5((key + str(time.time_ns())).encode("ascii")).hexdigest()
    query = urllib.parse.urlencode({
        "homeId": group_mid, "sourceType": "MYHOME", "ruid": ruid})
    current_media = [_cafe_upload_media(lp, timeline, media)
                     for media in medias if isinstance(media, dict)]
    payload = {
        "contents": {
            "text": text,
            # Match the already working Timeline create payload. Current v57
            # accepts this for text, media, sticker and location Notes.
            "contentsStyle": {"mediaStyle": {"displayType": "GRID"}}},
        "postInfo": {"readPermission": {"type": "FRIEND", "gids": []}},
    }
    if current_media:
        payload["contents"]["media"] = current_media
        # ★2026-09-09 実測: 写真つきノートはこの3つが要る。これが無いと
        #   現行は code=117「LINEを最新バージョンに」/ code=420 を返す。
        #   端末種別でもAPI版でもチャネルトークンでもなかった。
        payload.update({"commandId": 4, "channelId": _CAFE_NOTE_CHANNEL_ID,
                        "commandType": 188051})
    current_stickers = []
    for sticker in sticker_medias[:4]:
        if not isinstance(sticker, dict):
            continue
        sticker_id = sticker.get("stickerId") or sticker.get("id")
        package_id = sticker.get("stickerPackageId") or sticker.get("packageId")
        if str(sticker_id or "").isdigit() and str(package_id or "").isdigit():
            current_stickers.append({
                "id": str(sticker_id), "packageId": str(package_id),
                "packageVersion": int(sticker.get("stickerPackageVersion") or
                                      sticker.get("packageVersion") or 1),
            })
    if current_stickers:
        payload["contents"]["stickers"] = current_stickers
    if isinstance(location, dict):
        point = location.get("point") if isinstance(location.get("point"), dict) else location
        try:
            latitude = float(point.get("latitude"))
            longitude = float(point.get("longitude"))
        except (TypeError, ValueError):
            latitude = longitude = None
        if (latitude is not None and longitude is not None and
                -90 <= latitude <= 90 and -180 <= longitude <= 180):
            # ★3.7.1 は地図から選んだ地点を name ではなく address に入れて
            #   送ってくることがある(実測 2026-09-08: name="" /
            #   address="〒480-1168 愛知県長久手市 坊の後1109")。
            #   現行 Note の locations は name しか受けないので、name が空なら
            #   address を name として送る。これをしないと投稿は通るのに
            #   地名が空の吹き出しになり「送れていない」ように見える。
            place = str(location.get("name") or "").strip()
            if not place:
                place = str(location.get("address") or "").strip()
            payload["contents"]["locations"] = [{
                "latitude": latitude, "longitude": longitude,
                "name": place[:200],
            }]
    current = timeline._current_request(
        vars(lp), lp.real_token(), "POST",
        "/ext/note/nt/api/v57/post/create.json?" + query, payload)
    current_result = current.get("result")
    if current_result is None:
        raise ValueError("Current Note create returned no result")

    # LCClient hands result directly to LCMixPost.initWithDictionary:.
    # Returning the current v57 {feed: ...} object makes the legacy model miss
    # owner/created, rendering "unknown" and 1970/1/1 after a successful post.
    found = []
    timeline._collect_posts(current_result, found)
    result = _cafe_note_item(group_mid, found[0]) if found else None
    if result is None:
        raise ValueError("Current Note create returned no convertible post")
    with _cafe_note_lock:
        _cafe_note_cache.pop(group_mid, None)
        _cafe_create_cache[key] = (now, result)
    log("CAFEAPI created current group Note")
    return result


def _cafe_current_request(method, path, payload=None):
    lp, timeline = _cafe_current_client()
    return timeline._current_request(
        vars(lp), lp.real_token(), method, path, payload)


def cafe_comments(group_mid, post_id, limit=20):
    query = urllib.parse.urlencode({
        "homeId": group_mid, "contentId": post_id,
        "commentLimit": max(1, min(int(limit or 20), 100)),
    })
    current = _cafe_current_request(
        "GET", "/ext/note/nt/api/v57/comment/getList.json?" + query)
    result = current.get("result") or {}
    comments = []
    for value in result.get("comments") or result.get("commentList") or []:
        converted = _cafe_comment(value)
        if converted:
            comments.append(converted)
    return {
        "items": comments, "nextCursor": result.get("scrollId"),
        "lastestComment": comments[-1] if comments else None,
        "commentReplyTotalCount": int(result.get("commentCount") or len(comments)),
    }


def cafe_create_comment(group_mid, post_id, text, parent_comment_id=None):
    text = str(text or "").strip()
    if not text or len(text) > 10000:
        raise ValueError("Invalid Cafe comment")
    query = urllib.parse.urlencode({"homeId": group_mid, "sourceType": "MYHOME"})
    request = {"contentId": post_id, "commentText": text,
               "recallInfos": [], "contentsList": []}
    if parent_comment_id:
        request["parentCommentId"] = str(parent_comment_id)
    current = _cafe_current_request(
        "POST", "/ext/note/nt/api/v57/comment/create.json?" + query,
        request)
    converted = _cafe_comment(current.get("result") or {})
    if converted is None:
        raise ValueError("Current Note returned no comment")
    with _cafe_note_lock:
        _cafe_note_cache.pop(group_mid, None)
    return converted


def cafe_likes(group_mid, post_id):
    query = urllib.parse.urlencode({
        "homeId": group_mid, "contentId": post_id,
        "includes": "ALL,GROUPED,STATS",
    })
    current = _cafe_current_request(
        "GET", "/ext/note/nt/api/v57/like/getList.json?" + query)
    result = current.get("result") or {}
    bucket = result.get("allLikes") if isinstance(result.get("allLikes"), dict) else result
    likes = []
    for value in (bucket.get("likeList") or bucket.get("likes") or
                  bucket.get("userList") or []):
        converted = _cafe_like(value)
        if converted:
            likes.append(converted)
    return {"items": likes, "nextCursor": bucket.get("scrollId")}


def cafe_set_like(group_mid, post_id, enabled):
    lp, timeline = _cafe_current_client()
    if enabled:
        payload = {"contentId": post_id, "actorId": lp.PROFILE.get(1),
                   "likeType": 1001, "sharable": False}
        query = urllib.parse.urlencode({"sourceType": "MYHOME"})
        current = timeline._current_request(
            vars(lp), lp.real_token(), "POST",
            "/ext/note/nt/api/v57/like/create.json?" + query, payload)
    else:
        query = urllib.parse.urlencode({
            "contentId": post_id, "sourceType": "MYHOME", "homeId": group_mid})
        current = timeline._current_request(
            vars(lp), lp.real_token(), "GET",
            "/ext/note/nt/api/v41/like/cancel.json?" + query)
    with _cafe_note_lock:
        _cafe_note_cache.pop(group_mid, None)
    return current.get("result") or {"success": True}


def cafe_delete_comment(group_mid, comment_id):
    lp, timeline = _cafe_current_client()
    query = urllib.parse.urlencode({
        "homeId": group_mid, "commentId": comment_id,
        "actorId": lp.PROFILE.get(1),
    })
    current = timeline._current_request(
        vars(lp), lp.real_token(), "GET",
        "/ext/note/nt/api/v57/comment/delete.json?" + query)
    with _cafe_note_lock:
        _cafe_note_cache.pop(group_mid, None)
    return current.get("result") or {"success": True}


# oid -> "<serviceName>/<obsNamespace>" for timeline videos, filled in by
# rts_url.nhn so the playback URL can look exactly like a talk video's.
_rts_targets = {}

MEDIA = os.path.join(BASE, "media")        # 受信メディア: <msgid> / <msgid>_preview
UPLOAD = os.path.join(BASE, "upload")      # 実機からのアップロード実体
RECV_OUT = os.path.join(BASE, "recv_out.jsonl")
_media_index = {}
_media_index_mtime = None


# Timeline videos are cached whole (10MB+ each) so playback can go through
# serve_media.  Talk media has no "oid" in its sidecar, so only our own entries
# are ever considered for eviction.
_RTS_CACHE_BYTES = int(os.environ.get("RTS_CACHE_BYTES", str(400 * 1024 * 1024)))


def _trim_rts_cache():
    """Drop the oldest cached timeline videos once the budget is exceeded."""
    entries = []
    total = 0
    try:
        names = os.listdir(MEDIA)
    except OSError:
        return
    for name in names:
        if not name.endswith(".json"):
            continue
        sidecar = os.path.join(MEDIA, name)
        try:
            with open(sidecar, encoding="utf-8") as f:
                rec = json.load(f)
        except (OSError, ValueError):
            continue
        if not rec.get("oid"):
            continue
        body = sidecar[:-len(".json")]
        try:
            size = os.path.getsize(body)
            entries.append((os.path.getmtime(body), size, body, sidecar))
            total += size
        except OSError:
            continue
    if total <= _RTS_CACHE_BYTES:
        return
    entries.sort()
    for _mtime, size, body, sidecar in entries:
        if total <= _RTS_CACHE_BYTES:
            break
        for victim in (body, sidecar):
            try:
                os.remove(victim)
            except OSError:
                pass
        total -= size
        log("RTS evicted %s (%dB)" % (os.path.basename(body), size))


def media_path(msgid, preview):
    name = f"{msgid}_preview" if preview else str(msgid)
    return os.path.join(MEDIA, name)


def _ensure_cafe_video_local(oid):
    """Cache a Cafe Note video locally for thumbnailing and Range playback."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", oid or ""):
        return None
    local_id = str(9000000000000000000 + (int(
        hashlib.sha1(oid.encode("utf-8")).hexdigest()[:15], 16) % 10 ** 17))
    target = media_path(local_id, False)
    if os.path.exists(target):
        return target
    captured = os.path.join(UPLOAD, oid + ".bin")
    os.makedirs(MEDIA, exist_ok=True)
    tmp = target + ".part"
    try:
        if os.path.exists(captured):
            shutil.copyfile(captured, tmp)
            source = "cafe-upload"
        else:
            service, namespace = _cafe_media_targets.get(
                oid, ("privnote", "post"))
            url = "https://obs.line-apps.com/r/%s/%s/%s" % (
                service, namespace, oid)
            status, _ctype, blob = fetch(url)
            if status != 200 or not blob or len(blob) > 128 * 1024 * 1024:
                return None
            with open(tmp, "wb") as output:
                output.write(blob)
            source = url
        os.replace(tmp, target)
        with open(target + ".json", "w", encoding="utf-8") as output:
            json.dump({"contentType": 2, "oid": oid, "source": source,
                       "plainSize": os.path.getsize(target)}, output)
        _trim_rts_cache()
        return target
    except Exception as e:
        log("CAFEAPI video cache failed %r" % (e,))
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass
        return None


def _ensure_cafe_video_thumbnail(oid):
    thumbnail = os.path.join(UPLOAD, oid + ".bin.thumb.jpg")
    if os.path.exists(thumbnail):
        return thumbnail
    source = _ensure_cafe_video_local(oid)
    if not source:
        return None
    try:
        subprocess.run([
            "ffmpeg", "-v", "error", "-y", "-ss", "0.1", "-i", source,
            "-frames:v", "1", "-vf", "scale=min(592\\,iw):-2", thumbnail,
        ], check=True, timeout=60, stdout=subprocess.DEVNULL,
           stderr=subprocess.DEVNULL)
        return thumbnail if os.path.exists(thumbnail) else None
    except (OSError, subprocess.SubprocessError):
        return None


def media_record(msgid):
    """Return the latest receive metadata for a locally cached media object."""
    global _media_index_mtime
    sidecar = media_path(msgid, False) + ".json"
    try:
        with open(sidecar, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        pass
    try:
        mtime = os.path.getmtime(RECV_OUT)
    except OSError:
        return _media_index.get(str(msgid), {})
    if mtime != _media_index_mtime:
        fresh = {}
        try:
            with open(RECV_OUT, encoding="utf-8") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if int(rec.get("contentType") or 0) in (1, 2, 3):
                        fresh[str(rec.get("id"))] = rec
            _media_index.clear()
            _media_index.update(fresh)
            _media_index_mtime = mtime
        except Exception as e:
            log(f"MEDIA index err {e!r}")
    return _media_index.get(str(msgid), {})


def media_mime(msgid, data, preview=False):
    if preview:
        return "image/jpeg"
    rec = media_record(msgid)
    ctype = int(rec.get("contentType") or 0)
    if ctype == 2:
        return "video/mp4"
    if ctype == 3:
        return "audio/mp4"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"GIF8"):
        return "image/gif"
    return "image/jpeg" if ctype == 1 or data.startswith(b"\xff\xd8") else "application/octet-stream"


def media_plain_size(msgid):
    meta = media_record(msgid).get("contentMetadata") or {}
    try:
        return int(meta.get("FILE_SIZE") or 0)
    except (TypeError, ValueError):
        return 0


def byte_range(value, size):
    """Parse a single byte range; return inclusive bounds or None."""
    m = re.fullmatch(r"bytes=(\d*)-(\d*)", (value or "").strip())
    if not m or size <= 0:
        return None
    if not m.group(1):
        suffix = int(m.group(2) or 0)
        if suffix <= 0:
            return None
        return max(0, size - suffix), size - 1
    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else size - 1
    if start >= size or end < start:
        return None
    return start, min(end, size - 1)


def serve_media(handler, path, body_wanted=True):
    """/os/m/<msgid>[/preview] を bridge_daemon が落としたファイルから返す。
    まだ落とせていなければ 404(アプリは後で再取得する)。

    動画を送ったあと、3.7.1 は自分でサムネイルを /talk/m/<msgid>/preview へ
    取りに来る(spaceID="m" / thumbID="preview")。上流へ流すと obs の
    /r/talk/m/... へ書き換わって 404 になるので、ここで母艦のファイルを返す。"""
    m = re.search(r"/(?:os|(?:r/)?talk)/m/(\d+)(?:/(preview|thumb))?", path)
    if m:
        msgid = m.group(1)
        preview = bool(m.group(2))
    else:
        # 旧OBSのダウンロード形式。動画を送ったあと 3.7.1 はこれで自分の
        # サムネイルを取りに来る: /talk/m/download.nhn?oid=<msgid>&tid=preview
        split = urllib.parse.urlsplit(path)
        if not re.fullmatch(r"/(?:r/)?talk/m/download\.nhn", split.path):
            return False
        query = urllib.parse.parse_qs(split.query)
        msgid = (query.get("oid") or [""])[0]
        if not re.fullmatch(r"\d+", msgid or ""):
            return False   # トーク以外(タイムライン等)は従来どおり上流へ
        preview = (query.get("tid") or [""])[0] == "preview"
    rec = media_record(msgid)
    rec_type = int(rec.get("contentType") or 0)
    p = media_path(msgid, preview)
    if not os.path.exists(p) and preview:
        # 音声/動画本体を image/jpeg として返すと旧LINEが再試行ループへ入る。
        if rec_type in (0, 1):
            p = media_path(msgid, False)
    if not os.path.exists(p):
        log(f"MEDIA-MISS {path}")
        handler.send_response(404)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
        return True
    data = open(p, "rb").read()
    # 過去キャッシュは末尾32-byte MACまで復号していた。本文は先頭
    # FILE_SIZE bytesで正しいため、既存ファイルも配信時に補正する。
    expected = media_plain_size(msgid)
    if not preview and expected > 0 and len(data) == expected + 32:
        data = data[:expected]
    full_size = len(data)
    bounds = byte_range(handler.headers.get("Range"), full_size)
    if bounds:
        start, end = bounds
        payload = data[start:end + 1]
        handler.send_response(206)
        handler.send_header("Content-Range", f"bytes {start}-{end}/{full_size}")
    else:
        payload = data
        handler.send_response(200)
    log(f"MEDIA {path} -> {os.path.basename(p)} ({len(payload)}/{full_size}B)")
    handler.send_header("Content-Type", media_mime(msgid, data, preview))
    handler.send_header("Accept-Ranges", "bytes")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    if body_wanted:
        handler.wfile.write(payload)
    return True



ZIPCACHE = os.path.join(BASE, "sticker_zips")


_PV_META_CACHE = {}


def _product_meta(pkg):
    """productInfo.meta(現行CDN, JSON)を取得。ディスクにもキャッシュする。"""
    pkg = int(pkg)
    if pkg in _PV_META_CACHE:
        return _PV_META_CACHE[pkg]
    cdir = os.path.join(BASE, "product_meta")
    cfile = os.path.join(cdir, "%d.json" % pkg)
    meta = None
    try:
        with open(cfile, encoding="utf-8") as f:
            meta = json.load(f)
    except Exception:
        meta = None
    if meta is None:
        url = "%s/stickershop/v1/product/%d/iphone/productInfo.meta" % (STICKER_CDN, pkg)
        try:
            _st, _ct, raw = fetch(url)
            meta = json.loads(raw.decode("utf-8"))
            os.makedirs(cdir, exist_ok=True)
            with open(cfile, "w", encoding="utf-8") as f:
                json.dump(meta, f, ensure_ascii=False)
        except Exception as e:
            log("productVersions: pkg %d の productInfo.meta 取得失敗 %r" % (pkg, e))
            meta = None
    _PV_META_CACHE[pkg] = meta
    return meta


def _id_ranges(ids):
    """連続するスタンプIDを [開始ID, 個数] に畳む(端末の Stickers.plist と同じ形)。"""
    out = []
    for i in sorted(int(x) for x in ids):
        if out and i == out[-1][0] + out[-1][1]:
            out[-1][1] += 1
        else:
            out.append([i, 1])
    return out


def build_package_versions_meta():
    """productVersions_<N>.meta の中身 = 所持パッケージの版数とスタンプID範囲。

    アプリはこれを読んで Sticker Packages/Stickers.plist を作り直す。ここが空だと
    ダウンロード済みのパッケージが1つも登録されない(2026-09-06 に判明)。
    形式: {"versions": [[packageId, version, [[開始スタンプID, 個数], ...]], ...]}
    """
    versions = []
    try:
        with open(os.path.join(BASE, "owned_stickers.json"), encoding="utf-8") as f:
            owned = json.load(f)
    except Exception as e:
        log("productVersions: 所持一覧が読めない %r" % (e,))
        owned = []
    for it in owned:
        try:
            pkg = int(it["packageId"]) if isinstance(it, dict) else int(it)
        except Exception:
            continue
        ver = 100 if 1 <= pkg <= 5 else 1
        meta = _product_meta(pkg)
        if not meta:
            log("productVersions: pkg %s の meta が無いので除外" % pkg)
            continue
        ids = [x.get("id") for x in (meta.get("stickers") or [])
               if isinstance(x, dict) and x.get("id")]
        if not ids:
            log("productVersions: pkg %s のスタンプIDが空なので除外" % pkg)
            continue
        versions.append([pkg, ver, _id_ranges(ids)])
    body = json.dumps({"versions": versions}, separators=(",", ":")).encode("utf-8")
    log("productVersions -> %d パッケージ (%dB)" % (len(versions), len(body)))
    return body


def build_product_zip(pkg):
    """旧アプリ用の product.zip を現行CDNの素材から組み立てる。

    現行CDNは product.zip を配信しない(404)ため、旧アプリはパッケージを
    導入できない。幸い中身は
        <stickerId>.png / <stickerId>@2x.png / productInfo.plist / tab_off*.png
    で、productInfo.plist のスキーマは現行の productInfo.meta(JSON) と同一
    (author/onSale/price/title/packageId/stickers/validDays)。∴変換して詰めれば良い。
    生成物はディスクにキャッシュする(1パッケージあたり数十枚のDLが要るため)。
    """
    os.makedirs(ZIPCACHE, exist_ok=True)
    cached = os.path.join(ZIPCACHE, f"{pkg}.zip")
    if os.path.exists(cached) and os.path.getsize(cached) > 0:
        return open(cached, "rb").read()

    base = f"{STICKER_CDN}/stickershop/v1/product/{pkg}/iphone"
    try:
        _, _, meta_raw = fetch(base + "/productInfo.meta")
        meta = json.loads(meta_raw.decode("utf-8"))
    except Exception as e:
        log(f"ZIP {pkg}: productInfo.meta 取得失敗 {e!r}")
        return None

    info = {k: meta[k] for k in
            ("author", "onSale", "price", "title", "packageId", "stickers", "validDays")
            if k in meta}
    info.setdefault("onSale", True)
    info.setdefault("validDays", 0)
    info.setdefault("price", [])

    buf = io.BytesIO()
    n_ok = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("productInfo.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        for st in meta.get("stickers", []):
            sid = st.get("id")
            if sid is None:
                continue
            for suffix, fname in (("", f"{sid}.png"), ("@2x", f"{sid}@2x.png")):
                url = f"{STICKER_CDN}/stickershop/v1/sticker/{sid}/iPhone/sticker{suffix}.png"
                try:
                    _, _, data = fetch(url)
                    z.writestr(fname, data)
                    n_ok += 1
                except Exception:
                    pass
        # タブ画像(無くても致命ではない)
        for src, dst in (("/tab_on.png", "tab_off.png"), ("/tab_on@2x.png", "tab_off@2x.png")):
            try:
                _, _, data = fetch(base + src)
                z.writestr(dst, data)
            except Exception:
                pass
    blob = buf.getvalue()
    with open(cached, "wb") as f:
        f.write(blob)
    log(f"ZIP {pkg}: 生成 {len(blob)}B (画像{n_ok}枚)")
    return blob



def build_stickers_zip(pkg, at2x):
    """現行CDNの stickers[@2x].zip を旧アプリが読める形に組み替える。

    LINE 3.7.1 の完了ブロックは productInfo.meta(JSON) を読み込み、端末側で
    productInfo.plist を生成してからパッケージを配置する。meta を消して事前生成した
    plist に置き換えると、JSON読込段階でダウンロード失敗になる。
    """
    os.makedirs(ZIPCACHE, exist_ok=True)
    tag = "2x" if at2x else "1x"
    cached = os.path.join(ZIPCACHE, f"{pkg}_stickers_{tag}.zip")
    if os.path.exists(cached) and os.path.getsize(cached) > 0:
        return open(cached, "rb").read()

    base = f"{STICKER_CDN}/stickershop/v1/product/{pkg}/iphone"
    name = "stickers@2x.zip" if at2x else "stickers.zip"
    try:
        _, _, raw = fetch(f"{base}/{name}")
    except Exception as e:
        log(f"ZIP {pkg}: {name} 取得失敗 {e!r}")
        return None
    try:
        src = zipfile.ZipFile(io.BytesIO(raw))
    except Exception as e:
        log(f"ZIP {pkg}: zip展開失敗 {e!r}")
        return None

    meta = {}
    try:
        meta = json.loads(src.read("productInfo.meta").decode("utf-8"))
    except Exception:
        try:
            _, _, mraw = fetch(base + "/productInfo.meta")
            meta = json.loads(mraw.decode("utf-8"))
        except Exception as e:
            log(f"ZIP {pkg}: productInfo.meta 無し {e!r}")
            return None
    info = {k: meta[k] for k in
            ("author", "onSale", "price", "title", "packageId", "stickers", "validDays")
            if k in meta}
    info.setdefault("onSale", True)
    info.setdefault("validDays", 0)
    info.setdefault("price", [])
    # ★旧アプリ(3.7.1)はアニメスタンプ非対応。ANIMATION 型のまま渡すと展開/インストールに
    #   失敗する(=DL成功後「失敗しました」)。STATIC に固定し静止画として入れる。
    info["hasAnimation"] = False
    info["hasSound"] = False
    info["stickerResourceType"] = "STATIC"

    buf = io.BytesIO()
    n = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("productInfo.meta", json.dumps(
            info, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        present = set()
        for nm in src.namelist():
            if nm == "productInfo.meta" or nm in present:
                continue
            z.writestr(nm, src.read(nm))
            present.add(nm)
            n += 1
        # tab_off が本体zipに無い場合だけ tab_on から補う(二重登録を避ける)。
        # ★2026-09-05: @2x の zip に 1x の tab_off.png を混ぜていた。8/20 にDLが通った
        #   4.100.linestk は tab_off@2x.png / tab_on@2x.png の2つだけで 1x を持たない。
        #   余分な 1x を入れると展開後のインストールが通らないので解像度を揃える。
        for f in (("tab_on@2x.png",) if at2x else ("tab_on.png",)):
            dst = f.replace("tab_on", "tab_off")
            if dst in present:
                continue
            try:
                _, _, d = fetch(base + "/" + f)
                z.writestr(dst, d); present.add(dst)
            except Exception:
                pass
    blob = buf.getvalue()
    with open(cached, "wb") as f:
        f.write(blob)
    log(f"ZIP {pkg}: {name} を旧形式へ変換 ({len(blob)}B, 画像{n}枚)")
    return blob


def _parse_multipart(body, boundary):
    """/talk/m/upload.nhn の multipart/form-data から oid(=msgId) と Filedata 実体を取り出す。
    params パート = JSON {type,sid,name,oid,ver}、Filedata パート = メディア実体。"""
    oid = None
    filedata = b""
    sep = b"--" + boundary
    for part in body.split(sep):
        part = part.lstrip(b"\r\n")
        if not part or part[:2] == b"--":
            continue
        he = part.find(b"\r\n\r\n")
        if he < 0:
            continue
        headers = part[:he].decode("latin1", "replace")
        content = part[he + 4:]
        if content.endswith(b"\r\n"):
            content = content[:-2]
        if 'name="params"' in headers:
            try:
                oid = str(json.loads(content.decode("utf-8", "replace")).get("oid") or "") or None
            except Exception:
                pass
        elif 'name="Filedata"' in headers or "filename=" in headers:
            filedata = content
    return oid, filedata


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.headers.get("Content-Type", "application/octet-stream"), r.read()


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "legy-cdn"

    def log_message(self, *a):
        pass

    def do_POST(self):
        """/bridge/config は設定.appのペインからの設定反映。それ以外は
        実機からのメディアアップロード捕捉(送信の実装用)。"""
        if self.path.startswith("/bridge/config"):
            return self._bridge_config()
        if self.path.endswith("/rts_url.nhn"):
            return self._video_url()
        if self._is_cafeapi():
            return self._cafeapi("POST")
        return self._upload()

    def _video_url(self):
        """Legacy 3.7.1 video URL response backed by the local decrypted file."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        oid = str((form.get("oid") or [""])[0])
        exists = bool(oid and os.path.exists(media_path(oid, False)))
        if exists:
            # LINE 3.7.1 の +[NLObjectStorageRTSResponse RTSResponseFromJSON:]
            # はトップレベルの "video" を先に取り出し、その内側だけを読む。
            # URLのキーも streamingURL ではなく streamingUrl / downloadUrl。
            stream = f"{LEGACY_MEDIA_BASE}/os/m/{oid}"
            video = {
                "result": 0,
                "resultMessage": "success",
                # 3.7.1 はこれらをNSNumberではなくNSStringとして読み、
                # isEqualToString:@"true" で判定する。JSON boolだとSIGABRTする。
                "directPlayable": "true",
                "streamingUrl": stream,
                "downloadUrl": stream,
                "seekable": "true",
                "livemode": "false",
            }
        elif re.fullmatch(r"[A-Za-z0-9_-]{8,256}", oid or ""):
            # A timeline video has no local copy.  Playback only ever works
            # through serve_media (/os/m/<numeric id>), which answers Range
            # requests -- the player fetches 8KB first, then the rest.  Handing
            # it an external URL, or an id that is not numeric, gets ignored
            # silently.  So fetch the object once into the same media store the
            # talk videos use and hand back an ordinary /os/m/<id> URL.
            prefix = urllib.parse.urlsplit(self.path).path[:-len("/rts_url.nhn")]
            bucket = prefix.strip("/")
            if bucket == "cafe/p":
                service, namespace = _cafe_media_targets.get(
                    oid, ("privnote", "post"))
                bucket = service + "/" + namespace
            _rts_targets[oid] = bucket
            local_id = str(9000000000000000000 + (int(
                hashlib.sha1(oid.encode("utf-8")).hexdigest()[:15], 16) % 10 ** 17))
            target = media_path(local_id, False)
            captured = os.path.join(UPLOAD, oid + ".bin")
            if not os.path.exists(target):
                if os.path.exists(captured):
                    os.makedirs(MEDIA, exist_ok=True)
                    tmp = target + ".part"
                    shutil.copyfile(captured, tmp)
                    os.replace(tmp, target)
                    with open(target + ".json", "w", encoding="utf-8") as f:
                        json.dump({"contentType": 2, "oid": oid,
                                   "source": "cafe-upload",
                                   "plainSize": os.path.getsize(target)}, f)
                    log("RTS reused captured Cafe video")
                    _trim_rts_cache()
                else:
                    url = "https://obs.line-apps.com/r/%s/%s" % (bucket, oid)
                    try:
                        status, ctype, blob = fetch(url)
                    except Exception as exc:
                        status, ctype, blob = 0, "", b""
                        log("RTS fetch failed %r" % (exc,))
                    if status == 200 and blob:
                        os.makedirs(MEDIA, exist_ok=True)
                        tmp = target + ".part"
                        with open(tmp, "wb") as f:
                            f.write(blob)
                        os.replace(tmp, target)
                        with open(target + ".json", "w", encoding="utf-8") as f:
                            json.dump({"contentType": 2, "oid": oid,
                                       "source": url, "plainSize": len(blob)}, f)
                        log("RTS cached current Note video (%dB %s)"
                            % (len(blob), ctype))
                        _trim_rts_cache()
            exists = os.path.exists(target)
            stream = "%s/os/m/%s" % (LEGACY_MEDIA_BASE, local_id)
            video = {
                "result": 0,
                "resultMessage": "success",
                "directPlayable": "true",
                "streamingUrl": stream,
                "downloadUrl": stream,
                "seekable": "true",
                "livemode": "false",
            }
        else:
            video = {
                "result": -1,
                "resultMessage": "media not ready",
                "directPlayable": "false",
                "streamingUrl": "",
                "downloadUrl": "",
                "seekable": "false",
                "livemode": "false",
            }
        data = json.dumps({"video": video}, separators=(",", ":")).encode("utf-8")
        log(f"RTS oid={oid or '-'} ready={exists} ({len(data)}B)")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def _bridge_config(self):
        """設定.app の LINE Bridge ペインから送られてくる設定を bridge.conf に
        反映し、ブリッジを張り直す。端末単体版になればこの経路は不要になる。"""
        try:
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
        except Exception as e:
            log(f"CONFIG parse err {e!r}")
            self.send_response(400); self.send_header("Content-Length", "0"); self.end_headers()
            return
        conf_path = os.path.join(BASE, "bridge.conf")
        conf = {}
        try:
            if os.path.exists(conf_path):
                conf = json.load(open(conf_path, encoding="utf-8"))
        except Exception:
            conf = {}
        allowed = {"DESKTOPWIN", "IOSIPAD", "DESKTOPMAC", "CHROMEOS"}
        changed = False
        dt = req.get("device_type")
        if dt in allowed and dt != conf.get("device_type"):
            conf["device_type"] = dt
            changed = True
        with open(conf_path, "w", encoding="utf-8") as f:
            json.dump(conf, f, ensure_ascii=False, indent=1)
        log(f"CONFIG device_type={conf.get('device_type')} changed={changed}")
        if changed:
            # 種別が変わったらセッションを張り直す必要がある。
            # ★かつてはここで start_bridge.sh を叩いて CHRLINE 版 bridge_daemon を
            #   起こしていたが、その構成は廃止した。プロセス管理は systemd に任せ、
            #   ここでは再起動が要ることを伝えるだけにする。
            log("CONFIG 種別が変わった。ブリッジを再起動すること "
                "(systemctl restart line-legacy-linejs-bridge)")
        body = json.dumps({"ok": True, "device_type": conf.get("device_type"),
                           "restarted": False, "restart_required": changed}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _upload(self):
        """実機からのメディアアップロードを捕捉して保存する(送信の実装用)。
        旧アプリの OBS アップロード形式を実測するため、パスとヘッダも全部記録する。"""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        body = self.rfile.read(n) if n else b""
        os.makedirs(UPLOAD, exist_ok=True)
        # 実機は sendMessage で採番されたIDのパス /os/m/<msgid> へPOSTしてくる(写真)。
        # そのIDで保存すると bridge_daemon 側の送信キューと突き合わせられる。
        m = re.search(r"/os/m/(\d+)", self.path)
        key = None
        filedata = body
        # ★グループアイコン / プロフィール画像は OBS への直接アップロードで来る。
        #   実測(2026-09-07): グループは POST /os/g/<グループMID>、
        #   自分のプロフィールは POST /os/p/<自分のMID>。
        #   以前は "/talk/g/upload.nhn" だと思い込んでいたため一度も拾えていなかった。
        pg = re.search(r"/os/([pg])/([A-Za-z0-9_-]+)", self.path)
        if m:
            key = m.group(1)
        elif pg:
            key = pg.group(2)
        else:
            # ★音声/動画は /talk/m/upload.nhn へ multipart/form-data で来る。
            #   params パートの JSON に oid(=msgId)、Filedata パートに実体。
            ctype = self.headers.get("Content-Type", "")
            bnd = None
            mb = re.search(r"boundary=([^\s;]+)", ctype)
            if mb:
                bnd = mb.group(1).encode()
            elif body[:2] == b"--":
                bnd = body[2:body.find(b"\r\n")]
            if bnd:
                oid, fdata = _parse_multipart(body, bnd)
                if fdata:
                    filedata = fdata
                if oid:
                    key = oid
        if not key:
            key = str(int(time.time() * 1000))
        with open(os.path.join(UPLOAD, f"{key}.bin"), "wb") as f:
            f.write(filedata)
        hdrs = {k: v for k, v in self.headers.items()}
        with open(os.path.join(UPLOAD, f"{key}.json"), "w", encoding="utf-8") as f:
            json.dump({"path": self.path, "headers": hdrs, "size": len(filedata)},
                      f, ensure_ascii=False, indent=1)
        log(f"UPLOAD {self.headers.get('Host', '')}{self.path} {len(filedata)}B(raw {len(body)}) -> {key}.bin")
        # グループのアイコン変更は RPC ではなく <host>/talk/g/upload.nhn への
        # アップロードそのもの(oid=グループMID)。現行OBSは同じ置き方をしないので、
        # ブリッジ側で updateChatProfileImage をやり直させる。
        # 自分のプロフィール画像は POST /os/p/<自分のMID>。
        # 現行では updateProfileImage を呼び直さないと反映されない。
        if pg and pg.group(1) == "p":
            mid = key if re.fullmatch(r"u[0-9a-f]{32}", key or "") else None
            if mid:
                try:
                    with open(os.path.join(BASE, "send_queue.jsonl"), "a",
                              encoding="utf-8") as f:
                        f.write(json.dumps({
                            "kind": "group_cmd", "op": "set_profile_picture",
                            "id": "picon_%s_%d" % (mid, int(time.time() * 1000)),
                            "mid": mid,
                            "file": os.path.join(UPLOAD, f"{key}.bin"),
                            "ts": int(time.time() * 1000)}) + chr(10))
                    log(f"PROFILE ICON {mid} をブリッジへ委譲")
                except Exception as e:
                    log(f"PROFILE ICON キュー書き込み失敗 {e!r}")
            else:
                log(f"PROFILE ICON: MIDが取れない path={self.path}")
        if "/talk/g/upload.nhn" in self.path or "/os/g/" in self.path:
            gid = key if re.fullmatch(r"c[0-9a-f]{32}", key or "") else None
            if not gid:
                found = re.search(r"c[0-9a-f]{32}", self.path)
                gid = found.group(0) if found else None
            if gid:
                try:
                    with open(os.path.join(BASE, "send_queue.jsonl"), "a",
                              encoding="utf-8") as f:
                        f.write(json.dumps({
                            "kind": "group_cmd", "op": "set_picture",
                            "id": "gicon_%s_%d" % (gid, int(time.time() * 1000)),
                            "groupId": gid,
                            "file": os.path.join(UPLOAD, f"{key}.bin"),
                            "ts": int(time.time() * 1000)}) + chr(10))
                    log(f"GROUP ICON {gid} をブリッジへ委譲")
                except Exception as e:
                    log(f"GROUP ICON キュー書き込み失敗 {e!r}")
            else:
                log(f"GROUP ICON: グループMIDが取れない path={self.path}")
        # アップロード完了を legy_proxy へ知らせる。legy_proxy はこれを見て
        # SEND_CONTENT(op type 27) を配信し、アプリの送信状態を「送信済み」にする。
        # アイコン/プロフィール画像はメッセージ送信ではないので除外する。
        if pg:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        try:
            with open(os.path.join(BASE, "upload_done.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps({"id": key, "size": len(filedata),
                                    "ts": int(time.time() * 1000)}) + chr(10))
        except Exception as e:
            log(f"UPLOAD 完了通知の書き込み失敗 {e!r}")
        # 実機(ASIHTTPRequest)がエラー扱いすると sendStatus=4 のままになるので、
        # 素直な 200 + 空ボディ + 明示 close で返す。
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _notice(self, body_wanted=True):
        """openapis.jboard.navercorp.jp -- 「お知らせ」(NHN jboard SDK)。

        そのホストは現在 NXDOMAIN で、旧LINEの掲示板はもう存在しない。放置すると
        -[NoticeViewController] は errorCell(通信失敗)を出し続けるので、ここで
        SDK が期待する形の応答を返し、少なくとも「まだ表示できるお知らせが
        ありません。」の状態にする。notices.json を置けばその中身を出す。

        実機バイナリより:
          一覧 /mobile/board/<serviceId>/<lang>?page=&pageSize=&nc=&mcc=&format=json
               -> {"jboard": {"documents": [...], "pageSize": n, "total": n}}
          本文 /mobile/document/<serviceId>/<lang>/<documentId>?format=json
               -> {"jboard": {"document": {...}}}
          新着 /mobile/count/<serviceId>/<lang>/<t>?format=json
               -> {"result": {"info": n}}
        各 document は documentId / title / contents / createTime / modifyTime。
        """
        route = urllib.parse.urlsplit(self.path).path
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        notices = []
        try:
            notice_file = os.environ.get(
                "LINE_LEGACY_NOTICES_FILE", os.path.join(BASE, "notices.json"))
            with open(notice_file, encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, list):
                notices = [n for n in loaded if isinstance(n, dict)]
        except (OSError, ValueError):
            pass
        documents = []
        for index, notice in enumerate(notices):
            created = float(notice.get("createTime")
                            or notice.get("created") or time.time() * 1000)
            documents.append({
                "documentId": str(notice.get("documentId") or (index + 1)),
                "title": str(notice.get("title") or ""),
                "contents": str(notice.get("contents") or ""),
                "createTime": created,
                "modifyTime": float(notice.get("modifyTime") or created),
            })
        if route.startswith("/mobile/count/"):
            raw_since = route.rstrip("/").rsplit("/", 1)[-1]
            try:
                since = float(raw_since)
                if since < 100000000000:
                    since *= 1000
            except ValueError:
                since = time.time() * 1000
            # NJBBSNoticeManager first reads top-level "result", then sends
            # objectForKey:@"info" to that value.  A string here raises an
            # unrecognized-selector exception and terminates LINE 3.7.1.
            payload = {"result": {"info": sum(
                1 for document in documents
                if float(document.get("createTime") or 0) > since)}}
        elif route.startswith("/mobile/document/"):
            wanted = route.rstrip("/").rsplit("/", 1)[-1]
            found = next((d for d in documents if d["documentId"] == wanted), None)
            payload = {"jboard": {"document": found or {}}}
        else:
            try:
                size = max(1, min(100, int((query.get("pageSize") or ["20"])[0])))
                page = max(1, int((query.get("page") or ["1"])[0]))
            except ValueError:
                size, page = 20, 1
            payload = {"jboard": {"documents": documents[(page - 1) * size:page * size],
                                  "pageSize": size, "total": len(documents)}}
        blob = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        log(f"NOTICE {route} -> {len(documents)} 件 ({len(blob)}B)")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        if body_wanted:
            self.wfile.write(blob)

    def _send_blob(self, status, ctype, data, body_wanted=True):
        self.send_response(status if status in (200, 206) else 200)
        self.send_header("Content-Type", ctype or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if body_wanted:
            self.wfile.write(data)

    # 3.7.1 の「その他」タブに元から並んでいるボタン。
    # +[LineMoreManager homeItems]/[items] は本来これを内蔵で作るが、
    # **parseList: が成功すると同じグローバル([0xad9b50+8] と +0xc)を上書きする**
    # ので、list.json を返した時点で内蔵ボタンは消える。したがって
    # こちらで同じ内容を送り直さないと「その他」タブが空になる。
    # 値は LINE371_phone.bin の +[LineMoreItem new*Item] を逆アセンブルして確定
    # (itemWithId:version:type:subType:tabType:...:  r2=id r3=version
    #  sp+0=type sp+4=subType sp+8=tabType sp+0x10=url sp+0x1c=newFlagVersion)。
    # ★type は parseItemData: が +1 して格納する(実機 cycript で確認)ので、
    #   内蔵と同じ値にするには「内蔵の type - 1」を送る。
    # ★tabType は JSON から読まれない。moreTabList の ids の並び順で決まり、
    #   先頭3件が tabType=1(上段グリッド)、4件目以降が tabType=2(下のリスト)。
    #   (parseMoretabData: 0x3aee8a: cmp count,#2 / movhi 2 / movls 1)
    # ★タイトルも自分で送らないと空になる。内蔵は
    #   [[NSBundle mainBundle] localizedStringForKey:<key> value:@"" table:nil]
    #   を使うが、置き換えた項目にはそれが無い。実機の LINE.app/<lang>.lproj/
    #   Localizable.strings から抜いた値を moretab_titles.json に置いてある。
    #   id  ver type sub tab  url                     文言キー   ※type は送る値(=内蔵値-1)
    MORETAB_BUILTINS = (
        (4, 1, 0, 2, 1, "line://nv/addFriends/transitionStyle=crossDissolve", "addFriends."),
        (3, 1, 0, 1, 1, "line://nv/settings/transitionStyle=crossDissolve", "settings."),
        (1, 1, 1, 1, 1, "line://ch/1341209850", "home."),
        (2, 1, 0, 4, 2, "line://nv/stickerShop/transitionStyle=crossDissolve", "settings.stickers.shop"),
        (5, 1, 0, 5, 2, "line://nv/officialAccounts/transitionStyle=crossDissolve", "buddy.title"),
        (6, 1, 0, 3, 2, "line://nv/notifications/transitionStyle=crossDissolve", "settings.notice"),
    )
    _moretab_titles = None

    @classmethod
    def moretab_title(cls, lang, key):
        if cls._moretab_titles is None:
            try:
                with open(os.path.join(BASE, "moretab_titles.json"),
                          encoding="utf-8") as f:
                    cls._moretab_titles = json.load(f)
            except Exception:
                cls._moretab_titles = {}
        table = cls._moretab_titles
        for candidate in (lang, (lang or "").split("-")[0], "en"):
            if candidate and candidate in table and table[candidate].get(key):
                return table[candidate][key]
        return key

    def _moretab(self, body_wanted=True):
        """appresources.line.naver.jp/moretab/list.json -- 「その他」タブの一覧。

        ホストは NXDOMAIN(LINE が廃止)なのでここで組み立てる。契約は
        LINE371_phone.bin の逆アセンブルで確定した:

        - +[LineMoreManager parseList:] は
            data          -> parseItemData:            (項目そのもの)
            moreTabList   -> parseMoretabData:withItemData:
            categoryList  -> parseCategorylistData:withItemData:
            shortcutList  -> parseShortcutData:withItemData:
          で、**moreTabList/categoryList/shortcutList は data の項目を id で参照するだけ**。
          data が空なら何も作られない。
        - parseMoretabData: の結果を `tabType = 1` で絞ったものが homeItems、
          `tabType = 2` で絞ったものが items になる。
        - downloadListWithCountry:language: は **homeItems が 0 件だと成功フラグを
          立てずに lineMoreItemDownloadFailed を投げる** = 「サーバーへ接続できません」。
          ∴ 空の一覧を返すのは必ず失敗する。
        - 項目もタブも `spec` を持ち、`[LineMoreManager version:CFBundleVersion
          isBiggerThanOrEqualTo:spec]`(ドット区切りの数値比較)が偽なら捨てられる。
          実機の CFBundleVersion は "3.7.1"。
        - トップレベルの `version` が端末保存値(TalkUserDefaultManager
          moreListVersion)より大きくないと parseList: 自体が走らない。
        """
        # ★2026-09-08: ミニアプリの中身は復元不能と結論したので「黙って何もしない」。
        #   公式の一覧は appresources.line.naver.jp(NXDOMAIN)にも、後継の
        #   scdn.line-apps.com/appresources(origin 死亡・503)にも無く、Wayback にも
        #   スナップショットが1件も無い。並んでいたサービス自体も終了済み。
        #
        #   ここで**エラーを出さずに**引き下がる方法は downloadListWithCountry:language:
        #   の分岐で決まっている:
        #     0x3b2c24  [LineMoreManager version:CFBundleVersion
        #                isBiggerThanOrEqualTo:<トップレベル spec>] が偽
        #               -> 0x3b2e4e: r4=1 のまま終了(通知なし・パースもしない)
        #     一方 homeItems が 0 件だと 0x3b2e62 で r4=0 -> lineMoreItemDownloadFailed
        #               = 「サーバーへ接続できません」
        #   ∴ spec を実機の CFBundleVersion(3.7.1)より新しくしておけば、アプリは
        #   内蔵の homeItems/items(友だち追加・設定・ホーム / スタンプショップ・
        #   公式アカウント・お知らせ)をそのまま使い続ける。ラベルも内蔵の
        #   ローカライズ名なので正しく出る。
        #
        #   ※一度パースに成功していると端末の
        #     Library/Caches/More Tab Files/list/moreList が起動時に読まれるので、
        #     それも消す必要がある(2026-09-08 に削除済み)。
        payload = {
            "version": 0,
            "spec": "99.0.0",
            "interval": 3600,
            "data": [],
            "moreTabList": {},
            "categoryList": [],
            "shortcutList": [],
        }
        log("MORETAB -> 何もしない応答(spec=99.0.0)")
        blob = json.dumps(payload, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body_wanted:
            self.wfile.write(blob)
        self.close_connection = True

    @staticmethod
    def _solid_png(red, green, blue, width=80, height=80):
        """Create a tiny dependency-free PNG for legacy More-tab icons."""
        signature = b"\x89PNG\r\n\x1a\n"

        def chunk(kind, value):
            return (struct.pack(">I", len(value)) + kind + value +
                    struct.pack(">I", zlib.crc32(kind + value) & 0xffffffff))

        header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
        row = b"\x00" + bytes((red, green, blue)) * width
        return (signature + chunk(b"IHDR", header) +
                chunk(b"IDAT", zlib.compress(row * height, 9)) +
                chunk(b"IEND", b""))

    def _miniapp(self, body_wanted=True):
        """Small iOS-6-safe pages that link only to current official LINE sites."""
        route = urllib.parse.urlsplit(self.path).path
        log("MINIAPP request %s" % route)
        pages = {
            "/miniapp/guide": (
                "LINE公式ガイド",
                "LINEの基本操作や新機能を確認できます。",
                "https://guide.line.me/ja/"),
            "/miniapp/help": (
                "LINEヘルプ",
                "困ったときの対処方法と公式のお知らせを確認できます。",
                "https://help.line.me/line/smartphone/?lang=ja"),
            "/miniapp/news": (
                "LINE公式ニュース",
                "LINEアプリに関する公式発表を確認できます。",
                "https://www.lycorp.co.jp/ja/news/release/lineapp/"),
        }
        page = pages.get(route)
        if not page:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        title, description, official_url = page
        document = ("<!doctype html><html><head>"
                    "<meta charset=\"utf-8\"><meta name=\"viewport\" "
                    "content=\"width=device-width,initial-scale=1\">"
                    "<title>%s</title><style>body{font-family:-apple-system,"
                    "Helvetica,sans-serif;margin:18px;color:#222}h1{font-size:"
                    "22px}p{line-height:1.6}.button{display:block;padding:12px;"
                    "background:#06c755;color:white;text-decoration:none;"
                    "text-align:center;border-radius:7px}</style></head><body>"
                    "<h1>%s</h1><p>%s</p><a class=\"button\" href=\"%s\">"
                    "公式ページを開く</a><p><small>提供元: LINE / LINEヤフー"
                    "公式サイト</small></p></body></html>" % tuple(
                        html.escape(value, quote=True) for value in
                        (title, title, description, official_url)))
        blob = document.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body_wanted:
            self.wfile.write(blob)
        self.close_connection = True

    def _serve(self, body_wanted=True):
        if os.environ.get("MORETAB") == "1" and \
                urllib.parse.urlsplit(self.path).path == "/moretab/list.json":
            return self._moretab(body_wanted)
        if os.environ.get("MORETAB") == "1" and \
                urllib.parse.urlsplit(self.path).path.startswith("/miniapp/"):
            return self._miniapp(body_wanted)
        if os.environ.get("MORETAB") == "1" and \
                urllib.parse.urlsplit(self.path).path.startswith("/miniicon/"):
            log("MINIICON request %s" % urllib.parse.urlsplit(self.path).path)
            return self._send_blob(200, "image/png",
                                   self._solid_png(6, 199, 85), body_wanted)
        host = self.headers.get("Host", "")
        # Cafe videos reuse their object id for the thumbnail request. Current
        # privnote/post has no compatible old m592x* transform, so serve the
        # JPEG generated when 3.7.1 uploaded the movie.
        cafe_download = re.fullmatch(
            r"/cafe/p/download\.nhn", urllib.parse.urlsplit(self.path).path)
        if cafe_download:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            oid = str((query.get("oid") or [""])[0])
            with _cafe_note_lock:
                is_video = oid in _cafe_video_oids
            thumbnail_path = _ensure_cafe_video_thumbnail(oid) if is_video else None
            if thumbnail_path:
                with open(thumbnail_path, "rb") as source:
                    blob = source.read()
                log("CAFEAPI served video thumbnail")
                return self._send_blob(200, "image/jpeg", blob, body_wanted)
        # 8/20の実ダウンロード成功時と同じく未提供扱いにする。
        # 空JSONや合成manifestはupdatePackageMetadataを動かし、DL完了処理を変えてしまう。
        if re.search(r"/products/productVersions_\d+\.meta", self.path):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # product.zip は現行CDNに無いので素材から組み立てて返す
        mz = re.search(r"/products/\d+/\d+/\d+/(\d+)/[^/]+/(product|stickers|stickers@2x)\.zip",
                       self.path)
        if mz:
            kind = mz.group(2)
            if kind == "product":
                blob = build_product_zip(mz.group(1))
            else:
                blob = build_stickers_zip(mz.group(1), kind.endswith("@2x"))
            if blob:
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(blob)))
                self.end_headers()
                if body_wanted:
                    self.wfile.write(blob)
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
            return
        if urllib.parse.urlsplit(self.path).path.startswith("/mobile/"):
            return self._notice(body_wanted)
        # 受信メディア(/os/m/<msgid>)はローカルのファイルから返す。
        # op45 を受けたサムネイル取得は OBS 形式の /r/talk/m/<msgid>/preview で来る。
        if "/os/m/" in self.path or "/talk/m/" in self.path:
            if serve_media(self, self.path, body_wanted):
                return
        url = translate(host, self.path)
        if not url:
            log(f"MISS {host}{self.path}")
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            st, ctype, data = fetch(url)
        except urllib.error.HTTPError as e:
            # A size suffix that current OBS does not have (the default home
            # cover only exists at full size, for instance) answers 404.  Retry
            # once without it rather than losing the image altogether.
            retry = re.sub(r"/[A-Za-z0-9]{1,16}$", "", url) if e.code == 404 else None
            if retry and retry != url and "/r/" in retry:
                try:
                    st, ctype, data = fetch(retry)
                    log(f"FALLBACK {url} -> {retry} ({len(data)}B {ctype})")
                    self._send_blob(st, ctype, data, body_wanted)
                    return
                except Exception:
                    pass
            log(f"UPSTREAM {e.code} {url}")
            self.send_response(e.code)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        except Exception as e:
            log(f"ERR {e!r} {url}")
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        log(f"OK {host}{self.path} -> {url} ({len(data)}B {ctype})")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if body_wanted:
            self.wfile.write(data)

    def do_GET(self):
        # tauth.line.naver.jp/getToken/<service> -- 3.7.1 asks for an OBS access
        # token right before playing a timeline video (see -[NLMovieURLLoader
        # loadMovieWithOBSParameters:]).  Our relay reaches OBS without any
        # token, so the value only has to exist for playback to continue.
        if urllib.parse.urlsplit(self.path).path.startswith("/getToken"):
            return self._obs_token()
        if self._is_cafeapi():
            return self._cafeapi("GET")
        self._serve(True)

    def do_DELETE(self):
        if self._is_cafeapi():
            return self._cafeapi("DELETE")
        self.send_error(404)

    def _is_cafeapi(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host.endswith("cafeapi.line.naver.jp")

    def _cafeapi(self, method):
        """グループのボード(ノート) -- LINE Cafe SDK。

        3.7.1 は http://cafeapi.line.naver.jp へ平文HTTPで話す。ホスト自体が
        現行では消えているので、こちらで現行のグループノートへ中継する。
        旧 Cafe の cafe/board ID は廃止済みなので、X-Line-Group のグループMIDを
        両方の安定IDとして使う。これで旧SDKが次の要求を /(null)/posts/all に
        してしまうのを防ぎ、現行のグループノートへ繋げられる。
        """
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        body = self.rfile.read(n) if n else b""
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "method": method,
               "path": self.path,
               "headers": {k: v for k, v in self.headers.items()},
               "body": body.decode("utf-8", "replace")}
        try:
            with open(os.path.join(BASE, "cafeapi_requests.jsonl"), "a",
                      encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + chr(10))
        except Exception as e:
            log("CAFEAPI 記録失敗 %r" % (e,))
        log("CAFEAPI %s %s (%dB)" % (method, self.path, len(body)))
        route = urllib.parse.urlsplit(self.path).path
        try:
            request_json = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeError, json.JSONDecodeError):
            request_json = {}

        def request_value(*names):
            def walk(value):
                if not isinstance(value, dict):
                    return None
                for name in names:
                    if value.get(name) not in (None, ""):
                        return value.get(name)
                for child in value.values():
                    found = walk(child)
                    if found not in (None, ""):
                        return found
                return None
            return walk(request_json)
        group_mid = self.headers.get("X-Line-Group") or self.headers.get("X-Line-Cafe") or ""
        if group_mid == "0":
            group_mid = ""
        # cafe info の後の要求には X-Line-Group が無い場合があるので、URL内の
        # board/cafe ID（ここではグループMIDそのもの）から復元する。
        path_mid = re.search(r"/(c[0-9a-f]{32})(?:/|$)", route, re.I)
        if not group_mid and path_mid:
            group_mid = path_mid.group(1)
        # ★詳細画面の引っ張って再読み込みは X-Line-Group を付けず
        #   X-Line-Cafe: 0 で来る(実測 2026-09-08)。/post/<id>/slide/... は
        #   URL にもグループが入らないので、直前に確定したものを使う。
        #   これを 400 で返すと result が null になり、アプリが空の投稿を
        #   表示する(= unknown / 1970/1/1)。
        if not re.fullmatch(r"c[0-9a-f]{32}", group_mid or "", re.I):
            fallback = globals().get("_cafe_last_group") or ""
            if re.fullmatch(r"c[0-9a-f]{32}", fallback, re.I):
                log("CAFEAPI グループ未指定 -> 直前の %s を使う" % fallback)
                group_mid = fallback
        if re.fullmatch(r"c[0-9a-f]{32}", group_mid or "", re.I):
            globals()["_cafe_last_group"] = group_mid
        if not re.fullmatch(r"c[0-9a-f]{32}", group_mid or "", re.I):
            payload = {"code": 400, "message": "invalid group", "result": None}
        else:
            group_name = "LINE Group"
            try:
                with open(os.path.join(BASE, "groups.json"), encoding="utf-8") as source:
                    for item in json.load(source):
                        if item.get("id") == group_mid:
                            group_name = str(item.get("name") or group_name)
                            break
            except (OSError, ValueError, TypeError) as e:
                log("CAFEAPI groups load failed %r" % (e,))
            is_create = method == "POST" and route == "/post"
            is_write = is_create or method in ("POST", "DELETE")
            note_items = [] if is_write else cafe_note_items(group_mid)
            cafe = {
                "id": group_mid, "type": "GROUP", "name": group_name,
                "newFlag": False, "joined": True, "lineGroupId": group_mid,
                "cafeStatistics": {"postCount": len(note_items)},
            }
            board = {
                "id": group_mid, "status": "NORMAL", "type": "ALL",
                "cafe": cafe, "name": "ノート",
            }
            if is_create:
                try:
                    legacy_post = json.loads(body.decode("utf-8"))
                    result = cafe_create_note(group_mid, legacy_post)
                    payload = {"code": 0, "message": "success", "result": result}
                except (ValueError, TypeError, UnicodeError, json.JSONDecodeError) as e:
                    log("CAFEAPI create rejected %r" % (e,))
                    payload = {"code": 400, "message": str(e), "result": None}
                except Exception as e:
                    log("CAFEAPI create failed %r" % (e,))
                    payload = {"code": 500, "message": "group note create failed",
                               "result": None}
            elif re.fullmatch(r"/cafe/(?:0|c[0-9a-f]{32})", route, re.I):
                # LCClient didReceiveCafeInfoResult reads these exact keys.
                payload = {"code": 0, "message": "success", "result": {
                    "cafe": cafe, "boards": [board],
                    "postDefaultBoard": {"id": group_mid},
                    "linkableUserRegularExpressions": [],
                }}
            elif re.fullmatch(r"/c[0-9a-f]{32}/boards", route, re.I):
                payload = {"code": 0, "message": "success",
                           "result": {"items": [board]}}
            elif re.fullmatch(r"/c[0-9a-f]{32}/posts/all", route, re.I):
                payload = {"code": 0, "message": "success",
                           "result": {"items": note_items, "nextCursor": None}}
            elif re.fullmatch(r"/post/[0-9]+/slide/[A-Z]+", route):
                post_id = route.split("/")[2]
                item = cafe_note_item_by_id(group_mid, post_id)
                if item:
                    if int(item.get("commentCount") or 0) > 0:
                        try:
                            comment_result = cafe_comments(group_mid, post_id, 20)
                            item["comments"] = comment_result.get("items") or []
                            item["commentReplyTotalCount"] = int(
                                comment_result.get("commentReplyTotalCount") or
                                len(item["comments"]))
                        except Exception as e:
                            log("CAFEAPI detail comments unavailable %r" % (e,))
                    if int(item.get("likeCount") or 0) > 0:
                        try:
                            like_result = cafe_likes(group_mid, post_id)
                            item["likeUsers"] = like_result.get("items") or []
                        except Exception as e:
                            log("CAFEAPI detail likes unavailable %r" % (e,))
                    # Do not serialize absent legacy objects as JSON null.
                    # LINE 3.7.1 checks only for Objective-C nil.  NSNull is
                    # non-nil, so it sends objectForKey: to NSNull and aborts
                    # the reload, leaving its unknown/1970 placeholder.
                    slide_result = {"item": item}
                    comments = item.get("comments") or []
                    if comments:
                        slide_result["lastestComment"] = comments[-1]
                    payload = {"code": 0, "message": "success",
                               "result": slide_result}
                else:
                    payload = {"code": 404, "message": "post not found",
                               "result": None}
            elif method == "GET" and re.fullmatch(r"/[0-9]+/comments", route):
                post_id = route.split("/")[1]
                limit = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(self.path).query).get("fetchSize", [20])[0]
                try:
                    result = cafe_comments(group_mid, post_id, limit)
                    payload = {"code": 0, "message": "success", "result": result}
                except Exception as e:
                    log("CAFEAPI comments failed %r" % (e,))
                    payload = {"code": 500, "message": "comments unavailable",
                               "result": None}
            elif method == "POST" and route == "/comment":
                post_dict = request_json.get("post") if isinstance(request_json, dict) else {}
                post_id = str(request_value("postId", "contentId") or
                              (post_dict.get("id") if isinstance(post_dict, dict) else "") or "")
                text_value = str(request_value("text", "commentText") or "")
                if not re.fullmatch(r"[0-9]+", post_id):
                    payload = {"code": 400, "message": "invalid comment target",
                               "result": None}
                elif not text_value.strip():
                    payload = {"code": 400, "message": "empty comment",
                               "result": None}
                else:
                    try:
                        result = cafe_create_comment(group_mid, post_id, text_value)
                        payload = {"code": 0, "message": "success", "result": result}
                    except Exception as e:
                        log("CAFEAPI comment create failed %r" % (e,))
                        payload = {"code": 500, "message": "comment create failed",
                                   "result": None}
            elif method == "POST" and route == "/reply":
                post_dict = request_json.get("post") if isinstance(request_json, dict) else {}
                parent_dict = (request_json.get("parentComment")
                               if isinstance(request_json, dict) else {})
                post_id = str(request_value("postId", "contentId") or
                              (post_dict.get("id") if isinstance(post_dict, dict) else "") or "")
                parent_id = str(request_value("parentCommentId", "commentId") or
                                (parent_dict.get("id") if isinstance(parent_dict, dict) else "") or "")
                text_value = str(request_value("text", "commentText") or "")
                if not re.fullmatch(r"[0-9]+", post_id) or not re.fullmatch(r"[0-9]+", parent_id):
                    payload = {"code": 400, "message": "invalid reply target",
                               "result": None}
                elif not text_value.strip():
                    payload = {"code": 400, "message": "empty reply",
                               "result": None}
                else:
                    try:
                        result = cafe_create_comment(
                            group_mid, post_id, text_value, parent_id)
                        payload = {"code": 0, "message": "success", "result": result}
                    except Exception as e:
                        log("CAFEAPI reply create failed %r" % (e,))
                        payload = {"code": 500, "message": "reply create failed",
                                   "result": None}
            elif method == "DELETE" and re.fullmatch(r"/comment/[0-9]+", route):
                comment_id = route.rsplit("/", 1)[-1]
                try:
                    result = cafe_delete_comment(group_mid, comment_id)
                    payload = {"code": 0, "message": "success", "result": result}
                except Exception as e:
                    log("CAFEAPI comment delete failed %r" % (e,))
                    payload = {"code": 500, "message": "comment delete failed",
                               "result": None}
            elif method == "GET" and re.fullmatch(r"/[0-9]+/likes", route):
                post_id = route.split("/")[1]
                try:
                    result = cafe_likes(group_mid, post_id)
                    payload = {"code": 0, "message": "success", "result": result}
                except Exception as e:
                    log("CAFEAPI likes failed %r" % (e,))
                    payload = {"code": 500, "message": "likes unavailable",
                               "result": None}
            elif method == "POST" and re.fullmatch(r"/like/[0-9]+", route):
                post_id = route.rsplit("/", 1)[-1]
                try:
                    result = cafe_set_like(group_mid, post_id, True)
                    payload = {"code": 0, "message": "success", "result": result}
                except Exception as e:
                    log("CAFEAPI like create failed %r" % (e,))
                    payload = {"code": 500, "message": "like create failed",
                               "result": None}
            elif method == "DELETE" and re.fullmatch(r"/like/[0-9]+", route):
                post_id = route.rsplit("/", 1)[-1]
                try:
                    result = cafe_set_like(group_mid, post_id, False)
                    payload = {"code": 0, "message": "success", "result": result}
                except Exception as e:
                    log("CAFEAPI like delete failed %r" % (e,))
                    payload = {"code": 500, "message": "like delete failed",
                               "result": None}
            else:
                payload = {"code": 404, "message": "unsupported cafe route",
                           "result": None}
        data = json.dumps(payload, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        try:
            res = payload.get("result")
            if isinstance(res, dict):
                shape = "dict keys=%s" % sorted(res.keys())
                item = res.get("item")
                if isinstance(item, dict):
                    shape += " item.created=%r item.owner=%r" % (
                        item.get("created"),
                        (item.get("owner") or {}).get("name"))
                elif "item" in res:
                    shape += " item=%r" % (item,)
            else:
                shape = repr(res)[:80]
            log("CAFEAPI-RESP %s code=%s %dB %s"
                % (self.path[:70], payload.get("code"), len(data), shape))
        except Exception as e:
            log("CAFEAPI-RESP log err %r" % (e,))
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def _obs_token(self):
        service = urllib.parse.urlsplit(self.path).path.rsplit("/", 1)[-1] or "myhome"
        token = hashlib.sha1(
            ("legy-obs-" + service + str(int(time.time()) // 3600))
            .encode("utf-8")).hexdigest()
        # The completion block parses this as JSON, takes result, and installs
        # it as the "tat" cookie before fetching the movie.  Plain text makes
        # objectFromJSONString return nil and playback stops right there.
        data = json.dumps({"result": token}, separators=(",", ":")).encode("utf-8")
        log("OBS-TOKEN %s -> %dB" % (service, len(data)))
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def do_HEAD(self):
        self._serve(False)


def serve(port, certfile=None):
    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile)
        try:                       # iOS6 は TLS1.2 まで。古い暗号スイートを許可する
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, AttributeError):
            pass
        for c in ("ALL:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0", "ALL"):
            try:
                ctx.set_ciphers(c)
                break
            except ssl.SSLError:
                continue
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    log(f"cdn_proxy listening on :{port}{' (TLS)' if certfile else ''}")
    srv.serve_forever()


if __name__ == "__main__":
    load_pictures()
    # 引数: <http_port> [https_port] [certfile]
    # アイコン(os.line.naver.jp)は **HTTPS(443)** で取りに来る(バイナリ内に
    # https://os.line.naver.jp:443/ がある)。証明書の SAN に *.line.naver.jp が
    # 含まれるので legy_proxy と同じ server.pem がそのまま使える。
    http_port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    https_port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    cert = sys.argv[3] if len(sys.argv) > 3 else os.path.join(BASE, "server.pem")
    if https_port and os.path.exists(cert):
        threading.Thread(target=serve, args=(https_port, cert), daemon=True).start()
    elif https_port:
        log(f"cert not found: {cert} (HTTPSは起動しない)")
    serve(http_port)
