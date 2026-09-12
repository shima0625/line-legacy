"""Translate LINE 3.7.1 MyHome/Timeline REST calls to current Home APIs."""
import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import subprocess
import threading
import time
import urllib.parse

import legacy_friend_add


_lock = threading.RLock()
_completed = {}
_MAX_BODY = 128 * 1024
_MAX_RESPONSE = 4 * 1024 * 1024
_MAX_TEXT_CHARS = 10000
_HOME_CHANNEL_ID = "1341209850"
_TIMELINE_CHANNEL_ID = "1341209950"
_STATE_DIR = os.environ.get("ARTIFACTS_DIR") or os.environ.get("LINE_LEGACY_HOME") or os.path.dirname(__file__)
_TIMELINE_PICTURES = os.path.join(_STATE_DIR, "timeline_pictures.json")
_INCLUDE_RECOMMENDED = os.environ.get("TIMELINE_INCLUDE_RECOMMENDED", "0") == "1"


def _rpc_seq():
    """Return a cross-process-resistant positive i32 Thrift sequence ID."""
    return int(time.time_ns() & 0x7fffffff) or 1


def _json(code, message, result=None):
    return json.dumps({"code": code, "message": message, "result": result},
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _one(values, *names):
    for name in names:
        value = values.get(name)
        if isinstance(value, list):
            value = value[0] if value else None
        if value is not None:
            return str(value)
    return None


def _parse_values(path, headers, body):
    values = dict(urllib.parse.parse_qs(
        urllib.parse.urlsplit(path).query, keep_blank_values=True))
    if not body:
        return values
    if len(body) > _MAX_BODY:
        raise ValueError("Legacy Timeline request is too large")
    content_type = next((v for k, v in headers.items()
                         if k.lower() == "content-type"), "")
    if "json" in content_type.lower():
        decoded = json.loads(body.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("Legacy Timeline JSON is not an object")
        values.update(decoded)
    else:
        values.update(urllib.parse.parse_qs(
            body.decode("utf-8"), keep_blank_values=True))
    return values


def _as_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, str):
        return value
    raise ValueError("Expected text")


def _uuid_from_digest(digest):
    return (digest[:8] + "-" + digest[8:12] + "-" + digest[12:16]
            + "-" + digest[16:20] + "-" + digest[20:32])


def _issue_home_token(g, primary_token, seq):
    result, _ = legacy_friend_add.rpc(
        g, primary_token, "approveChannelAndIssueChannelToken", "/CH4",
        g["_tc_str"](1, _HOME_CHANNEL_ID), seq)
    channel = result.get(0)
    if not channel or channel[0] != 12:
        raise ValueError("Home channel token was rejected")
    # ChannelToken.channelAccessToken is field 5; field 1 is rejected here.
    value = channel[1].get(5)
    if not value or value[0] != 8:
        raise ValueError("Home channel access token is missing")
    token = _as_text(value[1])
    if not token or len(token) > 8192:
        raise ValueError("Invalid Home channel access token")
    return token


def _issue_timeline_token(g, primary_token, seq):
    result, _ = legacy_friend_add.rpc(
        g, primary_token, "approveChannelAndIssueChannelToken", "/CH4",
        g["_tc_str"](1, _TIMELINE_CHANNEL_ID), seq)
    channel = result.get(0)
    if not channel or channel[0] != 12:
        raise ValueError("Timeline channel token was rejected")
    value = channel[1].get(5)
    if not value or value[0] != 8:
        raise ValueError("Timeline channel access token is missing")
    token = _as_text(value[1])
    if not token or len(token) > 8192:
        raise ValueError("Invalid Timeline channel access token")
    return token


def _current_request(g, primary_token, method, path, payload=None,
                     timeline_channel=False):
    if not primary_token:
        raise ValueError("Bridge account token is unavailable")
    g["maybe_reload_profile"]()
    mid = g["bridge_mid"]()
    if not isinstance(mid, str) or not re.fullmatch(r"u[0-9a-f]{32}", mid):
        raise ValueError("Current profile MID is unavailable")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": g["bridge_user_agent"](),
        "X-Line-Application": g["bridge_app_string"](),
        "X-Line-Mid": mid,
        "X-Line-Access": primary_token,
        "X-Line-ChannelToken": (
            _issue_timeline_token(g, primary_token, _rpc_seq())
            if timeline_channel else
            _issue_home_token(g, primary_token, _rpc_seq())),
        "X-Line-BDBTemplateVersion": "v1",
        "X-Line-Global-Config":
            "discover.enable=true; follow.enable=true; reboot.phase=scenario",
        "X-LAL": "ja_JP",
        "X-LSR": "JP",
        "X-LPV": "1",
        "X-LHM": method,
    }
    body = None if payload is None else json.dumps(
        payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    conn = http.client.HTTPSConnection(
        "gw.line.naver.jp", timeout=20, context=ssl.create_default_context())
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read(_MAX_RESPONSE + 1)
        if response.status != 200 or len(data) > _MAX_RESPONSE:
            raise ValueError("Current Home HTTP request failed")
        decoded = json.loads(data.decode("utf-8"))
        if not isinstance(decoded, dict) or decoded.get("code") != 0:
            raise ValueError("Current Home API rejected: code=%r message=%r" %
                             (decoded.get("code") if isinstance(decoded, dict) else None,
                              decoded.get("message") if isinstance(decoded, dict) else None))
        return decoded
    finally:
        conn.close()


def _json_from_current(current):
    return _json(current.get("code", 0), current.get("message", "success"),
                 current.get("result"))


def _list(g, path, primary_token):
    values = _parse_values(path, {}, b"")
    g["maybe_reload_profile"]()
    home_id = _one(values, "userMid", "homeId") or g["PROFILE"].get(1)
    if not isinstance(home_id, str) or not re.fullmatch(r"[us][0-9a-f]{32}", home_id):
        raise ValueError("Invalid Home ID")
    query = urllib.parse.urlencode({
        "homeId": home_id,
        "sourceType": _one(values, "sourceType") or "TIMELINE",
        "postLimit": _one(values, "postLimit") or "20",
        "likeLimit": _one(values, "likeSize", "likeLimit") or "6",
        "commentLimit": _one(values, "commentSize", "commentLimit") or "2",
    })
    current = _current_request(
        g, primary_token, "GET", "/mh/api/v57/post/list.json?" + query)
    result = current.get("result") or {}
    route = urllib.parse.urlsplit(path).path
    if route == "/api/v1_6/myhome/get.json":
        # v1_6 expects the Home object directly; v57 nests it in homeInfo.
        home = result.get("homeInfo") if isinstance(result, dict) else None
        if not isinstance(home, dict):
            home = {}
        user = home.get("userInfo") if isinstance(home.get("userInfo"), dict) else {}
        mid = user.get("mid") or user.get("userMid") or home.get("homeId") or home_id
        display_name = (user.get("nickname") or user.get("displayName") or
                        home.get("nickname") or home.get("displayName") or
                        g["PROFILE"].get(20) or "LINE")
        picture_status = (user.get("pictureStatus") or home.get("pictureStatus") or
                          g["PROFILE"].get(22) or "")
        picture_url = (user.get("pictureUrl") or user.get("profileImageUrl") or
                       home.get("pictureUrl") or home.get("profileImageUrl") or "")
        if not picture_url and picture_status:
            picture_url = "https://profile.line-scdn.net/%s/large" % picture_status
        # LINE 3.7.1 reads these values directly from the Home object, while
        # current Home nests them under userInfo.
        home.update({
            "homeId": mid, "userMid": mid, "mid": mid,
            "displayName": str(display_name), "nickname": str(display_name),
            "pictureStatus": str(picture_status),
            "pictureUrl": str(picture_url),
            "profileImageUrl": str(picture_url),
        })
        # Do not strip objectId even when the cover is a placeholder:
        # -[MBMyhome coverImageURLWithMyhomeInfo:] requires it and throws
        # without it, which crashes the app on a background queue.  A 404 on
        # myhome/c/download.nhn is harmless by comparison.
        if isinstance(mid, str) and isinstance(picture_url, str) and picture_url.startswith("https://"):
            try:
                pictures = {}
                try:
                    with open(_TIMELINE_PICTURES, encoding="utf-8") as f:
                        loaded = json.load(f)
                    if isinstance(loaded, dict):
                        pictures.update(loaded)
                except (OSError, ValueError):
                    pass
                pictures[mid] = picture_url
                tmp = _TIMELINE_PICTURES + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(pictures, f, ensure_ascii=False, separators=(",", ":"))
                os.replace(tmp, _TIMELINE_PICTURES)
            except OSError as exc:
                g["log"]("  [timeline-rest] home picture map write failed: %r" % exc)
        return _json(0, "success", home)
    raise ValueError("Unexpected Home route for the myhome/get handler")


_probe_cache = {}


def _probed_size(object_id):
    """Pixel size of a video we uploaded, read back from the stored file.

    Current OBS does not report width/height for videos we pushed, and a
    zero-sized media collapses the cell in 3.7.1 -- no thumbnail, misplaced
    play button.  Our own uploads are still in upload/, so ffprobe can答える.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", object_id or ""):
        return None
    if object_id in _probe_cache:
        return _probe_cache[object_id]
    size = None
    path = os.path.join(_UPLOAD_DIR, object_id + ".bin")
    if os.path.exists(path):
        try:
            out = subprocess.run(
                ["ffprobe", "-v", "error", "-select_streams", "v:0",
                 "-show_entries", "stream=width,height", "-of", "csv=p=0", path],
                capture_output=True, timeout=30,
                check=False).stdout.decode("ascii", "ignore")
            parts = [p for p in re.split(r"[,\s]+", out.strip()) if p.isdigit()]
            if len(parts) >= 2 and int(parts[0]) > 0:
                size = (int(parts[0]), int(parts[1]))
        except (OSError, subprocess.SubprocessError, ValueError):
            size = None
    _probe_cache[object_id] = size
    return size


def _collect_posts(value, out):
    """Collect every current-format post object inside a v57 response."""
    if isinstance(value, dict):
        if (isinstance(value.get("postInfo"), dict)
                and isinstance(value.get("contents"), dict)):
            out.append(value)
            return
        for child in value.values():
            _collect_posts(child, out)
    elif isinstance(value, list):
        for child in value:
            _collect_posts(child, out)


def _legacy_location(contents):
    """The single location a post carries, as -[MBLocation initWithLocationInfo:]
    reads it: name / latitude / longitude."""
    for entry in (contents.get("locations") or []):
        if not isinstance(entry, dict):
            continue
        try:
            latitude = float(entry.get("latitude"))
            longitude = float(entry.get("longitude"))
        except (TypeError, ValueError):
            continue
        return {"name": str(entry.get("name") or ""),
                "latitude": latitude, "longitude": longitude}
    return None


def _legacy_stickers(contents):
    """Stickers in the shape 3.7.1 stores them."""
    stickers = []
    for entry in (contents.get("stickers") or [])[:4]:
        if not isinstance(entry, dict) or entry.get("id") is None:
            continue
        stickers.append({
            "stickerNo": int(entry.get("stickerNo") or 0),
            "id": str(entry.get("id")),
            "packageId": str(entry.get("packageId") or ""),
            "packageVersion": int(entry.get("packageVersion") or 1),
            "width": int(entry.get("width") or 0),
            "height": int(entry.get("height") or 0),
            "hasAnimation": bool(entry.get("hasAnimation")),
            "hasSound": bool(entry.get("hasSound")),
        })
    return stickers


def _legacy_post(post):
    """Convert one current post into the 3.7.1 MyHome post model.

    Keys verified against -[MBActivity setupWithMyhomeInfo:] and the content
    classes in the shipping 3.7.1 binary (LINE371_phone.bin):
    postId / postType / userMid / createdDate / updatedDate / liked /
    likeCount / commentCount / commentLikeValid / likes / comments / status,
    plus body (MBTextLocation) and medias (MBPhotos, MBMovie).

    postType decides everything: it becomes the activityType that
    MBActivityContentMap contentTypesForActivityType: looks up, and an
    unknown value renders MBUnknownContentView, i.e. the "please update your
    LINE app" placeholder instead of the post.  createdDate goes through
    longLongValue / 1000, so it has to stay in milliseconds.
    """
    info = post.get("postInfo") or {}
    user = post.get("userInfo") or {}
    contents = post.get("contents") or {}
    post_id = str(info.get("postId") or "")
    user_mid = (user.get("mid") or user.get("writerMid")
                or info.get("homeId"))
    if not post_id or not isinstance(user_mid, str):
        return None
    try:
        created = int(info.get("createdTime"))
    except (TypeError, ValueError):
        created = int(time.time() * 1000)
    try:
        updated = int(info.get("updatedTime"))
    except (TypeError, ValueError):
        updated = created
    medias = []
    for item in (contents.get("media") or [])[:9]:
        if not isinstance(item, dict) or not item.get("objectId"):
            continue
        kind = str(item.get("type") or "").upper()
        if kind in ("IMAGE", "PHOTO"):
            kind = "PHOTO"
        elif kind != "VIDEO":
            continue
        width = int(item.get("width") or 0)
        height = int(item.get("height") or 0)
        if width <= 0 or height <= 0:
            probed = _probed_size(str(item.get("objectId")))
            if probed:
                width, height = probed
        medias.append({
            "type": kind,
            "objectId": str(item.get("objectId")),
            "serviceName": str(item.get("serviceName") or "myhome"),
            "obsNamespace": str(item.get("obsNamespace") or "hex"),
            "width": width,
            "height": height,
        })
    # postType is a number, not a string: -[MBActivity setupWithMyhomeInfo:]
    # takes its intValue and runs it through activityTypeWithTypeNumber:,
    # whose jump table maps 1000/1002 -> TEXT, 1001/1003 -> PHOTO and
    # 1008/1010 -> VIDEO.  Anything it does not know becomes activityType 0,
    # which the cell renders as MBUnknownContentView ("please update").
    if any(m["type"] == "VIDEO" for m in medias):
        post_type = 1008
    elif medias:
        post_type = 1001
    else:
        post_type = 1000
    location = _legacy_location(contents)
    stickers = _legacy_stickers(contents)
    if stickers:
        post_type = 1004
    body = contents.get("text")
    if not isinstance(body, str):
        body = ""
    if not body.strip() and not medias and not location and not stickers:
        body = "［投稿］"
    extra = {}
    if location:
        extra["location"] = location
    if stickers:
        extra["stickers"] = stickers
    # -[MBActivity setupWithMyhomeInfo:] builds the comment and like lists from
    # these, so returning empty arrays means a post never shows its comments.
    comments = []
    for entry in (post.get("comments") or [])[:20]:
        if isinstance(entry, dict):
            comment = _legacy_comment(entry)
            if comment is not None:
                comments.append(comment)
    likes = []
    for entry in (post.get("likes") or [])[:20]:
        if isinstance(entry, dict):
            like = _legacy_like(entry)
            if like is not None:
                likes.append(like)
    return {
        "postId": post_id,
        "postType": post_type,
        "serviceName": "myhome",
        "status": str(info.get("status") or "NORMAL"),
        "userMid": user_mid,
        "createdDate": created,
        "updatedDate": updated,
        "body": body,
        "liked": bool(info.get("liked")),
        "likeCount": int(info.get("likeCount") or 0),
        "commentCount": int(info.get("commentCount") or 0),
        "commentLikeValid": True,
        "medias": medias,
        "likes": likes,
        "comments": comments,
        **extra,
    }


def _home_post_list(g, path, primary_token):
    """GET /api/v1_6/post/list.json -- the Home tab's own post list.

    -[MBMyhomeManager handleUpdate:] reads result.total, result.hasPrevious
    and result.list, then builds one MBPost per list entry.  It never looks
    at activityList, which is why the Timeline shape left Home empty.
    """
    values = _parse_values(path, {}, b"")
    g["maybe_reload_profile"]()
    home_id = _one(values, "userMid", "homeId") or g["PROFILE"].get(1)
    if not isinstance(home_id, str) or not re.fullmatch(r"[us][0-9a-f]{32}", home_id):
        raise ValueError("Invalid Home ID")
    query = urllib.parse.urlencode({
        "homeId": home_id,
        "sourceType": "MYHOME",
        "postLimit": _one(values, "postLimit") or "20",
        "likeLimit": _one(values, "likeSize", "likeLimit") or "6",
        "commentLimit": _one(values, "commentSize", "commentLimit") or "2",
    })
    current = _current_request(
        g, primary_token, "GET", "/mh/api/v57/post/list.json?" + query)
    found = []
    _collect_posts(current.get("result") or {}, found)
    posts = []
    seen = set()
    for post in found:
        legacy = _legacy_post(post)
        if legacy is None or legacy["postId"] in seen:
            continue
        seen.add(legacy["postId"])
        posts.append(legacy)
    g["log"]("  [timeline-rest] home post/list -> %d post(s)" % len(posts))
    return _json(0, "success", {
        "total": len(posts), "hasPrevious": False, "list": posts})


def _post_get(g, path, primary_token):
    """GET /api/v1_6/post/get.json -- one post, opened from Home or Timeline."""
    values = _parse_values(path, {}, b"")
    g["maybe_reload_profile"]()
    post_id = _one(values, "postId", "postID", "id")
    if not post_id or not re.fullmatch(r"[0-9]{1,32}", post_id):
        raise ValueError("Invalid post ID")
    home_id = _one(values, "userMid", "homeId") or g["PROFILE"].get(1)
    if not isinstance(home_id, str) or not re.fullmatch(r"[us][0-9a-f]{32}", home_id):
        raise ValueError("Invalid Home ID")
    query = urllib.parse.urlencode({
        "homeId": home_id, "postId": post_id,
        "likeLimit": _one(values, "likeSize", "likeLimit") or "6",
        "commentLimit": _one(values, "commentSize", "commentLimit") or "10",
    })
    current = _current_request(
        g, primary_token, "GET", "/mh/api/v57/post/get.json?" + query)
    found = []
    _collect_posts(current.get("result") or {}, found)
    post = _legacy_post(found[0]) if found else None
    g["log"]("  [timeline-rest] post/get %s -> %s" %
             (post_id, "ok" if post else "not found"))
    if post is None:
        raise ValueError("Post was not found upstream")
    return _json(0, "success", post)


_AUTOOPEN_PATH = os.path.join(_STATE_DIR, "timeline_autoopen.json")


def _autoopen(g, path, headers, body, update):
    """GET/POST /mapi/v4/contact/autoopen -- "open to new friends" toggle.

    -[MBHiddenManager requestAutoOpen] only reads result.autoOpen as a bool.
    The value is kept here rather than pushed to the live account, so opening
    the settings screen cannot silently change what the current app does.
    """
    stored = False
    try:
        with open(_AUTOOPEN_PATH, encoding="utf-8") as f:
            stored = bool(json.load(f).get("autoOpen"))
    except (OSError, ValueError):
        pass
    if update:
        values = _parse_values(path, headers, body)
        raw = _one(values, "autoOpen", "autoopen", "value", "enable")
        if isinstance(raw, str):
            stored = raw.strip().lower() in ("1", "true", "y", "yes", "on")
        try:
            tmp = _AUTOOPEN_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"autoOpen": stored}, f)
            os.replace(tmp, _AUTOOPEN_PATH)
        except OSError as exc:
            g["log"]("  [timeline-rest] autoOpen save failed: %r" % exc)
    g["log"]("  [timeline-rest] autoOpen%s -> %s"
             % (" update" if update else "", stored))
    return _json(0, "success", {"autoOpen": stored})


_CONTACT_LISTS_PATH = os.path.join(_STATE_DIR, "timeline_contact_lists.json")


def _contact_list(g, path, headers, body, name, add=None):
    """The hide / block lists behind the Timeline privacy screens.

    -[MBHiddenManager requestHideList] reads result via the key path
    "contacts.id", so the body is {"contacts": [{"id": "u…"}, …]}.  The lists
    live here rather than on the live account: the legacy screens should not
    silently change who the current app hides or blocks.
    """
    lists = {}
    try:
        with open(_CONTACT_LISTS_PATH, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            lists = loaded
    except (OSError, ValueError):
        pass
    members = [m for m in (lists.get(name) or []) if isinstance(m, str)]
    if add is not None:
        values = _parse_values(path, headers, body)
        raw = values.get("contactIds") or values.get("ids") or values.get("id")
        if isinstance(raw, str):
            raw = [raw]
        targets = [str(v) for v in (raw or [])
                   if re.fullmatch(r"u[0-9a-f]{32}", str(v))]
        for target in targets:
            if add and target not in members:
                members.append(target)
            elif not add and target in members:
                members.remove(target)
        lists[name] = members
        try:
            tmp = _CONTACT_LISTS_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(lists, f, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, _CONTACT_LISTS_PATH)
        except OSError as exc:
            g["log"]("  [timeline-rest] %s list save failed: %r" % (name, exc))
    g["log"]("  [timeline-rest] %s list%s -> %d entry(ies)"
             % (name, "" if add is None else " update", len(members)))
    return _json(0, "success", {"contacts": [{"id": m} for m in members]})


def _target_ids(g, values):
    """Map 3.7.1's (activityExternalId, actorId) onto (contentId, homeId).

    3.7.1 sends the post as activityExternalId and its owner as actorId; the
    current API calls those contentId and homeId, and keeps actorId for the
    person doing the liking or commenting -- us.
    """
    content_id = _one(values, "activityExternalId", "contentId", "postId")
    if not content_id or not re.fullmatch(r"[0-9]{1,32}", content_id):
        raise ValueError("Invalid content ID")
    g["maybe_reload_profile"]()
    self_mid = g["PROFILE"].get(1)
    if not isinstance(self_mid, str) or not re.fullmatch(r"u[0-9a-f]{32}", self_mid):
        raise ValueError("Current profile MID is unavailable")
    home_id = _one(values, "actorId", "homeId", "userMid") or self_mid
    if not re.fullmatch(r"[us][0-9a-f]{32}", home_id):
        home_id = self_mid
    return content_id, home_id, self_mid


def _legacy_like(entry):
    """One entry of the legacy userList, per -[MBLike initWithLikeInfo:parent:]."""
    user = entry.get("userInfo") or entry.get("actor") or {}
    actor = user.get("mid") or user.get("writerMid") or entry.get("actorId")
    if not isinstance(actor, str):
        return None
    try:
        like_type = int(entry.get("likeType") or 1001)
    except (TypeError, ValueError):
        like_type = 1001
    return {
        "likeSn": str(entry.get("likeId") or entry.get("likeSn") or actor),
        "likeType": like_type,
        # +[MBActor actorWithActorInfo:] only reads actorId and userValid, then
        # resolves the name and picture from the device's own contact store.
        # Without userValid the actor comes out as "unknown".
        "from": {"actorId": actor, "userValid": True},
    }


def _legacy_comment(entry):
    """One entry of the legacy commentList, per -[MBComment initWithCommentInfo:parent:]."""
    user = entry.get("userInfo") or {}
    actor = user.get("mid") or user.get("writerMid")
    comment_id = entry.get("commentId")
    if not isinstance(actor, str) or not comment_id:
        return None
    try:
        created = int(entry.get("createdTime"))
    except (TypeError, ValueError):
        created = int(time.time() * 1000)
    return {
        "commentSn": str(comment_id),
        "groupNo": 0,
        "seqNo": 0,
        "commentText": str(entry.get("commentText") or ""),
        # createdAt must be a string: -[MBComment initWithCommentInfo:parent:]
        # runs it through a helper that raises "Null string." on a number, and
        # the exception lands on a background queue and kills the app.
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(created / 1000)),
        "blind": False,
        "contentsList": [],
        "extData": {},
        "from": {"actorId": actor, "userValid": True},
    }


def _like_write(g, path, headers, body, primary_token, create):
    """POST /mapi/v4/like/create and /mapi/v4/like/del.

    create takes a JSON body (contentId/actorId/likeType); cancel is a GET with
    contentId + homeId in the query.  Sending either the other way answers 101.
    """
    values = _parse_values(path, headers, body)
    content_id, home_id, self_mid = _target_ids(g, values)
    if create:
        try:
            like_type = int(_one(values, "likeType") or 1001)
        except (TypeError, ValueError):
            like_type = 1001
        _current_request(
            g, primary_token, "POST", "/mh/api/v57/like/create.json",
            {"contentId": content_id, "actorId": self_mid,
             "likeType": like_type, "sharable": False})
    else:
        query = urllib.parse.urlencode({"contentId": content_id, "homeId": home_id})
        try:
            _current_request(
                g, primary_token, "GET", "/mh/api/v57/like/cancel.json?" + query)
        except ValueError as exc:
            # Cancelling a like that is already gone answers 109; the legacy UI
            # only cares that the like is not there any more.
            g["log"]("  [timeline-rest] like cancel: %s" % str(exc)[:120])
    g["log"]("  [timeline-rest] like %s on %s"
             % ("create" if create else "cancel", content_id))
    # The list endpoint lags a moment behind a write, so reconcile what it
    # reports with what we just did instead of echoing a stale answer.
    return _like_list(g, path, headers, body, primary_token,
                      expect_self=create, self_mid=self_mid)


def _like_list(g, path, headers, body, primary_token,
               expect_self=None, self_mid=None):
    """GET /mapi/v4/like -- MBLikeListManager reads likeCount/existNext/userList."""
    values = _parse_values(path, headers, body)
    content_id, home_id, _self = _target_ids(g, values)
    query = urllib.parse.urlencode({"contentId": content_id, "homeId": home_id})
    likes, count = [], 0
    try:
        current = _current_request(
            g, primary_token, "GET", "/mh/api/v57/like/getList.json?" + query)
        result = current.get("result") or {}
        # like/getList.json nests everything under allLikes.
        bucket = result.get("allLikes") if isinstance(result.get("allLikes"), dict) else result
        count = int(bucket.get("likeCount") or 0)
        for entry in (bucket.get("likeList") or bucket.get("likes")
                      or bucket.get("userList") or []):
            if not isinstance(entry, dict):
                continue
            like = _legacy_like(entry)
            if like is not None:
                likes.append(like)
    except (ValueError, KeyError, TypeError, UnicodeError, OSError,
            json.JSONDecodeError) as exc:
        g["log"]("  [timeline-rest] like list unavailable: %r" % exc)
    if expect_self is not None and self_mid:
        present = any((entry.get("from") or {}).get("actorId") == self_mid
                      for entry in likes)
        if expect_self and not present:
            likes.insert(0, {"likeSn": self_mid, "likeType": 1001,
                             "from": {"actorId": self_mid, "userValid": True}})
            count = max(count, 0) + 1
        elif not expect_self and present:
            likes = [entry for entry in likes
                     if (entry.get("from") or {}).get("actorId") != self_mid]
            count = max(count - 1, 0)
    return _json(0, "success", {
        "likeCount": count if count else len(likes),
        "existNext": False, "userList": likes})


def _comment_write(g, path, headers, body, primary_token, create):
    """POST /mapi/v4/comment/create and /mapi/v4/comment/del."""
    values = _parse_values(path, headers, body)
    content_id, home_id, self_mid = _target_ids(g, values)
    if create:
        # 3.7.1 sends the comment as a nested object, not a plain string:
        # {"comment": {"commentText": "…", "from": {...}}}.  Flattening it with
        # str() posts the dictionary itself as the comment body.
        raw = values.get("comment")
        if isinstance(raw, list) and raw:
            raw = raw[0]
        if isinstance(raw, dict):
            text = str(raw.get("commentText") or raw.get("text") or "").strip()
        else:
            text = (_one(values, "comment", "commentText", "text") or "").strip()
        if not text or len(text) > _MAX_TEXT_CHARS:
            raise ValueError("Invalid comment length")
        query = urllib.parse.urlencode({"homeId": home_id, "sourceType": "MYHOME"})
        current = _current_request(
            g, primary_token, "POST",
            "/mh/api/v57/comment/create.json?" + query,
            {"actorId": self_mid, "contentId": content_id,
             "commentText": text, "recallInfos": [], "contentsList": []})
        g["log"]("  [timeline-rest] comment created on %s" % content_id)
        # The completion block feeds result straight into
        # -[MBComment initWithCommentInfo:parent:], so it wants the single new
        # comment -- handing it a list inserts an "unknown" author instead.
        created = _legacy_comment(current.get("result") or {})
        if created is not None:
            return _json(0, "success", created)
    else:
        comment_id = _one(values, "commentSn", "commentId")
        if not comment_id:
            raise ValueError("Invalid comment ID")
        query = urllib.parse.urlencode({
            "homeId": home_id, "commentId": comment_id, "actorId": self_mid})
        _current_request(
            g, primary_token, "GET",
            "/mh/api/v57/comment/delete.json?" + query)
        g["log"]("  [timeline-rest] comment %s deleted" % comment_id)
    return _comment_list(g, path, headers, body, primary_token)


def _comment_list(g, path, headers, body, primary_token):
    """GET /mapi/v4/comments -- the legacy comment list for one post."""
    values = _parse_values(path, headers, body)
    content_id, home_id, _self = _target_ids(g, values)
    query = urllib.parse.urlencode({
        "homeId": home_id, "contentId": content_id,
        "commentLimit": _one(values, "limit", "commentLimit") or "20"})
    comments, count = [], 0
    try:
        current = _current_request(
            g, primary_token, "GET", "/mh/api/v57/comment/getList.json?" + query)
        result = current.get("result") or {}
        count = int(result.get("commentCount") or 0)
        for entry in (result.get("comments") or result.get("commentList") or []):
            if not isinstance(entry, dict):
                continue
            comment = _legacy_comment(entry)
            if comment is not None:
                comments.append(comment)
    except (ValueError, KeyError, TypeError, UnicodeError, OSError,
            json.JSONDecodeError) as exc:
        g["log"]("  [timeline-rest] comment list unavailable: %r" % exc)
    return _json(0, "success", {
        "commentCount": count or len(comments), "existNext": False,
        "commentList": comments})


def _picture_status(g, mid):
    """The profile picture id 3.7.1 needs to build an image URL."""
    if mid == g["PROFILE"].get(1):
        return str(g["PROFILE"].get(22) or "")
    for contact in (g.get("CONTACTS") or []):
        if isinstance(contact, dict) and contact.get("mid") == mid:
            return str(contact.get("pictureStatus") or "")
    return ""


# Every account that never set a cover reports this object id.  It exists in
# OBS, so it is also the safe placeholder when the lookup fails: objectId must
# never be empty or -[MBMyhome coverImageURLWithMyhomeInfo:] throws.
DEFAULT_COVER = ("c0000000000000000000000000000001", "c", "myhome")
_cover_cache = {}
_COVER_TTL = 600.0


def _cover(g, primary_token, mid):
    """(objectId, obsNamespace, serviceName) of a user's Home cover image.

    The profile popup background is the cover, not the profile picture.
    Returning the picture instead made 3.7.1 ask OBS for
    /r/talk/p/<pictureStatus>/640x520, which is a 404 there -- current profile
    pictures live on profile.line-scdn.net, and only the cover is a real OBS
    object.  post/list carries it in result.homeInfo.
    """
    cached = _cover_cache.get(mid)
    now = time.monotonic()
    if cached and now - cached[0] < _COVER_TTL:
        return cached[1]
    cover = DEFAULT_COVER
    try:
        query = urllib.parse.urlencode({"homeId": mid, "sourceType": "TIMELINE",
                                        "postLimit": "1"})
        current = _current_request(
            g, primary_token, "GET", "/mh/api/v57/post/list.json?" + query)
        home = (current.get("result") or {}).get("homeInfo")
        if isinstance(home, dict) and home.get("objectId"):
            cover = (str(home["objectId"]),
                     str(home.get("obsNamespace") or "c"),
                     str(home.get("serviceName") or "myhome"))
    except Exception as exc:
        g["log"]("  [timeline-rest] cover lookup for %s failed: %r"
                 % (str(mid)[:12], exc))
    _cover_cache[mid] = (now, cover)
    return cover


def _user_popup(g, path, primary_token, talk_room=False):
    """userpopup/getDetail.json, userpopup/get.json and talkroom/get.json.

    -[MBProfilePhoto initWithData:withOldData:] reads owner (not isOwner),
    hasNewPost, expireTime, userMid and the objectId / obsNamespace /
    serviceName triple it turns into an image URL.  objectId must never be
    missing: it goes straight into setObject:forKey:@"oid", and a nil there
    throws and takes the app down.
    """
    values = _parse_values(path, {}, b"")
    g["maybe_reload_profile"]()
    self_mid = g["PROFILE"].get(1)
    target = _one(values, "userMid", "homeId", "mid", "targetMid") or self_mid
    if not isinstance(target, str) or not re.fullmatch(r"u[0-9a-f]{32}", target):
        target = self_mid
    object_id, namespace, service = _cover(g, primary_token, target)
    result = {
        "owner": bool(target == self_mid),
        "hasNewPost": False,
        "expireTime": float(int((time.time() + 3600) * 1000)),
        "userMid": target,
        "objectId": object_id,
        "obsNamespace": namespace,
        "serviceName": service,
    }
    g["log"]("  [timeline-rest] %s for %s (owner=%s cover=%s/%s/%s)"
             % ("talkroom" if talk_room else "user popup", str(target)[:12],
                result["owner"], service, namespace, object_id[:24]))
    return _json(0, "success", result)


def _timeline_status(g, primary_token):
    return _json_from_current(_current_request(
        g, primary_token, "GET", "/tl/api/v57/timeline/tab/status.json"))


def _local_timeline_notice(g, path):
    """Return one valid legacy activity when the retired feed has no source."""
    values = _parse_values(path, {}, b"")
    g["maybe_reload_profile"]()
    actor_id = _one(values, "actorId") or g["PROFILE"].get(1)
    if not isinstance(actor_id, str) or not re.fullmatch(r"u[0-9a-f]{32}", actor_id):
        raise ValueError("Invalid Timeline actor ID")
    activity = {
        "activityExternalId": "legy-timeline-notice-v1",
        "status": "NORMAL",
        "from": {"actorId": actor_id},
        "activityType": 1000,
        "contentsList": [],
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%S+09:00"),
        "activityText": (
            "旧タイムラインへの接続は正常です。\n"
            "友だち全体の旧フィードはLINE側で終了したため、"
            "現在取得できる投稿はありません。"
        ),
        "commentCount": 0,
        "likeCount": 0,
        "liked": False,
        "extData": {
            "layout": {
                "useComment": False,
                "useLike": False,
                "allowShare": False,
                "allowEdit": False,
            },
            "readPermission": {"type": "FRIEND", "gids": []},
        },
        "appSn": 0,
    }
    return _json(0, "success", {"activityList": [activity]})


def _find_post(value):
    if isinstance(value, dict):
        if isinstance(value.get("postInfo"), dict) and isinstance(value.get("contents"), dict):
            return value
        for child in value.values():
            found = _find_post(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_post(child)
            if found is not None:
                return found
    return None


def _legacy_activity(post):
    info = post.get("postInfo") or {}
    user = post.get("userInfo") or {}
    contents = post.get("contents") or {}
    post_id = str(info.get("postId") or "")
    actor_id = user.get("mid") or user.get("writerMid")
    if not post_id or not isinstance(actor_id, str):
        return None
    created = info.get("createdTime")
    try:
        created = int(created)
    except (TypeError, ValueError):
        created = int(time.time() * 1000)
    location = _legacy_location(contents)
    stickers = _legacy_stickers(contents)
    text = contents.get("text")
    if not isinstance(text, str) or not text.strip():
        media = contents.get("media") or []
        if media:
            text = "［画像・動画の投稿］"
        elif location or stickers:
            text = ""
        else:
            text = "［投稿］"
    picture_url = str(user.get("pictureUrl") or "")
    picture_status = ""
    if picture_url.startswith("https://profile.line-scdn.net/"):
        picture_status = picture_url.rsplit("/", 1)[-1]
    legacy_media = []
    for media in (contents.get("media") or [])[:4]:
        if not isinstance(media, dict):
            continue
        media_type = str(media.get("type") or "").upper()
        category = "obsphoto" if media_type == "IMAGE" else (
            "obsvideo" if media_type == "VIDEO" else None)
        if category is None or not media.get("objectId"):
            continue
        width = int(media.get("width") or 0)
        height = int(media.get("height") or 0)
        if width <= 0 or height <= 0:
            probed = _probed_size(str(media.get("objectId")))
            if probed:
                width, height = probed
        legacy_media.append({
            "categoryId": category,
            "extData": {
                "objectId": str(media.get("objectId")),
                "serviceName": str(media.get("serviceName") or "myhome"),
                "obsNamespace": str(media.get("obsNamespace") or "hex"),
                "width": width,
                "height": height,
                "preferCdn": True,
                "forbiddenSave": False,
            },
        })
    # activityType drives the timeline exactly like postType drives Home:
    # MBCompositeActivity asks MBActivityContentMap contentTypesForActivityType:
    # and only then does MBMovie / MBPhotos get built and read contentsList.
    # Leaving it at 1000 (text) means media posts never create a player.
    # -[MBTextLocation setupWithTimelineInfo:] and -[MBSticker
    # setupWithTimelineInfo:] both read contentsList entries by categoryId, so a
    # location or sticker post travels the same way media does.
    if location:
        legacy_media.append({"categoryId": "location", "extData": dict(
            location, location=dict(location))})
    if stickers:
        legacy_media.append({"categoryId": "sticker",
                             "extData": {"stickers": stickers}})
    if any(m["categoryId"] == "obsvideo" for m in legacy_media):
        activity_type = 1008
    elif any(m["categoryId"] == "sticker" for m in legacy_media):
        activity_type = 1004
    elif any(m["categoryId"] == "obsphoto" for m in legacy_media):
        activity_type = 1001
    else:
        activity_type = 1000
    return {
        "activityExternalId": post_id,
        "status": "NORMAL",
        "from": {
            "actorId": actor_id,
            "displayName": str(user.get("nickname") or "LINE VOOM"),
            "nickname": str(user.get("nickname") or "LINE VOOM"),
            "pictureUrl": picture_url,
            "profileImageUrl": picture_url,
            "pictureStatus": picture_status,
        },
        "activityType": activity_type,
        "contentsList": legacy_media,
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(created / 1000)),
        "activityText": text,
        "commentCount": int(info.get("commentCount") or 0),
        "likeCount": int(info.get("likeCount") or 0),
        "liked": bool(info.get("liked")),
        "extData": {
            "layout": {
                "useComment": False, "useLike": False,
                "allowShare": False, "allowEdit": False,
            },
            "readPermission": {"type": "FRIEND", "gids": []},
        },
        "appSn": int(info.get("appSn") or 0),
    }


def _recommend_posts(g, primary_token, wanted):
    """Posts from the current VOOM discover feed (the "for you" tab).

    Once the account has posted, the tab feed answers with those own posts
    only, so the other people's posts the legacy Timeline used to show come
    from /tl/discover/api/v1/recommendTab/feeds instead.  The AD and LP
    content codes make that endpoint answer 404, so they are left out.
    """
    posts = []
    scroll_id = None
    for _ in range(3):
        payload = {"surelyRecommendFeed": True,
                   "contents": ["PV", "LS", "CP", "PI", "PL"]}
        if scroll_id:
            payload["nextScrollId"] = scroll_id
        current = _current_request(
            g, primary_token, "POST",
            "/tl/discover/api/v1/recommendTab/feeds", payload,
            timeline_channel=True)
        result = current.get("result") or {}
        found = []
        _collect_posts(result.get("feeds") or [], found)
        if not found:
            break
        posts.extend(found)
        if len(posts) >= wanted:
            break
        scroll_id = result.get("nextScrollId")
        if not isinstance(scroll_id, str) or not scroll_id:
            break
    return posts


def _current_timeline_activities(g, path, primary_token):
    now = int(time.time() * 1000)
    payload = {
        "feedRequests": {
            "FEED_LIST": {
                "version": "v57",
                "queryParams": {
                    "postLimit": 20, "requestTime": now,
                    "userAction": "TAP-NEW_POST",
                },
                "requestBody": {
                    "discover": {"contents": ["CP", "PI", "PV", "PL", "LS"]}
                },
            },
            "STORY": {"version": "v12"},
        }
    }
    current = _current_request(
        g, primary_token, "POST", "/tl/api/v57/timeline/tab/contents.json",
        payload, timeline_channel=True)
    result = current.get("result") or {}
    feeds = ((result.get("feedList") or {}).get("feeds") or [])
    g["maybe_reload_profile"]()
    self_mid = g["PROFILE"].get(1)
    collected = []
    for feed in feeds:
        post = _find_post(feed)
        if post is not None:
            collected.append(post)
    tab_count = len(collected)
    # Our own posts belong to the Home tab, not to the legacy Timeline.
    collected = [p for p in collected
                 if (p.get("userInfo") or {}).get("mid") != self_mid]
    # The legacy Timeline is a following feed.  Filling a short following feed
    # from VOOM's recommendation tab makes unrelated videos appear only on
    # low-activity accounts, so keep discovery opt-in.
    if _INCLUDE_RECOMMENDED and len(collected) < 20:
        try:
            for post in _recommend_posts(g, primary_token, 20 - len(collected)):
                if (post.get("userInfo") or {}).get("mid") == self_mid:
                    continue
                collected.append(post)
        except (ValueError, KeyError, TypeError, UnicodeError, OSError,
                json.JSONDecodeError) as exc:
            g["log"]("  [timeline-rest] discover feed unavailable: %r" % exc)
    activities = []
    pictures = {}
    seen = set()
    for post in collected:
        user = post.get("userInfo") or {}
        mid = user.get("mid") or user.get("writerMid")
        picture_url = user.get("pictureUrl")
        if isinstance(mid, str) and isinstance(picture_url, str) and picture_url.startswith("https://"):
            pictures[mid] = picture_url
        activity = _legacy_activity(post)
        if activity is None or activity["activityExternalId"] in seen:
            continue
        seen.add(activity["activityExternalId"])
        activities.append(activity)
    g["log"]("  [timeline-rest] timeline tab=%d -> %d activity(ies)" %
             (tab_count, len(activities)))
    if pictures:
        try:
            merged = {}
            try:
                with open(_TIMELINE_PICTURES, encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    merged.update(loaded)
            except (OSError, ValueError):
                pass
            merged.update(pictures)
            tmp = _TIMELINE_PICTURES + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(merged, f, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, _TIMELINE_PICTURES)
        except OSError as exc:
            g["log"]("  [timeline-rest] picture map write failed: %r" % exc)
    if not activities:
        return _local_timeline_notice(g, path)
    return _json(0, "success", {"activityList": activities[:20]})


# cdn_proxy stores captured uploads next to the service, which is where
# ARTIFACTS_DIR points; __file__ is wrong whenever this module is exercised
# from a copy.
_UPLOAD_DIR = os.path.join(
    os.environ.get("ARTIFACTS_DIR") or os.path.dirname(__file__), "upload")


def _obs_exists(object_id):
    """True when current OBS already stores this object id."""
    conn = http.client.HTTPSConnection(
        "obs.line-apps.com", timeout=20, context=ssl.create_default_context())
    try:
        # HEAD gets the connection reset; a one-byte ranged GET is accepted.
        conn.request("GET", "/r/myhome/h/" + object_id,
                     headers={"Range": "bytes=0-0"})
        response = conn.getresponse()
        response.read(64)
        return response.status in (200, 206)
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()


def _obs_upload(g, primary_token, object_id, kind, size=None):
    """Push an attachment 3.7.1 uploaded to us on to current OBS.

    cdn_proxy catches /myhome/h/upload.nhn and stores the bytes under
    upload/<oid>.bin.  Current OBS lets the client pick the object id, so the
    very same id 3.7.1 generated is reused and the post can reference it
    without any mapping.  Shape from linejs #uploadObjNhn: POST to
    obs.line-apps.com/<obsPath>/upload.nhn with the descriptor in a base64
    x-obs-params header; 201 means stored.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", object_id or ""):
        raise ValueError("Invalid attachment object id")
    path = os.path.join(_UPLOAD_DIR, object_id + ".bin")
    with open(path, "rb") as f:
        data = f.read()
    if not data or len(data) > 64 * 1024 * 1024:
        raise ValueError("Attachment is empty or too large")
    video = kind == "VIDEO"
    descriptor = {
        "name": object_id + (".mp4" if video else ".jpg"),
        "oid": object_id,
        "type": "video" if video else "image",
        "ver": "2.0",
    }
    if size and size[0] > 0 and size[1] > 0:
        descriptor["width"] = size[0]
        descriptor["height"] = size[1]
    params = base64.b64encode(json.dumps(
        descriptor, separators=(",", ":")).encode("utf-8")).decode("ascii")
    g["maybe_reload_profile"]()
    mid = g["PROFILE"].get(1)
    headers = {
        "Content-Type": "video/mp4" if video else "image/jpeg",
        "Content-Length": str(len(data)),
        "User-Agent": g["bridge_user_agent"](),
        "X-Line-Application": g["bridge_app_string"](),
        "X-Line-Mid": mid,
        "X-Line-Access": primary_token,
        "X-Line-ChannelToken": _issue_home_token(g, primary_token, _rpc_seq()),
        "x-obs-params": params,
        "x-lal": "ja_JP",
        "x-lpv": "1",
    }
    if _obs_exists(object_id):
        # OBS never overwrites an object id.  Re-sending a large file makes it
        # answer 423 and close the socket mid-body (BrokenPipeError), so check
        # first and skip -- this is the normal path when a post is retried.
        g["log"]("  [timeline-rest] %s already on OBS (%dB)" % (object_id, len(data)))
        return object_id
    conn = http.client.HTTPSConnection(
        "obs.line-apps.com", timeout=60, context=ssl.create_default_context())
    try:
        conn.request("POST", "/myhome/h/upload.nhn", body=data, headers=headers)
        response = conn.getresponse()
        response.read(4096)
        status = response.status
        # 423 Locked means this object id is already stored -- OBS never
        # overwrites -- which is exactly what we want when a post is retried.
        if status not in (200, 201, 423):
            raise ValueError("OBS upload rejected with HTTP %d" % status)
    finally:
        conn.close()
    g["log"]("  [timeline-rest] %s %s on OBS (%dB %s)"
             % ("reused" if status == 423 else "uploaded", object_id,
                len(data), "video" if video else "image"))
    return object_id


def _media_size(g, object_id, width, height):
    """Fill in a video's pixel size; 3.7.1 posts videos as 0x0.

    A zero-sized media collapses the cell in the legacy timeline: the
    thumbnail has nowhere to draw and the play button ends up misplaced.
    """
    if width > 0 and height > 0:
        return width, height
    path = os.path.join(_UPLOAD_DIR, object_id + ".bin")
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "error", "-select_streams", "v:0",
             "-show_entries", "stream=width,height", "-of", "csv=p=0", path],
            capture_output=True, timeout=30, check=False).stdout.decode("ascii", "ignore")
        parts = [p for p in re.split(r"[,\s]+", out.strip()) if p.isdigit()]
        if len(parts) >= 2:
            g["log"]("  [timeline-rest] probed %s as %sx%s"
                     % (object_id, parts[0], parts[1]))
            return int(parts[0]), int(parts[1])
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        g["log"]("  [timeline-rest] ffprobe failed: %r" % exc)
    return width, height


def _attachments(g, values, primary_token):
    """The medias[] 3.7.1 posts alongside the text, pushed on to current OBS."""
    media = []
    for index in range(9):
        object_id = _one(values, "medias[%d].objectId" % index)
        if not object_id:
            break
        kind = str(_one(values, "medias[%d].type" % index) or "PHOTO").upper()
        if kind not in ("PHOTO", "VIDEO"):
            kind = "PHOTO"
        try:
            width = int(_one(values, "medias[%d].width" % index) or 0)
            height = int(_one(values, "medias[%d].height" % index) or 0)
        except (TypeError, ValueError):
            width = height = 0
        if kind == "VIDEO":
            width, height = _media_size(g, object_id, width, height)
        _obs_upload(g, primary_token, object_id, kind, (width, height))
        # Only objectId/type/obsFace may be sent: adding width/height makes the
        # create call answer 101.  The size travels in the upload descriptor.
        media.append({"objectId": object_id, "type": kind, "obsFace": "[]"})
    return media


def _link_text(values, text):
    """Fold 3.7.1's link attachment into the body.

    A link post arrives as postType 2501 with an empty body and the URL in
    additionalContent.url.targetUrl.  Current VOOM has no such field -- the web
    client simply posts the URL as text and the server builds the card -- so
    the URL is appended to the body unless it is already there.
    """
    url = (_one(values, "additionalContent.url.targetUrl",
                "additionalContent.title") or "").strip()
    if not url or not re.match(r"https?://", url) or len(url) > 2000:
        return text
    if url in text:
        return text
    return (text + "\n" + url).strip() if text else url


def _locations(values):
    """The single location 3.7.1 attaches, as current VOOM expects it."""
    lat = _one(values, "location.latitude")
    lon = _one(values, "location.longitude")
    if lat is None or lon is None:
        return []
    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        return []
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return []
    name = (_one(values, "location.name") or "").strip()[:200]
    return [{"latitude": lat, "longitude": lon, "name": name}]


def _stickers(values):
    """The stickers 3.7.1 attaches (stickers[N].id / packageId / packageVersion)."""
    stickers = []
    for index in range(4):
        sticker_id = _one(values, "stickers[%d].id" % index)
        package_id = _one(values, "stickers[%d].packageId" % index)
        if not sticker_id or not package_id:
            break
        if not (str(sticker_id).isdigit() and str(package_id).isdigit()):
            break
        try:
            version = int(_one(values, "stickers[%d].packageVersion" % index) or 1)
        except (TypeError, ValueError):
            version = 1
        stickers.append({"id": str(sticker_id), "packageId": str(package_id),
                         "packageVersion": version})
    return stickers


def _create_current(g, primary_token, mid, text, ruid, permission,
                    media=None, locations=None, stickers=None):
    """Create one post the way the current LINE VOOM web client does.

    The web client posts exactly this and nothing else:
        POST /api/post/create?sourceType=TIMELINE
        {"contents":{"text":"…","contentsStyle":{"mediaStyle":{"displayType":"GRID"}}},
         "postInfo":{"readPermission":{"gids":[],"type":"ALL"}}}

    The extra fields linejs and CHRLINE send -- contentsStyle.textStyle, the
    empty stickers/locations/media arrays and displayType "GRID_1_A" -- are
    what the server was rejecting with code 101.  With this body the same
    /mh endpoint accepts the post, with or without homeId.

    Only ALL, NONE and GROUP take effect; FRIEND is silently stored as NONE
    because current VOOM has no friends-only scope any more, so "friends"
    becomes GROUP against a share list.
    """
    query = urllib.parse.urlencode({
        "homeId": mid, "sourceType": "TIMELINE", "ruid": ruid})
    contents = {
        "text": text,
        "contentsStyle": {"mediaStyle": {"displayType": "GRID"}}}
    if media:
        contents["media"] = media
    if locations:
        contents["locations"] = locations
    if stickers:
        contents["stickers"] = stickers
    payload = {
        "contents": contents,
        "postInfo": {"readPermission": {
            "gids": list(permission.get("gids") or []),
            "type": permission.get("type") or "ALL"}},
    }
    return _current_request(
        g, primary_token, "POST",
        "/mh/api/v57/post/create.json?" + query, payload)


_DEFAULT_READ_PERMISSION = os.environ.get("TIMELINE_READ_PERMISSION", "ALL")
# Current VOOM dropped the friends-only scope: a post asking for FRIEND is
# stored as NONE.  A share list stands in for it -- the audience becomes
# {"type": "GROUP", "gids": [<list id>]} -- so 3.7.1's "friends" setting maps
# onto the list of this name.
_FRIEND_LIST_NAME = os.environ.get("TIMELINE_FRIEND_LIST", "LINE友だち")
_share_lists_cache = {"at": 0.0, "lists": []}


def _share_lists(g, primary_token):
    """The account's VOOM share lists, cached for an hour.

    sharelist/sync only answers when the request carries x-lhm GET; sending it
    as a plain POST returns 405 Method Not Allowed.
    """
    now = time.monotonic()
    with _lock:
        cached = _share_lists_cache["lists"]
        if cached and now - _share_lists_cache["at"] < 3600:
            return cached
    g["maybe_reload_profile"]()
    owner = g["PROFILE"].get(1)
    if not isinstance(owner, str) or not re.fullmatch(r"u[0-9a-f]{32}", owner):
        return []
    query = urllib.parse.urlencode({"ownerMid": owner, "lastUpdated": "0"})
    current = _current_request(
        g, primary_token, "GET",
        "/ext/timeline/tlgw/sl/api/v2/sharelist/sync?" + query)
    lists = (current.get("result") or {}).get("updated") or []
    lists = [entry for entry in lists if isinstance(entry, dict) and entry.get("sid")]
    with _lock:
        _share_lists_cache["lists"] = lists
        _share_lists_cache["at"] = now
    g["log"]("  [timeline-rest] share lists: %s" % ", ".join(
        "%s(%s)" % (entry.get("name"), entry.get("sid")) for entry in lists))
    return lists


def _friend_audience(g, primary_token):
    """The share list that stands in for "friends", if the account has one."""
    try:
        lists = _share_lists(g, primary_token)
    except (ValueError, KeyError, TypeError, UnicodeError, OSError,
            json.JSONDecodeError) as exc:
        g["log"]("  [timeline-rest] share list lookup failed: %r" % exc)
        return None
    for entry in lists:
        if entry.get("name") == _FRIEND_LIST_NAME:
            return {"type": "GROUP", "gids": [str(entry["sid"])]}
    return None


def _read_permission(g, values, primary_token):
    """Pick the post's audience, honouring 3.7.1's own setting when it sends one.

    Which key 3.7.1 uses is not known yet, so every candidate is checked and
    the request's field names are logged -- that log names the real parameter.
    """
    raw = _one(values, "readPermissionType", "readPermission", "publicType",
               "privacy", "permission", "scope")
    kind = None
    if isinstance(raw, str):
        table = {
            "ALL": "ALL", "PUBLIC": "ALL", "OPEN": "ALL", "0": "ALL",
            "FRIEND": "FRIEND", "FRIENDS": "FRIEND", "GROUP": "FRIEND", "1": "FRIEND",
            "NONE": "NONE", "PRIVATE": "NONE", "SELF": "NONE", "2": "NONE",
        }
        kind = table.get(raw.strip().upper())
        if kind:
            g["log"]("  [timeline-rest] post audience %r -> %s" % (raw, kind))
    if kind is None:
        kind = _DEFAULT_READ_PERMISSION
    if kind == "FRIEND":
        audience = _friend_audience(g, primary_token)
        if audience is not None:
            return audience
        g["log"]("  [timeline-rest] no %r share list; posting as %s"
                 % (_FRIEND_LIST_NAME, _DEFAULT_READ_PERMISSION))
        kind = _DEFAULT_READ_PERMISSION
    return {"type": kind, "gids": []}


def _create(g, path, headers, body, primary_token):
    values = _parse_values(path, headers, body)
    # Log the shape of what 3.7.1 sends so the audience parameter can be
    # identified; text is only counted, never written out.
    g["log"]("  [timeline-rest] create fields: %s" % ", ".join(
        "%s=%s" % (k, ("<%d chars>" % len(str(_one(values, k) or "")))
                   if k in ("body", "text") else repr(_one(values, k))[:40])
        for k in sorted(values)))
    text = (_one(values, "body", "text") or "").strip()
    text = _link_text(values, text)
    media = _attachments(g, values, primary_token)
    locations = _locations(values)
    stickers = _stickers(values)
    # A photo-, location- or sticker-only post carries no text at all, so an
    # empty body is only an error when nothing else came with it.
    if (len(text) > _MAX_TEXT_CHARS or len(text.encode("utf-8")) > 30000
            or not (text or media or locations or stickers)):
        raise ValueError("Invalid Timeline text length")
    g["maybe_reload_profile"]()
    mid = g["PROFILE"].get(1)
    if not isinstance(mid, str) or not re.fullmatch(r"u[0-9a-f]{32}", mid):
        raise ValueError("Current profile MID is unavailable")
    bucket = int(time.time()) // 600
    operation = hashlib.sha256(
        str(bucket).encode("ascii") + b"\0" + body + b"\0"
        + urllib.parse.urlsplit(path).query.encode("utf-8")).hexdigest()
    with _lock:
        now = time.monotonic()
        for old_key, (_, expiry) in list(_completed.items()):
            if expiry <= now:
                del _completed[old_key]
        cached = _completed.get(operation)
        if cached:
            g["log"]("  [timeline-rest] duplicate create; reused response")
            return cached[0]
        current = _create_current(
            g, primary_token, mid, text, _uuid_from_digest(operation),
            _read_permission(g, values, primary_token), media,
            locations, stickers)
        # -[MBPostManager handleUpdate:] hands result straight to
        # +[MBCompositeActivity myhomeActivityWithInfo:], so the body has to be
        # one legacy post -- the same shape Home's list entries use.  Passing
        # the current {"feed": ...} through renders the "please update" card.
        found = []
        _collect_posts(current.get("result") or {}, found)
        created = _legacy_post(found[0]) if found else None
        payload = _json(0, "success", created)
        _completed[operation] = (payload, now + 600)
        g["log"]("  [timeline-rest] v1_6 text post -> current Home create")
        return payload


def handle(g, method, host, path, headers, body, primary_token):
    route = urllib.parse.urlsplit(path).path
    g["log"]("  [timeline-rest] %s %s host=%s body=%dB" %
             (method, route, host, len(body)))
    json_headers = b"server: legy\r\ncontent-type: application/json;charset=UTF-8\r\n"
    try:
        if method == "POST" and route == "/api/v1_6/post/create.json":
            return b"200 OK", json_headers, _create(
                g, path, headers, body, primary_token)
        if method == "GET" and route == "/api/v1_6/myhome/get.json":
            return b"200 OK", json_headers, _list(g, path, primary_token)
        if method == "GET" and route == "/api/v1_6/post/list.json":
            return b"200 OK", json_headers, _home_post_list(
                g, path, primary_token)
        if route in ("/api/v1/userpopup/getDetail.json",
                     "/api/v1/userpopup/get.json"):
            return b"200 OK", json_headers, _user_popup(g, path, primary_token)
        if route == "/api/v1/talkroom/get.json":
            return b"200 OK", json_headers, _user_popup(
                g, path, primary_token, talk_room=True)
        if method == "GET" and route == "/api/v1_6/post/get.json":
            return b"200 OK", json_headers, _post_get(g, path, primary_token)
        if route == "/mapi/v4/contact/autoopen":
            return b"200 OK", json_headers, _autoopen(
                g, path, headers, body, False)
        if route == "/mapi/v4/contact/autoopen/update":
            return b"200 OK", json_headers, _autoopen(
                g, path, headers, body, True)
        if route == "/mapi/v4/like/create":
            return b"200 OK", json_headers, _like_write(
                g, path, headers, body, primary_token, True)
        if route in ("/mapi/v4/like/del", "/mapi/v4/like/cancel"):
            return b"200 OK", json_headers, _like_write(
                g, path, headers, body, primary_token, False)
        if route in ("/mapi/v4/like", "/mapi/v4/likes"):
            return b"200 OK", json_headers, _like_list(
                g, path, headers, body, primary_token)
        if route == "/mapi/v4/comment/create":
            return b"200 OK", json_headers, _comment_write(
                g, path, headers, body, primary_token, True)
        if route in ("/mapi/v4/comment/del", "/mapi/v4/comment/recall"):
            return b"200 OK", json_headers, _comment_write(
                g, path, headers, body, primary_token, False)
        if route == "/mapi/v4/comments":
            return b"200 OK", json_headers, _comment_list(
                g, path, headers, body, primary_token)
        if route == "/mapi/v4/contacts/block":
            return b"200 OK", json_headers, _contact_list(
                g, path, headers, body, "block")
        if route == "/mapi/v4/contacts/hide":
            return b"200 OK", json_headers, _contact_list(
                g, path, headers, body, "hide")
        if route == "/mapi/v4/contact/hide/add":
            return b"200 OK", json_headers, _contact_list(
                g, path, headers, body, "hide", add=True)
        if route == "/mapi/v4/contact/hide/del":
            return b"200 OK", json_headers, _contact_list(
                g, path, headers, body, "hide", add=False)
        if route == "/mapi/v4/contact/block/add":
            return b"200 OK", json_headers, _contact_list(
                g, path, headers, body, "block", add=True)
        if route == "/mapi/v4/contact/release/add":
            return b"200 OK", json_headers, _contact_list(
                g, path, headers, body, "block", add=False)
        if method == "GET" and route == "/mapi/v7/timelinestatus":
            return b"200 OK", json_headers, _timeline_status(g, primary_token)
        if method == "GET" and route == "/mapi/v7/activities":
            return b"200 OK", json_headers, _current_timeline_activities(
                g, path, primary_token)
        return b"501 Not Implemented", json_headers, _json(
            -1, "Legacy Timeline endpoint not translated yet")
    except (ValueError, KeyError, TypeError, UnicodeError, OSError,
            json.JSONDecodeError) as exc:
        g["log"]("  [timeline-rest] request failed: %s: %s" %
                 (type(exc).__name__, str(exc)[:300]))
        return b"400 Bad Request", json_headers, _json(
            -1, "Unable to process legacy Timeline request")
