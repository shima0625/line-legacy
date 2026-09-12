#!/usr/bin/env python3
"""Privacy-safe smoke test for the LINE 3.7.1 Cafe compatibility API."""

import json
import os
import sys
import time
import urllib.request


BASE = os.environ.get("LINE_LEGACY_SMOKE_URL", "http://127.0.0.1:8081").rstrip("/")
GROUP = os.environ.get("LINE_LEGACY_TEST_GROUP", "")


def get_json(path):
    request = urllib.request.Request(
        BASE + path, headers={
            "Host": "cafeapi.line.naver.jp",
            "X-Line-Group": GROUP,
        })
    with urllib.request.urlopen(request, timeout=25) as response:
        return response.status, json.load(response)


def send_json(path, value, method="POST"):
    request = urllib.request.Request(
        BASE + path,
        data=json.dumps(value).encode("utf-8"),
        headers={
            "Host": "cafeapi.line.naver.jp",
            "X-Line-Group": GROUP,
            "Content-Type": "application/json",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        return response.status, json.load(response)


def main():
    if not GROUP:
        print("set LINE_LEGACY_TEST_GROUP to a group MID owned by the test account",
              file=sys.stderr)
        return 2
    status, payload = get_json("/%s/posts/all?limit=20" % GROUP)
    items = ((payload.get("result") or {}).get("items") or [])
    checks = {
        "list_http_200": status == 200,
        "list_code_0": payload.get("code") == 0,
        "item_count": len(items),
    }
    if not items:
        print(json.dumps(checks, sort_keys=True))
        return 1

    item = items[0]
    post_id = str(item.get("id") or "")
    created = item.get("created")
    owner = item.get("owner") or {}
    now_ms = int(time.time() * 1000)
    checks.update({
        "list_numeric_id": post_id.isdigit(),
        "list_date_valid": isinstance(created, int)
        and 1262304000000 <= created <= now_ms + 86400000,
        "list_owner_valid": bool(owner.get("userHash") and owner.get("name")),
        "list_media_shape": all(
            media.get("type") in ("I", "V") and bool(media.get("oid"))
            for media in (item.get("medias") or [])),
    })

    detail_status, detail_payload = get_json(
        "/post/%s/slide/NOTE" % post_id)
    detail = ((detail_payload.get("result") or {}).get("item") or {})
    detail_owner = detail.get("owner") or {}
    detail_created = detail.get("created")
    checks.update({
        "detail_http_200": detail_status == 200,
        "detail_code_0": detail_payload.get("code") == 0,
        "detail_same_id": str(detail.get("id") or "") == post_id,
        "detail_date_valid": isinstance(detail_created, int)
        and 1262304000000 <= detail_created <= now_ms + 86400000,
        "detail_owner_valid": bool(
            detail_owner.get("userHash") and detail_owner.get("name")),
        "detail_slide_shape": all(
            key in (detail_payload.get("result") or {})
            for key in ("item", "prevItem", "nextItem",
                        "prevNotificationType", "nextNotificationType",
                        "lastestComment")),
    })

    invalid_status, invalid_comment = send_json(
        "/comment", {"post": {"id": "invalid"}, "text": "x"})
    empty_status, empty_reply = send_json(
        "/reply", {
            "post": {"id": post_id},
            "parentComment": {"id": "1"},
            "text": "",
        })
    checks.update({
        "invalid_comment_http_200": invalid_status == 200,
        "invalid_comment_code_400": invalid_comment.get("code") == 400,
        "empty_reply_http_200": empty_status == 200,
        "empty_reply_code_400": empty_reply.get("code") == 400,
    })

    image_checked = False
    for candidate in items:
        for media in candidate.get("medias") or []:
            if media.get("type") != "I" or not media.get("oid"):
                continue
            oid = str(media["oid"])
            request = urllib.request.Request(
                BASE + "/cafe/p/download.nhn?tid=m592x170&oid=%s&ver=1.0" % oid,
                headers={
                    "Host": "dl.os.line.naver.jp",
                    "Range": "bytes=0-1023",
                })
            with urllib.request.urlopen(request, timeout=25) as response:
                data = response.read(1024)
                checks["image_http_ok"] = response.status in (200, 206)
                checks["image_jpeg"] = data.startswith(b"\xff\xd8")
                checks["image_nonempty"] = bool(data)
            image_checked = True
            break
        if image_checked:
            break
    checks["image_checked"] = image_checked

    print(json.dumps(checks, sort_keys=True))
    boolean_failures = [
        key for key, value in checks.items()
        if key != "item_count" and isinstance(value, bool) and not value
        and key != "image_checked"
    ]
    return 1 if boolean_failures else 0


if __name__ == "__main__":
    sys.exit(main())
