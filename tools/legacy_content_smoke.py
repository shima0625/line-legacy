#!/usr/bin/env python3
"""Non-mutating smoke test for legacy More-tab and JBoard compatibility."""

import json
import sys
import urllib.request


BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8081"


def fetch(path, host):
    request = urllib.request.Request(BASE + path, headers={"Host": host})
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.status, response.headers.get_content_type(), response.read()


def main():
    checks = {}
    status, content_type, body = fetch(
        "/moretab/list.json?lang=ja&device=iphone&region=JP&v=2",
        "appresources.line.naver.jp")
    value = json.loads(body)
    items = value.get("data") or []
    checks.update({
        "more_http_200": status == 200,
        "more_json": content_type == "application/json",
        # ★`version > 1` を条件に足さないこと。現行の応答は version<=1 を返すので、
        #   健全な状態でも必ず落ちる(Pi の原本がその状態で放置されていた)。
        "more_envelope": (isinstance(value.get("version"), int)
                          and bool(value.get("spec"))
                          and isinstance(value.get("interval"), int)),
        "more_items": len(items),
        # ★その他タブ(ミニアプリ)は現行側で廃止されている。0件が正しい応答なので、
        #   ここを「非空であること」に変えてはいけない(健全な状態で必ず落ちる)。
        "more_builtin_baseline": len(items) == 0,
        "more_data_array": isinstance(items, list),
        "more_item_shape": all(all(key in item for key in (
            "id", "spec", "type", "subType", "version", "title",
            "iconUrlBase", "targetUrl")) for item in items),
        "more_lists_top_level": all(key in value for key in (
            "moreTabList", "categoryList", "shortcutList")),
        "more_group_spec": all(group.get("spec") for group in
                               (value.get("moreTabList") or [])),
    })
    page_status, page_type, page = fetch(
        "/miniapp/guide", "appresources.line.naver.jp")
    icon_status, icon_type, icon = fetch(
        "/miniicon/101_grid.png", "appresources.line.naver.jp")
    checks.update({
        "mini_page_http_200": page_status == 200,
        "mini_page_html": page_type == "text/html" and b"<!doctype html>" in page,
        "mini_icon_http_200": icon_status == 200,
        "mini_icon_png": icon_type == "image/png" and icon.startswith(b"\x89PNG"),
    })
    notice_status, notice_type, notice_body = fetch(
        "/mobile/board/line_iphone/ja?page=1&pageSize=20&format=json",
        "openapis.jboard.navercorp.jp")
    notices = (json.loads(notice_body).get("jboard") or {}).get("documents") or []
    checks.update({
        "notice_http_200": notice_status == 200,
        "notice_json": notice_type == "application/json",
        "notice_count": len(notices),
        "notice_shape": all(all(key in notice for key in (
            "documentId", "title", "contents", "createTime", "modifyTime"))
            for notice in notices),
    })
    print(json.dumps(checks, ensure_ascii=False, sort_keys=True))
    failed = [key for key, value in checks.items()
              if isinstance(value, bool) and not value]
    return 1 if failed or not notices else 0


if __name__ == "__main__":
    sys.exit(main())
