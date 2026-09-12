#!/usr/bin/env python3
"""Refresh legacy JBoard notices from LINE's official notice board.

LINE 3.7.1 reads notices from the NHN jboard API (openapis.jboard.navercorp.jp),
which no longer exists.  The current LINE apps read the same board through the
LINE Notice API that LINE 5.x already used:

  https://notice.line.me/v1/line/ios/document/notice?lang=ja&includeBody=true

This copies those official documents one to one (id, title, body, dates) into
notices.json, which cdn_proxy serves in the jboard format.  Nothing is written
by us: the body is only converted from HTML to plain text, because
NJBBSNoticeCell shows `contents` with setText: in a UITextView (links stay
tappable through its data detectors).
"""

import html
import json
import os
import re
import sys
import urllib.parse
import urllib.request


BASE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.environ.get("LINE_LEGACY_NOTICES_FILE",
                        os.path.join(BASE, "notices.json"))
LANG = os.environ.get("LINE_LEGACY_NOTICE_LANG", "ja")
PLATFORM = os.environ.get("LINE_LEGACY_NOTICE_PLATFORM", "ios")
COUNT = 20
SOURCE = ("https://notice.line.me/v1/line/%s/document/notice?%s" % (
    PLATFORM, urllib.parse.urlencode({"lang": LANG, "size": COUNT, "includeBody": "true"})))
USER_AGENT = "Mozilla/5.0 (compatible; LINE-Legacy-Notice/2.0)"


def html_to_text(value):
    """Official HTML body -> plain text with the same line structure."""
    text = value or ""
    # <a href="URL">label</a> -> "label (URL)" so the URL remains tappable.
    def link(match):
        url = html.unescape(match.group(1)).strip()
        label = re.sub(r"<[^>]+>", "", match.group(2)).strip()
        label = html.unescape(label)
        if not url or url.startswith("javascript:"):
            return label
        return url if not label or label == url else "%s (%s)" % (label, url)
    text = re.sub(r'<a\b[^>]*href="([^"]*)"[^>]*>(.*?)</a>', link, text, flags=re.S | re.I)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"<li\b[^>]*>", "・", text, flags=re.I)
    text = re.sub(r"</(div|p|li|ul|ol|h[1-6]|tr|table)>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text).replace("\xa0", " ").replace("\r", "")
    lines = [line.strip() for line in text.split("\n")]
    text = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def main():
    request = urllib.request.Request(SOURCE, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError("notice.line.me returned HTTP %d" % response.status)
        data = json.loads(response.read(4 * 1024 * 1024).decode("utf-8"))
    documents = (data.get("result") or {}).get("documents") or []
    values = []
    for document in documents:
        if not isinstance(document, dict) or document.get("id") is None:
            continue
        created = int(document.get("registered") or document.get("open") or 0)
        body = html_to_text(document.get("body"))
        landing = ((document.get("lgAtcAttr") or {}).get("landingUrl") or "").strip()
        if landing and landing not in body:
            body = (body + "\n\n" + landing).strip()
        values.append({
            "documentId": str(document["id"]),
            "title": str(document.get("title") or ""),
            "contents": body,
            "createTime": created,
            "modifyTime": int(document.get("updated") or created),
            "source": "notice.line.me",
        })
    if not values:
        raise RuntimeError("notice.line.me returned no documents")
    temporary = OUTPUT + ".tmp"
    with open(temporary, "w", encoding="utf-8") as output:
        json.dump(values, output, ensure_ascii=False, indent=2)
        output.write("\n")
    os.replace(temporary, OUTPUT)
    print("updated %d official notice(s)" % len(values))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print("notice refresh failed: %s" % error, file=sys.stderr)
        sys.exit(1)
