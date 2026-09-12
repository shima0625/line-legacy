#!/bin/sh
# Apply the call/media patch to the installed @evex/linejs.
#
# 3.7.1 の通話とメディア送信は、素の @evex/linejs 3.2.1 では通りません。
# patches/linejs-3.2.1-call.patch が当たっていないと次のようになります。
#
#   - 通話: PLANET からの RTP が全て "SRTP auth tag mismatch" で復号できず、
#           相手の声が一切聞こえない
#   - 音声: 送信した音声メッセージに長さが付かず、相手側の表示が 0:00 になる
#
# npm install のあとに一度だけ実行してください。既に当たっている場合は何もしません。
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bridge_dir=${LINEJS_BRIDGE_DIR:-/opt/line-legacy/linejs-bridge}
patch_file="$repo_dir/patches/linejs-3.2.1-call.patch"
package_dir="$bridge_dir/node_modules/@evex/linejs"

if [ ! -f "$patch_file" ]; then
  echo "patch not found: $patch_file" >&2
  exit 1
fi
if [ ! -d "$package_dir" ]; then
  echo "@evex/linejs is not installed under $bridge_dir; run npm install first" >&2
  exit 1
fi

cd "$package_dir"
if patch -p1 --dry-run --silent < "$patch_file" >/dev/null 2>&1; then
  patch -p1 < "$patch_file"
  echo "applied $patch_file"
elif patch -p1 -R --dry-run --silent < "$patch_file" >/dev/null 2>&1; then
  echo "already applied; nothing to do"
else
  echo "patch does not apply cleanly. @evex/linejs 3.2.1 以外が入っている可能性があります。" >&2
  exit 1
fi
