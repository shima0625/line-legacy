#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
install_root=${LINE_LEGACY_INSTALL_ROOT:-/opt/line-legacy}
config_root=${LINE_LEGACY_CONFIG_ROOT:-/etc/line-legacy}
service_user=${LINE_LEGACY_SERVICE_USER:-linelegacy}

if ! id "$service_user" >/dev/null 2>&1; then
  useradd --system --home-dir "$install_root" --shell /usr/sbin/nologin "$service_user"
fi

install -d -m 0750 -o "$service_user" -g "$service_user" "$install_root"
install -d -m 0750 -o "$service_user" -g "$service_user" "$install_root/linejs-bridge"
install -d -m 0750 -o root -g "$service_user" "$config_root"

for source_file in "$repo_dir"/src/*.py; do
  install -m 0640 -o "$service_user" -g "$service_user" "$source_file" "$install_root/"
done
for source_file in bridge_worker.mjs video_worker.mjs legacy_call_gateway.mjs call_route_helper.mjs eas1_helper.mjs common.mjs setup-login.mjs package.json .npmrc; do
  install -m 0640 -o "$service_user" -g "$service_user" \
    "$repo_dir/src/$source_file" "$install_root/linejs-bridge/$source_file"
done
install -m 0750 -o "$service_user" -g "$service_user" \
  "$repo_dir/tools/refresh_official_notices.py" "$install_root/refresh_official_notices.py"
install -m 0640 -o "$service_user" -g "$service_user" \
  "$repo_dir/src/requirements.txt" "$install_root/requirements.txt"

# 通話とメディアに要る @evex/linejs のパッチ。npm install のあとに当てる。
# 応答トランザクションIDの互換修正もこの1ファイルに統合済み。
install -d -m 0755 -o root -g root "$install_root/patches"
install -m 0644 -o root -g root "$repo_dir/patches/linejs-3.2.1-call.patch" "$install_root/patches/linejs-3.2.1-call.patch"
install -d -m 0755 -o root -g root "$install_root/tools"
install -m 0755 -o root -g root "$repo_dir/tools/patch-linejs.sh" "$install_root/tools/patch-linejs.sh"
install -m 0755 -o root -g root "$repo_dir/tools/doctor.sh" "$install_root/tools/doctor.sh"
install -m 0755 -o root -g root "$repo_dir/tools/setup.sh" "$install_root/tools/setup.sh"

# EAS1 helper sources. The helper binary and libamp.so are not shipped; build
# them here (see eas1-helper/README.md) if call support is needed.
install -d -m 0750 -o "$service_user" -g "$service_user" "$install_root/eas1-helper"
for source_file in amp_manual_loader.c amp_compat.c build.sh README.md; do
  install -m 0640 -o "$service_user" -g "$service_user" \
    "$repo_dir/eas1-helper/$source_file" "$install_root/eas1-helper/$source_file"
done
chmod 0750 "$install_root/eas1-helper/build.sh"
install -m 0640 -o "$service_user" -g "$service_user" \
  "$repo_dir/README.md" "$install_root/README.md"

# 標準スタンプ(1〜4)の所持一覧。無いと getActivePurchases が 0 件を返し、
# スタンプ画面が「接続できません」になる。既にあるものは書き換えない。
if [ ! -e "$install_root/owned_stickers.json" ]; then
  echo '[{"packageId":1,"version":100},{"packageId":2,"version":100},{"packageId":3,"version":100},{"packageId":4,"version":100}]' > "$install_root/owned_stickers.json"
  chown "$service_user":"$service_user" "$install_root/owned_stickers.json"
  chmod 0640 "$install_root/owned_stickers.json"
  echo "created $install_root/owned_stickers.json (標準スタンプ1〜4)"
fi

if [ ! -e "$config_root/line-legacy.env" ]; then
  install -m 0640 -o root -g "$service_user" \
    "$repo_dir/.env.example" "$config_root/line-legacy.env"
  echo "created $config_root/line-legacy.env; set host and account values before starting services"
fi

for unit in "$repo_dir"/systemd/*; do
  install -m 0644 -o root -g root "$unit" /etc/systemd/system/
done
systemctl daemon-reload

# 旧アプリはスタンプ・着せ替え・お知らせを HTTP 80 番で取りに来る。Apache が
# あれば 80 -> 8081 の転送設定を入れる(LINE_LEGACY_SKIP_APACHE=1 で抑止)。
if [ "${LINE_LEGACY_SKIP_APACHE:-0}" != "1" ] && [ -d /etc/apache2/sites-available ]; then
  install -m 0644 -o root -g root "$repo_dir/apache/line-legacy-content.conf" /etc/apache2/sites-available/line-legacy-content.conf
  if command -v a2enmod >/dev/null 2>&1 && command -v a2ensite >/dev/null 2>&1; then
    a2enmod proxy proxy_http >/dev/null
    a2ensite line-legacy-content >/dev/null
    echo "enabled apache site line-legacy-content (80 -> 8081)"
    echo "  無効化: a2dissite line-legacy-content && systemctl reload apache2"
    systemctl reload apache2 2>/dev/null || echo "  apache2 の reload は手動で"
  else
    echo "installed /etc/apache2/sites-available/line-legacy-content.conf (有効化は手動)"
  fi
else
  echo "HTTP 80 番の転送は未設定です。apache/line-legacy-content.conf を参考に、"
  echo "  80 番へ来た旧LINEのコンテンツ要求を 127.0.0.1:8081 へ渡してください。"
fi

echo "files installed; no service was enabled or started"
echo "provide your own certificate and install the Node dependencies before login"

echo "npm install のあとに tools/patch-linejs.sh を実行してください(通話と音声の長さに必要)"
