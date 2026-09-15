#!/bin/sh
set -eu

image_root=${LINE_LEGACY_IMAGE_ROOT:-/opt/line-legacy/image}
state_root=${LINE_LEGACY_STATE_ROOT:-/state}
data_root="$state_root/data"
config_root="$state_root/config"
runtime_root="$state_root/run"
config_file="$config_root/line-legacy.env"

mkdir -p "$data_root" "$data_root/linejs-bridge" "$config_root" "$runtime_root" "$state_root/eas1"

if [ -r "$config_file" ]; then
  # Windows で clone したりメモ帳で編集したりすると CRLF になる。そのまま読むと
  # 空行の CR をコマンドとして実行して `\r: not found` で止まり、止まらなかった
  # 行も値の末尾に CR が付く(LINE_LEGACY_SERVER_IP=192.168.1.10\r)。setup の直後の
  # login でこれに当たったので、読む前に LF へ揃える。書き戻せない場合も、揃えた
  # 写しを読むので起動は続けられる。
  normalized_config=$(mktemp)
  tr -d '\r' < "$config_file" > "$normalized_config"
  if ! cmp -s "$normalized_config" "$config_file"; then
    { cat "$normalized_config" > "$config_file"; } 2>/dev/null \
      || echo "warning: could not rewrite $config_file with LF line endings" >&2
  fi
  set -a
  # This file is created from .env.example and is controlled by the operator.
  # shellcheck disable=SC1090
  . "$normalized_config"
  set +a
  rm -f "$normalized_config"
fi

export LINE_LEGACY_HOME="$data_root"
export LINE_LEGACY_DIR="$data_root"
export LINEJS_BRIDGE_DIR="$data_root/linejs-bridge"
export ARTIFACTS_DIR="$data_root"
export LINE_LEGACY_EAS1_SOCKET="$runtime_root/eas1.sock"
export LINE_LEGACY_NOTICES_FILE="$data_root/notices.json"
if [ -n "${DOCKER_CDN_BACKEND:-}" ]; then
  export CDN_BACKEND="$DOCKER_CDN_BACKEND"
fi

if [ ! -e "$data_root/owned_stickers.json" ]; then
  printf '%s\n' '[{"packageId":1,"version":100},{"packageId":2,"version":100},{"packageId":3,"version":100},{"packageId":4,"version":100}]' > "$data_root/owned_stickers.json"
fi

set_config() {
  key=$1
  value=$2
  temporary=$(mktemp)
  awk -v wanted="$key" -v replacement="$value" '
    BEGIN { replaced=0 }
    index($0, wanted "=") == 1 {
      print wanted "=" replacement
      replaced=1
      next
    }
    { print }
    END { if (!replaced) print wanted "=" replacement }
  ' "$config_file" > "$temporary"
  cat "$temporary" > "$config_file"
  rm -f "$temporary"
}

# 既存の設定に無いキーだけを .env.example から補う。値は上書きしない。
# 空の設定ファイルが残っていると、以前の setup は存在だけを見てひな形を入れず、
# IP の3行だけの設定になった(CHUNKED などの互換スイッチが全部抜ける)。
add_missing_config() {
  missing=$(awk '
    NR == FNR {
      if (match($0, /^[A-Za-z_][A-Za-z0-9_]*=/)) have[substr($0, 1, RLENGTH - 1)] = 1
      next
    }
    match($0, /^[A-Za-z_][A-Za-z0-9_]*=/) && !(substr($0, 1, RLENGTH - 1) in have) { print }
  ' "$config_file" "$image_root/.env.example")
  [ -n "$missing" ] || return 0
  printf '\n# Added by setup from .env.example\n%s\n' "$missing" >> "$config_file"
  echo "added missing settings from .env.example:"
  printf '%s\n' "$missing" | sed 's/=.*//; s/^/  /'
}

case "${1:-}" in
  setup)
    server_ip=${SETUP_SERVER_IP:-}
    phone_ip=${SETUP_PHONE_IP:-}
    [ -n "$server_ip" ] || { echo "SETUP_SERVER_IP is required" >&2; exit 2; }
    case "$server_ip$phone_ip" in
      *[!A-Za-z0-9._:-]*) echo "invalid server or phone address" >&2; exit 2 ;;
    esac
    # login は中身があるか(-s)で判定するので、setup も同じ基準で見る。
    if [ ! -s "$config_file" ]; then
      cp "$image_root/.env.example" "$config_file"
    else
      add_missing_config
    fi
    set_config LINE_LEGACY_SERVER_IP "$server_ip"
    set_config LINE_LEGACY_CALL_HOST "$server_ip"
    set_config LINE_LEGACY_MEDIA_BASE "http://$server_ip:8081"
    [ -z "$phone_ip" ] || set_config LINE_LEGACY_PHONE_IP "$phone_ip"

    if [ ! -e "$config_root/server.key" ] && [ ! -e "$config_root/server.crt" ]; then
      openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
        -subj '/CN=LINE Legacy Bridge' \
        -keyout "$config_root/server.key" \
        -out "$config_root/server.crt"
      cat "$config_root/server.key" "$config_root/server.crt" > "$config_root/server.pem"
      chmod 0600 "$config_root/server.key" "$config_root/server.pem"
      chmod 0644 "$config_root/server.crt"
      echo "created a new TLS certificate"
    elif [ ! -s "$config_root/server.key" ] || [ ! -s "$config_root/server.crt" ]; then
      echo "only one of server.key and server.crt exists, or one is empty; refusing to overwrite it" >&2
      exit 1
    elif [ ! -s "$config_root/server.pem" ]; then
      cat "$config_root/server.key" "$config_root/server.crt" > "$config_root/server.pem"
      chmod 0600 "$config_root/server.pem"
    else
      echo "kept the existing TLS certificate"
    fi
    echo
    echo "Portable setup complete. Enter this fingerprint in LINEBridge:"
    openssl x509 -in "$config_root/server.crt" -noout -fingerprint -sha256
    echo
    echo "Next: docker compose run --rm login"
    ;;
  login)
    [ -s "$config_file" ] || { echo "run the setup container first" >&2; exit 1; }
    exec node "$image_root/linejs-bridge/setup-login.mjs"
    ;;
  cdn)
    exec /opt/line-legacy/venv/bin/python "$image_root/cdn_proxy.py" 8081
    ;;
  gateway)
    [ -s "$config_root/server.pem" ] || { echo "server.pem is missing; run setup first" >&2; exit 1; }
    exec /opt/line-legacy/venv/bin/python "$image_root/legy_proxy.py" --cert "$config_root/server.pem" --port 8443 --log "$data_root/proxy.log"
    ;;
  bridge)
    exec node "$image_root/linejs-bridge/bridge_worker.mjs"
    ;;
  worker)
    exec /opt/line-legacy/venv/bin/python "$image_root/local_worker.py"
    ;;
  video)
    exec node "$image_root/linejs-bridge/video_worker.mjs"
    ;;
  enable-video)
    : > "$data_root/linejs-bridge/video_enabled"
    echo "video sending is enabled"
    ;;
  call)
    exec node "$image_root/linejs-bridge/legacy_call_gateway.mjs"
    ;;
  notices)
    while :; do
      /opt/line-legacy/venv/bin/python "$image_root/refresh_official_notices.py" || true
      sleep 21600
    done
    ;;
  skyglow)
    exec /opt/line-legacy/venv/bin/python "$image_root/line_skyglow_notify.py"
    ;;
  doctor)
    exec /usr/local/bin/line-legacy-doctor
    ;;
  *)
    echo "unknown command: ${1:-}" >&2
    exit 2
    ;;
esac
