#!/bin/sh
set -u

image_root=${LINE_LEGACY_IMAGE_ROOT:-/opt/line-legacy/image}
state_root=${LINE_LEGACY_STATE_ROOT:-/state}
status=0

LINE_LEGACY_INSTALL_ROOT="$state_root/data" \
LINE_LEGACY_CONFIG_ROOT="$state_root/config" \
LINE_LEGACY_SERVICE_USER=root \
LINE_LEGACY_PYTHON=/opt/line-legacy/venv/bin/python \
LINE_LEGACY_LINEJS_PACKAGE_DIR="$image_root/linejs-bridge/node_modules/@evex/linejs" \
LINE_LEGACY_PATCH_FILE="$image_root/patches/linejs-3.2.1-call.patch" \
  "$image_root/tools/doctor.sh" --files-only || status=1

check_http() {
  name=$1
  url=$2
  host=${3:-}
  if [ -n "$host" ]; then
    if curl -fsS --max-time 4 -H "Host: $host" "$url" >/dev/null 2>&1; then
      echo "[PASS] $name"
    else
      echo "[FAIL] $name"
      status=1
    fi
  elif curl -fsS --max-time 4 "$url" >/dev/null 2>&1; then
    echo "[PASS] $name"
  else
    echo "[FAIL] $name"
    status=1
  fi
}

check_http "content gateway responds inside the Compose network" "http://cdn:8081/bridge/config"
if openssl s_client -connect gateway:8443 -servername gw.line.naver.jp </dev/null >/dev/null 2>&1; then
  echo "[PASS] TLS gateway accepts connections inside the Compose network"
else
  echo "[FAIL] TLS gateway did not accept a connection"
  status=1
fi

echo
if [ "$status" -eq 0 ]; then
  echo "Container checks passed. Run 'docker compose ps' to inspect process health."
else
  echo "Container checks failed. Run 'docker compose logs --tail=100' for details."
fi
exit "$status"
