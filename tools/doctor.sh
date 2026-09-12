#!/bin/sh
# Read-only health check for an installed LINE Legacy gateway.
set -u

install_root=${LINE_LEGACY_INSTALL_ROOT:-/opt/line-legacy}
config_root=${LINE_LEGACY_CONFIG_ROOT:-/etc/line-legacy}
service_user=${LINE_LEGACY_SERVICE_USER:-linelegacy}
venv_python=${LINE_LEGACY_PYTHON:-$install_root/venv/bin/python}
linejs_dir=${LINE_LEGACY_LINEJS_PACKAGE_DIR:-$install_root/linejs-bridge/node_modules/@evex/linejs}
patch_file=${LINE_LEGACY_PATCH_FILE:-$install_root/patches/linejs-3.2.1-call.patch}
files_only=0

usage() {
  cat <<'EOF'
Usage: doctor.sh [--files-only]

Checks a LINE Legacy installation without changing it.
  --files-only  Skip systemd, port, and HTTP checks.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --files-only) files_only=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ -t 1 ]; then
  green='\033[32m'; yellow='\033[33m'; red='\033[31m'; blue='\033[36m'; reset='\033[0m'
else
  green=''; yellow=''; red=''; blue=''; reset=''
fi

passes=0
warnings=0
failures=0

pass() { passes=$((passes + 1)); printf '%b[PASS]%b %s\n' "$green" "$reset" "$*"; }
warn() { warnings=$((warnings + 1)); printf '%b[WARN]%b %s\n' "$yellow" "$reset" "$*"; }
fail() { failures=$((failures + 1)); printf '%b[FAIL]%b %s\n' "$red" "$reset" "$*"; }
info() { printf '%b[INFO]%b %s\n' "$blue" "$reset" "$*"; }

has() { command -v "$1" >/dev/null 2>&1; }

env_value() {
  key=$1
  [ -r "$config_root/line-legacy.env" ] || return 1
  awk -v wanted="$key" '
    index($0, wanted "=") == 1 {
      value = substr($0, length(wanted) + 2)
      sub(/\r$/, "", value)
      print value
      exit
    }
  ' "$config_root/line-legacy.env"
}

unit_active() {
  systemctl is-active --quiet "$1" >/dev/null 2>&1
}

unit_enabled() {
  systemctl is-enabled --quiet "$1" >/dev/null 2>&1
}

check_unit() {
  unit=$1
  required=$2
  if unit_active "$unit"; then
    pass "$unit is active"
  elif [ "$required" = required ]; then
    fail "$unit is not active"
  elif unit_enabled "$unit"; then
    warn "$unit is enabled but not active"
  else
    info "$unit is not enabled (optional)"
  fi
}

port_listening() {
  protocol=$1
  port=$2
  if [ "$protocol" = tcp ]; then
    ss -ltn 2>/dev/null | awk -v port=":$port" 'NR > 1 && $4 ~ port "$" { found=1 } END { exit !found }'
  else
    ss -lun 2>/dev/null | awk -v port=":$port" 'NR > 1 && $4 ~ port "$" { found=1 } END { exit !found }'
  fi
}

printf 'LINE Legacy doctor\n'
printf '  install: %s\n  config:  %s\n\n' "$install_root" "$config_root"

for command_name in python3 node npm openssl patch; do
  if has "$command_name"; then
    pass "$command_name is installed"
  else
    fail "$command_name is not installed"
  fi
done

if has node; then
  node_major=$(node --version 2>/dev/null | sed 's/^v//' | cut -d. -f1)
  case "$node_major" in
    ''|*[!0-9]*) warn "could not determine the Node.js version" ;;
    *)
      if [ "$node_major" -ge 20 ]; then
        pass "Node.js $(node --version) meets the recommended version"
      else
        warn "Node.js $(node --version) is older than the recommended v20"
      fi
      ;;
  esac
fi

if id "$service_user" >/dev/null 2>&1; then
  pass "service user $service_user exists"
else
  fail "service user $service_user does not exist"
fi

if [ -r "$config_root/line-legacy.env" ]; then
  pass "line-legacy.env is readable"
else
  fail "$config_root/line-legacy.env is missing or unreadable; run with sudo for a complete check"
fi

server_ip=$(env_value LINE_LEGACY_SERVER_IP 2>/dev/null || true)
media_base=$(env_value LINE_LEGACY_MEDIA_BASE 2>/dev/null || true)
phone_ip=$(env_value LINE_LEGACY_PHONE_IP 2>/dev/null || true)

case "$server_ip" in
  ''|127.0.0.1) fail "LINE_LEGACY_SERVER_IP is not set to the gateway LAN address" ;;
  *) pass "LINE_LEGACY_SERVER_IP is configured" ;;
esac
case "$media_base" in
  ''|*bridge-host-or-ip*) fail "LINE_LEGACY_MEDIA_BASE still contains the example value" ;;
  *) pass "LINE_LEGACY_MEDIA_BASE is configured" ;;
esac

for certificate_file in server.key server.crt server.pem; do
  if [ -s "$config_root/$certificate_file" ]; then
    pass "$certificate_file exists"
  else
    fail "$config_root/$certificate_file is missing"
  fi
done

if has openssl && [ -s "$config_root/server.crt" ]; then
  if openssl x509 -in "$config_root/server.crt" -noout >/dev/null 2>&1; then
    pass "server.crt is a valid X.509 certificate"
    if openssl x509 -checkend 86400 -in "$config_root/server.crt" -noout >/dev/null 2>&1; then
      pass "server.crt remains valid for at least 24 hours"
    else
      fail "server.crt is expired or expires within 24 hours"
    fi
    fingerprint=$(openssl x509 -in "$config_root/server.crt" -noout -fingerprint -sha256 2>/dev/null || true)
    [ -n "$fingerprint" ] && info "$fingerprint"
  else
    fail "server.crt is not a valid X.509 certificate"
  fi
fi

if has openssl && [ -s "$config_root/server.crt" ] && [ -s "$config_root/server.key" ]; then
  certificate_key=$(openssl x509 -in "$config_root/server.crt" -pubkey -noout 2>/dev/null |
    openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null || true)
  private_key=$(openssl pkey -in "$config_root/server.key" -pubout -outform DER 2>/dev/null |
    openssl dgst -sha256 2>/dev/null || true)
  if [ -n "$certificate_key" ] && [ "$certificate_key" = "$private_key" ]; then
    pass "server.crt and server.key match"
  else
    fail "server.crt and server.key do not match"
  fi
fi

if [ -x "$venv_python" ]; then
  pass "Python virtual environment exists"
  if "$venv_python" -m pip check >/dev/null 2>&1; then
    pass "Python dependencies are consistent"
  else
    fail "Python dependencies are missing or inconsistent"
  fi
else
  fail "$venv_python is missing"
fi

if [ -d "$linejs_dir" ]; then
  pass "@evex/linejs is installed"
else
  fail "@evex/linejs is not installed"
fi
if [ -d "$linejs_dir" ] && [ -r "$patch_file" ] && has patch; then
  if (cd "$linejs_dir" && patch -p1 -R --dry-run --silent < "$patch_file") >/dev/null 2>&1; then
    pass "LINEJS compatibility patch is applied"
  elif (cd "$linejs_dir" && patch -p1 --dry-run --silent < "$patch_file") >/dev/null 2>&1; then
    fail "LINEJS compatibility patch is not applied; run $install_root/tools/patch-linejs.sh"
  else
    fail "LINEJS files do not match the supported patched or unpatched version"
  fi
else
  fail "LINEJS patch cannot be checked"
fi

if [ -s "$install_root/authtoken.txt" ]; then
  pass "authentication token exists"
else
  fail "authentication token is missing; run setup-login.mjs"
fi
storage_count=$(find "$install_root/linejs-bridge" -maxdepth 1 -type f -name '*-storage.json' 2>/dev/null | wc -l | tr -d ' ')
if [ "$storage_count" -gt 0 ]; then
  pass "LINEJS storage exists"
else
  fail "LINEJS storage is missing; run setup-login.mjs"
fi

if [ "$files_only" -eq 0 ]; then
  if has systemctl; then
    for unit in line-legacy-cdn.service line-legacy-legy.service line-legacy-linejs-bridge.service line-legacy-local-worker.service line-legacy-notices.timer; do
      check_unit "$unit" required
    done

    check_unit line-legacy-video.service optional
    check_unit line-legacy-eas1.service optional
    check_unit line-legacy-call.service optional
    check_unit line-legacy-skyglow.service optional

    failed_units=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
    if [ -n "$failed_units" ]; then
      fail "failed systemd units: $failed_units"
    else
      pass "systemd reports no failed units"
    fi
  else
    fail "systemctl is not installed"
  fi

  if has ss; then
    for port in 80 443 8081; do
      if port_listening tcp "$port"; then
        pass "TCP $port is listening"
      else
        fail "TCP $port is not listening"
      fi
    done
    if has systemctl && { unit_active line-legacy-call.service || unit_enabled line-legacy-call.service; }; then
      for port in 19000 20000; do
        if port_listening udp "$port"; then
          pass "UDP $port is listening"
        else
          warn "UDP $port is not listening while call support is enabled"
        fi
      done
    fi
  else
    warn "ss is unavailable; listening ports were not checked"
  fi

  if has curl; then
    if curl -fsS --max-time 3 -H 'Host: dl.stickershop.line.naver.jp' http://127.0.0.1/bridge/config >/dev/null 2>&1; then
      pass "Apache content route responds on TCP 80"
    else
      fail "Apache content route did not answer on TCP 80"
    fi
    if curl -fsS --max-time 3 http://127.0.0.1:8081/bridge/config >/dev/null 2>&1; then
      pass "content gateway responds on TCP 8081"
    else
      fail "content gateway did not answer on TCP 8081"
    fi
  else
    warn "curl is unavailable; HTTP endpoints were not checked"
  fi

  if has systemctl && { unit_active line-legacy-eas1.service || unit_enabled line-legacy-eas1.service; }; then
    [ -x "$install_root/eas1-helper/eas1_helper" ] && pass "EAS1 helper binary exists" || fail "EAS1 helper binary is missing"
    [ -s "$install_root/eas1-helper/libamp.so" ] && pass "libamp.so exists" || fail "libamp.so is missing"
    [ -S /run/line-eas1/eas1.sock ] && pass "EAS1 socket is available" || fail "EAS1 socket is unavailable"
    case "$phone_ip" in ''|127.0.0.1) warn "LINE_LEGACY_PHONE_IP is not set for calls" ;; *) pass "LINE_LEGACY_PHONE_IP is configured" ;; esac
  fi

  if has systemctl && { unit_active line-legacy-skyglow.service || unit_enabled line-legacy-skyglow.service; }; then
    [ -S /var/run/docker.sock ] && pass "Docker socket exists for Skyglow" || fail "Docker socket is missing for Skyglow"
    if id -nG "$service_user" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
      pass "$service_user belongs to the docker group"
    else
      fail "$service_user does not belong to the docker group"
    fi
  fi
else
  info "live service, port, and HTTP checks were skipped"
fi

printf '\nSummary: %s passed, %s warnings, %s failures\n' "$passes" "$warnings" "$failures"
if [ "$failures" -gt 0 ]; then
  printf 'Next: fix the FAIL items, then run this command again.\n'
  if [ "$files_only" -eq 0 ]; then
    printf 'Restart: sudo systemctl restart line-legacy.target\n'
    printf 'Logs: sudo journalctl -u line-legacy-legy.service -u line-legacy-linejs-bridge.service -n 100 --no-pager\n'
  fi
  exit 1
fi
exit 0
