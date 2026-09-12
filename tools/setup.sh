#!/bin/sh
# Install the core gateway without overwriting credentials or certificates.
set -eu

server_ip=
phone_ip=
skip_apt=0
run_login=0
start_services=0

usage() {
  cat <<'EOF'
Usage: sudo ./tools/setup.sh --server-ip ADDRESS [options]

Required:
  --server-ip ADDRESS  LAN address of this gateway

Options:
  --phone-ip ADDRESS   LAN address of the legacy iPhone (for calls)
  --skip-apt           Do not install Ubuntu packages
  --login              Run the interactive LINE QR login
  --start              Enable and start the core services after setup
  -h, --help           Show this help

Only the requested network fields are updated. Certificates and login data are preserved.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --server-ip)
      [ "$#" -ge 2 ] || { echo "--server-ip requires a value" >&2; exit 2; }
      server_ip=$2; shift
      ;;
    --phone-ip)
      [ "$#" -ge 2 ] || { echo "--phone-ip requires a value" >&2; exit 2; }
      phone_ip=$2; shift
      ;;
    --skip-apt) skip_apt=1 ;;
    --login) run_login=1 ;;
    --start) start_services=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "run this script with sudo" >&2; exit 1; }
[ -n "$server_ip" ] || { echo "--server-ip is required" >&2; usage >&2; exit 2; }

validate_address() {
  case "$1" in
    *[!A-Za-z0-9._:-]*|'') return 1 ;;
    *) return 0 ;;
  esac
}
validate_address "$server_ip" || { echo "invalid --server-ip value" >&2; exit 2; }
[ -z "$phone_ip" ] || validate_address "$phone_ip" || { echo "invalid --phone-ip value" >&2; exit 2; }

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
install_root=${LINE_LEGACY_INSTALL_ROOT:-/opt/line-legacy}
config_root=${LINE_LEGACY_CONFIG_ROOT:-/etc/line-legacy}
service_user=${LINE_LEGACY_SERVICE_USER:-linelegacy}
env_file="$config_root/line-legacy.env"

if [ "$skip_apt" -eq 0 ]; then
  command -v apt-get >/dev/null 2>&1 || { echo "apt-get was not found; this automatic setup supports Ubuntu/Debian" >&2; exit 1; }
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git curl python3 python3-venv nodejs npm ffmpeg apache2 patch openssl iproute2
fi

"$repo_dir/tools/install-files.sh"

if [ ! -x "$install_root/venv/bin/python" ]; then
  python3 -m venv "$install_root/venv"
fi
"$install_root/venv/bin/pip" install -r "$install_root/requirements.txt"
chown -R "$service_user:$service_user" "$install_root/venv"

runuser -u "$service_user" -- sh -c 'cd "$1" && npm install' sh "$install_root/linejs-bridge"
"$install_root/tools/patch-linejs.sh"

if [ ! -e "$config_root/server.key" ] && [ ! -e "$config_root/server.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -subj '/CN=LINE Legacy Bridge' \
    -keyout "$config_root/server.key" \
    -out "$config_root/server.crt"
  cat "$config_root/server.key" "$config_root/server.crt" > "$config_root/server.pem"
  chown root:"$service_user" "$config_root/server.key" "$config_root/server.crt" "$config_root/server.pem"
  chmod 0640 "$config_root/server.key" "$config_root/server.crt" "$config_root/server.pem"
  echo "created a new TLS certificate"
elif [ ! -s "$config_root/server.key" ] || [ ! -s "$config_root/server.crt" ]; then
  echo "only one of server.key and server.crt exists, or one is empty; refusing to overwrite it" >&2
  exit 1
elif [ ! -s "$config_root/server.pem" ]; then
  cat "$config_root/server.key" "$config_root/server.crt" > "$config_root/server.pem"
  chown root:"$service_user" "$config_root/server.pem"
  chmod 0640 "$config_root/server.pem"
  echo "created server.pem from the existing key and certificate"
else
  echo "kept the existing TLS certificate"
fi

set_env() {
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
  ' "$env_file" > "$temporary"
  install -m 0640 -o root -g "$service_user" "$temporary" "$env_file"
  rm -f "$temporary"
}

set_env LINE_LEGACY_SERVER_IP "$server_ip"
set_env LINE_LEGACY_CALL_HOST "$server_ip"
set_env LINE_LEGACY_MEDIA_BASE "http://$server_ip:8081"
[ -z "$phone_ip" ] || set_env LINE_LEGACY_PHONE_IP "$phone_ip"

systemctl daemon-reload

if [ "$run_login" -eq 1 ]; then
  runuser -u "$service_user" -- env \
    LINE_LEGACY_DIR="$install_root" \
    LINEJS_BRIDGE_DIR="$install_root/linejs-bridge" \
    node "$install_root/linejs-bridge/setup-login.mjs"
fi

if [ "$start_services" -eq 1 ]; then
  if [ ! -s "$install_root/authtoken.txt" ]; then
    echo "cannot start: authentication token is missing; rerun with --login first" >&2
    exit 1
  fi
  systemctl enable --now line-legacy.target
fi

echo
echo "Setup complete. Enter this certificate fingerprint in LINEBridge:"
openssl x509 -in "$config_root/server.crt" -noout -fingerprint -sha256
echo
if [ "$run_login" -eq 0 ]; then
  echo "Next: run the QR login:"
  echo "  sudo -u $service_user env LINE_LEGACY_DIR=$install_root LINEJS_BRIDGE_DIR=$install_root/linejs-bridge node $install_root/linejs-bridge/setup-login.mjs"
fi
if [ "$start_services" -eq 0 ]; then
  echo "Then start the core services:"
  echo "  sudo systemctl enable --now line-legacy.target"
fi
echo "Check the installation at any time:"
echo "  sudo $install_root/tools/doctor.sh"

"$install_root/tools/doctor.sh" --files-only || true
