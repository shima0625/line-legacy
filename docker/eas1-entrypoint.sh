#!/bin/sh
set -eu

state_root=${LINE_LEGACY_STATE_ROOT:-/state}
library="$state_root/eas1/libamp.so"
socket="$state_root/run/eas1.sock"

[ -s "$library" ] || { echo "$library is missing" >&2; exit 1; }
mkdir -p "$state_root/run"
rm -f "$socket"
exec qemu-arm -L / /opt/line-legacy/eas1/eas1_helper --server "$socket" "$library"
