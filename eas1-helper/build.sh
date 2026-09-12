#!/bin/sh
# Build the EAS1 helper for armv7 (hard float).
#
# The helper loads libamp.so itself, so no patchelf step is required. The
# Bionic-only symbols that libamp.so imports come from amp_compat.c, which is
# linked into the executable; --export-dynamic makes them visible to the
# dlsym(RTLD_DEFAULT) lookups the loader performs while relocating the image.
set -eu

cd "$(dirname "$0")"
CC=${CC:-arm-linux-gnueabihf-gcc}

"$CC" -O2 -Wall -Wextra -Wl,--export-dynamic \
    -o eas1_helper amp_manual_loader.c amp_compat.c -ldl

echo "built: $(pwd)/eas1_helper"
