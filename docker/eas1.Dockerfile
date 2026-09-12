FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# libc6-dev-armhf-cross is only a Recommends of gcc-arm-linux-gnueabihf, so it
# has to be named explicitly while --no-install-recommends is in effect.
# Without it the cross compiler has no headers (dlfcn.h, ctype.h) or libdl.
RUN dpkg --add-architecture armhf \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
      libc6:armhf libgles2:armhf libstdc++6:armhf qemu-user \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/line-legacy/eas1
COPY eas1-helper/amp_manual_loader.c eas1-helper/amp_compat.c eas1-helper/build.sh ./
RUN CC=arm-linux-gnueabihf-gcc sh build.sh

COPY docker/eas1-entrypoint.sh /usr/local/bin/line-legacy-eas1
RUN chmod 0755 /usr/local/bin/line-legacy-eas1

ENTRYPOINT ["/usr/local/bin/line-legacy-eas1"]
