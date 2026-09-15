FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates curl ffmpeg openssl patch python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/line-legacy/image

COPY src/requirements.txt ./requirements.txt
RUN python3 -m venv /opt/line-legacy/venv \
    && /opt/line-legacy/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY src/package.json src/.npmrc ./linejs-bridge/
RUN cd linejs-bridge && npm install --omit=dev

COPY patches/linejs-3.2.1-call.patch ./patches/linejs-3.2.1-call.patch
RUN cd linejs-bridge/node_modules/@evex/linejs \
    && patch -p1 < /opt/line-legacy/image/patches/linejs-3.2.1-call.patch

COPY src/*.py ./
COPY src/*.mjs ./linejs-bridge/
COPY .env.example ./.env.example
COPY tools/doctor.sh ./tools/doctor.sh
COPY tools/refresh_official_notices.py ./refresh_official_notices.py
# Windows で clone したツリーからビルドすると .env.example が CRLF で入り、
# setup がそれをそのまま line-legacy.env に複製する。
RUN chmod 0755 /opt/line-legacy/image/tools/doctor.sh \
    && sed -i 's/\r$//' /opt/line-legacy/image/.env.example

COPY docker/entrypoint.sh /usr/local/bin/line-legacy-entrypoint
COPY docker/doctor.sh /usr/local/bin/line-legacy-doctor
RUN chmod 0755 /usr/local/bin/line-legacy-entrypoint /usr/local/bin/line-legacy-doctor

ENTRYPOINT ["/usr/local/bin/line-legacy-entrypoint"]
CMD ["bridge"]
