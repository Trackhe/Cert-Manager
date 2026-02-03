# Cert-Manager – CA mit Web-Dashboard und ACME-Server
# Build (lokal):     docker build -t cert-manager .
# Build (ARM+x86):  docker buildx build --platform linux/amd64,linux/arm64 -t trackhe/cert-manager:latest --push .
# Run:              docker run -d -p 3000:3000 -v cert-manager-data:/data -e DATA_DIR=/data -e DB_PATH=/data/cert-manager.db trackhe/cert-manager

FROM oven/bun:alpine AS base
WORKDIR /app

# OCI-Labels (Version/Revision setzt CI per --label)
LABEL org.opencontainers.image.source="https://github.com/Trackhe/Cert-Manager"
LABEL org.opencontainers.image.title="Cert-Manager"
LABEL org.opencontainers.image.description="Eigene CA mit Web-Dashboard und ACME-Server für Zertifikate (Certbot, NPM)."
LABEL org.opencontainers.image.licenses="MIT"

# Abhängigkeiten installieren (lockfile für reproduzierbaren Build)
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

# Quellcode
COPY index.ts ./
COPY src ./src
COPY tsconfig.json ./

EXPOSE 3000

ENV PORT=3000
ENV HOST=0.0.0.0
ENV DATA_DIR=/data
ENV DB_PATH=/data/cert-manager.db

VOLUME /data

CMD ["bun", "run", "index.ts"]
