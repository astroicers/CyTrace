# CyTrace 容器映像（ADR-012）：cytrace serve Web 服務模式。
# 四階段；base image 全 digest 釘選、引擎 SHA256 驗證、可重現、供應鏈可稽核。
# 只建 linux/amd64（GHCR 私有；場域以 docker save/load 離線搬運）。
#
# grype DB 採選項 B（slim image + /db volume）：DB 月更只換 volume、image 不動。
# syntax=docker/dockerfile:1

# ── Stage 1：前端（報表樣板 + console SPA）──
FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS frontend-builder
WORKDIR /app/frontend
RUN corepack enable && corepack prepare pnpm@10 --activate
# 先只 COPY lockfile → install（layer cache），再 COPY 其餘前端
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
COPY locales/ /app/locales/
# 報表樣板（singlefile）+ console SPA（多 asset）
RUN pnpm build && pnpm build:console

# ── Stage 2：Rust musl 靜態 build ──
FROM rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS rust-builder
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /build
COPY . .
# 以前端產物覆蓋 commit 版（保證 image 內容 = 原始碼；杜絕產物漂移）
COPY --from=frontend-builder /app/frontend/dist/index.html crates/cytrace-report/assets/report-template.html
RUN rm -rf crates/cytrace-server/assets/console \
    && mkdir -p crates/cytrace-server/assets/console
COPY --from=frontend-builder /app/frontend/dist-console/ crates/cytrace-server/assets/console/
# BuildKit cache mount 加速；cache 內 binary 需 cp 出到普通 layer 供下一 stage COPY
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --target x86_64-unknown-linux-musl -p cytrace-cli \
    && cp target/x86_64-unknown-linux-musl/release/cytrace /usr/local/bin/cytrace
# 預建 non-root 可寫的資料目錄（distroless 無 shell 無法 runtime mkdir/chown）
RUN mkdir -p /scaffold/data && chown -R 65532:65532 /scaffold

# ── Stage 3：釘選引擎下載（SHA256 驗證，不符即 build fail）──
FROM debian:bookworm-slim AS engines
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
ARG SYFT_VERSION=1.45.1
ARG GRYPE_VERSION=0.114.0
ARG SYFT_LINUX_AMD64_SHA256=20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716
ARG GRYPE_LINUX_AMD64_SHA256=edda0968d8827daab01d32b3cd7de192ae0915005e7bbfcfef9e68e79bc43343
WORKDIR /engines
RUN set -eux; \
    wget -q "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" -O syft.tgz; \
    echo "${SYFT_LINUX_AMD64_SHA256}  syft.tgz" | sha256sum -c -; \
    tar -xzf syft.tgz syft; \
    wget -q "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -O grype.tgz; \
    echo "${GRYPE_LINUX_AMD64_SHA256}  grype.tgz" | sha256sum -c -; \
    tar -xzf grype.tgz grype; \
    chmod +x syft grype

# ── Stage 4：runtime（distroless static，non-root）──
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=rust-builder /usr/local/bin/cytrace /usr/local/bin/cytrace
COPY --from=engines /engines/syft /engines/grype /usr/local/bin/
# /data 由 65532 擁有（掛 volume 時，空 volume 繼承此目錄的 ownership → 可寫）
COPY --from=rust-builder --chown=65532:65532 /scaffold/data /data
# 離線鐵則烤死進 image（含 update-check——現行裸機 wrapper 未關的 outbound 洩漏點）
ENV PATH=/usr/local/bin:$PATH \
    GRYPE_DB_CACHE_DIR=/db \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_DB_VALIDATE_AGE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    TMPDIR=/tmp \
    HOME=/data \
    TZ=Asia/Taipei \
    CYTRACE_BIND=0.0.0.0:8443 \
    CYTRACE_DATA_DIR=/data
USER 65532:65532
VOLUME ["/data", "/db", "/scan-targets", "/certs"]
EXPOSE 8443
LABEL org.opencontainers.image.title="CyTrace" \
      org.opencontainers.image.description="地端依賴風險掃描 Web 服務（air-gapped）" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/usr/local/bin/cytrace"]
CMD ["serve"]
