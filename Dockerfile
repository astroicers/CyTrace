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
# touch：固定 WORKDIR + target cache mount + COPY 保留來源 mtime，versions.env 若比 cache 裡上次
# 建置舊，cargo 不重跑 build script，映像內 binary 標舊的 theia 版號（T909 第三輪複審 build#0）
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    touch scripts/versions.env \
    && cargo build --release --locked --target x86_64-unknown-linux-musl -p cytrace-cli \
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

# ── Stage 3b：CBOM 引擎（cbomkit-theia，自源碼建置；ADR-013 決策 1）──
# 與 syft/grype 不同：不用上游 release binary，改為釘 commit 自建，
# 並以固定參數確保可重現；建置產物 SHA256 須與 versions.env 相符，不符即 build fail。
# base image 以 digest 釘選（比照其他 stage；對應 versions.env 的 THEIA_GO_IMAGE）
FROM golang:1.26.1@sha256:cd78d88e00afadbedd272f977d375a6247455f3a4b1178f8ae8bbcb201743a8a AS theia-builder
ARG THEIA_COMMIT=dcd95ac86d1cbe6e867ff3ee059b9ef77bac6a59
ARG THEIA_LINUX_AMD64_SHA256=672a3d06ce32d1a242f0f4c10dc0280c257fa4717ecf9c7c6e5f2718bf3adecf
WORKDIR /src
RUN set -eux; \
    git clone --no-checkout https://github.com/cbomkit/cbomkit-theia.git .; \
    git checkout "${THEIA_COMMIT}"; \
    test "$(git rev-parse HEAD)" = "${THEIA_COMMIT}"; \
    go mod vendor; \
    CGO_ENABLED=0 GOFLAGS=-mod=vendor \
      go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/cbomkit-theia .; \
    echo "${THEIA_LINUX_AMD64_SHA256}  /out/cbomkit-theia" | sha256sum -c -

# ── Stage 3c：CBOM 引擎的 Windows 版（T911；交叉編譯，同一份釘選源碼與 Go image）──
# 不進容器映像：產物給 Windows 交付包用（CI windows-package job、release 資產）。
# 沿用 theia-builder 已 vendor 的 /src，只換 GOOS/GOARCH；參數與 Linux 版相同，SHA 同樣釘死。
FROM theia-builder AS theia-builder-windows
ARG THEIA_WINDOWS_AMD64_SHA256=3e2e437105759963a4ef8ff0ce477cececca80436c1beff521a14c1286d21073
RUN set -eux; \
    cd /src; \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOFLAGS=-mod=vendor \
      go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/cbomkit-theia.exe .; \
    echo "${THEIA_WINDOWS_AMD64_SHA256}  /out/cbomkit-theia.exe" | sha256sum -c -

# ── Stage 4：runtime（distroless static，non-root）──
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=rust-builder /usr/local/bin/cytrace /usr/local/bin/cytrace
COPY --from=engines /engines/syft /engines/grype /usr/local/bin/
COPY --from=theia-builder /out/cbomkit-theia /usr/local/bin/cbomkit-theia
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
