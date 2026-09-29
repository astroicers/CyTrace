#!/usr/bin/env bash
# 建置 CBOM 引擎 cbomkit-theia（ADR-013 決策 1：自源碼建置，不用上游 release binary）。
#
# 以 Dockerfile 的 theia-builder stage 建置後取出產物——與 CI／容器交付走同一條路徑，
# 確保三者產出同一個 SHA256（可重現建置）。
#
# 用法：scripts/build-theia.sh [輸出目錄=~/.local/bin]
#   建置階段需要網路（git clone + go mod vendor）；產物驗 SHA256 後才安裝。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$HOME/.local/bin}"
# shellcheck source=versions.env
. "$ROOT/scripts/versions.env"

echo "📦 建置 cbomkit-theia v${THEIA_VERSION}（commit ${THEIA_COMMIT:0:12}）"
docker build --target theia-builder -t cytrace-theia-builder "$ROOT"

TMP="$(mktemp -d)"
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT
CID="$(docker create cytrace-theia-builder)"
docker cp "$CID:/out/cbomkit-theia" "$TMP/cbomkit-theia"

echo "${THEIA_LINUX_AMD64_SHA256}  $TMP/cbomkit-theia" | sha256sum -c - \
  || { echo "✗ 產物 SHA256 與 versions.env 不符——非可重現建置"; exit 1; }

mkdir -p "$OUT_DIR"
install -m 0755 "$TMP/cbomkit-theia" "$OUT_DIR/cbomkit-theia"
echo "✅ 已安裝：$OUT_DIR/cbomkit-theia"
