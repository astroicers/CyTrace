#!/usr/bin/env bash
# 建置 CBOM 引擎 cbomkit-theia（ADR-013 決策 1：自源碼建置，不用上游 release binary）。
#
# 以 Dockerfile 的 theia-builder stage 建置後取出產物——與 CI／容器交付走同一條路徑，
# 確保三者產出同一個 SHA256（可重現建置）。
#
# 用法：scripts/build-theia.sh [輸出目錄=~/.local/bin] [linux|windows=linux]
#   建置階段需要網路（git clone + go mod vendor）；產物驗 SHA256 後才安裝。
#   windows：交叉編譯 cbomkit-theia.exe（T911），供 Windows 交付包使用（放到 dist/ 給 package.ps1）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$HOME/.local/bin}"
OS="${2:-linux}"
# shellcheck source=versions.env
. "$ROOT/scripts/versions.env"

case "$OS" in
  linux)   STAGE=theia-builder;         FILE=cbomkit-theia;     SHA="$THEIA_LINUX_AMD64_SHA256" ;;
  windows) STAGE=theia-builder-windows; FILE=cbomkit-theia.exe; SHA="$THEIA_WINDOWS_AMD64_SHA256" ;;
  *) echo "✗ 不支援的 OS：$OS（linux|windows）" >&2; exit 2 ;;
esac

echo "📦 建置 cbomkit-theia v${THEIA_VERSION}（commit ${THEIA_COMMIT:0:12}，$OS）"
docker build --target "$STAGE" -t "cytrace-$STAGE" \
  --build-arg THEIA_COMMIT="$THEIA_COMMIT" \
  --build-arg THEIA_LINUX_AMD64_SHA256="$THEIA_LINUX_AMD64_SHA256" \
  --build-arg THEIA_WINDOWS_AMD64_SHA256="$THEIA_WINDOWS_AMD64_SHA256" \
  "$ROOT"

TMP="$(mktemp -d)"
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT
CID="$(docker create "cytrace-$STAGE")"
docker cp "$CID:/out/$FILE" "$TMP/$FILE"

echo "${SHA}  $TMP/$FILE" | sha256sum -c - \
  || { echo "✗ 產物 SHA256 與 versions.env 不符——非可重現建置"; exit 1; }

mkdir -p "$OUT_DIR"
install -m 0755 "$TMP/$FILE" "$OUT_DIR/$FILE"
echo "✅ 已安裝：$OUT_DIR/$FILE"
