#!/usr/bin/env bash
# console 零外連靜態自檢（ADR-011）：console 產物不得「載入」外部 http(s) 資源。
# console 允許同源 API（相對路徑），但禁止任何外部 origin 的資源載入。
# runtime 防線是 CSP connect-src 'self'；此為 build-time 靜態防線。
#
# 只比對「實際載入外部資源」的語法，而非字串常數
# （框架的錯誤訊息連結、CSS 註解中的網址等不算資源載入）。
set -euo pipefail

DIR="${1:-frontend/dist-console}"

if [ ! -d "$DIR" ]; then
  echo "✗ 找不到 console 產物目錄：$DIR（先跑 pnpm build:console）"
  exit 1
fi

# 資源載入語法：HTML src/href 屬性、CSS url()、動態 import()/fetch/new URL 指向外部。
PATTERN='(src|href)[[:space:]]*=[[:space:]]*["'"'"']https?://|url\([[:space:]]*["'"'"']?https?://|import\([[:space:]]*["'"'"']https?://|fetch\([[:space:]]*["'"'"']https?://'

hits=$(grep -rnoE "$PATTERN" "$DIR" 2>/dev/null || true)

if [ -n "$hits" ]; then
  echo "✗ console 產物載入外部資源（違反 air-gapped）："
  echo "$hits"
  exit 1
fi
echo "✓ console 零外部資源載入（僅同源 API）"
