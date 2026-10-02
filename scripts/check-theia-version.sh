#!/usr/bin/env bash
# 用法：scripts/check-theia-version.sh <versions.env>
# 印出 THEIA_VERSION；不符規則時印原因到 stderr 並 exit 1。
#
# 與 crates/cytrace-core/theia_version_rule.rs（build.rs 用）同一條規則，由
# crates/cytrace-core/tests/theia_version.rs 以同一組樣本機械對帳：註解以外只准有一行提到
# THEIA_VERSION，且那一行逐字是 THEIA_VERSION=<數字(.數字)+>。另外再以 shell 實際載入一次，
# 斷言載入後的值等於字面值——擋住規則沒列舉到的再賦值寫法。
set -euo pipefail
f="${1:?用法：$0 <versions.env>}"
[ -f "$f" ] || { echo "✗ 找不到 $f" >&2; exit 1; }
n=$(grep -v '^[[:space:]]*#' "$f" | grep -cw 'THEIA_VERSION' || true)
[ "$n" = 1 ] || { echo "✗ $f：註解以外應恰有一行提到 THEIA_VERSION，實際 $n 行" >&2; exit 1; }
line=$(grep -v '^[[:space:]]*#' "$f" | grep -w 'THEIA_VERSION' | tr -d '\r')
raw="${line#THEIA_VERSION=}"
[ "$raw" != "$line" ] \
  || { echo "✗ $f：THEIA_VERSION 那一行必須逐字是 THEIA_VERSION=<版本>：$line" >&2; exit 1; }
[[ "$raw" =~ ^[0-9]+(\.[0-9]+)+$ ]] \
  || { echo "✗ $f：THEIA_VERSION='$raw' 不是 數字(.數字)+" >&2; exit 1; }
sourced=$(bash -c '. "$1" >/dev/null 2>&1; printf %s "${THEIA_VERSION-}"' _ "$f" | tr -d '\r')
[ "$sourced" = "$raw" ] \
  || { echo "✗ $f：shell 載入後 THEIA_VERSION='$sourced'，與字面值 '$raw' 不同" >&2; exit 1; }
printf '%s\n' "$raw"
