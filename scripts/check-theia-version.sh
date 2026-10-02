#!/usr/bin/env bash
# 用法：scripts/check-theia-version.sh <versions.env>
# 印出 THEIA_VERSION；不符規則時印原因到 stderr 並 exit 1。
#
# 與 crates/cytrace-core/theia_version_rule.rs（build.rs 用）同一條規則，由
# crates/cytrace-core/tests/theia_version.rs 以同一組位元組樣本機械對帳（含兩種呼叫者 locale）：
# UTF-8；以 \n 切行、每行去一個行尾 \r；註解行不算；其餘只准一行以 ASCII 詞邊界提到
# THEIA_VERSION，且逐字是 THEIA_VERSION=<數字(.數字)+>。
#
# 不 source 這個檔：前版另以 shell 實際載入、斷言載入值等於字面值，但那道檢查是 shell 獨有的，
# 能觸發它的輸入依構造就是兩端判定不同的輸入；而 package.sh 寫 NOTICE 用的是本腳本印出的字面值，
# 那道檢查並沒有保護任何出貨內容（T909 第四輪複審 build#2）。
set -euo pipefail
export LC_ALL=C # [[:space:]] 與 grep -w 的詞字元只認 ASCII，判定不隨呼叫者的 locale 改變
f="${1:?用法：$0 <versions.env>}"
[ -f "$f" ] || { echo "✗ 找不到 $f" >&2; exit 1; }
iconv -f UTF-8 -t UTF-8 "$f" >/dev/null 2>&1 || { echo "✗ $f：不是 UTF-8" >&2; exit 1; }
# NUL：bash 變數裝不下（指令替換會默默丟掉），兩端讀到的字會不同——直接拒收
tr -d '\000' < "$f" | cmp -s - "$f" || { echo "✗ $f：含 NUL 位元組" >&2; exit 1; }
lines=$(sed 's/\r$//' "$f" | grep -av '^[[:space:]]*#' | grep -aw 'THEIA_VERSION' || true)
n=$(printf '%s' "$lines" | grep -ac '' || true)
[ "$n" = 1 ] || { echo "✗ $f：註解以外應恰有一行提到 THEIA_VERSION，實際 $n 行" >&2; exit 1; }
raw="${lines#THEIA_VERSION=}"
[ "$raw" != "$lines" ] \
  || { echo "✗ $f：THEIA_VERSION 那一行必須逐字是 THEIA_VERSION=<版本>：$lines" >&2; exit 1; }
[[ "$raw" =~ ^[0-9]+(\.[0-9]+)+$ ]] \
  || { echo "✗ $f：THEIA_VERSION='$raw' 不是 數字(.數字)+" >&2; exit 1; }
printf '%s\n' "$raw"
