#!/usr/bin/env bash
# CyTrace 離線安裝包組裝（ADR-007 / DELIVERY_SOP）。
# 用法：scripts/package.sh [輸出目錄=delivery]
# 需求：cargo + musl target + musl-tools（musl-gcc）、syft、grype（PATH 或 ~/.local/bin）、已 grype db update。
# 簽章（可選）：minisign 在 PATH 且 CYTRACE_MINISIGN_SECKEY 指向私鑰檔（DELIVERY_SOP §3）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# 引擎版本與校驗和的單一事實源（ADR-012 決策 7 / ADR-013 決策 1）
# shellcheck source=versions.env
[ -f "$ROOT/scripts/versions.env" ] && . "$ROOT/scripts/versions.env"
# THEIA_VERSION 同時被 build.rs（編進報表）與本檔（寫進 NOTICE）讀，兩邊必須取到同一個值：
# 規則與 build.rs 共用（check-theia-version.sh，由 cytrace-core 的 theia_version 測試對帳）。
# 前版只數 `^THEIA_VERSION=` 行數、驗 source 後的值，多一行 `export THEIA_VERSION=…` 就讓
# NOTICE 與報表分歧（T909 第三輪複審 build#1）。
THEIA_VERSION="$("$ROOT/scripts/check-theia-version.sh" "$ROOT/scripts/versions.env")" || exit 1
OUT_DIR="${1:-$ROOT/delivery}"
TARGET="x86_64-unknown-linux-musl"
VERSION="$(grep -m1 '^version' "$ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
BUNDLE="$OUT_DIR/cytrace-$VERSION"
export PATH="$HOME/.local/bin:$PATH"

say() { printf '  → %s\n' "$1"; }

command -v syft >/dev/null || { echo "✗ 找不到 syft"; exit 1; }
command -v grype >/dev/null || { echo "✗ 找不到 grype"; exit 1; }
# ring 的 C 部分需要 musl 的 C 編譯器；缺了 cargo 會在建置中途失敗（T920 實測）
command -v musl-gcc >/dev/null || command -v x86_64-linux-musl-gcc >/dev/null \
  || { echo "✗ 找不到 musl-gcc（Debian/Ubuntu：apt-get install musl-tools）"; exit 1; }

echo "📦 組裝 CyTrace $VERSION → $BUNDLE"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/bin" "$BUNDLE/db"

# 1) musl 靜態 binary
say "build musl 靜態 cytrace"
# touch：同路徑重建時 cargo 依 mtime 判新鮮，versions.env 若比上次建置舊，build script 不重跑、
# 報表沿用舊的 theia 版號（第三輪複審 build#0）。強制重跑，讀到當前檔案的值。
touch "$ROOT/scripts/versions.env"
# 輸出收進記錄檔；失敗時印出尾段——整段丟進 /dev/null 的話，失敗時只看到腳本默默結束（T920 實測）
BUILD_LOG="$(mktemp)"
if ! ( cd "$ROOT" && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target "$TARGET" -p cytrace-cli >"$BUILD_LOG" 2>&1 ); then
  echo "✗ cargo build 失敗（$TARGET），最後 30 行："
  tail -n 30 "$BUILD_LOG"
  exit 1
fi
rm -f "$BUILD_LOG"
cp "$ROOT/target/$TARGET/release/cytrace" "$BUNDLE/bin/cytrace"

# 2) 釘選引擎——**版本必須符 versions.env**，不驗就是「收集 PATH 上剛好有的版本」。
# 實地翻車記錄（2026-09-29）：build 機的 syft 漂到 1.51.1（釘選 1.45.1），
# 它預設輸出 CycloneDX 1.7，grype 0.114 直接 `sbom format not recognized`——
# 不驗版本的包在場域會整條 vuln 管線壞掉（release 準備複審 major #16）。
say "收集釘選引擎 syft/grype（驗版本 against versions.env）"
require_engine_version() { # $1=name $2=expected
  local got
  got=$("$1" --version 2>/dev/null | head -1 | awk '{print $2}')
  if [ "$got" != "$2" ]; then
    echo "✗ $1 版本 $got ≠ 釘選版 $2（scripts/versions.env）"
    echo "  build 機請安裝釘選版；環境漂移的引擎不得進交付包"
    exit 1
  fi
  echo "  ✓ $1 $got"
}
require_engine_version syft  "${SYFT_VERSION:?versions.env 未載入}"
require_engine_version grype "${GRYPE_VERSION:?versions.env 未載入}"
cp "$(command -v syft)" "$BUNDLE/bin/syft"
cp "$(command -v grype)" "$BUNDLE/bin/grype"

# 2b) CBOM 引擎 cbomkit-theia（ADR-013）——自源碼建置之產物，SHA256 須符 versions.env
if command -v cbomkit-theia >/dev/null; then
  say "收集 CBOM 引擎 cbomkit-theia"
  cp "$(command -v cbomkit-theia)" "$BUNDLE/bin/cbomkit-theia"
  if [ -n "${THEIA_LINUX_AMD64_SHA256:-}" ]; then
    echo "${THEIA_LINUX_AMD64_SHA256}  $BUNDLE/bin/cbomkit-theia" | sha256sum -c - \
      || { echo "  ❌ cbomkit-theia SHA256 與 versions.env 不符（非可重現建置之產物）"; exit 1; }
  fi
elif [ "${WITHOUT_CBOM:-0}" = "1" ]; then
  echo "  ℹ️  WITHOUT_CBOM=1：本包刻意不含 CBOM 引擎，--cbom 將降級為「未盤點」"
else
  # fail-hard（比照 syft/grype）：靜默出一個少了引擎的包，交付方不會發現，
  # 而 NOTICE 仍會宣稱含 CBOM 引擎——寧可打包失敗
  echo "✗ 找不到 cbomkit-theia（CBOM 引擎）"
  echo "  先建置：scripts/build-theia.sh；或顯式以 WITHOUT_CBOM=1 打包不含 CBOM 的版本"
  exit 1
fi

# 3) grype DB 離線快照
DBROOT="${GRYPE_DB_CACHE_DIR:-$HOME/.cache/grype/db}"
if [ -d "$DBROOT" ] && [ -n "$(ls -A "$DBROOT" 2>/dev/null)" ]; then
  say "打包 grype DB 快照（$DBROOT）"
  cp -r "$DBROOT"/* "$BUNDLE/db/"
elif [ "${WITHOUT_DB:-0}" = "1" ]; then
  echo "  ℹ️  WITHOUT_DB=1：本包刻意不含 DB 快照（例如 DB 另通道交付）"
else
  # fail-hard（比照 theia）：原本只警告仍 exit 0、結尾照樣印「✅ 完成」——
  # 可以產出一個無 DB 的「完整」簽章包，場域拆包才發現比對整條不能用
  #（release 準備複審 major #17）
  echo "✗ 找不到 grype DB（$DBROOT）；先 'grype db update'，或顯式 WITHOUT_DB=1"
  exit 1
fi

# 3b) 變更記錄——air-gapped 場域唯一的版本說明（release 準備複審 major #21）
say "收入 CHANGELOG"
cp "$ROOT/CHANGELOG.md" "$BUNDLE/CHANGELOG.md"

# 4) 自產 SBOM（dogfooding，FR-009）— 排除 dev-only node_modules/target
say "產 CyTrace 自產 SBOM"
syft scan "dir:$ROOT" --exclude './frontend/node_modules/**' --exclude './target/**' \
  --exclude './delivery/**' -o cyclonedx-json -q > "$BUNDLE/cytrace.sbom.cdx.json"

# 5) NOTICE（theia 段落依**實際是否收進包內**輸出，避免宣稱不存在的元件）
if [ -f "$BUNDLE/bin/cbomkit-theia" ]; then
  THEIA_NOTICE="$(cat <<THEIA
  - CBOMkit-theia (PQCA / Linux Foundation, Apache-2.0) — 密碼學資產盤點（CBOM；ADR-013）
    自源碼建置（tag v${THEIA_VERSION}），非上游 release binary。
    其相依含下列非 Apache-2.0 成分：
      · gitleaks v8（MIT）、gitleaks/go-gitdiff（MIT）— 內嵌之機密偵測規則
      · MPL-2.0（檔案級弱 copyleft）：hashicorp/golang-lru、hashicorp/go-version、
        cyphar/filepath-securejoin
THEIA
)"
else
  THEIA_NOTICE="  （本包不含 CBOM 引擎；cytrace --cbom 將降級為「未盤點」）"
fi

cat > "$BUNDLE/NOTICE" <<NOTICE
CyTrace $VERSION — 第三方元件授權聲明（NOTICE）

本產品封裝下列工具（未修改）。完整相依清單與授權見各上游 vendor 目錄；
本產品僅散布建置產物，未修改原始碼（Apache-2.0 §4(b)）：
  - Syft          (Anchore, Apache-2.0)  — SBOM 產生
  - Grype         (Anchore, Apache-2.0)  — 漏洞比對
${THEIA_NOTICE}

Web 服務模式（cytrace serve，ADR-011）的 TLS 由 rustls + ring 提供：
  - ring — 授權為 ISC 與 OpenSSL/BoringSSL 混合（見 ring crate LICENSE）。
    全部 Rust 相依套件授權（含 tokio/axum/argon2 等）與版本見隨附 cytrace.sbom.cdx.json。

供應鏈純淨：本產品不含中國大陸來源依賴（如 OpenSCA-cli）。
  本宣告之審查範圍為相依套件的**來源網域、著作權聲明與維護組織**；
  不含個別貢獻者之國籍或居住地（ADR-013「鐵則涵蓋範圍之裁定」）。
Rust 相依經 cargo-deny（license/來源白名單）於 CI 把關。
NOTICE

# 6) 離線執行 wrapper
cat > "$BUNDLE/cytrace-offline" <<'WRAP'
#!/usr/bin/env bash
# 離線執行 wrapper：固定使用包內引擎與 DB 快照，強制離線。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HERE/bin:$PATH"
export GRYPE_DB_CACHE_DIR="$HERE/db"
export GRYPE_DB_AUTO_UPDATE=false
export GRYPE_DB_VALIDATE_AGE=false
# 關閉 syft/grype 的 app update-check outbound（零外連；與容器 ENV 一致，ADR-012）
export GRYPE_CHECK_FOR_APP_UPDATE=false
export SYFT_CHECK_FOR_APP_UPDATE=false
exec "$HERE/bin/cytrace" "$@"
WRAP
chmod +x "$BUNDLE/cytrace-offline" "$BUNDLE/bin/cytrace"

# 7) SHA256SUMS（完整性）
say "產生 SHA256SUMS"
( cd "$BUNDLE" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )

# 8) 簽章（真實性，可選）— 需 minisign 與私鑰
if command -v minisign >/dev/null && [ -n "${CYTRACE_MINISIGN_SECKEY:-}" ]; then
  say "minisign 簽章 SHA256SUMS"
  minisign -Sm "$BUNDLE/SHA256SUMS" -s "$CYTRACE_MINISIGN_SECKEY" >/dev/null
else
  echo "  ℹ️  跳過簽章（無 minisign 或未設 CYTRACE_MINISIGN_SECKEY）；見 DELIVERY_SOP §3"
fi

echo "✅ 完成：$BUNDLE"
du -sh "$BUNDLE" | sed 's/^/   總大小：/'
