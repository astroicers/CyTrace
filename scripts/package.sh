#!/usr/bin/env bash
# CyTrace 離線安裝包組裝（ADR-007 / DELIVERY_SOP）。
# 用法：scripts/package.sh [輸出目錄=delivery]
# 需求：cargo + musl target、syft、grype（PATH 或 ~/.local/bin）、已 grype db update。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT/delivery}"
TARGET="x86_64-unknown-linux-musl"
VERSION="$(grep -m1 '^version' "$ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
BUNDLE="$OUT_DIR/cytrace-$VERSION"
export PATH="$HOME/.local/bin:$PATH"

say() { printf '  → %s\n' "$1"; }

command -v syft >/dev/null || { echo "✗ 找不到 syft"; exit 1; }
command -v grype >/dev/null || { echo "✗ 找不到 grype"; exit 1; }

echo "📦 組裝 CyTrace $VERSION → $BUNDLE"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/bin" "$BUNDLE/db"

# 1) musl 靜態 binary
say "build musl 靜態 cytrace"
( cd "$ROOT" && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target "$TARGET" -p cytrace-cli >/dev/null 2>&1 )
cp "$ROOT/target/$TARGET/release/cytrace" "$BUNDLE/bin/cytrace"

# 2) 釘選引擎
say "收集釘選引擎 syft/grype"
cp "$(command -v syft)" "$BUNDLE/bin/syft"
cp "$(command -v grype)" "$BUNDLE/bin/grype"

# 3) grype DB 離線快照
DBROOT="${GRYPE_DB_CACHE_DIR:-$HOME/.cache/grype/db}"
if [ -d "$DBROOT" ]; then
  say "打包 grype DB 快照（$DBROOT）"
  cp -r "$DBROOT"/* "$BUNDLE/db/"
else
  echo "  ⚠️  找不到 grype DB（$DBROOT）；請先 'grype db update'"
fi

# 4) 自產 SBOM（dogfooding，FR-009）— 排除 dev-only node_modules/target
say "產 CyTrace 自產 SBOM"
syft scan "dir:$ROOT" --exclude './frontend/node_modules/**' --exclude './target/**' \
  --exclude './delivery/**' -o cyclonedx-json -q > "$BUNDLE/cytrace.sbom.cdx.json"

# 5) NOTICE
cat > "$BUNDLE/NOTICE" <<NOTICE
CyTrace $VERSION — 第三方元件授權聲明（NOTICE）

本產品封裝下列 Apache-2.0 工具（未修改）：
  - Syft  (Anchore, Apache-2.0)  — SBOM 產生
  - Grype (Anchore, Apache-2.0)  — 漏洞比對

Rust 相依套件之授權見隨附 cytrace.sbom.cdx.json。
供應鏈純淨：本產品不含中國大陸來源依賴（如 OpenSCA-cli）。
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
