//! 把 `scripts/versions.env` 的釘選 theia 版本帶進 binary（NFR-03 可稽核）。
//!
//! theia 1.1.2 沒有 `--version` 旗標，無法於執行期查詢；syft/grype 則一律執行期查詢，
//! 以免交付包被換過引擎時報表說謊。
//!
//! 讀不到檔或缺 `THEIA_VERSION=` 一律建置失敗：靜默略過會建出「完成掃描卻不標引擎版本」
//! 的 binary，而且 cargo 會把那份輸出當成新鮮的一直沿用（實際踩過：共用 `target/` 的
//! 原始碼副本缺檔，污染了主樹的建置快取，表現為一支看似無關的測試紅燈）。

use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/versions.env");
    println!("cargo:rerun-if-changed={}", root.display());
    let text = std::fs::read_to_string(&root).unwrap_or_else(|e| {
        panic!(
            "讀不到 {}：{e}——無從標示 theia 版本（NFR-03）",
            root.display()
        )
    });
    let version = text
        .lines()
        .find_map(|l| l.strip_prefix("THEIA_VERSION="))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| panic!("{} 缺 THEIA_VERSION=", root.display()));
    println!("cargo:rustc-env=CYTRACE_THEIA_VERSION={version}");
}
