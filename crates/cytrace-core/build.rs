//! 把 `scripts/versions.env` 的釘選 theia 版本帶進 binary（NFR-03 可稽核）。
//!
//! theia 1.1.2 沒有 `--version` 旗標，無法於執行期查詢；syft/grype 則一律執行期查詢，
//! 以免交付包被換過引擎時報表說謊。

use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/versions.env");
    println!("cargo:rerun-if-changed={}", root.display());
    if let Ok(text) = std::fs::read_to_string(&root) {
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("THEIA_VERSION=") {
                println!("cargo:rustc-env=CYTRACE_THEIA_VERSION={}", v.trim());
            }
        }
    }
}
