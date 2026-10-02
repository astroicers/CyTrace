//! 把 `scripts/versions.env` 的釘選 theia 版本帶進 binary（NFR-03 可稽核）。
//!
//! theia 1.1.2 沒有 `--version` 旗標，無法於執行期查詢；syft/grype 則一律執行期查詢，
//! 以免交付包被換過引擎時報表說謊。
//!
//! 值有任何歧義一律建置失敗。取值規則在 `theia_version_rule.rs`（與測試共用），shell 端
//! （`scripts/check-theia-version.sh`，package.sh 用它寫 NOTICE）由 `tests/theia_version.rs`
//! 以同一組樣本對帳——否則交付包的 NOTICE 與報表上的引擎版本會靜默分歧。
//!
//! 路徑在**執行期**取 `CARGO_MANIFEST_DIR`（cargo 每次執行 build script 都設成當前這棵樹），
//! 不用 `env!`：`env!` 是**本 build script 被編譯時**的值，共用 `target/` 的另一棵樹若重用了這支
//! 已編好的 build script，就會去讀編它那棵樹的 versions.env（T909 第二輪完整性批判，副本實測：
//! B 樹改成 9.9.9，binary 仍標 A 樹的 1.1.2，無任何警告）。
//!
//! **本檔管不到的**（第三輪複審 build#0，更正前版「根治」的說法）：同一路徑、versions.env 的
//! mtime 比上次建置舊時，cargo 依 mtime 判定新鮮、根本不重跑 build script——讀的是執行期還是
//! `env!` 都無從介入。Docker（固定 WORKDIR + target cache mount、COPY 保留來源 mtime）正是這一型；
//! 故 Dockerfile、package.sh、package.ps1 在 cargo build 前 `touch` versions.env 強制重跑。
//! `tests/theia_version.rs` 對帳的是 `cargo test` 的 debug 單元，不是出貨的 release 單元。

use std::path::Path;

include!("theia_version_rule.rs");

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("cargo 執行 build script 必設 CARGO_MANIFEST_DIR");
    let root = Path::new(&dir).join("../../scripts/versions.env");
    println!("cargo:rerun-if-changed={}", root.display());
    let bytes = std::fs::read(&root).unwrap_or_else(|e| {
        panic!(
            "讀不到 {}：{e}——無從標示 theia 版本（NFR-03）",
            root.display()
        )
    });
    let version =
        theia_version_from_bytes(&bytes).unwrap_or_else(|why| panic!("{}：{why}", root.display()));
    println!("cargo:rustc-env=CYTRACE_THEIA_VERSION={version}");
}
