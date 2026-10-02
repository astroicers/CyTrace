//! 把 `scripts/versions.env` 的釘選 theia 版本帶進 binary（NFR-03 可稽核）。
//!
//! theia 1.1.2 沒有 `--version` 旗標，無法於執行期查詢；syft/grype 則一律執行期查詢，
//! 以免交付包被換過引擎時報表說謊。
//!
//! 值有任何歧義一律建置失敗：讀不到檔、沒有或有**多於一行** `THEIA_VERSION=`、值不是
//! `數字(.數字)+`。同一份檔案還有 shell（package.sh `.` 載入，重複時取最後一行、會剝引號）
//! 與 PowerShell（package.ps1）在讀；只接受三者讀法必然一致的形狀，否則交付包的 NOTICE
//! 與報表上的引擎版本會靜默分歧（T909 第二輪複審 build#1：重複行時本檔取第一行、shell 取
//! 最後一行）。
//!
//! 路徑在**執行期**取 `CARGO_MANIFEST_DIR`（cargo 每次執行 build script 都設成當前這棵樹），
//! 不用 `env!`：`env!` 是**本 build script 被編譯時**的值，共用 `target/` 的另一棵樹若重用了這支
//! 已編好的 build script，就會去讀編它那棵樹的 versions.env——7e7bc1e 那次事故的真正病根
//! （T909 第二輪完整性批判，副本實測：B 樹改成 9.9.9，binary 仍標 A 樹的 1.1.2，無任何警告）。
//! 編進去的值另由 `tests/theia_version.rs` 在執行期對帳 versions.env（第二輪複審 build#0）。

use std::path::Path;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("cargo 執行 build script 必設 CARGO_MANIFEST_DIR");
    let root = Path::new(&dir).join("../../scripts/versions.env");
    println!("cargo:rerun-if-changed={}", root.display());
    let text = std::fs::read_to_string(&root).unwrap_or_else(|e| {
        panic!(
            "讀不到 {}：{e}——無從標示 theia 版本（NFR-03）",
            root.display()
        )
    });
    let found: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("THEIA_VERSION="))
        .collect();
    let [raw] = found.as_slice() else {
        panic!(
            "{} 應恰有一行 THEIA_VERSION=，實際 {} 行：{found:?}",
            root.display(),
            found.len()
        )
    };
    let version = raw.trim();
    let well_formed = version.split('.').count() >= 2
        && version
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if !well_formed {
        panic!(
            "{} 的 THEIA_VERSION={raw:?} 不是 數字(.數字)+（引號、行內註解、空白會讓 shell 與本檔讀出不同值）",
            root.display()
        );
    }
    println!("cargo:rustc-env=CYTRACE_THEIA_VERSION={version}");
}
