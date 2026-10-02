//! 報表標示的 theia 版本 == `scripts/versions.env` 的釘選值（NFR-03）。
//!
//! `collect_cbom.rs` 的 `done.theia.is_some()` 在 `env!` 之後恆為真，分辨不出值對不對：
//! build.rs 寫錯鍵名得 `"N=1.1.2"`、寫死別的值、或共用 `target/` 的原始碼副本讓 cargo 沿用
//! 別棵樹的 build script 輸出（編進去的是**有效但過期**的值），全部照綠
//! （T909 第二輪複審 build#0，2/3 確認；三種都在副本實測過）。
//!
//! 本測試在**執行期**讀檔——不能用 `env!("CARGO_MANIFEST_DIR")`：污染時編進去的會是副本的
//! 路徑。cargo 執行測試時把 `CARGO_MANIFEST_DIR` 設為受測 package 的目錄。

use cytrace_core::engine::tool_versions;
use cytrace_types::CbomStatus;
use std::path::PathBuf;

fn versions_env() -> PathBuf {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo test 應設定 CARGO_MANIFEST_DIR");
    PathBuf::from(dir).join("../../scripts/versions.env")
}

#[test]
fn completed_scan_stamps_the_pinned_theia_version() {
    let path = versions_env();
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("THEIA_VERSION="))
        .map(str::trim)
        .collect();
    let [pinned] = lines.as_slice() else {
        panic!("versions.env 應恰有一行 THEIA_VERSION=：{lines:?}")
    };

    // 交付端的打包腳本以 shell 載入同一份檔（package.sh 把它寫進 NOTICE）——兩種讀法必須一致
    #[cfg(unix)]
    {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(r#". "$1"; printf %s "$THEIA_VERSION""#)
            .arg("_")
            .arg(&path)
            .output()
            .expect("執行 bash");
        assert!(out.status.success(), "bash 載入 versions.env 失敗");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            *pinned,
            "shell 讀出的 THEIA_VERSION 與逐行讀法不同——NOTICE 與報表會分歧"
        );
    }

    let done = tool_versions(&CbomStatus::Completed);
    assert_eq!(
        done.theia.as_deref(),
        Some(*pinned),
        "編進 binary 的 theia 版本與 {} 不符——build.rs 取值錯誤，或建置快取沿用了別棵樹的輸出",
        path.display()
    );
}
