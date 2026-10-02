//! 報表標示的 theia 版本 == `scripts/versions.env` 的釘選值（NFR-03）；且三個讀取端取值規則一致。
//!
//! `collect_cbom.rs` 的 `done.theia.is_some()` 在 `env!` 之後恆為真，分辨不出值對不對：
//! build.rs 寫錯鍵名得 `"N=1.1.2"`、寫死別的值、或共用 `target/` 的原始碼副本讓 cargo 沿用
//! 別棵樹的 build script 輸出（編進去的是**有效但過期**的值），全部照綠
//! （T909 第二輪複審 build#0，2/3 確認；三種都在副本實測過）。
//!
//! 本測試在**執行期**讀檔——不能用 `env!("CARGO_MANIFEST_DIR")`：污染時編進去的會是副本的
//! 路徑。cargo 執行測試時把 `CARGO_MANIFEST_DIR` 設為受測 package 的目錄。
//!
//! 範圍限制：對帳的是 `cargo test` 編出的 debug 單元，不是出貨的 release 單元；同路徑舊 mtime
//! 那一型由 Dockerfile / package.sh 在建置前 `touch` versions.env 承擔（第三輪複審 build#0）。

use cytrace_core::engine::tool_versions;
use cytrace_types::CbomStatus;
use std::path::PathBuf;

// build.rs 用的同一份規則
include!("../theia_version_rule.rs");

fn repo_root() -> PathBuf {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo test 應設定 CARGO_MANIFEST_DIR");
    PathBuf::from(dir).join("../..")
}

#[test]
fn completed_scan_stamps_the_pinned_theia_version() {
    let path = repo_root().join("scripts/versions.env");
    let pinned = theia_version_from(&std::fs::read_to_string(&path).unwrap())
        .unwrap_or_else(|why| panic!("{}：{why}", path.display()));

    let done = tool_versions(&CbomStatus::Completed);
    assert_eq!(
        done.theia.as_deref(),
        Some(pinned.as_str()),
        "編進 binary 的 theia 版本與 {} 不符——build.rs 取值錯誤，或建置快取沿用了別棵樹的輸出",
        path.display()
    );
}

/// build.rs（Rust 規則）與 package.sh（`scripts/check-theia-version.sh`）對同一組 versions.env
/// 樣本必須給出相同判定與相同取值——兩者分別把版本寫進報表與 NOTICE。
///
/// 前版的 package.sh 只數 `^THEIA_VERSION=` 行數、驗 source 後的值：多一行
/// `export THEIA_VERSION=1.2.0` 就讓 NOTICE 寫 1.2.0、報表標 1.1.2，建置與打包都放行
/// （T909 第三輪複審 build#1／claims#5，2/3 確認）。
#[cfg(unix)]
#[test]
fn rust_and_shell_readers_agree_on_every_sample() {
    let script = repo_root().join("scripts/check-theia-version.sh");
    let base = "SYFT_VERSION=1.45.1\n# THEIA_VERSION 與 THEIA_COMMIT 一起改（註解行不算）\n";
    let samples: &[(&str, String, Option<&str>)] = &[
        (
            "正常",
            format!("{base}THEIA_VERSION=1.1.2\nTHEIA_COMMIT=abc\n"),
            Some("1.1.2"),
        ),
        (
            "CRLF",
            format!("{base}THEIA_VERSION=1.1.2\r\nTHEIA_COMMIT=abc\r\n")
                .replace("1.45.1\n", "1.45.1\r\n"),
            Some("1.1.2"),
        ),
        (
            "相似名稱不算",
            format!("{base}THEIA_VERSION=1.1.2\nTHEIA_VERSION_NOTE=x\n"),
            Some("1.1.2"),
        ),
        (
            "重複行",
            format!("{base}THEIA_VERSION=1.1.2\nTHEIA_VERSION=1.2.0\n"),
            None,
        ),
        (
            "export 再賦值",
            format!("{base}THEIA_VERSION=1.1.2\nexport THEIA_VERSION=1.2.0\n"),
            None,
        ),
        (
            "+= 再賦值",
            format!("{base}THEIA_VERSION=1.1.2\nTHEIA_VERSION+=.9\n"),
            None,
        ),
        (
            "只有 export 形",
            format!("{base}export THEIA_VERSION=1.1.2\n"),
            None,
        ),
        ("縮排", format!("{base}  THEIA_VERSION=1.1.2\n"), None),
        ("等號後空白", format!("{base}THEIA_VERSION= 1.1.2\n"), None),
        ("引號", format!("{base}THEIA_VERSION=\"1.1.2\"\n"), None),
        (
            "行內註解",
            format!("{base}THEIA_VERSION=1.1.2 # pinned\n"),
            None,
        ),
        (
            "預發布版號",
            format!("{base}THEIA_VERSION=1.2.0-rc1\n"),
            None,
        ),
        ("缺鍵", base.to_string(), None),
    ];
    let dir = std::env::temp_dir().join(format!("cytrace-theia-rule-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, (name, text, want)) in samples.iter().enumerate() {
        let rust = theia_version_from(text).ok();
        let f = dir.join(format!("v{i}.env"));
        std::fs::write(&f, text).unwrap();
        let out = std::process::Command::new(&script)
            .arg(&f)
            .output()
            .expect("執行 check-theia-version.sh");
        let shell = out
            .status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string());
        assert_eq!(rust.as_deref(), *want, "{name}：Rust 規則判定錯誤");
        assert_eq!(
            shell,
            rust,
            "{name}：shell 與 Rust 的判定不一致（stderr：{}）",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
