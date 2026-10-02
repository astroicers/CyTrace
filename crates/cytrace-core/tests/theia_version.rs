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
    let pinned = theia_version_from_bytes(&std::fs::read(&path).unwrap())
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
/// **位元組**樣本必須給出相同判定與相同取值——兩者分別把版本寫進報表與 NOTICE。
/// shell 端各以兩種呼叫者 locale（C、C.UTF-8）執行，判定不得隨 locale 改變。
///
/// 歷程：第三輪處置時只有 13 組 `String` 樣本，第四輪複審（build#1、build#2）找到：
/// - 樣本以外的輸入兩端判定不同（裸 CR、非 UTF-8、Unicode 空白、非 ASCII 相鄰字），
///   而且 shell 的判定會隨 locale 改變；
/// - 有四種突變對帳測試照綠（缺縮排註解與左右邊界樣本）；
/// - shell 獨有的「載入值＝字面值」那道檢查沒有任何樣本會觸發。那道檢查已刪除，理由見腳本檔頭。
#[cfg(unix)]
#[test]
fn rust_and_shell_readers_agree_on_every_sample() {
    let script = repo_root().join("scripts/check-theia-version.sh");
    let base = "SYFT_VERSION=1.45.1\n# THEIA_VERSION 與 THEIA_COMMIT 一起改（註解行不算）\n";
    let s = |t: &str| format!("{base}{t}").into_bytes();
    let samples: Vec<(&str, Vec<u8>, Option<&str>)> = vec![
        (
            "正常",
            s("THEIA_VERSION=1.1.2\nTHEIA_COMMIT=abc\n"),
            Some("1.1.2"),
        ),
        (
            "CRLF",
            format!("{base}THEIA_VERSION=1.1.2\r\nTHEIA_COMMIT=abc\r\n")
                .replace("1.45.1\n", "1.45.1\r\n")
                .into_bytes(),
            Some("1.1.2"),
        ),
        (
            "最後一行無換行、帶 CR",
            s("THEIA_VERSION=1.1.2\r"),
            Some("1.1.2"),
        ),
        ("最後一行無換行", s("THEIA_VERSION=1.1.2"), Some("1.1.2")),
        ("CR CR LF", s("THEIA_VERSION=1.1.2\r\r\n"), None),
        ("值中間有 CR", s("THEIA_VERSION=1.1\r.2\n"), None),
        (
            "相似名稱：後綴",
            s("THEIA_VERSION=1.1.2\nTHEIA_VERSION_NOTE=x\n"),
            Some("1.1.2"),
        ),
        (
            "相似名稱：前綴",
            s("THEIA_VERSION=1.1.2\nMY_THEIA_VERSION=9.9.9\n"),
            Some("1.1.2"),
        ),
        (
            "ASCII 詞字元相鄰",
            s("THEIA_VERSION=1.1.2\nNOTE=xTHEIA_VERSION\n"),
            Some("1.1.2"),
        ),
        (
            "非 ASCII 字相鄰",
            s("THEIA_VERSION=1.1.2\nNOTE=版本THEIA_VERSION\n"),
            None,
        ),
        (
            "縮排的註解提到鍵名",
            s("  # 改 THEIA_VERSION 時一起改 COMMIT\nTHEIA_VERSION=1.1.2\n"),
            Some("1.1.2"),
        ),
        (
            "tab 縮排的註解",
            s("\t# THEIA_VERSION=9.9.9\nTHEIA_VERSION=1.1.2\n"),
            Some("1.1.2"),
        ),
        (
            "NBSP 縮排的「註解」不算註解",
            s("\u{a0}# THEIA_VERSION=9.9.9\nTHEIA_VERSION=1.1.2\n"),
            None,
        ),
        (
            "重複行",
            s("THEIA_VERSION=1.1.2\nTHEIA_VERSION=1.2.0\n"),
            None,
        ),
        (
            "export 再賦值",
            s("THEIA_VERSION=1.1.2\nexport THEIA_VERSION=1.2.0\n"),
            None,
        ),
        (
            "+= 再賦值",
            s("THEIA_VERSION=1.1.2\nTHEIA_VERSION+=.9\n"),
            None,
        ),
        ("只有 export 形", s("export THEIA_VERSION=1.1.2\n"), None),
        ("縮排", s("  THEIA_VERSION=1.1.2\n"), None),
        ("等號後空白", s("THEIA_VERSION= 1.1.2\n"), None),
        ("引號", s("THEIA_VERSION=\"1.1.2\"\n"), None),
        ("行內註解", s("THEIA_VERSION=1.1.2 # pinned\n"), None),
        ("預發布版號", s("THEIA_VERSION=1.2.0-rc1\n"), None),
        ("缺鍵", base.as_bytes().to_vec(), None),
        ("空檔", Vec::new(), None),
        (
            "非 UTF-8（Big5 存檔的註解）",
            [
                base.as_bytes(),
                b"# \xaa\xa9\xa5\xbb\nTHEIA_VERSION=1.1.2\n",
            ]
            .concat(),
            None,
        ),
        (
            "含 NUL",
            [base.as_bytes(), b"# a\x00b\nTHEIA_VERSION=1.1.2\n"].concat(),
            None,
        ),
        (
            "eval 組出的再賦值（字面上不提鍵名）",
            s("THEIA_VERSION=1.1.2\neval 'THEIA''_VERSION=1.2.0'\n"),
            Some("1.1.2"),
        ),
    ];
    let dir = std::env::temp_dir().join(format!("cytrace-theia-rule-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, (name, bytes, want)) in samples.iter().enumerate() {
        let rust = theia_version_from_bytes(bytes).ok();
        assert_eq!(rust.as_deref(), *want, "{name}：Rust 規則判定錯誤");
        let f = dir.join(format!("v{i}.env"));
        std::fs::write(&f, bytes).unwrap();
        for locale in ["C", "C.UTF-8"] {
            let out = std::process::Command::new(&script)
                .arg(&f)
                .env("LC_ALL", locale)
                .output()
                .expect("執行 check-theia-version.sh");
            let shell = out
                .status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string());
            assert_eq!(
                shell,
                rust,
                "{name}（LC_ALL={locale}）：shell 與 Rust 的判定不一致（stderr：{}）",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
