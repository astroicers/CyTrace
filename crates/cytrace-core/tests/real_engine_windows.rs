//! Windows 上的真引擎煙霧測試（T911）。
//!
//! `real_engine.rs` 整份限定 unix：它的案例依賴 symlink、FIFO、權限位元、openssl／ssh-keygen。
//! Windows 交付包從 T911 起內含交叉編譯的 `cbomkit-theia.exe`，但「編得出來」不等於「跑得起來」——
//! 例如 Go 在 Windows 上以 USERPROFILE 而非 HOME 找家目錄，環境沒給對就會把警告印進 stdout、
//! 汙染 JSON。本檔以真引擎跑最小的兩個情境，證明這條路徑在 Windows 上確實能用。
//!
//! 跑法（CI windows-package job）：`cbomkit-theia.exe` 在 PATH 上，
//! `cargo test -p cytrace-core --test real_engine_windows -- --ignored`。
//! 缺引擎時**失敗**，不靜默通過。

#![cfg(windows)]

use cytrace_core::collect_cbom;
use cytrace_core::engine::RealEngine;
use cytrace_types::CbomStatus;
use std::path::PathBuf;

const FIXTURE_CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/e2e-selfsigned.crt"
);

fn workspace(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cytrace-rew-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn require_theia() {
    let present = std::process::Command::new("cbomkit-theia")
        .arg("--help")
        .output()
        .map(|o| o.status.success() || !o.stdout.is_empty())
        .unwrap_or(false);
    assert!(
        present,
        "cbomkit-theia 不在 PATH——本測試必須有引擎才算數，不得靜默通過"
    );
}

#[test]
#[ignore = "需要 cbomkit-theia.exe 在 PATH（CI windows-package job）"]
fn certificate_is_detected_on_windows() {
    require_theia();
    let dir = workspace("cert");
    std::fs::copy(FIXTURE_CERT, dir.join("server.crt")).unwrap();

    let inv = collect_cbom(&RealEngine, &dir.display().to_string());
    assert_eq!(inv.status, CbomStatus::Completed, "{inv:?}");
    assert!(
        inv.assets.iter().any(|a| a.asset_type == "certificate"),
        "應偵測到憑證：{:?}",
        inv.assets
    );
}

#[test]
#[ignore = "需要 cbomkit-theia.exe 在 PATH（CI windows-package job）"]
fn empty_directory_is_completed_with_zero_assets() {
    require_theia();
    let dir = workspace("empty");
    let inv = collect_cbom(&RealEngine, &dir.display().to_string());
    // 「完成且 0 項」與「失敗」必須可區分（ADR-013 決策 4）——stdout 被警告汙染時會落到 Failed
    assert_eq!(inv.status, CbomStatus::Completed, "{inv:?}");
    assert!(inv.assets.is_empty(), "{:?}", inv.assets);
}
